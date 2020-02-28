# -*- coding: utf-8 -*-
"""
Amazon S3 Fileserver Backend

.. versionadded:: 0.16.0

This backend exposes directories in S3 buckets as Salt environments. To enable
this backend, add ``s3fs`` to the :conf_master:`fileserver_backend` option in the
Master config file.

.. code-block:: yaml

    fileserver_backend:
      - s3fs

S3 credentials must also be set in the master config file:

.. code-block:: yaml

    s3.keyid: GKTADJGHEIQSXMKKRBJ08H
    s3.key: askdjghsdfjkghWupUjasdflkdfklgjsdfjajkghs

Alternatively, if on EC2 these credentials can be automatically loaded from
instance metadata.

This fileserver supports two modes of operation for the buckets:

1. :strong:`A single bucket per environment`

   .. code-block:: yaml

    s3.buckets:
      production:
        - bucket1
        - bucket2
      staging:
        - bucket3
        - bucket4

2. :strong:`Multiple environments per bucket`

   .. code-block:: yaml

    s3.buckets:
      - bucket1
      - bucket2
      - bucket3
      - bucket4

Note that bucket names must be all lowercase both in the AWS console and in
Salt, otherwise you may encounter ``SignatureDoesNotMatch`` errors.

A multiple-environment bucket must adhere to the following root directory
structure::

    s3://<bucket name>/<environment>/<files>

.. note:: This fileserver back-end requires the use of the MD5 hashing algorithm.
    MD5 may not be compliant with all security policies.

.. note:: This fileserver back-end is only compatible with MD5 ETag hashes in
    the S3 metadata. This means that you must use SSE-S3 or plaintext for
    bucket encryption, and that you must not use multipart upload when
    uploading to your bucket. More information here:
    https://docs.aws.amazon.com/AmazonS3/latest/API/RESTCommonResponseHeaders.html

    Objects without an MD5 ETag will be fetched on every fileserver update.

    If you deal with objects greater than 8MB, then you should use the
    following AWS CLI config to avoid mutipart upload:

    .. code-block::

        s3 =
          multipart_threshold = 1024MB

    More info here:
    https://docs.aws.amazon.com/AmazonS3/latest/API/RESTCommonResponseHeaders.html
"""

# Import python libs

import datetime
import os
import time
import pickle
import logging

# Import salt libs
import salt.fileserver as fs
import salt.modules
import salt.utils.files
import salt.utils.gzip_util
import salt.utils.hashutils
import salt.utils.versions

# Import 3rd-party libs
# pylint: disable=import-error,no-name-in-module,redefined-builtin
from salt.ext import six
from salt.ext.six.moves import filter
from salt.ext.six.moves.urllib.parse import quote as _quote
# pylint: enable=import-error,no-name-in-module,redefined-builtin

from hubblestack.utils.signing import find_wrapf

log = logging.getLogger(__name__)

S3_CACHE_EXPIRE = 1800  # cache for 30 minutes
S3_SYNC_ON_UPDATE = True  # sync cache on update rather than jit


def envs():
    """
    Return a list of directories within the bucket that can be
    used as environments.
    """
    # update and grab the envs from the metadata keys
    metadata = _init()
    return list(metadata.keys())


def update():
    """
    Update the cache file for the bucket.
    """
    metadata = _init()

    if S3_SYNC_ON_UPDATE and metadata:
        # sync the buckets to the local cache
        log.info('Syncing local cache from S3...')
        for saltenv, env_meta in six.iteritems(metadata):
            for bucket_files in _find_files(env_meta):
                for bucket, files in six.iteritems(bucket_files):
                    for file_path in files:
                        cached_file_path = _get_cached_file_name(bucket, saltenv, file_path)
                        log.info('%s - %s : %s', bucket, saltenv, file_path)

                        # load the file from S3 if it's not in the cache or it's old
                        _get_file_from_s3(metadata, saltenv, bucket, file_path, cached_file_path)

        log.info('Sync local cache from S3 completed.')


@find_wrapf(not_found={'bucket': None, 'path': None}, real_path='cpath')
def find_file(path, saltenv='base', **kwargs):
    """
    Look through the buckets cache file for a match.
    If the field is found, it is retrieved from S3 only if its cached version
    is missing, or if the MD5 does not match.
    """
    if 'env' in kwargs:
        # "env" is not supported; Use "saltenv".
        kwargs.pop('env')

    fnd = {'bucket': None,
           'path': None}

    metadata = _init()
    if not metadata or saltenv not in metadata:
        return fnd

    env_files = _find_files(metadata[saltenv])

    if not _is_env_per_bucket():
        path = os.path.join(saltenv, path)

    # look for the files and check if they're ignored globally
    for bucket in env_files:
        for bucket_name, files in six.iteritems(bucket):
            if path in files and not fs.is_file_ignored(__opts__, path):
                fnd['bucket'] = bucket_name
                fnd['path'] = path
                break
        else:
            continue  # only executes if we didn't break
        break

    if not fnd['path'] or not fnd['bucket']:
        return fnd

    fnd['cpath'] = _get_cached_file_name(fnd['bucket'], saltenv, path)

    try:
        # jit load the file from S3 if it's not in the cache or it's old
        _get_file_from_s3(metadata, saltenv, fnd['bucket'], path, fnd['cpath'])
    except Exception as exc:
        if not os.path.isfile(fnd['cpath']):
            raise exc

    return fnd


def file_hash(load, fnd):
    """
    Return an MD5 file hash
    """
    if 'env' in load:
        # "env" is not supported; Use "saltenv".
        load.pop('env')

    ret = {}

    if 'saltenv' not in load:
        return ret

    if 'path' not in fnd or 'bucket' not in fnd or not fnd['path']:
        return ret

    cached_file_path = _get_cached_file_name(
        fnd['bucket'],
        load['saltenv'],
        fnd['path'])

    if os.path.isfile(cached_file_path):
        ret['hsum'] = salt.utils.hashutils.get_hash(cached_file_path)
        ret['hash_type'] = 'md5'

    return ret


def serve_file(load, fnd):
    """
    Return a chunk from a file based on the data received
    """
    if 'env' in load:
        # "env" is not supported; Use "saltenv".
        load.pop('env')

    ret = {'data': '',
           'dest': ''}

    if 'path' not in load or 'loc' not in load or 'saltenv' not in load:
        return ret

    if 'path' not in fnd or 'bucket' not in fnd:
        return ret

    gzip = load.get('gzip', None)

    # get the saltenv/path file from the cache
    cached_file_path = _get_cached_file_name(
        fnd['bucket'],
        load['saltenv'],
        fnd['path'])

    ret['dest'] = _trim_env_off_path([fnd['path']], load['saltenv'])[0]

    with salt.utils.files.fopen(cached_file_path, 'rb') as fp_:
        fp_.seek(load['loc'])
        data = fp_.read(__opts__['file_buffer_size'])
        if data and six.PY3 and not salt.utils.files.is_binary(cached_file_path):
            data = data.decode(__salt_system_encoding__)
        if gzip and data:
            data = salt.utils.gzip_util.compress(data, gzip)
            ret['gzip'] = gzip
        ret['data'] = data
    return ret


def file_list(load):
    """
    Return a list of all files on the file server in a specified environment
    """
    if 'env' in load:
        # "env" is not supported; Use "saltenv".
        load.pop('env')

    ret = []

    if 'saltenv' not in load:
        return ret

    saltenv = load['saltenv']
    metadata = _init()

    if not metadata or saltenv not in metadata:
        return ret
    for bucket in _find_files(metadata[saltenv]):
        for buckets in six.itervalues(bucket):
            files = [f for f in buckets if not fs.is_file_ignored(__opts__, f)]
            ret += _trim_env_off_path(files, saltenv)

    return ret


def file_list_emptydirs(load): # pylint: disable=unused-argument ; just a todo
    """
    Return a list of all empty directories on the master
    """
    # TODO - implement this
    _init()

    return []


def dir_list(load):
    """
    Return a list of all directories on the master
    """
    if 'env' in load:
        # "env" is not supported; Use "saltenv".
        load.pop('env')

    ret = []

    if 'saltenv' not in load:
        return ret

    saltenv = load['saltenv']
    metadata = _init()

    if not metadata or saltenv not in metadata:
        return ret

    # grab all the dirs from the buckets cache file
    for bucket in _find_dirs(metadata[saltenv]):
        for dirs in six.itervalues(bucket):
            # trim env and trailing slash
            dirs = _trim_env_off_path(dirs, saltenv, trim_slash=True)
            # remove empty string left by the base env dir in single bucket mode
            ret += [_f for _f in dirs if _f]

    return ret


def _get_s3_key():
    """
    Get AWS keys from pillar or config
    """

    defaults = {
        'https_enable': True,
        'verify_ssl': True,
        'location': None,
        'path_style': None,
        'service_url': None,
        'keyid': None,
        'key': None,
        'cache_expire': S3_CACHE_EXPIRE,
    }

    ret = dict()
    for k in defaults:
        s3k = 's3.' + k
        ret[k] = __opts__.get(s3k, defaults[k])

    # kms_keyid = __opts__['aws.kmw.keyid'] if 'aws.kms.keyid' in __opts__ else None
    #
    # original was likely bugged: aws.kms.keyid is probably right, but people
    # that needed this may have entered it incorrectly to match. Support both for now.
    ret['kms_keyid'] = __opts__.get('aws.kms.keyid', __opts__.get('aws.kmw.keyid'))

    return ret


def _init():
    """
    Connect to S3 and download the metadata for each file in all buckets
    specified and cache the data to disk.
    """
    cache_file = _get_buckets_cache_filename()
    cache_expire_time = float(_get_s3_key().get('cache_expire'))
    exp = time.time() - cache_expire_time

    log.debug('S3 cache expire time is %ds', cache_expire_time)
    # check mtime of the buckets files cache
    metadata = None
    try:
        if os.path.getmtime(cache_file) > exp:
            metadata = _read_buckets_cache_file(cache_file)
    except OSError:
        pass

    if metadata is None:
        # bucket files cache expired or does not exist
        try:
            metadata = _refresh_buckets_cache_file(cache_file)
        except Exception:
            # If we failed to fetch new metadata, then try to fallback on the cache
            try:
                if os.path.isfile(cache_file):
                    metadata = _read_buckets_cache_file(cache_file)
                    return metadata
            except OSError:
                pass
            # No cache file, so raise.
            raise

    return metadata


def _get_cache_dir():
    """
    Return the path to the s3cache dir
    """
    # Or is that making too many assumptions?
    return os.path.join(__opts__['cachedir'], 's3cache')


def _get_cached_file_name(bucket_name, saltenv, path):
    """
    Return the cached file name for a bucket path file
    """
    file_path = os.path.join(_get_cache_dir(), saltenv, bucket_name, path)

    # make sure bucket and saltenv directories exist
    if not os.path.exists(os.path.dirname(file_path)):
        os.makedirs(os.path.dirname(file_path))

    return file_path


def _get_buckets_cache_filename():
    """
    Return the filename of the cache for bucket contents.
    Create the path if it does not exist.
    """
    cache_dir = _get_cache_dir()
    if not os.path.exists(cache_dir):
        os.makedirs(cache_dir)

    return os.path.join(cache_dir, 'buckets_files.cache')


def _refresh_buckets_cache_file(cache_file):
    """
    Retrieve the content of all buckets and cache the metadata to the buckets
    cache file
    """
    log.debug('Refreshing buckets cache file')

    s3_key_kwargs = _get_s3_key()
    metadata = {}

    # helper s3 query function
    def __get_s3_meta(bucket, key=s3_key_kwargs['key'], keyid=s3_key_kwargs['keyid']):
        ret, marker = [], ''
        while True:
            tmp = __utils__['s3.query'](key=key,
                                        keyid=keyid,
                                        kms_keyid=keyid,
                                        bucket=bucket,
                                        service_url=s3_key_kwargs['service_url'],
                                        verify_ssl=s3_key_kwargs['verify_ssl'],
                                        location=s3_key_kwargs['location'],
                                        return_bin=False,
                                        path_style=s3_key_kwargs['path_style'],
                                        https_enable=s3_key_kwargs['https_enable'],
                                        params={'marker': marker})
            if not tmp:
                return None

            headers = []
            for header in tmp:
                if 'Key' in header:
                    break
                headers.append(header)
            ret.extend(tmp)
            if all([header.get('IsTruncated', 'false') == 'false' for header in headers]):
                break
            marker = tmp[-1]['Key']
        return ret

    def _parse_buckets(buckets, salt_env=None):
        """
        Go over each bucket in buckets, extract metadata and update the `metadata` dict.

        ``buckets`` - list of bucket names

        ``salt_env`` - salt_env from _get_buckets();
                     - gets passed if there is a single environment per bucket
        """
        bucket_files_list = []
        for bucket_name in buckets:
            s3_meta = __get_s3_meta(bucket_name)

            # s3 query returned nothing
            if not s3_meta:
                continue

            # grab only the files/dirs
            files = [k for k in s3_meta if 'Key' in k]
            bucket_files_list.append({bucket_name: files})

            # check to see if we added any keys, otherwise investigate possible error conditions
            if not files:
                meta_response = {}
                for k in s3_meta:
                    if 'Code' in k or 'Message' in k:
                        # assumes no duplicate keys, consisdent with current error response.
                        meta_response.update(k)
                # attempt use of human readable output first.
                try:
                    log.warning(
                        "'%s' response for bucket '%s'", meta_response['Message'], bucket_name)
                    continue
                except KeyError:
                    # no human readable error message provided
                    if 'Code' in meta_response:
                        log.warning(
                            "'%s' response for bucket '%s'", meta_response['Code'], bucket_name)
                        continue
                    else:
                        log.warning('S3 Error! Do you have any files in your S3 bucket?')
                        return {}

            # one environment per bucket, nothing left to parse
            if salt_env:
                continue

            environments = set([(os.path.dirname(k['Key']).split('/', 1))[0] for k in files])

            # pull out the files for the environment
            _parse_env(environments=environments, bucket_name=bucket_name, files=files)

        if salt_env:
            metadata[salt_env] = bucket_files_list

        return True

    def _parse_env(environments, bucket_name, files):
        """
        Go over each saltenv in environments, grab the files that
        match the saltenv and add them to the metadata dict
        """
        for saltenv in environments:
            # grab only files/dirs that match this saltenv
            env_files = [k for k in files if k['Key'].startswith(saltenv)]

            if saltenv not in metadata:
                metadata[saltenv] = []

            found = False
            for bucket_files in metadata[saltenv]:
                if bucket_name in bucket_files:
                    bucket_files[bucket_name] += env_files
                    found = True
                    break
            if not found:
                metadata[saltenv].append({bucket_name: env_files})

    if _is_env_per_bucket():
        # Single environment per bucket
        for saltenv, buckets in six.iteritems(_get_buckets()):
            ret = _parse_buckets(buckets=buckets, salt_env=saltenv)
            # S3 error
            if not ret:
                return ret

    else:
        # Multiple environments per buckets
        ret = _parse_buckets(buckets=_get_buckets())
        # S3 error
        if not ret:
            return ret

    # write the metadata to disk
    if os.path.isfile(cache_file):
        os.remove(cache_file)

    log.debug('Writing buckets cache file')

    with salt.utils.files.fopen(cache_file, 'wb') as fp_:
        pickle.dump(metadata, fp_)

    return metadata


def _read_buckets_cache_file(cache_file):
    """
    Return the contents of the buckets cache file
    """
    log.debug('Reading buckets cache file')

    with salt.utils.files.fopen(cache_file, 'rb') as fp_:
        try:
            data = pickle.load(fp_)
            # check for 'corrupted' cache data ex: {u'base':[]}
            if not any(data.values()):
                data = None

        except (pickle.UnpicklingError, AttributeError, EOFError, ImportError,
                IndexError, KeyError) as eobj:
            log.info('error unpickling buckets cache file (%s): %s',
                cache_file, repr(eobj))
            data = None

    return data


def _find_files(metadata):
    """
    Looks for all the files in the S3 bucket cache metadata
    """
    ret = []
    found = {}

    for bucket_dict in metadata:
        for bucket_name, data in six.iteritems(bucket_dict):
            file_paths = [k['Key'] for k in data]
            file_paths = [k for k in file_paths if not k.endswith('/')]
            if bucket_name not in found:
                found[bucket_name] = True
                ret.append({bucket_name: file_paths})
            else:
                for bucket in ret:
                    if bucket_name in bucket:
                        bucket[bucket_name] += file_paths
                        break
    return ret


def _find_dirs(metadata):
    """
    Looks for all the directories in the S3 bucket cache metadata.

    Supports trailing '/' keys (as created by S3 console) as well as
    directories discovered in the path of file keys.
    """
    ret = []
    found = {}

    for bucket_dict in metadata:
        for bucket_name, data in six.iteritems(bucket_dict):
            dir_paths = set()
            for path in [k['Key'] for k in data]:
                prefix = ''
                for part in path.split('/')[:-1]:
                    directory = prefix + part + '/'
                    dir_paths.add(directory)
                    prefix = directory
            if bucket_name not in found:
                found[bucket_name] = True
                ret.append({bucket_name: list(dir_paths)})
            else:
                for bucket in ret:
                    if bucket_name in bucket:
                        bucket[bucket_name] += list(dir_paths)
                        bucket[bucket_name] = list(set(bucket[bucket_name]))
                        break
    return ret


def _find_file_meta(metadata, bucket_name, saltenv, path):
    """
    Looks for a file's metadata in the S3 bucket cache file
    """
    env_meta = metadata[saltenv] if saltenv in metadata else {}
    bucket_meta = {}
    for bucket in env_meta:
        if bucket_name in bucket:
            bucket_meta = bucket[bucket_name]
    files_meta = list(list(filter((lambda k: 'Key' in k), bucket_meta)))

    for item_meta in files_meta:
        if 'Key' in item_meta and item_meta['Key'] == path:
            try:
                # Get rid of quotes surrounding md5
                item_meta['ETag'] = item_meta['ETag'].strip('"')
            except KeyError:
                pass
            return item_meta

    return None


def _get_buckets():
    """
    Return the configuration buckets
    """

    return __opts__['s3.buckets'] if 's3.buckets' in __opts__ else {}


def _get_file_from_s3(metadata, saltenv, bucket_name, path, cached_file_path):
    """
    Checks the local cache for the file, if it's old or missing go grab the
    file from S3 and update the cache
    """
    s3_key_kwargs = _get_s3_key()

    def _get_file():
        """
        Helper function that gets the file from S3 and checks if it can be skipped.
        Returns True if the file was downloaded and False if the download was skipped.
        """
        ret = __utils__['s3.query'](
            key=s3_key_kwargs['key'],
            keyid=s3_key_kwargs['keyid'],
            kms_keyid=s3_key_kwargs['keyid'],
            method='HEAD',
            bucket=bucket_name,
            service_url=s3_key_kwargs['service_url'],
            verify_ssl=s3_key_kwargs['verify_ssl'],
            location=s3_key_kwargs['location'],
            path=_quote(path),
            local_file=cached_file_path,
            full_headers=True,
            path_style=s3_key_kwargs['path_style'],
            https_enable=s3_key_kwargs['https_enable'])
        if ret:
            for header_name, header_value in ret['headers'].items():
                header_name = header_name.strip()
                header_value = header_value.strip()
                if six.text_type(header_name).lower() == 'last-modified':
                    s3_file_mtime = datetime.datetime.strptime(
                        header_value, '%a, %d %b %Y %H:%M:%S %Z')
                elif six.text_type(header_name).lower() == 'content-length':
                    s3_file_size = int(header_value)
            if cached_file_data['size'] == s3_file_size and \
                    cached_file_data['mtime'] > s3_file_mtime:
                log.info(
                    '%s - %s : %s skipped download since cached file size '
                    'equal to and mtime after s3 values',
                    bucket_name, saltenv, path)
                return False
        return True

    # check the local cache...
    if os.path.isfile(cached_file_path):
        file_meta = _find_file_meta(metadata, bucket_name, saltenv, path)
        if file_meta:
            if file_meta['ETag'].find('-') == -1:
                cached_md5 = salt.utils.hashutils.get_hash(cached_file_path, 'md5')

                # hashes match we have a cache hit
                if cached_md5 == file_meta['ETag']:
                    return
            else:
                cached_file_stat = os.stat(cached_file_path)
                cached_file_data = {
                    'size': cached_file_stat.st_size,
                    'mtime': datetime.datetime.fromtimestamp(cached_file_stat.st_mtime),
                    'lastmod': datetime.datetime.strptime(
                        file_meta['LastModified'], '%Y-%m-%dT%H:%M:%S.%fZ')}

                if (cached_file_data['size'] == int(file_meta['Size']) and
                        cached_file_data['mtime'] > cached_file_data['lastmod']):
                    log.debug('cached file size equal to metadata size and '
                              'cached file mtime later than metadata last '
                              'modification time.')
                    if not _get_file():
                        # skipped download
                        return

    # ... or get the file from S3
    __utils__['s3.query'](
        key=s3_key_kwargs['key'],
        keyid=s3_key_kwargs['keyid'],
        kms_keyid=s3_key_kwargs['keyid'],
        bucket=bucket_name,
        service_url=s3_key_kwargs['service_url'],
        verify_ssl=s3_key_kwargs['verify_ssl'],
        location=s3_key_kwargs['location'],
        path=_quote(path),
        local_file=cached_file_path,
        path_style=s3_key_kwargs['path_style'],
        https_enable=s3_key_kwargs['https_enable'],
    )


def _trim_env_off_path(paths, saltenv, trim_slash=False):
    """
    Return a list of file paths with the saltenv directory removed
    """
    env_len = None if _is_env_per_bucket() else len(saltenv) + 1
    slash_len = -1 if trim_slash else None

    return [d[env_len:slash_len] for d in paths]


def _is_env_per_bucket():
    """
    Return the configuration mode, either buckets per environment or a list of
    buckets that have environment dirs in their root
    """
    buckets = _get_buckets()
    if isinstance(buckets, dict):
        return True
    elif isinstance(buckets, list):
        return False
    else:
        raise ValueError('Incorrect s3.buckets type given in config')
