# -*- coding: utf-8 -*-
"""
The backend for serving files from the Azure blob storage service.

To enable, add ``azurefs`` to the :conf_master:`fileserver_backend` option in
the Master config file.

.. code-block:: yaml

    fileserver_backend:
      - azurefs

Starting in Oxygen, this fileserver requires the standalone Azure Storage SDK
for Python. Due to recent changes in the structure of the azure storage SDK,
we now require the azure base library at 3.0 or higher, with the azure-storage-blob
and azure-storage-common libraries.

Each storage container will be mapped to an environment. By default, containers
will be mapped to the ``base`` environment. You can override this behavior with
the ``saltenv`` configuration option. You can have an unlimited number of
storage containers, and can have a storage container serve multiple
environments, or have multiple storage containers mapped to the same
environment. Normal first-found rules apply, and storage containers are
searched in the order they are defined.

You must have either an account_key or a sas_token defined for each container,
if it is private. If you use a sas_token, it must have READ and LIST
permissions. Proxy can also be provided in the configuration.

.. code-block:: yaml

    azurefs:
      - account_name: my_storage
        account_key: 'fNH9cRp0+qVIVYZ+5rnZAhHc9ycOUcJnHtzpfOr0W0sxrtL2KVLuMe1xDfLwmfed+JJInZaEdWVCPHD4d/oqeA=='
        container_name: my_container
        proxy: 10.10.10.10:8080
      - account_name: my_storage
        sas_token: 'ss=b&sp=&sv=2015-07-08&sig=cohxXabx8FQdXsSEHyUXMjsSfNH2tZ2OB97Ou44pkRE%3D&srt=co&se=2017-04-18T21%3A38%3A01Z'
        container_name: my_dev_container
        saltenv: dev
      - account_name: my_storage
        container_name: my_public_container

.. note::

    Do not include the leading ? for sas_token if generated from the web
"""

import base64
import json
import logging
import os
import os.path
import shutil

import hubblestack.fileserver
import hubblestack.utils.files
import hubblestack.utils.gzip_util
import hubblestack.utils.hashutils
from hubblestack.utils.signing_utils import find_file_func_wrapper

try:
    from azure.storage.blob import BlobServiceClient

    HAS_AZURE = True
except ImportError:
    HAS_AZURE = False

__virtualname__ = "azurefs"

# Setting azure logger to warn, as it logs every GET request and params
az_log = logging.getLogger("azure")
az_log.setLevel(logging.WARN)

# app logger
log = logging.getLogger()


def __virtual__():
    """
    Only load if defined in fileserver_backend and azure.storage.common is present
    """
    if __virtualname__ not in __opts__["fileserver_backend"]:
        return False

    if not HAS_AZURE:
        return False

    if "azurefs" not in __opts__:
        return False

    if not _validate_config():
        return False

    return True


@find_file_func_wrapper(not_found={"path": "", "rel": ""})
def find_file(path, saltenv="base", **kwargs):  # pylint: disable=unused-argument
    """
    Search the environment for the relative path
    """
    fnd = {"path": "", "rel": ""}
    for container in __opts__.get("azurefs", []):
        if container.get("saltenv", "base") != saltenv:
            continue
        full = os.path.join(_get_container_path(container), path)
        if os.path.isfile(full) and not hubblestack.fileserver.is_file_ignored(__opts__, path):
            fnd["path"] = full
            fnd["rel"] = path
            try:
                # Converting the stat result to a list, the elements of the
                # list correspond to the following stat_result params:
                # 0 => st_mode=33188
                # 1 => st_ino=10227377
                # 2 => st_dev=65026
                # 3 => st_nlink=1
                # 4 => st_uid=1000
                # 5 => st_gid=1000
                # 6 => st_size=1056233
                # 7 => st_atime=1468284229
                # 8 => st_mtime=1456338235
                # 9 => st_ctime=1456338235
                fnd["stat"] = list(os.stat(full))
            except Exception:
                pass
            return fnd
    return fnd


def envs():
    """
    Each container configuration can have an environment setting, or defaults
    to base
    """
    saltenvs = []
    for container in __opts__.get("azurefs", []):
        saltenvs.append(container.get("saltenv", "base"))
    # Remove duplicates
    return list(set(saltenvs))


def serve_file(load, fnd):
    """
    Return a chunk from a file based on the data received
    """
    ret = {"data": "", "dest": ""}
    required_load_keys = set(["path", "loc", "saltenv"])
    if not all(x in load for x in required_load_keys):
        log.debug(
            "Not all of the required keys present in payload. "
            "Missing: {0}".format(", ".join(required_load_keys.difference(load)))
        )
        return ret
    if not fnd["path"]:
        return ret
    ret["dest"] = fnd["rel"]
    gzip = load.get("gzip", None)
    fpath = os.path.normpath(fnd["path"])
    with hubblestack.utils.files.fopen(fpath, "rb") as fp_:
        fp_.seek(load["loc"])
        data = fp_.read(__opts__["file_buffer_size"])
        if data and not hubblestack.utils.files.is_binary(fpath):
            data = data.decode(__salt_system_encoding__)
        if gzip and data:
            data = hubblestack.utils.gzip_util.compress(data, gzip)
            ret["gzip"] = gzip
        ret["data"] = data
    return ret


def update():
    """
    Update caches of the storage containers.

    Compares the md5 of the files on disk to the md5 of the blobs in the
    container, and only updates if necessary.

    Also processes deletions by walking the container caches and comparing
    with the list of blobs in the container
    """
    log.info("Updating cache of azure container")
    for container in __opts__["azurefs"]:
        path = _get_container_path(container)
        try:
            if not os.path.exists(path):
                os.makedirs(path)
            elif not os.path.isdir(path):
                shutil.rmtree(path)
                os.makedirs(path)
        except Exception as exc:
            log.exception("Error occurred creating cache directory for azurefs")
            continue
        blob_service = _get_container_service(container)
        name = container["container_name"]
        blobs_data = []
        try:
            blob_list = blob_service.list_blobs()
            for blob in blob_list:
                # list_blobs returns an iterator
                # and we iterate over it more than once
                blobs_data.append(blob)
        except Exception as exc:
            log.exception("Error occurred fetching blob list for azurefs")

            if not __opts__["delete_inaccessible_azure_containers"] or (
                not "<class 'azure.common.AzureHttpError'>" in str(type(exc))
                and not "<class 'azure.common.AzureMissingResourceHttpError'>" in str(type(exc))
            ):
                continue

            if (
                "<Code>AuthenticationFailed</Code>" in str(exc)
                or "<Code>AuthorizationPermissionMismatch</Code>" in str(exc)
                or "<Code>ContainerNotFound</Code>" in str(exc)
            ):

                log.debug('Could not connect to azure container "{0}"'.format(name))
                container_cache_folder = _get_container_path(container)
                log.debug('Trying to delete the cache of container "{0}"'.format(name))
                try:
                    container_cachedir = os.path.join(__opts__["cachedir"], "azurefs", container_cache_folder)
                    container_filelist = container_cachedir + ".list"
                    if os.path.exists(container_cachedir):
                        shutil.rmtree(container_cachedir)
                    if os.path.exists(container_filelist):
                        os.remove(container_filelist)
                except Exception:
                    log.exception('Problem occurred trying to invalidate cache for container "{0}"'.format(name))
            continue

        # Walk the cache directory searching for deletions
        blob_names = [blob.name for blob in blobs_data]
        blob_set = set(blob_names)
        for root, dirs, files in os.walk(path):
            for f in files:
                fname = os.path.join(root, f)
                relpath = os.path.relpath(fname, path)
                if relpath not in blob_set:
                    hubblestack.fileserver.wait_lock(fname + ".lk", fname)
                    try:
                        os.unlink(fname)
                    except Exception:
                        pass
            if not dirs and not files:
                shutil.rmtree(root)

        for blob in blobs_data:
            fname = os.path.join(path, blob.name)
            update = False
            if os.path.exists(fname):
                # File exists, check the hashes
                source_md5 = blob.content_settings.content_md5
                local_md5_hex = hubblestack.utils.hashutils.get_hash(fname, "md5")
                local_md5 = base64.b64encode(bytes.fromhex(local_md5_hex))
                if local_md5 != source_md5:
                    update = True
            else:
                update = True

            if update:
                if not os.path.exists(os.path.dirname(fname)):
                    os.makedirs(os.path.dirname(fname))
                # Lock writes
                lk_fn = fname + ".lk"
                hubblestack.fileserver.wait_lock(lk_fn, fname)
                with hubblestack.utils.files.fopen(lk_fn, "w+") as fp_:
                    fp_.write("")

                try:
                    blob_client = blob_service.get_blob_client(blob)

                    with open(fname, "wb") as download_file:
                        download_file.write(blob_client.download_blob().readall())
                except Exception as exc:
                    log.exception("Error occurred fetching blob from azurefs")

                    if not __opts__["delete_inaccessible_azure_containers"] or (
                        not "<class 'azure.common.AzureHttpError'>" in str(type(exc))
                        and not "<class 'azure.common.AzureMissingResourceHttpError'>" in str(type(exc))
                    ):
                        continue

                    if (
                        "<Code>AuthenticationFailed</Code>" in str(exc)
                        or "<Code>AuthorizationPermissionMismatch</Code>" in str(exc)
                        or "<Code>ContainerNotFound</Code>" in str(exc)
                    ):

                        try:
                            if os.path.exists(fname):
                                os.remove(fname)
                                os.unlink(lk_fn)
                        except Exception:
                            log.exception('Problem occurred trying to delete the corrupt file "{0}"'.format(fname))
                    continue

                # Unlock writes
                try:
                    os.unlink(lk_fn)
                except Exception:
                    pass

        # Write out file list
        container_list = path + ".list"
        lk_fn = container_list + ".lk"
        hubblestack.fileserver.wait_lock(lk_fn, container_list)
        with hubblestack.utils.files.fopen(lk_fn, "w+") as fp_:
            fp_.write("")
        with hubblestack.utils.files.fopen(container_list, "w") as fp_:
            fp_.write(json.dumps(blob_names))
        try:
            os.unlink(lk_fn)
        except Exception:
            pass
        try:
            # Do not move this statement above 'delete_inaccessible_azure_containers' logic.
            hash_cachedir = os.path.join(__opts__["cachedir"], "azurefs", "hashes")
            if os.path.exists(hash_cachedir):
                shutil.rmtree(hash_cachedir)
        except Exception:
            log.exception("Problem occurred trying to invalidate hash cach for azurefs")


def file_hash(load, fnd):
    """
    Return a file hash based on the hash type set in the master config
    """
    if not all(x in load for x in ("path", "saltenv")):
        return "", None
    ret = {"hash_type": __opts__["hash_type"]}
    relpath = fnd["rel"]
    path = fnd["path"]
    hash_cachedir = os.path.join(__opts__["cachedir"], "azurefs", "hashes")
    hashdest = hubblestack.utils.path.join(
        hash_cachedir, load["saltenv"], "{0}.hash.{1}".format(relpath, __opts__["hash_type"])
    )
    if not os.path.isfile(hashdest):
        if not os.path.exists(os.path.dirname(hashdest)):
            os.makedirs(os.path.dirname(hashdest))
        ret["hsum"] = hubblestack.utils.hashutils.get_hash(path, __opts__["hash_type"])
        with hubblestack.utils.files.fopen(hashdest, "w+") as fp_:
            fp_.write(ret["hsum"])
        return ret
    else:
        with hubblestack.utils.files.fopen(hashdest, "rb") as fp_:
            ret["hsum"] = fp_.read()
        return ret


def file_list(load):
    """
    Return a list of all files in a specified environment
    """
    ret = set()
    try:
        for container in __opts__["azurefs"]:
            if container.get("saltenv", "base") != load["saltenv"]:
                continue
            container_list = _get_container_path(container) + ".list"
            with_lk_extension = container_list + ".lk"
            hubblestack.fileserver.wait_lock(with_lk_extension, container_list, 5)
            if not os.path.exists(container_list):
                continue
            with hubblestack.utils.files.fopen(container_list, "r") as fp_:
                ret.update(set(json.load(fp_)))
    except Exception as exc:
        log.error(
            "azurefs: an error ocurred retrieving file lists. "
            "It should be resolved next time the fileserver "
            "updates. Please do not manually modify the azurefs "
            "cache directory."
        )
    return list(ret)


def dir_list(load):
    """
    Return a list of all directories in a specified environment
    """
    ret = set()
    files = file_list(load)
    for f in files:
        dirname = f
        while dirname:
            dirname = os.path.dirname(dirname)
            if dirname:
                ret.add(dirname)
    return list(ret)


def _get_container_path(container):
    """
    Get the cache path for the container in question

    Cache paths are generate by combining the account name, container name,
    and saltenv, separated by underscores
    """
    root = os.path.join(__opts__["cachedir"], "azurefs")
    container_dir = "{0}_{1}_{2}".format(
        container.get("account_name", ""), container.get("container_name", ""), container.get("saltenv", "base")
    )
    return os.path.join(root, container_dir)


def _get_container_service(container):
    """
    Get the azure block blob service for the container in question

    Try account_key, sas_token, and no auth in that order
    """
    # the account_url_suffix can be provided via config. Defaults to "blob.core.windows.net"
    account_url_suffix = container.get("account_url_suffix", "blob.core.windows.net")
    account_url = f'https://{container["account_name"]}.{account_url_suffix}'

    proxies = None
    if "proxy" in container:
        proxies = {"http": container["proxy"]}
    # If 'proxy' isn't specified in container block, check if 'https_proxy' is set.
    elif "https_proxy" in __opts__:
        proxies = {"https": __opts__["https_proxy"]}

    # instantiate based upon credential
    if "account_key" in container:
        blob_service = BlobServiceClient(account_url=account_url, credential=container["account_key"], proxies=proxies)
    elif "sas_token" in container:
        blob_service = BlobServiceClient(account_url=account_url, credential=container["sas_token"], proxies=proxies)
    else:
        blob_service = BlobServiceClient(account_url=account_url, proxies=proxies)

    return blob_service.get_container_client(container["container_name"])


def _validate_config():
    """
    Validate azurefs config, return False if it doesn't validate
    """
    if not isinstance(__opts__["azurefs"], list):
        log.error("azurefs configuration is not formed as a list, skipping azurefs")
        return False
    for container in __opts__["azurefs"]:
        if not isinstance(container, dict):
            log.error(
                "One or more entries in the azurefs configuration list "
                "are not formed as a dict. Skipping azurefs: {0}".format(container)
            )
            return False
        if "account_name" not in container or "container_name" not in container:
            log.error(
                "An azurefs container configuration is missing either "
                "an account_name or a container_name: {0}".format(container)
            )
            return False
    return True
