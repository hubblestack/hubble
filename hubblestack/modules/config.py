# -*- coding: utf-8 -*-
'''
Return config information
'''

# Import python libs
from __future__ import absolute_import, print_function, unicode_literals
import copy
import re
import os
import logging

# Import salt libs
import hubblestack.config
import hubblestack.utils.data
import hubblestack.utils.dictupdate
import hubblestack.utils.files
import hubblestack.utils.platform
try:
    # Gated for salt-ssh (hubblestack.utils.cloud imports msgpack)
    import hubblestack.utils.cloud
    HAS_CLOUD = True
except ImportError:
    HAS_CLOUD = False

import hubblestack._compat
import hubblestack.syspaths as syspaths

# Import 3rd-party libs
from hubblestack.ext import six

if hubblestack.utils.platform.is_windows():
    _HOSTS_FILE = os.path.join(
        os.environ['SystemRoot'], 'System32', 'drivers', 'etc', 'hosts')
else:
    _HOSTS_FILE = os.path.join(os.sep, 'etc', 'hosts')

log = logging.getLogger(__name__)

__proxyenabled__ = ['*']

# Set up the default values for all systems
DEFAULTS = {'mongo.db': 'salt',
            'mongo.password': '',
            'mongo.port': 27017,
            'mongo.user': '',
            'redis.db': '0',
            'redis.host': 'salt',
            'redis.port': 6379,
            'test.foo': 'unconfigured',
            'ca.cert_base_path': '/etc/pki',
            'solr.cores': [],
            'solr.host': 'localhost',
            'solr.port': '8983',
            'solr.baseurl': '/solr',
            'solr.type': 'master',
            'solr.request_timeout': None,
            'solr.init_script': '/etc/rc.d/solr',
            'solr.dih.import_options': {'clean': False, 'optimize': True,
                                        'commit': True, 'verbose': False},
            'solr.backup_path': None,
            'solr.num_backups': 1,
            'poudriere.config': '/usr/local/etc/poudriere.conf',
            'poudriere.config_dir': '/usr/local/etc/poudriere.d',
            'ldap.uri': '',
            'ldap.server': 'localhost',
            'ldap.port': '389',
            'ldap.tls': False,
            'ldap.no_verify': False,
            'ldap.anonymous': True,
            'ldap.scope': 2,
            'ldap.attrs': None,
            'ldap.binddn': '',
            'ldap.bindpw': '',
            'hosts.file': _HOSTS_FILE,
            'aliases.file': '/etc/aliases',
            'virt': {'tunnel': False,
                     'images': os.path.join(syspaths.SRV_ROOT_DIR, 'salt-images')},
            }


def backup_mode(backup=''):
    '''
    Return the backup mode

    CLI Example:

    .. code-block:: bash

        salt '*' config.backup_mode
    '''
    if backup:
        return backup
    return option('backup_mode')


def manage_mode(mode):
    '''
    Return a mode value, normalized to a string

    CLI Example:

    .. code-block:: bash

        salt '*' config.manage_mode
    '''
    # config.manage_mode should no longer be invoked from the __salt__ dunder
    # in Salt code, this function is only being left here for backwards
    # compatibility.
    return hubblestack.utils.files.normalize_mode(mode)


def valid_fileproto(uri):
    '''
    Returns a boolean value based on whether or not the URI passed has a valid
    remote file protocol designation

    CLI Example:

    .. code-block:: bash

        salt '*' config.valid_fileproto salt://path/to/file
    '''
    try:
        return bool(re.match('^(?:salt|https?|ftp)://', uri))
    except Exception:
        return False


def option(
        value,
        default='',
        omit_opts=False,
        omit_master=False,
        omit_pillar=False):
    '''
    Pass in a generic option and receive the value that will be assigned

    CLI Example:

    .. code-block:: bash

        salt '*' config.option redis.host
    '''
    if not omit_opts:
        if value in __opts__:
            return __opts__[value]
    if not omit_master:
        if value in __pillar__.get('master', {}):
            return __pillar__['master'][value]
    if not omit_pillar:
        if value in __pillar__:
            return __pillar__[value]
    if value in DEFAULTS:
        return DEFAULTS[value]
    return default


def merge(value,
          default='',
          omit_opts=False,
          omit_master=False,
          omit_pillar=False):
    '''
    Retrieves an option based on key, merging all matches.

    Same as ``option()`` except that it merges all matches, rather than taking
    the first match.

    CLI Example:

    .. code-block:: bash

        salt '*' config.merge schedule
    '''
    ret = None
    if not omit_opts:
        if value in __opts__:
            ret = __opts__[value]
            if isinstance(ret, six.string_types):
                return ret
    if not omit_master:
        if value in __pillar__.get('master', {}):
            tmp = __pillar__['master'][value]
            if ret is None:
                ret = tmp
                if isinstance(ret, six.string_types):
                    return ret
            elif isinstance(ret, dict) and isinstance(tmp, dict):
                tmp.update(ret)
                ret = tmp
            elif isinstance(ret, (list, tuple)) and isinstance(tmp,
                                                               (list, tuple)):
                ret = list(ret) + list(tmp)
    if not omit_pillar:
        if value in __pillar__:
            tmp = __pillar__[value]
            if ret is None:
                ret = tmp
                if isinstance(ret, six.string_types):
                    return ret
            elif isinstance(ret, dict) and isinstance(tmp, dict):
                tmp.update(ret)
                ret = tmp
            elif isinstance(ret, (list, tuple)) and isinstance(tmp,
                                                               (list, tuple)):
                ret = list(ret) + list(tmp)
    if ret is None and value in DEFAULTS:
        return DEFAULTS[value]
    if ret is None:
        return default
    return ret


def get(key, default='', delimiter=':', omit_opts=False, omit_grains=False):
    '''
    .. versionadded: 0.14.0

    Attempt to retrieve the named value from the minion config file, pillar,
    grains or the master config. If the named value is not available, return the
    value specified by ``default``. If not specified, the default is an empty
    string.

    Values can also be retrieved from nested dictionaries. Assume the below
    data structure:

    .. code-block:: python

        {'pkg': {'apache': 'httpd'}}

    To retrieve the value associated with the ``apache`` key, in the
    sub-dictionary corresponding to the ``pkg`` key, the following command can
    be used:

    .. code-block:: bash

        salt myminion config.get pkg:apache

    The ``:`` (colon) is used to represent a nested dictionary level.

    .. versionchanged:: 2015.5.0
        The ``delimiter`` argument was added, to allow delimiters other than
        ``:`` to be used.

    This function traverses these data stores in this order, returning the
    first match found:

    - Minion configuration
    - Minion's grains
    - Minion's pillar data
    - Master configuration (requires :conf_minion:`pillar_opts` to be set to
      ``True`` in Minion config file in order to work)

    This means that if there is a value that is going to be the same for the
    majority of minions, it can be configured in the Master config file, and
    then overridden using the grains, pillar, or Minion config file.

    Adding config options to the Master or Minion configuration file is easy:

    .. code-block:: yaml

        my-config-option: value
        cafe-menu:
          - egg and bacon
          - egg sausage and bacon
          - egg and spam
          - egg bacon and spam
          - egg bacon sausage and spam
          - spam bacon sausage and spam
          - spam egg spam spam bacon and spam
          - spam sausage spam spam bacon spam tomato and spam

    .. note::
        Minion configuration options built into Salt (like those defined
        :ref:`here <configuration-salt-minion>`) will *always* be defined in
        the Minion configuration and thus *cannot be overridden by grains or
        pillar data*. However, additional (user-defined) configuration options
        (as in the above example) will not be in the Minion configuration by
        default and thus can be overridden using grains/pillar data by leaving
        the option out of the minion config file.

    **Arguments**

    delimiter
        .. versionadded:: 2015.5.0

        Override the delimiter used to separate nested levels of a data
        structure.
    '''

    if not omit_opts:
        ret = hubblestack.utils.data.traverse_dict_and_list(
            __opts__,
            key,
            '_|-',
            delimiter=delimiter)

    if not omit_grains:
        ret = hubblestack.utils.data.traverse_dict_and_list(
            __grains__,
            key,
            '_|-',
            delimiter)

    ret = hubblestack.utils.data.traverse_dict_and_list(
        DEFAULTS,
        key,
        '_|-',
        delimiter=delimiter)

    return default


def dot_vals(value):
    '''
    Pass in a configuration value that should be preceded by the module name
    and a dot, this will return a list of all read key/value pairs

    CLI Example:

    .. code-block:: bash

        salt '*' config.dot_vals host
    '''
    ret = {}
    for key, val in six.iteritems(__pillar__.get('master', {})):
        if key.startswith('{0}.'.format(value)):
            ret[key] = val
    for key, val in six.iteritems(__opts__):
        if key.startswith('{0}.'.format(value)):
            ret[key] = val
    return ret


def items():
    '''
    Return the complete config from the currently running minion process.
    This includes defaults for values not set in the config file.

    CLI Example:

    .. code-block:: bash

        salt '*' config.items
    '''
    return __opts__
