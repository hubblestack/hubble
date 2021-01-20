# -*- coding: utf-8 -*-
"""
All Hubble configuration loading and defaults should be in this module
"""

# Import python libs
import os
import re
import sys
import glob
import time
import codecs
import logging
import types
from copy import deepcopy

import hubblestack.utils.data
import hubblestack.utils.dictupdate
import hubblestack.utils.files
import hubblestack.utils.network
import hubblestack.utils.path
import hubblestack.utils.platform
import hubblestack.utils.stringutils
import hubblestack.utils.user
import hubblestack.utils.validate.path
import hubblestack.utils.yaml
import hubblestack.syspaths
import hubblestack.defaults.exitcodes
import hubblestack.utils.builtin_hacking

from hubblestack.exceptions import HubbleConfigurationError
from hubblestack.utils.url import urlparse

try:
    import psutil

    if not hasattr(psutil, "virtual_memory"):
        raise ImportError("Version of psutil too old.")
    HAS_PSUTIL = True
except ImportError:
    HAS_PSUTIL = False

log = logging.getLogger(__name__)

_DFLT_LOG_DATEFMT = "%H:%M:%S"
_DFLT_LOG_DATEFMT_LOGFILE = "%Y-%m-%d %H:%M:%S"
_DFLT_LOG_FMT_CONSOLE = "[%(levelname)-8s] %(message)s"
_DFLT_LOG_FMT_LOGFILE = "%(asctime)s,%(msecs)03d [%(name)-17s:%(lineno)-4d][%(levelname)-8s][%(process)d] %(message)s"
_DFLT_LOG_FMT_JID = "[JID: %(jid)s]"
_DFLT_REFSPECS = ["+refs/heads/*:refs/remotes/origin/*", "+refs/tags/*:refs/tags/*"]
DEFAULT_INTERVAL = 60

if hubblestack.utils.platform.is_windows():
    # Since an 'ipc_mode' of 'ipc' will never work on Windows due to lack of
    # support in ZeroMQ, we want the default to be something that has a
    # chance of working.
    _DFLT_IPC_MODE = "tcp"
else:
    _DFLT_IPC_MODE = "ipc"


def _gather_buffer_space():
    """
    Gather some system data and then calculate
    buffer space.

    Result is in bytes.
    """
    if HAS_PSUTIL and psutil.version_info >= (0, 6, 0):
        # Oh good, we have psutil. This will be quick.
        total_mem = psutil.virtual_memory().total
    else:
        # Avoid loading core grains unless absolutely required
        import hubblestack.grains.hubble_core as core

        # We need to load up ``mem_total`` grain. Let's mimic required OS data.
        if not hasattr(core, '__opts__'):
            core.__opts__ = dict()
        grains = core._memdata(core.os_data())
        total_mem = grains["mem_total"]
    # Return the higher number between 5% of the system memory and 10MiB
    return max([total_mem * 0.05, 10 << 20])


# For the time being this will be a fixed calculation
# TODO: Allow user configuration
_DFLT_IPC_WBUFFER = _gather_buffer_space() * 0.5
# TODO: Reserved for future use
_DFLT_IPC_RBUFFER = _gather_buffer_space() * 0.5

VALID_OPTS = {
    # The address of the salt master. May be specified as IP address or hostname
    "master": (str, list),
    # The TCP/UDP port of the master to connect to in order to listen to publications
    "master_port": (str, int),
    # The behaviour of the minion when connecting to a master. Can specify 'failover',
    # 'disable', 'distributed', or 'func'. If 'func' is specified, the 'master' option should be
    # set to an exec module function to run to determine the master hostname. If 'disable' is
    # specified the minion will run, but will not try to connect to a master. If 'distributed'
    # is specified the minion will try to deterministically pick a master based on its' id.
    "master_type": str,
    # Specify the format in which the master address will be specified. Can
    # specify 'default' or 'ip_only'. If 'ip_only' is specified, then the
    # master address will not be split into IP and PORT.
    "master_uri_format": str,
    # The following optiosn refer to the Minion only, and they specify
    # the details of the source address / port to be used when connecting to
    # the Master. This is useful when dealing withmachines where due to firewall
    # rules you are restricted to use a certain IP/port combination only.
    "source_interface_name": str,
    "source_address": str,
    "source_ret_port": (str, int),
    "source_publish_port": (str, int),
    # The fingerprint of the master key may be specified to increase security. Generate
    # a master fingerprint with `salt-key -F master`
    "master_finger": str,
    # When in multi-master mode, temporarily remove a master from the list if a conenction
    # is interrupted and try another master in the list.
    "master_alive_interval": int,
    # When in multi-master failover mode, fail back to the first master in the list if it's back
    # online.
    "master_failback": bool,
    # When in multi-master mode, and master_failback is enabled ping the top master with this
    # interval.
    "master_failback_interval": int,
    # The name of the signing key-pair
    "master_sign_key_name": str,
    # Sign the master auth-replies with a cryptographic signature of the masters public key.
    "master_sign_pubkey": bool,
    # Enables verification of the master-public-signature returned by the master in auth-replies.
    # Must also set master_sign_pubkey for this to work
    "verify_master_pubkey_sign": bool,
    # If verify_master_pubkey_sign is enabled, the signature is only verified, if the public-key of
    # the master changes. If the signature should always be verified, this can be set to True.
    "always_verify_signature": bool,
    # The name of the file in the masters pki-directory that holds the pre-calculated signature of
    # the masters public-key
    "master_pubkey_signature": str,
    # Instead of computing the signature for each auth-reply, use a pre-calculated signature.
    # The master_pubkey_signature must also be set for this.
    "master_use_pubkey_signature": bool,
    # Enable master stats eveents to be fired, these events will contain information about
    # what commands the master is processing and what the rates are of the executions
    "master_stats": bool,
    "master_stats_event_iter": int,
    # The caching mechanism to use for the PKI key store. Can substantially decrease master publish
    # times. Available types:
    # 'maint': Runs on a schedule as a part of the maintanence process.
    # '': Disable the key cache [default]
    "key_cache": str,
    # The user under which the daemon should run
    "user": str,
    # The root directory prepended to these options: pki_dir, cachedir,
    # sock_dir, log_file, autosign_file, autoreject_file, extension_modules,
    # key_logfile, pidfile:
    "root_dir": str,
    # The directory used to store public key data
    "pki_dir": str,
    # A unique identifier for this daemon
    "id": str,
    # Use a module function to determine the unique identifier. If this is
    # set and 'id' is not set, it will allow invocation of a module function
    # to determine the value of 'id'. For simple invocations without function
    # arguments, this may be a string that is the function name. For
    # invocations with function arguments, this may be a dictionary with the
    # key being the function name, and the value being an embedded dictionary
    # where each key is a function argument name and each value is the
    # corresponding argument value.
    "id_function": (dict, str),
    # The directory to store all cache files.
    "cachedir": str,
    # Append minion_id to these directories.  Helps with
    # multiple proxies and minions running on the same machine.
    # Allowed elements in the list: pki_dir, cachedir, extension_modules, pidfile
    "append_minionid_config_dirs": list,
    # Flag to cache jobs locally.
    "cache_jobs": bool,
    # The path to the salt configuration file
    "conf_file": str,
    # The pool size of unix sockets, it is necessary to avoid blocking waiting for zeromq and tcp communications.
    "sock_pool_size": int,
    # Specifies how the file server should backup files, if enabled. The backups
    # live in the cache dir.
    "backup_mode": str,
    # A default renderer for all operations on this host
    "renderer": str,
    # Renderer whitelist. The only renderers from this list are allowed.
    "renderer_whitelist": list,
    # Rendrerer blacklist. Renderers from this list are disalloed even if specified in whitelist.
    "renderer_blacklist": list,
    # A flag indicating that a highstate run should immediately cease if a failure occurs.
    "failhard": bool,
    # A flag to indicate that highstate runs should force refresh the modules prior to execution
    "autoload_dynamic_modules": bool,
    # Force the minion into a single environment when it fetches files from the master
    "saltenv": (type(None), str),
    # Prevent saltenv from being overridden on the command line
    "lock_saltenv": bool,
    # Force the minion into a single pillar root when it fetches pillar data from the master
    "pillarenv": (type(None), str),
    # Make the pillarenv always match the effective saltenv
    "pillarenv_from_saltenv": bool,
    # Allows a user to provide an alternate name for top.sls
    "state_top": str,
    "state_top_saltenv": (type(None), str),
    # States to run when a minion starts up
    "startup_states": str,
    # List of startup states
    "sls_list": list,
    # Configuration for snapper in the state system
    "snapper_states": bool,
    "snapper_states_config": str,
    # A top file to execute if startup_states == 'top'
    "top_file": str,
    # Location of the files a minion should look for. Set to 'local' to never ask the master.
    "file_client": str,
    "local": bool,
    # other non-salt hubble-specific things
    "fileserver_update_frequency": int,
    "grains_refresh_frequency": int,
    "scheduler_sleep_frequency": float,
    "default_include": str,
    "logfile_maxbytes": int,
    "logfile_backups": int,
    "delete_inaccessible_azure_containers": bool,
    "enable_globbing_in_nebula_masking": bool,
    "osquery_logfile_maxbytes": int,
    "osquery_logfile_maxbytes_toparse": int,
    "osquery_backuplogs_count": int,
    # When using a local file_client, this parameter is used to allow the client to connect to
    # a master for remote execution.
    "use_master_when_local": bool,
    # A map of saltenvs and fileserver backend locations
    "file_roots": dict,
    # The type of hashing algorithm to use when doing file comparisons
    "hash_type": str,
    # Order of preference for optimized .pyc files (PY3 only)
    "optimization_order": list,
    # Refuse to load these modules
    "disable_modules": list,
    # Refuse to load these returners
    "disable_returners": list,
    # Tell the loader to only load modules in this list
    "whitelist_modules": list,
    # A list of additional directories to search for salt modules in
    "module_dirs": list,
    # A list of additional directories to search for salt returners in
    "returner_dirs": list,
    # A list of additional directories to search for salt states in
    "grains_dirs": list,
    # A list of additional directories to search for salt renderers in
    "utils_dirs": list,
    # some hubble additions
    'fdg_dirs': list,
    'audit_dirs': list,
    # this is a hubble addition, but it may have already been in use
    'fileserver_dirs': list,
    # salt cloud providers
    "providers": dict,
    # First remove all modules during any sync operation
    "clean_dynamic_modules": bool,
    # A flag indicating that a master should accept any minion connection without any authentication
    "open_mode": bool,
    # Whether or not processes should be forked when needed. The alternative is to use threading.
    "multiprocessing": bool,
    # Maximum number of concurrently active processes at any given point in time
    "process_count_max": int,
    # Whether or not the salt minion should run scheduled mine updates
    "mine_enabled": bool,
    # Whether or not scheduled mine updates should be accompanied by a job return for the job cache
    "mine_return_job": bool,
    # The number of minutes between mine updates.
    "mine_interval": int,
    # The ipc strategy. (i.e., sockets versus tcp, etc)
    "ipc_mode": str,
    # Enable ipv6 support for daemons
    "ipv6": (type(None), bool),
    # The chunk size to use when streaming files with the file server
    "file_buffer_size": int,
    # The TCP port on which minion events should be published if ipc_mode is TCP
    "tcp_pub_port": int,
    # The TCP port on which minion events should be pulled if ipc_mode is TCP
    "tcp_pull_port": int,
    # The TCP port on which events for the master should be published if ipc_mode is TCP
    "tcp_master_pub_port": int,
    # The TCP port on which events for the master should be pulled if ipc_mode is TCP
    "tcp_master_pull_port": int,
    # The TCP port on which events for the master should pulled and then republished onto
    # the event bus on the master
    "tcp_master_publish_pull": int,
    # The TCP port for mworkers to connect to on the master
    "tcp_master_workers": int,
    # The file to send logging data to
    "log_file": str,
    # The level of verbosity at which to log
    "log_level": str,
    # The log level to log to a given file
    "log_level_logfile": (type(None), str),
    # The format to construct dates in log files
    "log_datefmt": str,
    # The dateformat for a given logfile
    "log_datefmt_logfile": str,
    # The format for console logs
    "log_fmt_console": str,
    # The format for a given log file
    "log_fmt_logfile": (tuple, str),
    # A dictionary of logging levels
    "log_granular_levels": dict,
    # The maximum number of bytes a single log file may contain before
    # it is rotated. A value of 0 disables this feature.
    # Currently only supported on Windows. On other platforms, use an
    # external tool such as 'logrotate' to manage log files.
    "log_rotate_max_bytes": int,
    # The number of backup files to keep when rotating log files. Only
    # used if log_rotate_max_bytes is greater than 0.
    # Currently only supported on Windows. On other platforms, use an
    # external tool such as 'logrotate' to manage log files.
    "log_rotate_backup_count": int,
    # If an event is above this size, it will be trimmed before putting it on the event bus
    "max_event_size": int,
    # Enable old style events to be sent on minion_startup. Change default to False in Sodium release
    "enable_legacy_startup_events": bool,
    # Always execute states with test=True if this flag is set
    "test": bool,
    # Tell the loader to attempt to import *.pyx cython files if cython is available
    "cython_enable": bool,
    # Whether or not to load grains for the GPU
    "enable_gpu_grains": bool,
    # Tell the loader to attempt to import *.zip archives
    "enable_zip_modules": bool,
    # Tell the client to show minions that have timed out
    "show_timeout": bool,
    # Tell the client to display the jid when a job is published
    "show_jid": bool,
    # Ensure that a generated jid is always unique. If this is set, the jid
    # format is different due to an underscore and process id being appended
    # to the jid. WARNING: A change to the jid format may break external
    # applications that depend on the original format.
    "unique_jid": bool,
    # Tells the highstate outputter to show successful states. False will omit successes.
    "state_verbose": bool,
    # Specify the format for state outputs. See highstate outputter for additional details.
    "state_output": str,
    # Tells the highstate outputter to only report diffs of states that changed
    "state_output_diff": bool,
    # When true, states run in the order defined in an SLS file, unless requisites re-order them
    "state_auto_order": bool,
    # Fire events as state chunks are processed by the state compiler
    "state_events": bool,
    # The number of seconds a minion should wait before retry when attempting authentication
    "acceptance_wait_time": float,
    # The number of seconds a minion should wait before giving up during authentication
    "acceptance_wait_time_max": float,
    # Retry a connection attempt if the master rejects a minion's public key
    "rejected_retry": bool,
    # The interval in which a daemon's main loop should attempt to perform all necessary tasks
    # for normal operation
    "loop_interval": float,
    # Perform pre-flight verification steps before daemon startup, such as checking configuration
    # files and certain directories.
    "verify_env": bool,
    # The grains dictionary for a minion, containing specific "facts" about the minion
    "grains": dict,
    # Allow a daemon to function even if the key directories are not secured
    "permissive_pki_access": bool,
    # The passphrase of the master's private key
    "key_pass": (type(None), str),
    # The passphrase of the master's private signing key
    "signing_key_pass": (type(None), str),
    # The path to a directory to pull in configuration file includes
    "default_include": str,
    # If a minion is running an esky build of salt, upgrades can be performed using the url
    # defined here. See saltutil.update() for additional information
    "update_url": (bool, str),
    # If using update_url with saltutil.update(), provide a list of services to be restarted
    # post-install
    "update_restart_services": list,
    # The number of seconds to sleep between retrying an attempt to resolve the hostname of a
    # salt master
    "retry_dns": float,
    "retry_dns_count": (type(None), int),
    # In the case when the resolve of the salt master hostname fails, fall back to localhost
    "resolve_dns_fallback": bool,
    # set the zeromq_reconnect_ivl option on the minion.
    # http://lists.zeromq.org/pipermail/zeromq-dev/2011-January/008845.html
    "recon_max": float,
    # If recon_randomize is set, this specifies the lower bound for the randomized period
    "recon_default": float,
    # Tells the minion to choose a bounded, random interval to have zeromq attempt to reconnect
    # in the event of a disconnect event
    "recon_randomize": bool,
    "return_retry_timer": int,
    "return_retry_timer_max": int,
    # Specify one or more returners in which all events will be sent to. Requires that the returners
    # in question have an event_return(event) function!
    "event_return": (list, str),
    # The number of events to queue up in memory before pushing them down the pipe to an event
    # returner specified by 'event_return'
    "event_return_queue": int,
    # The number of seconds that events can languish in the queue before we flush them.
    # The goal here is to ensure that if the bus is not busy enough to reach a total
    # `event_return_queue` events won't get stale.
    "event_return_queue_max_seconds": int,
    # Only forward events to an event returner if it matches one of the tags in this list
    "event_return_whitelist": list,
    # Events matching a tag in this list should never be sent to an event returner.
    "event_return_blacklist": list,
    # default match type for filtering events tags: startswith, endswith, find, regex, fnmatch
    "event_match_type": str,
    # This pidfile to write out to when a daemon starts
    "pidfile": str,
    # osquery stuff
    "osquery_dbpath": str,
    "osquerylogpath": str,
    "osquerylog_backupdir": str,
    # Used with the SECO range master tops system
    "range_server": str,
    # The tcp keepalive interval to set on TCP ports. This setting can be used to tune Salt
    # connectivity issues in messy network environments with misbehaving firewalls
    "tcp_keepalive": bool,
    # Sets zeromq TCP keepalive idle. May be used to tune issues with minion disconnects
    "tcp_keepalive_idle": float,
    # Sets zeromq TCP keepalive count. May be used to tune issues with minion disconnects
    "tcp_keepalive_cnt": float,
    # Sets zeromq TCP keepalive interval. May be used to tune issues with minion disconnects.
    "tcp_keepalive_intvl": float,
    # The network interface for a daemon to bind to
    "interface": str,
    # The port for a salt master to broadcast publications on. This will also be the port minions
    # connect to to listen for publications.
    "publish_port": int,
    # TODO unknown option!
    "auth_mode": int,
    # listen queue size / backlog
    "zmq_backlog": int,
    # Set the zeromq high water mark on the publisher interface.
    # http://api.zeromq.org/3-2:zmq-setsockopt
    "pub_hwm": int,
    # IPC buffer size
    # Refs https://github.com/saltstack/salt/issues/34215
    "ipc_write_buffer": int,
    # The number of MWorker processes for a master to startup. This number needs to scale up as
    # the number of connected minions increases.
    "worker_threads": int,
    # The port for the master to listen to returns on. The minion needs to connect to this port
    # to send returns.
    "ret_port": int,
    # The number of hours to keep jobs around in the job cache on the master
    "keep_jobs": int,
    # If the returner supports `clean_old_jobs`, then at cleanup time,
    # archive the job data before deleting it.
    "archive_jobs": bool,
    # Add the proxymodule LazyLoader object to opts.  This breaks many things
    # but this was the default pre 2015.8.2.  This should default to
    # False in 2016.3.0
    "add_proxymodule_to_opts": bool,
    # Merge pillar data into configuration opts.
    # As multiple proxies can run on the same server, we may need different
    # configuration options for each, while there's one single configuration file.
    # The solution is merging the pillar data of each proxy minion into the opts.
    "proxy_merge_pillar_in_opts": bool,
    # Deep merge of pillar data into configuration opts.
    # Evaluated only when `proxy_merge_pillar_in_opts` is True.
    "proxy_deep_merge_pillar_in_opts": bool,
    # The strategy used when merging pillar into opts.
    # Considered only when `proxy_merge_pillar_in_opts` is True.
    "proxy_merge_pillar_in_opts_strategy": str,
    # Allow enabling mine details using pillar data.
    "proxy_mines_pillar": bool,
    # In some particular cases, always alive proxies are not beneficial.
    # This option can be used in those less dynamic environments:
    # the user can request the connection
    # always alive, or init-shutdown per command.
    "proxy_always_alive": bool,
    # Poll the connection state with the proxy minion
    # If enabled, this option requires the function `alive`
    # to be implemented in the proxy module
    "proxy_keep_alive": bool,
    # Frequency of the proxy_keep_alive, in minutes
    "proxy_keep_alive_interval": int,
    # Update intervals
    "roots_update_interval": int,
    "azurefs_update_interval": int,
    "gitfs_update_interval": int,
    "hgfs_update_interval": int,
    "minionfs_update_interval": int,
    "s3fs_update_interval": int,
    "svnfs_update_interval": int,
    # NOTE: git_pillar_base, git_pillar_branch, git_pillar_env, and
    # git_pillar_root omitted here because their values could conceivably be
    # loaded as non-string types, which is OK because git_pillar will normalize
    # them to strings. But rather than include all the possible types they
    # could be, we'll just skip type-checking.
    "git_pillar_ssl_verify": bool,
    "git_pillar_global_lock": bool,
    "git_pillar_user": str,
    "git_pillar_password": str,
    "git_pillar_insecure_auth": bool,
    "git_pillar_privkey": str,
    "git_pillar_pubkey": str,
    "git_pillar_passphrase": str,
    "git_pillar_refspecs": list,
    "git_pillar_includes": bool,
    "git_pillar_verify_config": bool,
    # NOTE: gitfs_base, gitfs_mountpoint, and gitfs_root omitted here because
    # their values could conceivably be loaded as non-string types, which is OK
    # because gitfs will normalize them to strings. But rather than include all
    # the possible types they could be, we'll just skip type-checking.
    "gitfs_remotes": list,
    "gitfs_insecure_auth": bool,
    "gitfs_privkey": str,
    "gitfs_pubkey": str,
    "gitfs_passphrase": str,
    "gitfs_env_whitelist": list,
    "gitfs_env_blacklist": list,
    "gitfs_saltenv_whitelist": list,
    "gitfs_saltenv_blacklist": list,
    "gitfs_ssl_verify": bool,
    "gitfs_global_lock": bool,
    "gitfs_saltenv": list,
    "gitfs_ref_types": list,
    "gitfs_refspecs": list,
    "gitfs_disable_saltenv_mapping": bool,
    "hgfs_remotes": list,
    "hgfs_mountpoint": str,
    "hgfs_root": str,
    "hgfs_base": str,
    "hgfs_branch_method": str,
    "hgfs_env_whitelist": list,
    "hgfs_env_blacklist": list,
    "hgfs_saltenv_whitelist": list,
    "hgfs_saltenv_blacklist": list,
    "svnfs_remotes": list,
    "svnfs_mountpoint": str,
    "svnfs_root": str,
    "svnfs_trunk": str,
    "svnfs_branches": str,
    "svnfs_tags": str,
    "svnfs_env_whitelist": list,
    "svnfs_env_blacklist": list,
    "svnfs_saltenv_whitelist": list,
    "svnfs_saltenv_blacklist": list,
    "minionfs_env": str,
    "minionfs_mountpoint": str,
    "minionfs_whitelist": list,
    "minionfs_blacklist": list,
    # Specify a list of external pillar systems to use
    "ext_pillar": list,
    # Reserved for future use to version the pillar structure
    "pillar_version": int,
    # Whether or not a copy of the master opts dict should be rendered into minion pillars
    "pillar_opts": bool,
    # Cache the master pillar to disk to avoid having to pass through the rendering system
    "pillar_cache": bool,
    # Pillar cache TTL, in seconds. Has no effect unless `pillar_cache` is True
    "pillar_cache_ttl": int,
    # Pillar cache backend. Defaults to `disk` which stores caches in the master cache
    "pillar_cache_backend": str,
    "pillar_safe_render_error": bool,
    # When creating a pillar, there are several strategies to choose from when
    # encountering duplicate values
    "pillar_source_merging_strategy": str,
    # Recursively merge lists by aggregating them instead of replacing them.
    "pillar_merge_lists": bool,
    # If True, values from included pillar SLS targets will override
    "pillar_includes_override_sls": bool,
    # How to merge multiple top files from multiple salt environments
    # (saltenvs); can be 'merge' or 'same'
    "top_file_merging_strategy": str,
    # The ordering for salt environment merging, when top_file_merging_strategy
    # is set to 'same'
    "env_order": list,
    # The salt environment which provides the default top file when
    # top_file_merging_strategy is set to 'same'; defaults to 'base'
    "default_top": str,
    "ping_on_rotate": bool,
    "peer": dict,
    "preserve_minion_cache": bool,
    "runner_dirs": list,
    "client_acl_verify": bool,
    "publisher_acl": dict,
    "publisher_acl_blacklist": dict,
    "sudo_acl": bool,
    "external_auth": dict,
    "token_expire": int,
    "token_expire_user_override": (bool, dict),
    "file_recv": bool,
    "file_recv_max_size": int,
    "file_ignore_regex": (list, str),
    "file_ignore_glob": (list, str),
    "fileserver_backend": list,
    "fileserver_followsymlinks": bool,
    "fileserver_ignoresymlinks": bool,
    "fileserver_limit_traversal": bool,
    "fileserver_verify_config": bool,
    # Optionally apply '*' permissioins to any user. By default '*' is a fallback case that is
    # applied only if the user didn't matched by other matchers.
    "permissive_acl": bool,
    # Optionally enables keeping the calculated user's auth list in the token file.
    "keep_acl_in_token": bool,
    # Auth subsystem module to use to get authorized access list for a user. By default it's the
    # same module used for external authentication.
    "eauth_acl_module": str,
    # Subsystem to use to maintain eauth tokens. By default, tokens are stored on the local
    # filesystem
    "eauth_tokens": str,
    # The number of open files a daemon is allowed to have open. Frequently needs to be increased
    # higher than the system default in order to account for the way zeromq consumes file handles.
    "max_open_files": int,
    # Automatically accept any key provided to the master. Implies that the key will be preserved
    # so that subsequent connections will be authenticated even if this option has later been
    # turned off.
    "auto_accept": bool,
    "autosign_timeout": int,
    # A mapping of external systems that can be used to generate topfile data.
    "master_tops": dict,
    # Whether or not matches from master_tops should be executed before or
    # after those from the top file(s).
    "master_tops_first": bool,
    # A flag that should be set on a top-level master when it is ordering around subordinate masters
    # via the use of a salt syndic
    "order_masters": bool,
    # Whether or not to cache jobs so that they can be examined later on
    "job_cache": bool,
    # Define a returner to be used as an external job caching storage backend
    "ext_job_cache": str,
    # Specify a returner for the master to use as a backend storage system to cache jobs returns
    # that it receives
    "master_job_cache": str,
    # Specify whether the master should store end times for jobs as returns come in
    "job_cache_store_endtime": bool,
    # The minion data cache is a cache of information about the minions stored on the master.
    # This information is primarily the pillar and grains data. The data is cached in the master
    # cachedir under the name of the minion and used to predetermine what minions are expected to
    # reply from executions.
    "minion_data_cache": bool,
    # The number of seconds between AES key rotations on the master
    "publish_session": int,
    # Defines a salt reactor. See http://docs.saltstack.com/en/latest/topics/reactor/
    "reactor": list,
    # The TTL for the cache of the reactor configuration
    "reactor_refresh_interval": int,
    # The number of workers for the runner/wheel in the reactor
    "reactor_worker_threads": int,
    # The queue size for workers in the reactor
    "reactor_worker_hwm": int,
    # Defines engines. See https://docs.saltstack.com/en/latest/topics/engines/
    "engines": list,
    # Whether or not to store runner returns in the job cache
    "runner_returns": bool,
    "serial": str,
    "search": str,
    # A compound target definition.
    # See: http://docs.saltstack.com/en/latest/topics/targeting/nodegroups.html
    "nodegroups": (dict, list),
    # The logfile location for salt-key
    "key_logfile": str,
    # The upper bound for the random number of seconds that a minion should
    # delay when starting in up before it connects to a master. This can be
    # used to mitigate a thundering-herd scenario when many minions start up
    # at once and attempt to all connect immediately to the master
    "random_startup_delay": int,

    # TO REMOVE: see below # # The source location for the winrepo sls files
    # TO REMOVE: see below # # (used by win_pkg.py, minion only)
    "winrepo_source_dir": str,
    # TO REMOVE: see below # "winrepo_dir": str,
    # TO REMOVE: see below # "winrepo_dir_ng": str,
    "winrepo_cachefile": str,
    # TO REMOVE: see below # # NOTE: winrepo_branch omitted here because its value could conceivably be
    # TO REMOVE: see below # # loaded as a non-string type, which is OK because winrepo will normalize
    # TO REMOVE: see below # # them to strings. But rather than include all the possible types it could
    # TO REMOVE: see below # # be, we'll just skip type-checking.
    "winrepo_cache_expire_max": int,
    "winrepo_cache_expire_min": int,
    # TO REMOVE: see below # "winrepo_remotes": list,
    # TO REMOVE: see below # "winrepo_remotes_ng": list,
    # TO REMOVE: see below # "winrepo_ssl_verify": bool,
    # TO REMOVE: see below # "winrepo_user": str,
    # TO REMOVE: see below # "winrepo_password": str,
    # TO REMOVE: see below # "winrepo_insecure_auth": bool,
    # TO REMOVE: see below # "winrepo_privkey": str,
    # TO REMOVE: see below # "winrepo_pubkey": str,
    # TO REMOVE: see below # "winrepo_passphrase": str,
    # TO REMOVE: see below # "winrepo_refspecs": list,

    # Set a hard limit for the amount of memory modules can consume on a minion.
    "modules_max_memory": int,
    # The number of minutes between the minion refreshing its cache of grains
    "grains_refresh_every": int,
    # Use lspci to gather system data for grains on a minion
    "enable_lspci": bool,
    # Override Jinja environment option defaults for all templates except sls templates
    "jinja_env": dict,
    # Set Jinja environment options for sls templates
    "jinja_sls_env": dict,
    # If this is set to True leading spaces and tabs are stripped from the start
    # of a line to a block.
    "jinja_lstrip_blocks": bool,
    # If this is set to True the first newline after a Jinja block is removed
    "jinja_trim_blocks": bool,
    # Cache minion ID to file
    "minion_id_caching": bool,
    # Always generate minion id in lowercase.
    "minion_id_lowercase": bool,
    "queue_dirs": list,
    # Instructs the minion to ping its master(s) every n number of minutes. Used
    # primarily as a mitigation technique against minion disconnects.
    "ping_interval": int,
    # Instructs the salt CLI to print a summary of a minion responses before returning
    "cli_summary": bool,
    # The maximum number of minion connections allowed by the master. Can have performance
    # implications in large setups.
    "max_minions": int,
    "username": (type(None), str),
    "password": (type(None), str),
    # Use zmq.SUSCRIBE to limit listening sockets to only process messages bound for them
    "zmq_filtering": bool,
    # Connection caching. Can greatly speed up salt performance.
    "con_cache": bool,
    "rotate_aes_key": bool,
    # Cache ZeroMQ connections. Can greatly improve salt performance.
    "cache_sreqs": bool,
    # Can be set to override the python_shell=False default in the cmd module
    "cmd_safe": bool,
    # Used strictly for performance testing in RAET.
    "dummy_publisher": bool,
    # Used by salt-api for master requests timeout
    "rest_timeout": int,
    # If set, all minion exec module actions will be rerouted through sudo as this user
    "sudo_user": str,
    # HTTP connection timeout in seconds. Applied for tornado http fetch functions like cp.get_url
    # should be greater than overall download time
    "http_connect_timeout": float,
    # HTTP request timeout in seconds. Applied for tornado http fetch functions like cp.get_url
    # should be greater than overall download time
    "http_request_timeout": float,
    # HTTP request max file content size.
    "http_max_body": int,
    # Delay in seconds before executing bootstrap (Salt Cloud)
    "bootstrap_delay": int,
    # If a proxymodule has a function called 'grains', then call it during
    # regular grains loading and merge the results with the proxy's grains
    # dictionary.  Otherwise it is assumed that the module calls the grains
    # function in a custom way and returns the data elsewhere
    #
    # Default to False for 2016.3 and 2016.11. Switch to True for 2017.7.0
    "proxy_merge_grains_in_module": bool,
    # Command to use to restart salt-minion
    "minion_restart_command": list,
    # Whether or not a minion should send the results of a command back to the master
    # Useful when a returner is the source of truth for a job result
    "pub_ret": bool,
    # HTTP proxy settings. Used in tornado fetch functions, apt-key etc
    "proxy_host": str,
    "proxy_username": str,
    "proxy_password": str,
    "proxy_port": int,
    # Exclude list of hostnames from proxy
    "no_proxy": list,
    # Minion de-dup jid cache max size
    "minion_jid_queue_hwm": int,
    # Minion data cache driver (one of satl.cache.* modules)
    "cache": str,
    # Enables a fast in-memory cache booster and sets the expiration time.
    "memcache_expire_seconds": int,
    # Set a memcache limit in items (bank + key) per cache storage (driver + driver_opts).
    "memcache_max_items": int,
    # Each time a cache storage got full cleanup all the expired items not just the oldest one.
    "memcache_full_cleanup": bool,
    # Enable collecting the memcache stats and log it on `debug` log level.
    "memcache_debug": bool,
    # Thin and minimal Salt extra modules
    "thin_extra_mods": str,
    "min_extra_mods": str,
    # Default returners minion should use. List or comma-delimited string
    "return": (str, list),
    # TLS/SSL connection options. This could be set to a dictionary containing arguments
    # corresponding to python ssl.wrap_socket method. For details see:
    # http://www.tornadoweb.org/en/stable/tcpserver.html#tornado.tcpserver.TCPServer
    # http://docs.python.org/2/library/ssl.html#ssl.wrap_socket
    # Note: to set enum arguments values like `cert_reqs` and `ssl_version` use constant names
    # without ssl module prefix: `CERT_REQUIRED` or `PROTOCOL_SSLv23`.
    "ssl": (dict, bool, type(None)),
    # Controls how a multi-function job returns its data. If this is False,
    # it will return its data using a dictionary with the function name as
    # the key. This is compatible with legacy systems. If this is True, it
    # will return its data using an array in the same order as the input
    # array of functions to execute. This allows for calling the same
    # function multiple times in the same multi-function job.
    "multifunc_ordered": bool,
    # Controls whether beacons are set up before a connection
    # to the master is attempted.
    "beacons_before_connect": bool,
    # Controls whether the scheduler is set up before a connection
    # to the master is attempted.
    "scheduler_before_connect": bool,
    # Whitelist/blacklist specific modules to be synced
    "extmod_whitelist": dict,
    "extmod_blacklist": dict,
    # django auth
    "django_auth_path": str,
    "django_auth_settings": str,
    # Number of times to try to auth with the master on a reconnect with the
    # tcp transport
    "tcp_authentication_retries": int,
    # Permit or deny allowing minions to request revoke of its own key
    "allow_minion_key_revoke": bool,
    # File chunk size for salt-cp
    "salt_cp_chunk_size": int,
    # Require that the minion sign messages it posts to the master on the event
    # bus
    "minion_sign_messages": bool,
    # Have master drop messages from minions for which their signatures do
    # not verify
    "drop_messages_signature_fail": bool,
    # Require that payloads from minions have a 'sig' entry
    # (in other words, require that minions have 'minion_sign_messages'
    # turned on)
    "require_minion_sign_messages": bool,
    # The list of config entries to be passed to external pillar function as
    # part of the extra_minion_data param
    # Subconfig entries can be specified by using the ':' notation (e.g. key:subkey)
    "pass_to_ext_pillars": (str, list),
    # Used by hubblestack.modules.dockermod.compare_container_networks to specify which keys are compared
    "docker.compare_container_networks": dict,
    # SSDP discovery publisher description.
    # Contains publisher configuration and minion mapping.
    # Setting it to False disables discovery
    "discovery": (dict, bool),
    # Scheduler should be a dictionary
    "schedule": dict,
    # Whether to fire auth events
    "auth_events": bool,
    # Whether to fire Minion data cache refresh events
    "minion_data_cache_events": bool,
    # client via the Salt API
    "netapi_allow_raw_shell": bool,
}

DEFAULT_CONF_FILE_NAME = DEFAULT_LOG_FILE_NAME = 'hubble'
DEFAULT_OSQUERY_DB_PATH = os.path.join(hubblestack.syspaths.CACHE_DIR, 'osquery')

if hubblestack.utils.platform.is_windows():
    DEFAULT_CONF_FILE_NAME = 'hubble.conf'
    DEFAULT_LOG_FILE_NAME = "hubble.log"
    DEFAULT_OSQUERY_DB_PATH = os.path.join(hubblestack.syspaths.ROOT_DIR, 'var', 'hubble_osquery_db')

# default configurations
DEFAULT_OPTS = {
    "interface": "0.0.0.0",
    "master": "salt",
    "master_type": "str",
    "master_uri_format": "default",
    "source_interface_name": "",
    "source_address": "",
    "source_ret_port": 0,
    "source_publish_port": 0,
    "master_port": 4506,
    "master_finger": "",
    "master_alive_interval": 0,
    "master_failback": False,
    "master_failback_interval": 0,
    "verify_master_pubkey_sign": False,
    "always_verify_signature": False,
    "master_sign_key_name": "master_sign",
    "user": hubblestack.utils.user.get_user(),
    "root_dir": hubblestack.syspaths.ROOT_DIR,
    "pki_dir": os.path.join(hubblestack.syspaths.CONFIG_DIR, "pki"),
    "id": "",
    "id_function": {},
    "cachedir": os.path.join(hubblestack.syspaths.CACHE_DIR),
    "append_minionid_config_dirs": [],
    "cache_jobs": False,
    "grains_cache": False,
    "grains_cache_expiration": 300,
    "grains_deep_merge": False,
    "conf_file": os.path.join(hubblestack.syspaths.CONFIG_DIR, DEFAULT_CONF_FILE_NAME),
    "sock_pool_size": 1,
    "backup_mode": "",
    "renderer": "jinja|yaml",
    "renderer_whitelist": [],
    "renderer_blacklist": [],
    "random_startup_delay": 0,
    "failhard": False,
    "autoload_dynamic_modules": True,
    "saltenv": None,
    "lock_saltenv": False,
    "pillarenv": None,
    "pillarenv_from_saltenv": False,
    "pillar_opts": False,
    "pillar_source_merging_strategy": "smart",
    "pillar_merge_lists": False,
    "pillar_includes_override_sls": False,
    # ``pillar_cache``, ``pillar_cache_ttl`` and ``pillar_cache_backend``
    # are not used on the minion but are unavoidably in the code path
    "pillar_cache": False,
    "pillar_cache_ttl": 3600,
    "pillar_cache_backend": "disk",
    "extension_modules": os.path.join(hubblestack.syspaths.CACHE_DIR, "extmods"),
    "state_top": "top.sls",
    "state_top_saltenv": None,
    "startup_states": "",
    "sls_list": [],
    "top_file": "",
    "file_client": "local",
    "fileserver_update_frequency": 43200, # 12 hours
    "grains_refresh_frequency": 3600, # 1 hour
    "scheduler_sleep_frequency": 0.5, # 500ms
    "default_include": 'hubble.d/*.conf',
    "logfile_maxbytes": 100000000, # 100MB kindof
    "logfile_backups": 1, # max rotated logs
    "delete_inaccessible_azure_containers": False,
    "enable_globbing_in_nebula_masking": False,
    "osquery_logfile_maxbytes": 50000000, # 50MB kindof
    "osquery_logfile_maxbytes_toparse": 100000000, # 100MB kindof
    "osquery_backuplogs_count": 2,
    "local": False,
    "use_master_when_local": False,
    "file_roots": { "base": list() },
    "top_file_merging_strategy": "merge",
    "env_order": [],
    "default_top": "base",
    "fileserver_limit_traversal": False,
    "file_recv": False,
    "file_recv_max_size": 100,
    "file_ignore_regex": [],
    "file_ignore_glob": [],
    "fileserver_backend": ["roots"],
    "fileserver_followsymlinks": True,
    "fileserver_ignoresymlinks": False,
    "on_demand_ext_pillar": ["libvirt", "virtkey"],
    # Update intervals
    "roots_update_interval": DEFAULT_INTERVAL,
    "azurefs_update_interval": DEFAULT_INTERVAL,
    "gitfs_update_interval": DEFAULT_INTERVAL,
    "hgfs_update_interval": DEFAULT_INTERVAL,
    "minionfs_update_interval": DEFAULT_INTERVAL,
    "s3fs_update_interval": DEFAULT_INTERVAL,
    "svnfs_update_interval": DEFAULT_INTERVAL,
    "git_pillar_base": "master",
    "git_pillar_branch": "master",
    "git_pillar_env": "",
    "git_pillar_root": "",
    "git_pillar_ssl_verify": True,
    "git_pillar_global_lock": True,
    "git_pillar_user": "",
    "git_pillar_password": "",
    "git_pillar_insecure_auth": False,
    "git_pillar_privkey": "",
    "git_pillar_pubkey": "",
    "git_pillar_passphrase": "",
    "git_pillar_refspecs": _DFLT_REFSPECS,
    "git_pillar_includes": True,
    "gitfs_remotes": [],
    "gitfs_mountpoint": "",
    "gitfs_root": "",
    "gitfs_base": "master",
    "gitfs_user": "",
    "gitfs_password": "",
    "gitfs_insecure_auth": False,
    "gitfs_privkey": "",
    "gitfs_pubkey": "",
    "gitfs_passphrase": "",
    "gitfs_env_whitelist": [],
    "gitfs_env_blacklist": [],
    "gitfs_saltenv_whitelist": [],
    "gitfs_saltenv_blacklist": [],
    "gitfs_global_lock": True,
    "gitfs_ssl_verify": True,
    "gitfs_saltenv": [],
    "gitfs_ref_types": ["branch", "tag", "sha"],
    "gitfs_refspecs": _DFLT_REFSPECS,
    "gitfs_disable_saltenv_mapping": False,
    "unique_jid": False,
    "hash_type": "sha256",
    "optimization_order": [0, 1, 2],
    "disable_modules": [],
    "disable_returners": [],
    "whitelist_modules": [],
    "module_dirs": [],
    "returner_dirs": [],
    "grains_dirs": [],
    "utils_dirs": [],
    'fdg_dirs': [],
    'audit_dirs': [],
    'fileserver_dirs': [],
    "publisher_acl": {},
    "publisher_acl_blacklist": {},
    "providers": {},
    "clean_dynamic_modules": True,
    "open_mode": False,
    "auto_accept": True,
    "autosign_timeout": 120,
    "multiprocessing": True,
    "process_count_max": -1,
    "mine_enabled": True,
    "mine_return_job": False,
    "mine_interval": 60,
    "ipc_mode": _DFLT_IPC_MODE,
    "ipc_write_buffer": _DFLT_IPC_WBUFFER,
    "ipv6": None,
    "file_buffer_size": 262144,
    "tcp_pub_port": 4510,
    "tcp_pull_port": 4511,
    "tcp_authentication_retries": 5,
    "log_file": os.path.join(hubblestack.syspaths.LOGS_DIR, DEFAULT_LOG_FILE_NAME),
    "log_level": "error",
    "log_level_logfile": None,
    "log_datefmt": _DFLT_LOG_DATEFMT,
    "log_datefmt_logfile": _DFLT_LOG_DATEFMT_LOGFILE,
    "log_fmt_console": _DFLT_LOG_FMT_CONSOLE,
    "log_fmt_logfile": _DFLT_LOG_FMT_LOGFILE,
    "log_fmt_jid": _DFLT_LOG_FMT_JID,
    "log_granular_levels": {},
    "log_rotate_max_bytes": 0,
    "log_rotate_backup_count": 0,
    "max_event_size": 1048576,
    "enable_legacy_startup_events": True,
    "test": False,
    "ext_job_cache": "",
    "cython_enable": False,
    "enable_gpu_grains": True,
    "enable_zip_modules": False,
    "state_verbose": True,
    "state_output": "full",
    "state_output_diff": False,
    "state_auto_order": True,
    "state_events": False,
    "state_aggregate": False,
    "snapper_states": False,
    "snapper_states_config": "root",
    "acceptance_wait_time": 10,
    "acceptance_wait_time_max": 0,
    "rejected_retry": False,
    "loop_interval": 1,
    "verify_env": True,
    "grains": {},
    "permissive_pki_access": False,
    "default_include": "hubble.d/*.conf",
    "update_url": False,
    "update_restart_services": [],
    "retry_dns": 30,
    "retry_dns_count": None,
    "resolve_dns_fallback": True,
    "recon_max": 10000,
    "recon_default": 1000,
    "recon_randomize": True,
    "return_retry_timer": 5,
    "return_retry_timer_max": 10,
    # NOTE: keeping this here for reference; but we hoppefully won't need it
    # after the windows phase of the saltless re-work
    #   "winrepo_dir": os.path.join(hubblestack.syspaths.BASE_FILE_ROOTS_DIR, "win", "repo"),
    #   "winrepo_dir_ng": os.path.join(hubblestack.syspaths.BASE_FILE_ROOTS_DIR, "win", "repo-ng"),
    "winrepo_source_dir": "salt://win/repo-ng/",
    "winrepo_cachefile": "winrepo.p",
    "winrepo_cache_expire_max": 21600,
    "winrepo_cache_expire_min": 1800,
    #   "winrepo_remotes": ["https://github.com/saltstack/salt-winrepo.git"],
    #   "winrepo_remotes_ng": ["https://github.com/saltstack/salt-winrepo-ng.git"],
    #   "winrepo_branch": "master",
    #   "winrepo_ssl_verify": True,
    #   "winrepo_user": "",
    #   "winrepo_password": "",
    #   "winrepo_insecure_auth": False,
    #   "winrepo_privkey": "",
    #   "winrepo_pubkey": "",
    #   "winrepo_passphrase": "",
    #   "winrepo_refspecs": _DFLT_REFSPECS,
    "pidfile": os.path.join(hubblestack.syspaths.PIDFILE_DIR, "hubble.pid"),
    "osquery_dbpath": DEFAULT_OSQUERY_DB_PATH,
    "osquerylogpath": os.path.join(hubblestack.syspaths.LOGS_DIR, 'hubble_osquery'),
    "osquerylog_backupdir": os.path.join(hubblestack.syspaths.LOGS_DIR, 'hubble_osquery', 'backuplogs'),
    "range_server": "range:80",
    "reactor_refresh_interval": 60,
    "reactor_worker_threads": 10,
    "reactor_worker_hwm": 10000,
    "engines": [],
    "tcp_keepalive": True,
    "tcp_keepalive_idle": 300,
    "tcp_keepalive_cnt": -1,
    "tcp_keepalive_intvl": -1,
    "modules_max_memory": -1,
    "grains_refresh_every": 0,
    "minion_id_caching": True,
    "minion_id_lowercase": False,
    "master_tops_first": False,
    "restart_on_error": False,
    "ping_interval": 0,
    "username": None,
    "password": None,
    "zmq_filtering": False,
    "zmq_monitor": False,
    "cache_sreqs": True,
    "cmd_safe": True,
    "sudo_user": "",
    "http_connect_timeout": 20.0,  # tornado default - 20 seconds
    "http_request_timeout": 1 * 60 * 60.0,  # 1 hour
    "http_max_body": 100 * 1024 * 1024 * 1024,  # 100GB
    "event_match_type": "startswith",
    "minion_restart_command": [],
    "pub_ret": True,
    "proxy_host": "",
    "proxy_username": "",
    "proxy_password": "",
    "proxy_port": 0,
    "minion_jid_queue_hwm": 100,
    "ssl": None,
    "multifunc_ordered": False,
    "beacons_before_connect": False,
    "scheduler_before_connect": False,
    "cache": "localfs",
    "salt_cp_chunk_size": 65536,
    "extmod_whitelist": {},
    "extmod_blacklist": {},
    "minion_sign_messages": False,
    "docker.compare_container_networks": {
        "static": ["Aliases", "Links", "IPAMConfig"],
        "automatic": ["IPAddress", "Gateway", "GlobalIPv6Address", "IPv6Gateway"],
    },
    "discovery": False,
    "schedule": {},
}

def _normalize_roots(file_roots):
    """
    Normalize file or pillar roots.
    """
    for saltenv, dirs in file_roots.items():
        normalized_saltenv = str(saltenv)
        if normalized_saltenv != saltenv:
            file_roots[normalized_saltenv] = file_roots.pop(saltenv)
        if not isinstance(dirs, (list, tuple)):
            file_roots[normalized_saltenv] = []
        file_roots[normalized_saltenv] = _expand_glob_path(
            file_roots[normalized_saltenv]
        )
    return file_roots


def _validate_file_roots(file_roots):
    """
    If the file_roots option has a key that is None then we will error out,
    just replace it with an empty list
    """
    if not isinstance(file_roots, dict):
        log.warning(
            "The file_roots parameter is not properly formatted," " using defaults"
        )
        return {"base": _expand_glob_path([hubblestack.syspaths.BASE_FILE_ROOTS_DIR])}
    return _normalize_roots(file_roots)


def _expand_glob_path(file_roots):
    """
    Applies shell globbing to a set of directories and returns
    the expanded paths
    """
    unglobbed_path = []
    for path in file_roots:
        try:
            if glob.has_magic(path):
                unglobbed_path.extend(glob.glob(path))
            else:
                unglobbed_path.append(path)
        except Exception:
            unglobbed_path.append(path)
    return unglobbed_path


def _validate_opts(opts):
    """
    Check that all of the types of values passed into the config are
    of the right types
    """

    def format_multi_opt(valid_type):
        try:
            num_types = len(valid_type)
        except TypeError:
            # Bare type name won't have a length, return the name of the type
            # passed.
            return valid_type.__name__
        else:

            def get_types(types, type_tuple):
                for item in type_tuple:
                    if isinstance(item, tuple):
                        get_types(types, item)
                    else:
                        try:
                            types.append(item.__name__)
                        except AttributeError:
                            log.warning(
                                "Unable to interpret type %s while validating "
                                "configuration",
                                item,
                            )

            types = []
            get_types(types, valid_type)

            ret = ", ".join(types[:-1])
            ret += " or " + types[-1]
            return ret

    errors = []

    err = (
        "Config option '{0}' with value {1} has an invalid type of {2}, a "
        "{3} is required for this option"
    )
    for key, val in opts.items():
        if key in VALID_OPTS:
            if val is None:
                if VALID_OPTS[key] is None:
                    continue
                else:
                    try:
                        if None in VALID_OPTS[key]:
                            continue
                    except TypeError:
                        # VALID_OPTS[key] is not iterable and not None
                        pass

            if isinstance(val, VALID_OPTS[key]):
                continue

            if hasattr(VALID_OPTS[key], "__call__"):
                try:
                    VALID_OPTS[key](val)
                    if isinstance(val, (list, dict)):
                        # We'll only get here if VALID_OPTS[key] is str or
                        # bool, and the passed value is a list/dict. Attempting
                        # to run int() or float() on a list/dict will raise an
                        # exception, but running str() or bool() on it will
                        # pass despite not being the correct type.
                        errors.append(
                            err.format(
                                key, val, type(val).__name__, VALID_OPTS[key].__name__
                            )
                        )
                except (TypeError, ValueError):
                    errors.append(
                        err.format(
                            key, val, type(val).__name__, VALID_OPTS[key].__name__
                        )
                    )
                continue

            errors.append(
                err.format(
                    key, val, type(val).__name__, format_multi_opt(VALID_OPTS[key])
                )
            )

    # Convert list to comma-delimited string for 'return' config option
    if isinstance(opts.get("return"), list):
        opts["return"] = ",".join(opts["return"])

    for error in errors:
        log.warning(error)
    if errors:
        return False
    return True


def _append_domain(opts):
    """
    Append a domain to the existing id if it doesn't already exist
    """
    # Domain already exists
    if opts["id"].endswith(opts["append_domain"]):
        return opts["id"]
    # Trailing dot should mean an FQDN that is terminated, leave it alone.
    if opts["id"].endswith("."):
        return opts["id"]
    return "{0[id]}.{0[append_domain]}".format(opts)


def _read_conf_file(path):
    """
    Read in a config file from a given path and process it into a dictionary
    """
    log.debug("Reading configuration from %s", path)
    with hubblestack.utils.files.fopen(path, "r") as conf_file:
        try:
            conf_opts = hubblestack.utils.yaml.safe_load(conf_file) or {}
        except hubblestack.utils.yaml.YAMLError as err:
            message = "Error parsing configuration file: {0} - {1}".format(path, err)
            log.error(message)
            raise HubbleConfigurationError(message)

        # only interpret documents as a valid conf, not things like strings,
        # which might have been caused by invalid yaml syntax
        if not isinstance(conf_opts, dict):
            message = (
                "Error parsing configuration file: {0} - conf "
                "should be a document, not {1}.".format(path, type(conf_opts))
            )
            log.error(message)
            raise HubbleConfigurationError(message)

        # allow using numeric ids: convert int to string
        if "id" in conf_opts:
            if not isinstance(conf_opts["id"], str):
                conf_opts["id"] = str(conf_opts["id"])
            else:
                conf_opts["id"] = hubblestack.utils.data.decode(conf_opts["id"])
        return conf_opts


def _absolute_path(path, relative_to=None):
    """
    Return an absolute path. In case ``relative_to`` is passed and ``path`` is
    not an absolute path, we try to prepend ``relative_to`` to ``path``and if
    that path exists, return that one
    """

    if path and os.path.isabs(path):
        return path
    if path and relative_to is not None:
        _abspath = os.path.join(relative_to, path)
        if os.path.isfile(_abspath):
            log.debug(
                "Relative path '%s' converted to existing absolute path " "'%s'",
                path,
                _abspath,
            )
            return _abspath
    return path


def load_config(path, env_var, exit_on_config_errors=True):
    """
    Returns configuration dict from parsing either the file described by
    ``path`` or the environment variable described by ``env_var`` as YAML.
    """

    path = env_path = os.environ.get(env_var, path)
    opts = {}

    if path is None:
        # When the passed path is None, we just want the configuration
        # defaults, not actually loading the whole configuration.
        return opts

    # If the configuration file is missing, attempt to copy the template,
    # after removing the first header line.
    if not os.path.isfile(path):
        template = "{0}.template".format(path)
        if os.path.isfile(template):
            log.debug("Writing %s based on %s", path, template)
            with hubblestack.utils.files.fopen(path, "w") as out:
                with hubblestack.utils.files.fopen(template, "r") as ifile:
                    ifile.readline()  # skip first line
                    out.write(ifile.read())

    if hubblestack.utils.validate.path.is_readable(path):
        try:
            opts = _read_conf_file(path)
            opts["conf_file"] = path
        except HubbleConfigurationError as error:
            log.error(error)
            if exit_on_config_errors:
                sys.exit(hubblestack.defaults.exitcodes.EX_GENERIC)
    else:
        log.debug("Missing configuration file: %s", path)

    return opts


def include_config(include, orig_path, verbose, exit_on_config_errors=False):
    """
    Parses extra configuration file(s) specified in an include list in the
    main config file.
    """
    # Protect against empty option
    if not include:
        return {}

    if orig_path is None:
        # When the passed path is None, we just want the configuration
        # defaults, not actually loading the whole configuration.
        return {}

    if isinstance(include, str):
        include = [include]

    configuration = {}
    for path in include:
        # Allow for includes like ~/foo
        path = os.path.expanduser(path)
        if not os.path.isabs(path):
            path = os.path.join(os.path.dirname(orig_path), path)

        # Catch situation where user typos path in configuration; also warns
        # for empty include directory (which might be by design)
        glob_matches = glob.glob(path)
        if not glob_matches:
            if verbose:
                log.warning(
                    'Warning parsing configuration file: "include" path/glob '
                    "'%s' matches no files",
                    path,
                )

        for fn_ in sorted(glob_matches):
            log.debug("Including configuration from '%s'", fn_)
            try:
                opts = _read_conf_file(fn_)
            except HubbleConfigurationError as error:
                log.error(error)
                if exit_on_config_errors:
                    sys.exit(hubblestack.defaults.exitcodes.EX_GENERIC)
                else:
                    # Initialize default config if we wish to skip config errors
                    opts = {}
            schedule = opts.get("schedule", {})
            if schedule and "schedule" in configuration:
                configuration["schedule"].update(schedule)
            include = opts.get("include", [])
            if include:
                opts.update(include_config(include, fn_, verbose))

            hubblestack.utils.dictupdate.update(configuration, opts, True, True)

    return configuration


def prepend_root_dir(opts, path_options):
    """
    Prepends the options that represent filesystem paths with value of the
    'root_dir' option.
    """
    root_dir = os.path.abspath(opts["root_dir"])
    def_root_dir = hubblestack.syspaths.ROOT_DIR.rstrip(os.sep)
    for path_option in path_options:
        if path_option in opts:
            path = opts[path_option]
            tmp_path_def_root_dir = None
            tmp_path_root_dir = None
            # When running testsuite, hubblestack.syspaths.ROOT_DIR is often empty
            if path == def_root_dir or path.startswith(def_root_dir + os.sep):
                # Remove the default root dir prefix
                tmp_path_def_root_dir = path[len(def_root_dir) :]
            if root_dir and (path == root_dir or path.startswith(root_dir + os.sep)):
                # Remove the root dir prefix
                tmp_path_root_dir = path[len(root_dir) :]
            if tmp_path_def_root_dir and not tmp_path_root_dir:
                # Just the default root dir matched
                path = tmp_path_def_root_dir
            elif tmp_path_root_dir and not tmp_path_def_root_dir:
                # Just the root dir matched
                path = tmp_path_root_dir
            elif tmp_path_def_root_dir and tmp_path_root_dir:
                # In this case both the default root dir and the override root
                # dir matched; this means that either
                # def_root_dir is a substring of root_dir or vice versa
                # We must choose the most specific path
                if def_root_dir in root_dir:
                    path = tmp_path_root_dir
                else:
                    path = tmp_path_def_root_dir
            elif hubblestack.utils.platform.is_windows() and not os.path.splitdrive(path)[0]:
                # In windows, os.path.isabs resolves '/' to 'C:\\' or whatever
                # the root drive is.  This elif prevents the next from being
                # hit, so that the root_dir is prefixed in cases where the
                # drive is not prefixed on a config option
                pass
            elif os.path.isabs(path):
                # Absolute path (not default or overridden root_dir)
                # No prepending required
                continue
            # Prepending the root dir
            opts[path_option] = hubblestack.utils.path.join(root_dir, path)


def insert_system_path(opts, paths):
    """
    Inserts path into python path taking into consideration 'root_dir' option.
    """
    if isinstance(paths, str):
        paths = [paths]
    for path in paths:
        path_options = {"path": path, "root_dir": opts["root_dir"]}
        prepend_root_dir(path_options, path_options)
        if os.path.isdir(path_options["path"]) and path_options["path"] not in sys.path:
            sys.path.insert(0, path_options["path"])


def get_config(
    path=DEFAULT_OPTS['conf_file'],
    env_var="HUBBLE_CONFIG",
    defaults=None,
    cache_minion_id=False,
    ignore_config_errors=True,
    minion_id=None
):
    """
    Reads in the configuration file

    .. code-block:: python

        import hubblestack.config
        __opts__ = hubblestack.config.get_config('/etc/hubble/hubble')


    Note that you're probably better off using the daemon loader though. It
    handles a few other things after it uses this get_config function to pull
    the configs from the file.

    .. code-block:: python

        import hubblestack.daemon
        __opts__ = hubblestack.daemon.load_config(['-c', '/etc/hubble/hubble'])

    """

    if defaults is None:
        defaults = DEFAULT_OPTS.copy()

    if not os.environ.get(env_var, None):
        # No valid setting was given using the configuration variable.
        # Lets see is SALT_CONFIG_DIR is of any use
        salt_config_dir = os.environ.get("SALT_CONFIG_DIR", None)
        if salt_config_dir:
            env_config_file_path = os.path.join(salt_config_dir, "hubble")
            if salt_config_dir and os.path.isfile(env_config_file_path):
                # We can get a configuration file using SALT_CONFIG_DIR, let's
                # update the environment with this information
                os.environ[env_var] = env_config_file_path

    overrides = load_config(path or DEFAULT_OPTS['conf_file'], env_var)
    default_include = overrides.get("default_include", defaults["default_include"])
    include = overrides.get("include", [])

    overrides.update(
        include_config(
            default_include,
            path,
            verbose=False,
            exit_on_config_errors=not ignore_config_errors,
        )
    )
    overrides.update(
        include_config(
            include, path, verbose=True, exit_on_config_errors=not ignore_config_errors
        )
    )

    opts = apply_config(
        overrides, defaults, cache_minion_id=cache_minion_id, minion_id=minion_id
    )
    opts['__role'] = 'minion' # vestigial, but various things look for it
    _validate_opts(opts)
    return opts

def get_id(opts, cache_minion_id=False):
    '''
    Guess the id of the minion.

    If CONFIG_DIR/minion_id exists, use the cached minion ID from that file.
    If no minion id is configured, use multiple sources to find a FQDN.
    If no FQDN is found you may get an ip address.

    Returns two values: the detected ID, and a boolean value noting whether or
    not an IP address is being used for the ID.
    '''
    if opts['root_dir'] is None:
        root_dir = hubblestack.syspaths.ROOT_DIR
    else:
        root_dir = opts['root_dir']

    config_dir = hubblestack.syspaths.CONFIG_DIR
    if config_dir.startswith(hubblestack.syspaths.ROOT_DIR):
        config_dir = config_dir.split(hubblestack.syspaths.ROOT_DIR, 1)[-1]

    # Check for cached minion ID
    id_cache = os.path.join(root_dir,
                            config_dir.lstrip(os.path.sep),
                            'minion_id')

    if opts.get('minion_id_caching', True):
        try:
            with hubblestack.utils.files.fopen(id_cache) as idf:
                name = hubblestack.utils.stringutils.to_unicode(idf.readline().strip())
                bname = hubblestack.utils.stringutils.to_bytes(name)
                if bname.startswith(codecs.BOM):  # Remove BOM if exists
                    name = hubblestack.utils.stringutils.to_str(bname.replace(codecs.BOM, '', 1))
            if name and name != 'localhost':
                log.debug('Using cached minion ID from %s: %s', id_cache, name)
                return name, False
        except (IOError, OSError):
            pass
    if '__role' in opts and opts.get('__role') == 'minion':
        log.debug(
            'Guessing ID. The id can be explicitly set in %s',
            os.path.join(hubblestack.syspaths.CONFIG_DIR, 'minion')
        )

    if opts.get('id_function'):
        newid = call_id_function(opts)
    else:
        newid = hubblestack.utils.network.generate_minion_id()

    if opts.get('minion_id_lowercase'):
        newid = newid.lower()
        log.debug('Changed minion id %s to lowercase.', newid)
    if '__role' in opts and opts.get('__role') == 'minion':
        if opts.get('id_function'):
            log.debug(
                'Found minion id from external function %s: %s',
                opts['id_function'], newid
            )
        else:
            log.debug('Found minion id from generate_minion_id(): %s', newid)
    if cache_minion_id and opts.get('minion_id_caching', True):
        _cache_id(newid, id_cache)
    is_ipv4 = hubblestack.utils.network.is_ipv4(newid)
    return newid, is_ipv4

def apply_config(overrides=None, defaults=None, cache_minion_id=False, minion_id=None):
    """
    Returns minion configurations dict.
    """
    if defaults is None:
        defaults = DEFAULT_OPTS
    if overrides is None:
        overrides = {}

    opts = defaults.copy()
    _adjust_log_file_override(overrides, defaults["log_file"])
    if overrides:
        opts.update(overrides)

    if "environment" in opts:
        if opts["saltenv"] is not None:
            log.warning(
                "The 'saltenv' and 'environment' minion config options "
                "cannot both be used. Ignoring 'environment' in favor of "
                "'saltenv'.",
            )
            # Set environment to saltenv in case someone's custom module is
            # refrencing __opts__['environment']
            opts["environment"] = opts["saltenv"]
        else:
            log.warning(
                "The 'environment' minion config option has been renamed "
                "to 'saltenv'. Using %s as the 'saltenv' config value.",
                opts["environment"],
            )
            opts["saltenv"] = opts["environment"]

    for idx, val in enumerate(opts["fileserver_backend"]):
        if val in ("git", "hg", "svn", "minion"):
            new_val = val + "fs"
            log.debug(
                "Changed %s to %s in minion opts' fileserver_backend list", val, new_val
            )
            opts["fileserver_backend"][idx] = new_val

    opts["__cli"] = hubblestack.utils.stringutils.to_unicode(os.path.basename(sys.argv[0]))

    # No ID provided. Will getfqdn save us?
    using_ip_for_id = False
    if not opts.get("id"):
        if minion_id:
            opts["id"] = minion_id
        else:
            opts["id"], using_ip_for_id = get_id(opts, cache_minion_id=cache_minion_id)

    # it does not make sense to append a domain to an IP based id
    if not using_ip_for_id and "append_domain" in opts:
        opts["id"] = _append_domain(opts)

    for directory in opts.get("append_minionid_config_dirs", []):
        if directory in ("pki_dir", "cachedir", "extension_modules"):
            newdirectory = os.path.join(opts[directory], opts["id"])
            opts[directory] = newdirectory
        elif directory == "default_include" and directory in opts:
            include_dir = os.path.dirname(opts[directory])
            new_include_dir = os.path.join(
                include_dir, opts["id"], os.path.basename(opts[directory])
            )
            opts[directory] = new_include_dir

    # pidfile can be in the list of append_minionid_config_dirs, but pidfile
    # is the actual path with the filename, not a directory.
    if "pidfile" in opts.get("append_minionid_config_dirs", []):
        newpath_list = os.path.split(opts["pidfile"])
        opts["pidfile"] = os.path.join(
            newpath_list[0], "salt", opts["id"], newpath_list[1]
        )

    # Enabling open mode requires that the value be set to True, and
    # nothing else!
    opts["open_mode"] = opts["open_mode"] is True
    opts["file_roots"] = _validate_file_roots(opts["file_roots"])

    # Make sure ext_mods gets set if it is an untrue value
    # (here to catch older bad configs)

    # Intentionally disabled loading extension modules from profile dirs
    #  (but only by not adding the extmods dirs in the cache locations...
    #   one could still allow this by explicitly setting such a thing in configs)
    # opts["extension_modules"] = opts.get("extension_modules") or os.path.join( opts["cachedir"], "extmods")
    # Set up the utils_dirs location from the extension_modules location
    # opts["utils_dirs"] = opts.get("utils_dirs") or [ os.path.join(opts["extension_modules"], "utils") ]

    # Insert all 'utils_dirs' directories to the system path
    insert_system_path(opts, opts["utils_dirs"])

    # Prepend root_dir to other paths
    prepend_root_dirs = [
        "pki_dir",
        "cachedir",
        "extension_modules",
        "pidfile",
    ]

    # These can be set to syslog, so, not actual paths on the system
    for config_key in ("log_file", "key_logfile"):
        if urlparse(opts.get(config_key, "")).scheme == "":
            prepend_root_dirs.append(config_key)

    prepend_root_dir(opts, prepend_root_dirs)

    # if there is no beacons option yet, add an empty beacons dict
    if "beacons" not in opts:
        opts["beacons"] = {}

    if overrides.get("ipc_write_buffer", "") == "dynamic":
        opts["ipc_write_buffer"] = _DFLT_IPC_WBUFFER
    if "ipc_write_buffer" not in overrides:
        opts["ipc_write_buffer"] = 0

    # Make sure hash_type is lowercase
    opts["hash_type"] = opts["hash_type"].lower()

    # Check and update TLS/SSL configuration
    _update_ssl_config(opts)

    return opts


def _adjust_log_file_override(overrides, default_log_file):
    """
    Adjusts the log_file based on the log_dir override
    """
    if overrides.get("log_dir"):
        # Adjust log_file if a log_dir override is introduced
        if overrides.get("log_file"):
            if not os.path.isabs(overrides["log_file"]):
                # Prepend log_dir if log_file is relative
                overrides["log_file"] = os.path.join(
                    overrides["log_dir"], overrides["log_file"]
                )
        else:
            # Create the log_file override
            overrides["log_file"] = os.path.join(
                overrides["log_dir"], os.path.basename(default_log_file)
            )


def _update_ssl_config(opts):
    '''
    Resolves string names to integer constant in ssl configuration.
    '''
    if opts['ssl'] in (None, False):
        opts['ssl'] = None
        return
    if opts['ssl'] is True:
        opts['ssl'] = {}
        return
    import ssl
    for key, prefix in (('cert_reqs', 'CERT_'),
                        ('ssl_version', 'PROTOCOL_')):
        val = opts['ssl'].get(key)
        if val is None:
            continue
        if not isinstance(val, str) or not val.startswith(prefix) or not hasattr(ssl, val):
            message = 'SSL option \'{0}\' must be set to one of the following values: \'{1}\'.' \
                    .format(key, '\', \''.join([val for val in dir(ssl) if val.startswith(prefix)]))
            log.error(message)
            raise HubbleConfigurationError(message)
        opts['ssl'][key] = getattr(ssl, val)
