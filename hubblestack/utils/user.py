# -*- coding: utf-8 -*-
'''
Functions for querying and modifying a user account and the groups to which it
belongs.
'''

# Import Python libs
import ctypes
import getpass
import logging
import os
import sys

from hubblestack.utils.exceptions import CommandExecutionError

# Conditional imports
try:
    import pwd
    HAS_PWD = True
except ImportError:
    HAS_PWD = False

try:
    import grp
    HAS_GRP = True
except ImportError:
    HAS_GRP = False

try:
    import pysss
    HAS_PYSSS = True
except ImportError:
    HAS_PYSSS = False

log = logging.getLogger(__name__)

def chugid_and_umask(runas, umask, group=None):
    '''
    Helper method for for subprocess.Popen to initialise uid/gid and umask
    for the new process.
    '''
    set_runas = False
    set_grp = False

    current_user = getpass.getuser()
    if runas and runas != current_user:
        set_runas = True
        runas_user = runas
    else:
        runas_user = current_user

    current_grp = grp.getgrgid(pwd.getpwnam(getpass.getuser()).pw_gid).gr_name
    if group and group != current_grp:
        set_grp = True
        runas_grp = group
    else:
        runas_grp = current_grp

    if set_runas or set_grp:
        chugid(runas_user, runas_grp)
    if umask is not None:
        os.umask(umask)  # pylint: disable=blacklisted-function

def chugid(runas, group=None):
    '''
    Change the current process to belong to the specified user (and the groups
    to which it belongs)
    '''
    uinfo = pwd.getpwnam(runas)
    supgroups = []
    supgroups_seen = set()

    if group:
        try:
            target_pw_gid = grp.getgrnam(group).gr_gid
        except KeyError as err:
            raise CommandExecutionError(
                'Failed to fetch the GID for {0}. Error: {1}'.format(
                    group, err
                )
            )
    else:
        target_pw_gid = uinfo.pw_gid

    # The line below used to exclude the current user's primary gid.
    # However, when root belongs to more than one group
    # this causes root's primary group of '0' to be dropped from
    # his grouplist.  On FreeBSD, at least, this makes some
    # command executions fail with 'access denied'.
    #
    # The Python documentation says that os.setgroups sets only
    # the supplemental groups for a running process.  On FreeBSD
    # this does not appear to be strictly true.
    group_list = get_group_dict(runas, include_default=True)
    if sys.platform == 'darwin':
        group_list = dict((k, v) for k, v in iter(group_list.items())
                          if not k.startswith('_'))
    for group_name in group_list:
        gid = group_list[group_name]
        if (gid not in supgroups_seen
           and not supgroups_seen.add(gid)):
            supgroups.append(gid)

    if os.getgid() != target_pw_gid:
        try:
            os.setgid(target_pw_gid)
        except OSError as err:
            raise CommandExecutionError(
                'Failed to change from gid {0} to {1}. Error: {2}'.format(
                    os.getgid(), target_pw_gid, err
                )
            )

    # Set supplemental groups
    if sorted(os.getgroups()) != sorted(supgroups):
        try:
            os.setgroups(supgroups)
        except OSError as err:
            raise CommandExecutionError(
                'Failed to set supplemental groups to {0}. Error: {1}'.format(
                    supgroups, err
                )
            )

    if os.getuid() != uinfo.pw_uid:
        try:
            os.setuid(uinfo.pw_uid)
        except OSError as err:
            raise CommandExecutionError(
                'Failed to change from uid {0} to {1}. Error: {2}'.format(
                    os.getuid(), uinfo.pw_uid, err
                )
            )

def get_group_dict(user=None, include_default=True):
    '''
    Returns a dict of all of the system groups as keys, and group ids
    as values, of which the user is a member.
    E.g.: {'staff': 501, 'sudo': 27}
    '''
    if HAS_GRP is False or HAS_PWD is False:
        return {}
    group_dict = {}
    group_names = get_group_list(user, include_default=include_default)
    for group in group_names:
        group_dict.update({group: grp.getgrnam(group).gr_gid})
    return group_dict

def get_group_list(user, include_default=True):
    '''
    Returns a list of all of the system group names of which the user
    is a member.
    '''
    if HAS_GRP is False or HAS_PWD is False:
        return []
    group_names = None
    ugroups = set()
    if hasattr(os, 'getgrouplist'):
        # Try os.getgrouplist, available in python >= 3.3
        log.trace('Trying os.getgrouplist for \'%s\'', user)
        try:
            group_names = [
                grp.getgrgid(grpid).gr_name for grpid in
                os.getgrouplist(user, pwd.getpwnam(user).pw_gid)
            ]
        except Exception:
            pass
    elif HAS_PYSSS:
        # Try pysss.getgrouplist
        log.trace('Trying pysss.getgrouplist for \'%s\'', user)
        try:
            group_names = list(pysss.getgrouplist(user))
        except Exception:
            pass

    if group_names is None:
        # Fall back to generic code
        # Include the user's default group to match behavior of
        # os.getgrouplist() and pysss.getgrouplist()
        log.trace('Trying generic group list for \'%s\'', user)
        group_names = [g.gr_name for g in grp.getgrall() if user in g.gr_mem]
        try:
            default_group = get_default_group(user)
            if default_group not in group_names:
                group_names.append(default_group)
        except KeyError:
            # If for some reason the user does not have a default group
            pass

    if group_names is not None:
        ugroups.update(group_names)

    if include_default is False:
        # Historically, saltstack code for getting group lists did not
        # include the default group. Some things may only want
        # supplemental groups, so include_default=False omits the users
        # default group.
        try:
            default_group = grp.getgrgid(pwd.getpwnam(user).pw_gid).gr_name
            ugroups.remove(default_group)
        except KeyError:
            # If for some reason the user does not have a default group
            pass
    log.trace('Group list for user \'%s\': %s', user, sorted(ugroups))
    return sorted(ugroups)

def get_default_group(user):
    '''
    Returns the specified user's default group. If the user doesn't exist, a
    KeyError will be raised.
    '''
    return grp.getgrgid(pwd.getpwnam(user).pw_gid).gr_name \
        if HAS_GRP and HAS_PWD \
        else None
