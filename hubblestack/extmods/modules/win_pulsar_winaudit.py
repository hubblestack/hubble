# win_notify
"""
This will setup your computer to enable auditing for specified folders inputted into a yaml file.
It will then scan the event log for changes to those folders and report when it finds one.
"""



import collections
import fnmatch
import glob
import logging
import os
import re
import yaml

import salt.ext.six
import salt.loader
import salt.utils.platform

from salt.exceptions import CommandExecutionError

log = logging.getLogger(__name__)
DEFAULT_MASK = ['ExecuteFile', 'Write', 'Delete', 'DeleteSubdirectoriesAndFiles',
                'ChangePermissions', 'TakeOwnership']  # ExecuteFile Is really chatty
DEFAULT_TYPE = 'all'

__virtualname__ = 'pulsar_winaudit'
CONFIG = None
CONFIG_STALENESS = 0

__version__ = 'v2017.8.3'


def __virtual__():
    if not salt.utils.platform.is_windows():
        return False, 'This module only works on windows'
    return __virtualname__


def process(configfile='salt://hubblestack_pulsar/hubblestack_pulsar_win_config.yaml',
            verbose=False):
    r"""
    Watch the configured files

    Example yaml config on fileserver (targeted by configfile option)

    .. code-block:: yaml

        C:\Users: {}
        C:\Windows:
          mask:
            - Write
            - Delete
            - DeleteSubdirectoriesAndFiles
            - ChangePermissions
            - TakeOwnership
          exclude:
            - C:\Windows\System32
        C:\temp: {}
        win_notify_interval: 30 # MUST be the same as interval in schedule
        return: splunk_pulsar_return
        batch: True

    Note that if `batch: True`, the configured returner must support receiving
    a list of events, rather than single one-off events.

    The mask list can contain the following events (the default mask is create, delete, and modify):

        1.  ExecuteFile                     - Traverse folder / execute file
        2.  ReadData                        - List folder / read data
        3.  ReadAttributes                  - Read attributes of object
        4.  ReadExtendedAttributes          - Read extended attributes of object
        5.  CreateFiles                     - Create files / write data
        6.  AppendData                      - Create folders / append data
        7.  WriteAttributes                 - Write attributes of object
        8.  WriteExtendedAttributes         - Write extended attributes of object
        9.  DeleteSubdirectoriesAndFiles    - Delete subfolders and files
        10. Delete                          - Delete an object
        11. ReadPermissions                 - Read Permissions of an object
        12. ChangePermissions               - Change permissions of an object
        13. TakeOwnership                   - Take ownership of an object
        14. Write                           - Combination of 5, 6, 7, 8
        15. Read                            - Combination of 2, 3, 4, 11
        16. ReadAndExecute                  - Combination of 1, 2, 3, 4, 11
        17. Modify                          - Combination of 1, 2, 3, 4, 5, 6, 7, 8, 10, 11

       *If you want to monitor everything (A.K.A. Full Control) then you want options 9, 12, 13, 17

    wtype:
        Type of Audit to watch for:
            1. Success  - Only report successful attempts
            2. Fail     - Only report failed attempts
            3. All      - Report both Success and Fail
    exclude:
        Exclude directories or files from triggering events in the watched directory.
        Note that directory excludes should *not* have a trailing slash.
    """
    config = __salt__['config.get']('hubblestack_pulsar', {})
    if isinstance(configfile, list):
        config['paths'] = configfile
    else:
        config['paths'] = [configfile]
    config['verbose'] = verbose
    global CONFIG_STALENESS
    global CONFIG
    if config.get('verbose'):
        log.debug('Pulsar module called.')
        log.debug('Pulsar module config from pillar:\n%s', config)
    sys_check = 0

    # Get config(s) from filesystem if we don't have them already
    update_acls = False
    if CONFIG and CONFIG_STALENESS < config.get('refresh_frequency', 60):
        CONFIG_STALENESS += 1
        CONFIG.update(config)
        CONFIG['verbose'] = config.get('verbose')
        config = CONFIG
    else:
        if config.get('verbose'):
            log.debug('No cached config found for pulsar, retrieving fresh from fileserver.')
        new_config = _get_config_from_fileserver(config)

        update_acls = True

        new_config.update(config)
        config = new_config
        CONFIG_STALENESS = 0
        CONFIG = config

    if config.get('verbose'):
        log.debug('Pulsar beacon config (compiled from config list):\n%s', config)

    # Validate Global Auditing with Auditpol
    global_check = __salt__['cmd.run']('auditpol /get /category:"Object Access" /r | '
                                       'findstr /C:"File System"', python_shell=True)
    if global_check:
        if not 'Success and Failure' in global_check:
            __salt__['cmd.run']('auditpol /set /subcategory:"file system"'
                                ' /success:enable /failure:enable', python_shell=True)
            sys_check = 1

    # Validate ACLs on watched folders/files and add if needed
    if update_acls:
        sys_check = _validate_paths(config, sys_check)
    # Read in events since last call.  Time_frame in minutes
    ret = _pull_events(config['win_notify_interval'])
    if sys_check == 1:
        log.error('The ACLs were not setup correctly, or global auditing is not enabled.'
                  ' This could have been remedied, but GP might need to be changed')

    if __salt__['config.get']('hubblestack:pulsar:maintenance', False):
        # We're in maintenance mode, throw away findings
        ret = []

    # Handle excludes
    ret = _handle_excludes(ret, config)

    return ret


def _get_config_from_fileserver(config):
    """
    Helper function that retrieves the config from the fileserver.
    """
    new_config = config
    if isinstance(config.get('paths'), list):
        for path in config['paths']:
            if 'salt://' in path:
                path = __salt__['cp.cache_file'](path)
            if os.path.isfile(path):
                with open(path, 'r') as cache_file:
                    new_config = _dict_update(new_config,
                                              yaml.safe_load(cache_file),
                                              recursive_update=True,
                                              merge_lists=True)
            else:
                log.error('Path %s does not exist or is not a file', path)
    else:
        log.error('Pulsar beacon \'paths\' data improperly formatted. Should be list of paths')

    return new_config


def _validate_paths(config, sys_check):
    """
    Helper function that validates ACLs on the file/folder found at path
    """
    for path in config:
        if path in ['win_notify_interval', 'return', 'batch', 'checksum',
                    'stats', 'paths', 'verbose']:
            return sys_check
        if not os.path.exists(path):
            log.info('The folder path %s does not exist', path)
            return sys_check
        if isinstance(config[path], dict):
            mask = config[path].get('mask', DEFAULT_MASK)
            wtype = config[path].get('wtype', DEFAULT_TYPE)
            recurse = config[path].get('recurse', True)
            if isinstance(mask, list) and isinstance(wtype, str) and isinstance(recurse, bool):
                success = _check_acl(path, mask, wtype, recurse)
                if not success:
                    _confirm = _add_acl(path, mask, wtype, recurse)
                    sys_check = 1
                if config[path].get('exclude', False):
                    _remove_excluded(config[path])

    return sys_check


def _handle_excludes(ret, config):
    """
    Helper function that goes over the events in ret,
    determines if it is valid - config is found and appends it to the new ret.
    """
    new_ret = []
    for event in ret:
        config_found = False
        config_path = config['paths'][0]
        pulsar_config = config_path[config_path.rfind('/') + 1:len(config_path)]
        event['pulsar_config'] = pulsar_config
        for path in config:
            if not event['Object Name'].startswith(path):
                continue
            config_found = True
            _append = _should_append(config, path, event)

        if _append and config_found:
            event['Hash'] = _get_item_hash(event['Object Name'], config.get('checksum', 'sha256'))
            new_ret.append(event)

    return new_ret


def _remove_excluded(config_path):
    """
    Helper function that goes over what should be excluded
    and called _remove_acl on them if they are valid
    """
    for exclude in config_path['exclude']:
        if not isinstance(exclude, str):
            continue
        if '*' in exclude:
            for wildcard_exclude in glob.iglob(exclude):
                _remove_acl(wildcard_exclude)
        else:
            _remove_acl(exclude)


def _should_append(config, path, event):
    """
    Helper function that checks if the path is in excludes.
    Returns False if it is, True otherwise.
    """
    _append = True
    if isinstance(config[path], dict) and 'exclude' in config[path]:
        for exclude in config[path]['exclude']:
            if isinstance(exclude, dict) and list(exclude.values())[0].get('regex', False):
                if re.search(list(exclude.keys())[0], event['Object Name']):
                    _append = False
            else:
                if fnmatch.fnmatch(event['Object Name'], exclude):
                    _append = False
                elif event['Object Name'].startswith(exclude):
                    # Startswith is well and good, but it needs to be a parent directory
                    # or it doesn't count
                    _, _, leftover = event['Object Name'].partition(exclude)
                    if leftover.startswith(os.sep):
                        _append = False

    return _append


def canary(change_file=None):
    """
    Simple module to change a file to trigger a FIM event (daily, etc)

    THE SPECIFIED FILE WILL BE CREATED AND DELETED

    Defaults to CONF_DIR/fim_canary.tmp, i.e. /etc/hubble/fim_canary.tmp
    """
    if change_file is None:
        conf_dir = os.path.dirname(__opts__['conf_file'])
        change_file = os.path.join(conf_dir, 'fim_canary.tmp')
    __salt__['file.touch'](change_file)
    os.remove(change_file)


def _check_acl(path, mask, wtype, recurse):
    audit_dict = {}
    if 'all' in wtype.lower():
        wtype = ['Success', 'Failure']
    else:
        wtype = [wtype]

    path = "'" + path + "'"
    audit_acl = __salt__['cmd.run']('(Get-Acl {0} -Audit).Audit | fl'.format(path),
                                    shell='powershell', python_shell=True)
    if not audit_acl:
        return False
    audit_acl = audit_acl.replace('\r', '').split('\n')
    newlines = []
    count = 0
    for line in audit_acl:
        if ':' not in line and count > 0:
            newlines[count - 1] += line.strip()
        else:
            newlines.append(line)
            count += 1
    for line in newlines:
        if line:
            if ':' in line:
                fields = line.split(':')
                audit_dict[fields[0].strip()] = fields[1].strip()

    return _was_successful(mask, wtype, recurse, audit_dict)


def _was_successful(mask, wtype, recurse, audit_dict):
    """
    Helper function that returns True if the audit was successful
    and False otherwise
    """
    success = True
    for item in mask:
        if item not in audit_dict['FileSystemRights']:
            success = False
    for item in wtype:
        if item not in audit_dict['AuditFlags']:
            success = False
    if 'Everyone' not in audit_dict['IdentityReference']:
        success = False
    if recurse:
        if 'ContainerInherit' and 'ObjectInherit' not in audit_dict['InheritanceFlags']:
            success = False
    else:
        if 'None' not in audit_dict['InheritanceFlags']:
            success = False
    if 'None' not in audit_dict['PropagationFlags']:
        success = False

    return success


def _add_acl(path, mask, wtype, recurse):
    r"""
    This will apply the needed audit ALC to the folder in question using PowerShells access to
    the .net library and WMI with the code below:
     $path = "C:\Path\here"
     $path = path.replace("\","\\")
     $user = "Everyone"

     $SD = ([WMIClass] "Win32_SecurityDescriptor").CreateInstance()
     $Trustee = ([WMIClass] "Win32_Trustee").CreateInstance()

     # One for Success and other for Failure events
     $ace1 = ([WMIClass] "Win32_ace").CreateInstance()
     $ace2 = ([WMIClass] "Win32_ace").CreateInstance()

     $SID = (new-object security.principal.ntaccount $user).translate(
        [security.principal.securityidentifier])

     [byte[]] $SIDArray = ,0 * $SID.BinaryLength
     $SID.GetBinaryForm($SIDArray,0)

     $Trustee.Name = $user
     $Trustee.SID = $SIDArray

    # Auditing
     $ace2.AccessMask = 2032127 # [System.Security.AccessControl.FileSystemRights]::FullControl
     $ace2.AceFlags = 131 #  FAILED_ACCESS_ACE_FLAG (128), CONTAINER_INHERIT_ACE (2),
                          # OBJECT_INHERIT_ACE (1)
     $ace2.AceType =2 # Audit
     $ace2.Trustee = $Trustee

     $SD.SACL += $ace1.psobject.baseobject
     $SD.SACL += $ace2.psobject.baseobject
     $SD.ControlFlags=16
     $wPrivilege = Get-WmiObject Win32_LogicalFileSecuritySetting -filter \
                    "path='$path'" -EnableAllPrivileges
     $wPrivilege.setsecuritydescriptor($SD)

    The ACE accessmask map key is below:

     1.  ReadData                        - 1
     2.  CreateFiles                     - 2
     3.  AppendData                      - 4
     4.  ReadExtendedAttributes          - 8
     5.  WriteExtendedAttributes         - 16
     6.  ExecuteFile                     - 32
     7.  DeleteSubdirectoriesAndFiles    - 64
     8.  ReadAttributes                  - 128
     9.  WriteAttributes                 - 256
     10. Write                           - 278    (Combo of CreateFiles, AppendData,
                                                   WriteAttributes, WriteExtendedAttributes)
     11. Delete                          - 65536
     12. ReadPermissions                 - 131072
     13. ChangePermissions               - 262144
     14. TakeOwnership                   - 524288
     15. Read                            - 131209 (Combo of ReadData, ReadAttributes,
                                                   ReadExtendedAttributes, ReadPermissions)
     16. ReadAndExecute                  - 131241 (Combo of ExecuteFile, ReadData, ReadAttributes,
                                                   ReadExtendedAttributes, ReadPermissions)
     17. Modify                          - 197055 (Combo of ExecuteFile, ReadData, ReadAttributes,
                                                   ReadExtendedAttributes, CreateFiles, AppendData,
                                                   WriteAttributes, WriteExtendedAttributes,
                                                   Delete, ReadPermissions)
    The Ace flags map key is below:
     1. ObjectInherit                    - 1
     2. ContainerInherit                 - 2
     3. NoPorpagateInherit               - 4
     4. SuccessfulAccess                 - 64  (Used with System-audit to generate audit messages
                                                for successful access attempts)
     5. FailedAccess                     - 128 (Used with System-audit to generate audit messages
                                                for Failed access attempts)

    The Ace type map key is below:
     1. Access Allowed                   - 0
     2. Access Denied                    - 1
     3. Audit                            - 2

    If you want multiple values you just add them together to get a desired outcome:
    ACCESSMASK of file_add_file file_add_subdirectory delete file_delete_child write_dac write_owner
     852038 =           2       +           4          + 65536 +        64        +   262144i

     FLAGS of ObjectInherit, ContainerInherit, SuccessfullAccess, FailedAccess:
     195 =         1       +        2        +        64        +      128

    This calls The function _get_ace_translation() to return the number it needs to set.
    :return:
    """
    path = path.replace('\\', '\\\\')
    audit_user = 'Everyone'
    audit_rules = ','.join(mask)
    if recurse:
        inherit_type = 'ContainerInherit,ObjectInherit'
    if 'all' in wtype:
        audit_type = 'Success,Failure'
    else:
        audit_type = wtype

    access_mask = _get_ace_translation(audit_rules)
    flags = _get_ace_translation(inherit_type, audit_type)

    __salt__['cmd.run'](
        '$SD = ([WMIClass] "Win32_SecurityDescriptor").CreateInstance();'
        '$Trustee = ([WMIClass] "Win32_Trustee").CreateInstance();'
        '$ace = ([WMIClass] "Win32_ace").CreateInstance();'
        '$SID = (new-object System.Security.Principal.NTAccount {0}).translate('
        '[security.principal.securityidentifier]);'
        '[byte[]] $SIDArray = ,0 * $SID.BinaryLength;'
        '$SID.GetBinaryForm($SIDArray,0);'
        '$Trustee.Name = "{0}";'
        '$Trustee.SID = $SIDArray;'
        '$ace.AccessMask = {1};'
        '$ace.AceFlags = {2};'
        '$ace.AceType = 2;'
        '$ace.Trustee = $Trustee;'
        '$SD.SACL += $ace.psobject.baseobject;'
        '$SD.ControlFlags=16;'
        '$wPrivilege = Get-WmiObject Win32_LogicalFileSecuritySetting -filter "path=\'{3}\'" '
        '-EnableAllPrivileges;'
        '$wPrivilege.setsecuritydescriptor($SD)'.format(audit_user, access_mask, flags, path),
        shell='powershell', python_shell=True)
    return 'ACL set up for {0} - with {1} user, {2} access mask, {3} flags'.format(
        path, audit_user, access_mask, flags)


def _remove_acl(path):
    """
    This will remove a currently configured ACL on the folder submited as item.
    This will be needed when you have a sub file or folder that you want to explicitly ignore
    within a folder being monitored.  You need to pass in the full folder path name for this to
    work properly
    """
    if os.path.exists(path):
        path = path.replace('\\', '\\\\')
        __salt__['cmd.run']('$SD = ([WMIClass] "Win32_SecurityDescriptor").CreateInstance();'
                            '$SD.ControlFlags=16;'
                            '$wPrivilege = Get-WmiObject Win32_LogicalFileSecuritySetting '
                            '-filter "path=\'{0}\'" -EnableAllPrivileges;'
                            '$wPrivilege.setsecuritydescriptor($SD)'.format(path),
                            shell='powershell', python_shell=True)


def _pull_events(time_frame):
    events_list = []
    command = 'mode con:cols=1000 lines=1000; Get-WinEvent ' \
              '-FilterHashTable @{{''LogName = "security"; ' \
              'StartTime = [datetime]::Now.AddSeconds(-' + str(time_frame) + ');''Id = 4663}} | fl'
    events_output = __salt__['cmd.run_stdout'](command.format(time_frame),
                                               shell='powershell', python_shell=True)
    events = events_output.split('\r\n\r\n')
    for event in events:
        if event:
            event_dict = {}
            items = event.split('\r\n')
            for item in items:
                if ':' in item:
                    item.replace('\t', '')
                    k, val = item.split(':', 1)
                    event_dict[k.strip()] = val.strip()
            # event_dict['Accesses'] = _get_access_translation(event_dict['Accesses'])
            # needs hostname, checksum, filepath, time stamp, action taken
            # Generate the dictionary without a dictionary comp, for py2.6
            tmpdict = {}
            for k in ('Message', 'Accesses', 'TimeCreated', 'Object Name'):
                tmpdict[k] = event_dict[k]
            events_list.append(tmpdict)
    return events_list


def _get_ace_translation(value, *args):
    """
    This will take the ace name and return the total number accosciated to all the
    ace accessmasks and flags
    Below you will find all the names accosiated to the numbers:

    """
    ret = 0
    ace_dict = {'ReadData': 1, 'CreateFiles': 2, 'AppendData': 4, 'ReadExtendedAttributes': 8,
                'WriteExtendedAttributes': 16, 'ExecuteFile': 32,
                'DeleteSubdirectoriesAndFiles': 64, 'ReadAttributes': 128, 'WriteAttributes': 256,
                'Write': 278, 'Delete': 65536, 'ReadPermissions': 131072,
                'ChangePermissions': 262144, 'TakeOwnership': 524288, 'Read': 131209,
                'ReadAndExecute': 131241, 'Modify': 197055, 'ObjectInherit': 1,
                'ContainerInherit': 2, 'NoPropagateInherit': 4, 'Success': 64, 'Failure': 128}
    aces = value.split(',')
    for arg in args:
        aces.extend(arg.split(','))

    for ace in aces:
        if ace in ace_dict:
            ret += ace_dict[ace]
    return ret


def _get_access_translation(access):
    """
    This will take the access number within the event, and return back a meaningful translation.
    These are all the translations of accesses:
        1537 DELETE - used to grant or deny delete access.
        1538 READ_CONTROL - used to grant or deny read access to the security descriptor and owner.
        1539 WRITE_DAC - used to grant or deny write access to the discretionary ACL.
        1540 WRITE_OWNER - used to assign a write owner.
        1541 SYNCHRONIZE - used to synchronize access and to allow a process to wait for
                            an object to enter the signaled state.
        1542 ACCESS_SYS_SEC
        4416 ReadData
        4417 WriteData
        4418 AppendData
        4419 ReadEA (Extended Attribute)
        4420 WriteEA (Extended Attribute)
        4421 Execute/Traverse
        4423 ReadAttributes
        4424 WriteAttributes
        4432 Query Key Value
        4433 Set Key Value
        4434 Create Sub Key
        4435 Enumerate sub-keys
        4436 Notify about changes to keys
        4437 Create Link
        6931 Print

    access
        The access number within the event
    """
    access_dict = {'1537': 'Delete', '1538': 'Read Control', '1539': 'Write DAC',
                   '1540': 'Write Owner', '1541': 'Synchronize', '1542': 'Access Sys Sec',
                   '4416': 'Read Data', '4417': 'Write Data', '4418': 'Append Data',
                   '4419': 'Read EA', '4420': 'Write EA', '4421': 'Execute/Traverse',
                   '4423': 'Read Attributes', '4424': 'Write Attributes', '4432': 'Query Key Value',
                   '4433': 'Set Key Value', '4434': 'Create Sub Key', '4435': 'Enumerate Sub-Keys',
                   '4436': 'Notify About Changes to Keys', '4437': 'Create Link', '6931': 'Print', }

    access = access.replace('%%', '').strip()
    ret_str = access_dict.get(access, False)
    if ret_str:
        return ret_str
    return 'Access number {0} is not a recognized access code.'.format(access)


def _get_item_hash(item, checksum):
    item = item.replace('\\\\', '\\')
    if os.path.isfile(item):
        try:
            hashy = __salt__['file.get_hash']('{0}'.format(item), form=checksum)
            return hashy
        except Exception:
            return ''
    else:
        return 'Item is a directory'


def _dict_update(dest, upd, recursive_update=True, merge_lists=False):
    """
    Recursive version of the default dict.update

    Merges upd recursively into dest

    If recursive_update=False, will use the classic dict.update, or fall back
    on a manual merge (helpful for non-dict types like FunctionWrapper)

    If merge_lists=True, will aggregate list object types instead of replace.
    This behavior is only activated when recursive_update=True. By default
    merge_lists=False.
    """
    if (not isinstance(dest, collections.Mapping)) \
            or (not isinstance(upd, collections.Mapping)):
        raise TypeError('Cannot update using non-dict types in dictupdate.update()')
    updkeys = list(upd.keys())
    if not set(list(dest.keys())) & set(updkeys):
        recursive_update = False
    if recursive_update:
        for key in updkeys:
            val = upd[key]
            try:
                dest_subkey = dest.get(key, None)
            except AttributeError:
                dest_subkey = None
            if isinstance(dest_subkey, collections.Mapping) \
                    and isinstance(val, collections.Mapping):
                ret = _dict_update(dest_subkey, val, merge_lists=merge_lists)
                dest[key] = ret
            elif isinstance(dest_subkey, list) \
                    and isinstance(val, list):
                if merge_lists:
                    dest[key] = dest.get(key, []) + val
                else:
                    dest[key] = upd[key]
            else:
                dest[key] = upd[key]
    else:
        for k in upd:
            dest[k] = upd[k]

    return dest


def top(topfile='salt://hubblestack_pulsar/win_top.pulsar', verbose=False):
    """
    Function that gets the pulsar config files and watches them
    """
    configs = get_top_data(topfile)

    configs = ['salt://hubblestack_pulsar/' + config.replace('.', '/') + '.yaml'
               for config in configs]

    return process(configs, verbose=verbose)


def get_top_data(topfile):
    """
    Function that reads the pulsar topdata from the topfile.
    """
    topfile = __salt__['cp.cache_file'](topfile)

    try:
        with open(topfile) as handle:
            topdata = yaml.safe_load(handle)
    except Exception as exc:
        raise CommandExecutionError('Could not load topfile: {0}'.format(exc))

    if not isinstance(topdata, dict) or 'pulsar' not in topdata or \
            not isinstance(topdata['pulsar'], dict):
        raise CommandExecutionError('Pulsar topfile not formatted correctly')

    topdata = topdata['pulsar']

    ret = []

    for match, data in topdata.items():
        if __salt__['match.compound'](match):
            ret.extend(data)

    return ret
