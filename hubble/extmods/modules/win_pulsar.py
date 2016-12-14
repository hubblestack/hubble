#win_notify
'''
This will setup your computer to enable auditing for specified folders inputted into a yaml file. It will
then scan the event log for changes to those folders every 5 minutes and report when it finds one.
'''


from __future__ import absolute_import

import collections
import datetime
import fnmatch
import logging
import multiprocessing
import os
import glob
import yaml

import salt.ext.six
import salt.loader

log = logging.getLogger(__name__)
DEFAULT_MASK = ['ExecuteFile', 'Write', 'Delete', 'DeleteSubdirectoriesAndFiles', 'ChangePermissions',
                'TakeOwnership'] #ExecuteFile Is really chatty
DEFAULT_TYPE = 'all'

__virtualname__ = 'pulsar'
__version__ = 'v2016.10.3'
CONFIG = None
CONFIG_STALENESS = 0


def __virtual__():
    if not salt.utils.is_windows():
        return False, 'This module only works on windows'
    return __virtualname__


def beacon(config):
    '''
    Watch the configured files

    Example Config

    .. code-block:: yaml

      beacons:
        win_notify:
          /path/to/file/or/dir:
            mask:
              - Write
              - ExecuteFile
              - Delete
              - DeleteSubdirectoriesAndFiles
            wtype: all
            recurse: True
            exclude:
              - /path/to/file/or/dir/exclude1
              - /path/to/*/file/or/dir/*/exclude2

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

    recurse:
        Recursively watch files in the directory
    wtype:
        Type of Audit to watch for:
            1. Success  - Only report successful attempts
            2. Fail     - Only report failed attempts
            3. All      - Report both Success and Fail
    exclude:
        Exclude directories or files from triggering events in the watched directory

    :return:
    '''
    global CONFIG_STALENESS
    global CONFIG
    if config.get('verbose'):
        log.debug('Pulsar beacon called.')
        log.debug('Pulsar beacon config from pillar:\n{0}'.format(config))
    ret = []
    sys_check = 0

    # Get config(s) from filesystem if we don't have them already
    if CONFIG and CONFIG_STALENESS < config.get('refresh_frequency', 60):
        CONFIG_STALENESS += 1
        CONFIG.update(config)
        CONFIG['verbose'] = config.get('verbose')
        config = CONFIG
    else:
        if config.get('verbose'):
            log.debug('No cached config found for pulsar, retrieving fresh from disk.')
        new_config = config
        if isinstance(config.get('paths'), list):
            for path in config['paths']:
                if 'salt://' in path:
                    log.error('Path {0} is not an absolute path. Please use a '
                              'scheduled cp.cache_file job to deliver the '
                              'config to the minion, then provide the '
                              'absolute path to the cached file on the minion '
                              'in the beacon config.'.format(path))
                    continue
                if os.path.isfile(path):
                    with open(path, 'r') as f:
                        new_config = _dict_update(new_config,
                                                  yaml.safe_load(f),
                                                  recursive_update=True,
                                                  merge_lists=True)
                else:
                    log.error('Path {0} does not exist or is not a file'.format(path))
        else:
            log.error('Pulsar beacon \'paths\' data improperly formatted. Should be list of paths')

        new_config.update(config)
        config = new_config
        CONFIG_STALENESS = 0
        CONFIG = config

    if config.get('verbose'):
        log.debug('Pulsar beacon config (compiled from config list):\n{0}'.format(config))

    # Validate Global Auditing with Auditpol
    global_check = __salt__['cmd.run']('auditpol /get /category:"Object Access" /r | find "File System"',
                                       python_shell=True)
    if global_check:
        if not 'Success and Failure' in global_check:
            __salt__['cmd.run']('auditpol /set /subcategory:"file system" /success:enable /failure:enable')
            sys_check = 1

    # Validate ACLs on watched folders/files and add if needed
    for path in config:
        if path == 'win_notify_interval':
            continue
        if isinstance(config[path], dict):
            mask = config[path].get('mask', DEFAULT_MASK)
            wtype = config[path].get('wtype', DEFAULT_TYPE)
            recurse = config[path].get('recurse', True)
            if isinstance(mask, list) and isinstance(wtype, str) and isinstance(recurse, bool):
                success = _check_acl(path, mask, wtype, recurse)
                if not success:
                    confirm = _add_acl(path, mask, wtype, recurse)
                    sys_check = 1
                if config[path].get('exclude', False):
                    for exclude in config[path]['exclude']:
                        if '*' in exclude:
                            for wildcard_exclude in glob.iglob(exclude):
                                _remove_acl(wildcard_exclude)
                        else:
                            _remove_acl(exclude)

    #Read in events since last call.  Time_frame in minutes
    ret = _pull_events(config['win_notify_interval'])
    if sys_check == 1:
        log.error('The ACLs were not setup correctly, or global auditing is not enabled.  This could have '
                  'been remedied, but GP might need to be changed')

    if __salt__['config.get']('hubblestack:pulsar:maintenance', False):
        # We're in maintenance mode, throw away findings
        ret = []

    if ret and 'return' in config:
        __opts__['grains'] = __grains__
        __opts__['pillar'] = __pillar__
        __returners__ = salt.loader.returners(__opts__, __salt__)
        return_config = config['return']
        if isinstance(return_config, salt.ext.six.string_types):
            tmp = {}
            for conf in return_config.split(','):
                tmp[conf] = None
            return_config = tmp
        for returner_mod in return_config:
            returner = '{0}.returner'.format(returner_mod)
            if returner not in __returners__:
                log.error('Could not find {0} returner for pulsar beacon'.format(config['return']))
                return ret
            batch_config = config.get('batch')
            if isinstance(return_config[returner_mod], dict) and return_config[returner_mod].get('batch'):
                batch_config = True
            if batch_config:
                transformed = []
                for item in ret:
                    transformed.append({'return': item})
                if config.get('multiprocessing_return', False):
                    p = multiprocessing.Process(target=_return, args=((transformed,), returner))
                    p.daemon = True
                    p.start()
                else:
                    __returners__[returner](transformed)
            else:
                for item in ret:
                    if config.get('multiprocessing_return', False):
                        p = multiprocessing.Process(target=_return, args=(({'return': item},), returner))
                        p.daemon = True
                        p.start()
                    else:
                        __returners__[returner]({'return': item})
        return []
    else:
        # Return event data
        return ret


def _return(args, returner):
    __returners__ = salt.loader.returners(__opts__, __salt__)
    __returners__[returner](*args)


def _check_acl(path, mask, wtype, recurse):
    audit_dict = {}
    success = True
    if 'all' in wtype.lower():
        wtype = ['Success', 'Failure']
    else:
        wtype = [wtype]

    audit_acl = __salt__['cmd.run']('(Get-Acl {0} -Audit).Audit | fl'.format(path), shell='powershell',
                                    python_shell=True)
    if not audit_acl:
        success = False
        return success
    audit_acl = audit_acl.replace('\r','').split('\n')
    newlines= []
    count = 0
    for line in audit_acl:
        if ':' not in line and count > 0:
            newlines[count-1] += line.strip()
        else:
            newlines.append(line)
            count += 1
    for line in newlines:
        if line:
            if ':' in line:
                d = line.split(':')
                audit_dict[d[0].strip()] = d[1].strip()
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
    '''
    This will apply the needed audit ALC to the folder in question using PowerShells access to the .net library and
    WMI with the code below:
     $path = "C:\Path\here"
     $path = path.replace("\","\\")
     $user = "Everyone"

     $SD = ([WMIClass] "Win32_SecurityDescriptor").CreateInstance()
     $Trustee = ([WMIClass] "Win32_Trustee").CreateInstance()

     # One for Success and other for Failure events
     $ace1 = ([WMIClass] "Win32_ace").CreateInstance()
     $ace2 = ([WMIClass] "Win32_ace").CreateInstance()

     $SID = (new-object security.principal.ntaccount $user).translate([security.principal.securityidentifier])

     [byte[]] $SIDArray = ,0 * $SID.BinaryLength
     $SID.GetBinaryForm($SIDArray,0)

     $Trustee.Name = $user
     $Trustee.SID = $SIDArray

    # Auditing
     $ace2.AccessMask = 2032127 # [System.Security.AccessControl.FileSystemRights]::FullControl
     $ace2.AceFlags = 131 #  FAILED_ACCESS_ACE_FLAG (128), CONTAINER_INHERIT_ACE (2), OBJECT_INHERIT_ACE (1)
     $ace2.AceType =2 # Audit
     $ace2.Trustee = $Trustee

     $SD.SACL += $ace1.psobject.baseobject
     $SD.SACL += $ace2.psobject.baseobject
     $SD.ControlFlags=16
     $wPrivilege = Get-WmiObject Win32_LogicalFileSecuritySetting -filter "path='$path'" -EnableAllPrivileges
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
     10. Write                           - 278    (Combo of CreateFiles, AppendData, WriteAttributes, WriteExtendedAttributes)
     11. Delete                          - 65536
     12. ReadPermissions                 - 131072
     13. ChangePermissions               - 262144
     14. TakeOwnership                   - 524288
     15. Read                            - 131209 (Combo of ReadData, ReadAttributes, ReadExtendedAttributes, ReadPermissions)
     16. ReadAndExecute                  - 131241 (Combo of ExecuteFile, ReadData, ReadAttributes, ReadExtendedAttributes,
                                                   ReadPermissions)
     17. Modify                          - 197055 (Combo of ExecuteFile, ReadData, ReadAttributes, ReadExtendedAttributes,
                                                   CreateFiles, AppendData, WriteAttributes, WriteExtendedAttributes,
                                                   Delete, ReadPermissions)
    The Ace flags map key is below:
     1. ObjectInherit                    - 1
     2. ContainerInherit                 - 2
     3. NoPorpagateInherit               - 4
     4. SuccessfulAccess                 - 64  (Used with System-audit to generate audit messages for successful access
                                                attempts)
     5. FailedAccess                     - 128 (Used with System-audit to generate audit messages for Failed access attempts)

    The Ace type map key is below:
     1. Access Allowed                   - 0
     2. Access Denied                    - 1
     3. Audit                            - 2

    If you want multiple values you just add them together to get a desired outcome:
     ACCESSMASK of file_add_file, file_add_subdirectory, delete, file_delete_child, write_dac, write_owner:
     852038 =           2       +           4          + 65536 +        64        +   262144i

     FLAGS of ObjectInherit, ContainerInherit, SuccessfullAccess, FailedAccess:
     195 =         1       +        2        +        64        +      128

    This calls The function _get_ace_translation() to return the number it needs to set.
    :return:
    '''
    path = path.replace('\\','\\\\')
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

    __salt__['cmd.run']('$SD = ([WMIClass] "Win32_SecurityDescriptor").CreateInstance();'
                        '$Trustee = ([WMIClass] "Win32_Trustee").CreateInstance();'
                        '$ace = ([WMIClass] "Win32_ace").CreateInstance();'
                        '$SID = (new-object System.Security.Principal.NTAccount {0}).translate([security.principal.securityidentifier]);'
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
                        '$wPrivilege = Get-WmiObject Win32_LogicalFileSecuritySetting -filter "path=\'{3}\'" -EnableAllPrivileges;'
                        '$wPrivilege.setsecuritydescriptor($SD)'.format(audit_user, access_mask, flags, path),
                         shell='powershell', python_shell=True)
    return 'ACL set up for {0} - with {1} user, {2} access mask, {3} flags'.format(path, audit_user, access_mask, flags)


def _remove_acl(path):
    '''
    This will remove a currently configured ACL on the folder submited as item.  This will be needed when you have
    a sub file or folder that you want to explicitly ignore within a folder being monitored.  You need to pass in the
    full folder path name for this to work properly
    :param item:
    :return:
    '''
    path = path.replace('\\','\\\\')
    __salt__['cmd.run']('$SD = ([WMIClass] "Win32_SecurityDescriptor").CreateInstance();'
                        '$SD.ControlFlags=16;'
                        '$wPrivilege = Get-WmiObject Win32_LogicalFileSecuritySetting -filter "path=\'{0}\'" -EnableAllPrivileges;'
                        '$wPrivilege.setsecuritydescriptor($SD)'.format(path), shell='powershell', python_shell=True)



def _pull_events(time_frame):
    events_list = []
    events_output = __salt__['cmd.run_stdout']('mode con:cols=1000 lines=1000; Get-EventLog -LogName Security '
                                               '-After ((Get-Date).AddSeconds(-{0})) -InstanceId 4663 | fl'.format(
                                                time_frame), shell='powershell', python_shell=True)
    events = events_output.split('\n\n')
    for event in events:
        if event:
            event_dict = {}
            items = event.split('\n')
            for item in items:
                if ':' in item:
                    item.replace('\t', '')
                    k, v = item.split(':', 1)
                    event_dict[k.strip()] = v.strip()
            event_dict['Accesses'] = _get_access_translation(event_dict['Accesses'])
            event_dict['Hash'] = _get_item_hash(event_dict['Object Name'])
            #needs hostname, checksum, filepath, time stamp, action taken
            events_list.append({k: event_dict[k] for k in ('EntryType', 'Accesses', 'TimeGenerated', 'Object Name', 'Hash')})
    return events_list


def _get_ace_translation(value, *args):
    '''
    This will take the ace name and return the total number accosciated to all the ace accessmasks and flags
    Below you will find all the names accosiated to the numbers:

    '''
    ret = 0
    ace_dict = {'ReadData': 1, 'CreateFiles': 2, 'AppendData': 4, 'ReadExtendedAttributes': 8,
                'WriteExtendedAttributes': 16, 'ExecuteFile': 32, 'DeleteSubdirectoriesAndFiles': 64,
                'ReadAttributes': 128, 'WriteAttributes': 256, 'Write': 278, 'Delete': 65536, 'ReadPermissions': 131072,
                'ChangePermissions': 262144, 'TakeOwnership': 524288, 'Read': 131209, 'ReadAndExecute': 131241,
                'Modify': 197055, 'ObjectInherit': 1, 'ContainerInherit': 2, 'NoPropagateInherit': 4, 'Success': 64,
                'Failure': 128}
    aces = value.split(',')
    for arg in args:
        aces.extend(arg.split(','))

    for ace in aces:
        if ace in ace_dict:
            ret += ace_dict[ace]
    return ret


def _get_access_translation(access):
    '''
    This will take the access number within the event, and return back a meaningful translation.
    These are all the translations of accesses:
        1537 DELETE - used to grant or deny delete access.
        1538 READ_CONTROL - used to grant or deny read access to the security descriptor and owner.
        1539 WRITE_DAC - used to grant or deny write access to the discretionary ACL.
        1540 WRITE_OWNER - used to assign a write owner.
        1541 SYNCHRONIZE - used to synchronize access and to allow a process to wait for an object to enter the signaled state.
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
    :param access:
    :return access_return:
    '''
    access_dict = {'1537': 'Delete', '1538': 'Read Control', '1539': 'Write DAC', '1540': 'Write Owner',
                   '1541': 'Synchronize', '1542': 'Access Sys Sec', '4416': 'Read Data', '4417': 'Write Data',
                   '4418': 'Append Data', '4419': 'Read EA', '4420': 'Write EA', '4421': 'Execute/Traverse',
                   '4423': 'Read Attributes', '4424': 'Write Attributes', '4432': 'Query Key Value',
                   '4433': 'Set Key Value', '4434': 'Create Sub Key', '4435': 'Enumerate Sub-Keys',
                   '4436': 'Notify About Changes to Keys', '4437': 'Create Link', '6931': 'Print', }

    access = access.replace('%%', '').strip()
    ret_str = access_dict.get(access, False)
    if ret_str:
        return ret_str
    else:
        return 'Access number {0} is not a recognized access code.'.format(access)


def _get_item_hash(item):
    item = item.replace('\\\\','\\')
    test = os.path.isfile(item)
    if os.path.isfile(item):
        hashy = __salt__['file.get_hash']('{0}'.format(item))
        return hashy
    else:
        return 'Item is a directory'

