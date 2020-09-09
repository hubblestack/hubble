# -*- coding: utf-8 -*-
'''
============
Windows DACL
============
This salt utility contains objects and functions for setting permissions to
objects in Windows. You can use the built in functions or access the objects
directly to create your own custom functionality. There are two objects, Flags
and Dacl.

If you need access only to flags, use the Flags object.

.. code-block:: python

    import hubblestack.utils.win_dacl
    flags = hubblestack.utils.win_dacl.Flags()
    flag_full_control = flags.ace_perms['file']['basic']['full_control']

The Dacl object inherits Flags. To use the Dacl object:

..code-block:: python

    import hubblestack.utils.win_dacl
    dacl = hubblestack.utils.win_dacl.Dacl(obj_type='file')
    dacl.add_ace('Administrators', 'grant', 'full_control')
    dacl.save('C:\\temp')

Object types are used by setting the `obj_type` parameter to a valid Windows
object. Valid object types are as follows:

- file
- service
- printer
- registry
- registry32 (for WOW64)
- share

Each object type has its own set up permissions and 'applies to' properties as
follows. At this time only basic permissions are used for setting. Advanced
permissions are listed for displaying the permissions of an object that don't
match the basic permissions, ie. Special permissions. These should match the
permissions you see when you look at the security for an object.

**Basic Permissions**

    ================  ====  ========  =====  =======  =======
    Permissions       File  Registry  Share  Printer  Service
    ================  ====  ========  =====  =======  =======
    full_control      X     X         X               X
    modify            X
    read_execute      X
    read              X     X         X               X
    write             X     X                         X
    read_write                                        X
    change                            X
    print                                    X
    manage_printer                           X
    manage_documents                         X
    ================  ====  ========  =====  =======  =======

**Advanced Permissions**

    =======================  ====  ========  =======  =======
    Permissions              File  Registry  Printer  Service
    =======================  ====  ========  =======  =======
    list_folder              X
    read_data                X
    create_files             X
    write_data               X
    create_folders           X
    append_data              X
    read_ea                  X
    write_ea                 X
    traverse_folder          X
    execute_file             X
    delete_subfolders_files  X
    read_attributes          X
    write_attributes         X
    delete                   X     X
    read_permissions         X               X        X
    change_permissions       X               X        X
    take_ownership           X               X
    query_value                    X
    set_value                      X
    create_subkey                  X
    enum_subkeys                   X
    notify                         X
    create_link                    X
    read_control                   X
    write_dac                      X
    write_owner                    X
    manage_printer                           X
    print                                    X
    query_config                                      X
    change_config                                     X
    query_status                                      X
    enum_dependents                                   X
    start                                             X
    stop                                              X
    pause_resume                                      X
    interrogate                                       X
    user_defined                                      X
    change_owner                                      X
    =======================  ====  ========  =======  =======

Only the registry and file object types have 'applies to' properties. These
should match what you see when you look at the properties for an object.

    **File types:**

        - this_folder_only: Applies only to this object
        - this_folder_subfolders_files (default): Applies to this object
          and all sub containers and objects
        - this_folder_subfolders: Applies to this object and all sub
          containers, no files
        - this_folder_files: Applies to this object and all file
          objects, no containers
        - subfolders_files: Applies to all containers and objects
          beneath this object
        - subfolders_only: Applies to all containers beneath this object
        - files_only: Applies to all file objects beneath this object

    **Registry types:**

        - this_key_only: Applies only to this key
        - this_key_subkeys: Applies to this key and all subkeys
        - subkeys_only: Applies to all subkeys beneath this object

'''
# Import Python libs
from __future__ import absolute_import, print_function, unicode_literals
import logging

from hubblestack.utils.exceptions import CommandExecutionError, HubbleInvocationError
import hubblestack.utils.platform
import hubblestack.utils.win_functions

# Import 3rd-party libs
HAS_WIN32 = False
try:
    import win32security
    import win32con
    import win32api
    import pywintypes
    HAS_WIN32 = True
except ImportError:
    pass

log = logging.getLogger(__name__)

__virtualname__ = 'dacl'


def __virtual__():
    '''
    Only load if Win32 Libraries are installed
    '''
    if not hubblestack.utils.platform.is_windows():
        return False, 'win_dacl: Requires Windows'

    if not HAS_WIN32:
        return False, 'win_dacl: Requires pywin32'

    return __virtualname__


def flags(instantiated=True):
    '''
    Helper function for instantiating a Flags object

    Args:

        instantiated (bool):
            True to return an instantiated object, False to return the object
            definition. Use False if inherited by another class. Default is
            True.

    Returns:
        object: An instance of the Flags object or its definition
    '''
    if not HAS_WIN32:
        return

    class Flags(object):
        '''
        Object containing all the flags for dealing with Windows permissions
        '''
        # Flag Dicts
        ace_perms = {
            'file': {
                'basic': {
                    0x1f01ff: 'Full control',
                    0x1301bf: 'Modify',
                    0x1201bf: 'Read & execute with write',
                    0x1200a9: 'Read & execute',
                    0x120089: 'Read',
                    0x100116: 'Write',
                    'full_control': 0x1f01ff,
                    'modify': 0x1301bf,
                    'read_execute': 0x1200a9,
                    'read': 0x120089,
                    'write': 0x100116,
                },
                'advanced': {
                    # Advanced
                    0x0001: 'List folder / read data',
                    0x0002: 'Create files / write data',
                    0x0004: 'Create folders / append data',
                    0x0008: 'Read extended attributes',
                    0x0010: 'Write extended attributes',
                    0x0020: 'Traverse folder / execute file',
                    0x0040: 'Delete subfolders and files',
                    0x0080: 'Read attributes',
                    0x0100: 'Write attributes',
                    0x10000: 'Delete',
                    0x20000: 'Read permissions',
                    0x40000: 'Change permissions',
                    0x80000: 'Take ownership',
                    # 0x100000: 'SYNCHRONIZE',  # This is in all of them
                    'list_folder': 0x0001,
                    'read_data': 0x0001,
                    'create_files': 0x0002,
                    'write_data': 0x0002,
                    'create_folders': 0x0004,
                    'append_data': 0x0004,
                    'read_ea': 0x0008,
                    'write_ea': 0x0010,
                    'traverse_folder': 0x0020,
                    'execute_file': 0x0020,
                    'delete_subfolders_files': 0x0040,
                    'read_attributes': 0x0080,
                    'write_attributes': 0x0100,
                    'delete': 0x10000,
                    'read_permissions': 0x20000,
                    'change_permissions': 0x40000,
                    'take_ownership': 0x80000,
                },
            },
            'registry': {
                'basic': {
                    0xf003f: 'Full Control',
                    0x20019: 'Read',
                    0x20006: 'Write',
                    # Generic Values (These sometimes get hit)
                    0x10000000: 'Full Control',
                    0x20000000: 'Execute',
                    0x40000000: 'Write',
                    0xffffffff80000000: 'Read',
                    'full_control': 0xf003f,
                    'read': 0x20019,
                    'write': 0x20006,
                },
                'advanced': {
                    # Advanced
                    0x0001: 'Query Value',
                    0x0002: 'Set Value',
                    0x0004: 'Create Subkey',
                    0x0008: 'Enumerate Subkeys',
                    0x0010: 'Notify',
                    0x0020: 'Create Link',
                    0x10000: 'Delete',
                    0x20000: 'Read Control',
                    0x40000: 'Write DAC',
                    0x80000: 'Write Owner',
                    'query_value': 0x0001,
                    'set_value': 0x0002,
                    'create_subkey': 0x0004,
                    'enum_subkeys': 0x0008,
                    'notify': 0x0010,
                    'create_link': 0x0020,
                    'delete': 0x10000,
                    'read_control': 0x20000,
                    'write_dac': 0x40000,
                    'write_owner': 0x80000,
                },
            },
            'share': {
                'basic': {
                    0x1f01ff: 'Full control',
                    0x1301bf: 'Change',
                    0x1200a9: 'Read',
                    'full_control': 0x1f01ff,
                    'change': 0x1301bf,
                    'read': 0x1200a9,
                },
                'advanced': {},  # No 'advanced' for shares, needed for lookup
            },
            'printer': {
                'basic': {
                    0x20008: 'Print',
                    0xf000c: 'Manage this printer',
                    0xf0030: 'Manage documents',
                    'print': 0x20008,
                    'manage_printer': 0xf000c,
                    'manage_documents': 0xf0030,
                },
                'advanced': {
                    # Advanced
                    0x10004: 'Manage this printer',
                    0x0008: 'Print',
                    0x20000: 'Read permissions',
                    0x40000: 'Change permissions',
                    0x80000: 'Take ownership',
                    'manage_printer': 0x10004,
                    'print': 0x0008,
                    'read_permissions': 0x20000,
                    'change_permissions': 0x40000,
                    'take_ownership': 0x80000,
                },
            },
            'service': {
                'basic': {
                    0xf01ff: 'Full Control',
                    0x2008f: 'Read & Write',
                    0x2018d: 'Read',
                    0x20002: 'Write',
                    'full_control': 0xf01ff,
                    'read_write': 0x2008f,
                    'read': 0x2018d,
                    'write': 0x20002,
                },
                'advanced': {
                    0x0001: 'Query Config',
                    0x0002: 'Change Config',
                    0x0004: 'Query Status',
                    0x0008: 'Enumerate Dependents',
                    0x0010: 'Start',
                    0x0020: 'Stop',
                    0x0040: 'Pause/Resume',
                    0x0080: 'Interrogate',
                    0x0100: 'User-Defined Control',
                    # 0x10000: 'Delete',  # Not visible in the GUI
                    0x20000: 'Read Permissions',
                    0x40000: 'Change Permissions',
                    0x80000: 'Change Owner',
                    'query_config': 0x0001,
                    'change_config': 0x0002,
                    'query_status': 0x0004,
                    'enum_dependents': 0x0008,
                    'start': 0x0010,
                    'stop': 0x0020,
                    'pause_resume': 0x0040,
                    'interrogate': 0x0080,
                    'user_defined': 0x0100,
                    'read_permissions': 0x20000,
                    'change_permissions': 0x40000,
                    'change_owner': 0x80000,
                },
            }
        }

        # These denote inheritance
        # 0x0000 : Not inherited, I don't know the enumeration for this
        # 0x0010 : win32security.INHERITED_ACE

        # All the values in the dict below are combinations of the following
        # enumerations or'ed together
        # 0x0001 : win32security.OBJECT_INHERIT_ACE
        # 0x0002 : win32security.CONTAINER_INHERIT_ACE
        # 0x0004 : win32security.NO_PROPAGATE_INHERIT_ACE
        # 0x0008 : win32security.INHERIT_ONLY_ACE
        ace_prop = {
            'file': {
                # for report
                0x0000: 'Not Inherited (file)',
                0x0001: 'This folder and files',
                0x0002: 'This folder and subfolders',
                0x0003: 'This folder, subfolders and files',
                0x0006: 'This folder only',
                0x0009: 'Files only',
                0x000a: 'Subfolders only',
                0x000b: 'Subfolders and files only',
                0x0010: 'Inherited (file)',
                # for setting
                'this_folder_only': 0x0006,
                'this_folder_subfolders_files': 0x0003,
                'this_folder_subfolders': 0x0002,
                'this_folder_files': 0x0001,
                'subfolders_files': 0x000b,
                'subfolders_only': 0x000a,
                'files_only': 0x0009,
            },
            'registry': {
                0x0000: 'Not Inherited',
                0x0002: 'This key and subkeys',
                0x0006: 'This key only',
                0x000a: 'Subkeys only',
                0x0010: 'Inherited',
                'this_key_only': 0x0006,
                'this_key_subkeys': 0x0002,
                'subkeys_only': 0x000a,
            },
            'registry32': {
                0x0000: 'Not Inherited',
                0x0002: 'This key and subkeys',
                0x0006: 'This key only',
                0x000a: 'Subkeys only',
                0x0010: 'Inherited',
                'this_key_only': 0x0006,
                'this_key_subkeys': 0x0002,
                'subkeys_only': 0x000a,
            },
        }

        ace_type = {
            'grant': win32security.ACCESS_ALLOWED_ACE_TYPE,
            'deny': win32security.ACCESS_DENIED_ACE_TYPE,
            win32security.ACCESS_ALLOWED_ACE_TYPE: 'grant',
            win32security.ACCESS_DENIED_ACE_TYPE: 'deny',
        }

        element = {
            'dacl': win32security.DACL_SECURITY_INFORMATION,
            'group': win32security.GROUP_SECURITY_INFORMATION,
            'owner': win32security.OWNER_SECURITY_INFORMATION,
        }

        inheritance = {
            'protected': win32security.PROTECTED_DACL_SECURITY_INFORMATION,
            'unprotected': win32security.UNPROTECTED_DACL_SECURITY_INFORMATION,
        }

        obj_type = {
            'file': win32security.SE_FILE_OBJECT,
            'service': win32security.SE_SERVICE,
            'printer': win32security.SE_PRINTER,
            'registry': win32security.SE_REGISTRY_KEY,
            'registry32': win32security.SE_REGISTRY_WOW64_32KEY,
            'share': win32security.SE_LMSHARE,
        }

    return Flags() if instantiated else Flags


def dacl(obj_name=None, obj_type='file'):
    '''
    Helper function for instantiating a Dacl class.

    Args:

        obj_name (str):
            The full path to the object. If None, a blank DACL will be created.
            Default is None.

        obj_type (str):
            The type of object. Default is 'File'

    Returns:
        object: An instantiated Dacl object
    '''

    if not HAS_WIN32:
        return

    class Dacl(flags(False)):
        '''
        DACL Object
        '''
        def __init__(self, obj_name=None, obj_type='file'):
            '''
            Either load the DACL from the passed object or create an empty DACL.
            If `obj_name` is not passed, an empty DACL is created.

            Args:

                obj_name (str):
                    The full path to the object. If None, a blank DACL will be
                    created

                obj_type (Optional[str]):
                    The type of object.

            Returns:
                obj: A DACL object

            Usage:

            .. code-block:: python

                # Create an Empty DACL
                dacl = Dacl(obj_type=obj_type)

                # Load the DACL of the named object
                dacl = Dacl(obj_name, obj_type)
            '''
            # Validate obj_type
            if obj_type.lower() not in self.obj_type:
                raise HubbleInvocationError(
                    'Invalid "obj_type" passed: {0}'.format(obj_type))

            self.dacl_type = obj_type.lower()

            if obj_name is None:
                self.dacl = win32security.ACL()
            else:
                if 'registry' in self.dacl_type:
                    obj_name = self.get_reg_name(obj_name)

                try:
                    sd = win32security.GetNamedSecurityInfo(
                        obj_name, self.obj_type[self.dacl_type], self.element['dacl'])
                except pywintypes.error as exc:
                    if 'The system cannot find' in exc.strerror:
                        msg = 'System cannot find {0}'.format(obj_name)
                        log.exception(msg)
                        raise CommandExecutionError(msg)
                    raise

                self.dacl = sd.GetSecurityDescriptorDacl()
                if self.dacl is None:
                    self.dacl = win32security.ACL()

        def get_reg_name(self, obj_name):
            '''
            Take the obj_name and convert the hive to a valid registry hive.

            Args:

                obj_name (str):
                    The full path to the registry key including the hive, eg:
                    ``HKLM\\SOFTWARE\\salt``. Valid options for the hive are:

                    - HKEY_LOCAL_MACHINE
                    - MACHINE
                    - HKLM
                    - HKEY_USERS
                    - USERS
                    - HKU
                    - HKEY_CURRENT_USER
                    - CURRENT_USER
                    - HKCU
                    - HKEY_CLASSES_ROOT
                    - CLASSES_ROOT
                    - HKCR

            Returns:
                str:
                    The full path to the registry key in the format expected by
                    the Windows API

            Usage:

            .. code-block:: python

                import hubblestack.utils.win_dacl
                dacl = hubblestack.utils.win_dacl.Dacl()
                valid_key = dacl.get_reg_name('HKLM\\SOFTWARE\\salt')

                # Returns: MACHINE\\SOFTWARE\\salt
            '''
            # Make sure the hive is correct
            # Should be MACHINE, USERS, CURRENT_USER, or CLASSES_ROOT
            hives = {
                # MACHINE
                'HKEY_LOCAL_MACHINE': 'MACHINE',
                'MACHINE': 'MACHINE',
                'HKLM': 'MACHINE',
                # USERS
                'HKEY_USERS': 'USERS',
                'USERS': 'USERS',
                'HKU': 'USERS',
                # CURRENT_USER
                'HKEY_CURRENT_USER': 'CURRENT_USER',
                'CURRENT_USER': 'CURRENT_USER',
                'HKCU': 'CURRENT_USER',
                # CLASSES ROOT
                'HKEY_CLASSES_ROOT': 'CLASSES_ROOT',
                'CLASSES_ROOT': 'CLASSES_ROOT',
                'HKCR': 'CLASSES_ROOT',
            }
            reg = obj_name.split('\\')
            passed_hive = reg.pop(0)

            try:
                valid_hive = hives[passed_hive.upper()]
            except KeyError:
                log.exception('Invalid Registry Hive: %s', passed_hive)
                raise CommandExecutionError(
                    'Invalid Registry Hive: {0}'.format(passed_hive))

            reg.insert(0, valid_hive)

            return r'\\'.join(reg)

        def add_ace(self, principal, access_mode, permissions, applies_to):
            '''
            Add an ACE to the DACL

            Args:

                principal (str):
                    The sid of the user/group to for the ACE

                access_mode (str):
                    Determines the type of ACE to add. Must be either ``grant``
                    or ``deny``.

                permissions (str, list):
                    The type of permissions to grant/deny the user. Can be one
                    of the basic permissions, or a list of advanced permissions.

                applies_to (str):
                    The objects to which these permissions will apply. Not all
                    these options apply to all object types.

            Returns:
                bool: True if successful, otherwise False

            Usage:

            .. code-block:: python

                dacl = Dacl(obj_type=obj_type)
                dacl.add_ace(sid, access_mode, permission, applies_to)
                dacl.save(obj_name, protected)
            '''
            sid = get_sid(principal)

            if self.dacl is None:
                raise HubbleInvocationError(
                    'You must load the DACL before adding an ACE')

            # Get the permission flag
            perm_flag = 0
            if isinstance(permissions, str):
                try:
                    perm_flag = self.ace_perms[self.dacl_type]['basic'][permissions]
                except KeyError as exc:
                    msg = 'Invalid permission specified: {0}'.format(permissions)
                    log.exception(msg)
                    raise CommandExecutionError(msg, exc)
            else:
                try:
                    for perm in permissions:
                        perm_flag |= self.ace_perms[self.dacl_type]['advanced'][perm]
                except KeyError as exc:
                    msg = 'Invalid permission specified: {0}'.format(perm)
                    log.exception(msg)
                    raise CommandExecutionError(msg, exc)

            if access_mode.lower() not in ['grant', 'deny']:
                raise HubbleInvocationError('Invalid Access Mode: {0}'.format(access_mode))

            # Add ACE to the DACL
            # Grant or Deny
            try:
                if access_mode.lower() == 'grant':
                    self.dacl.AddAccessAllowedAceEx(
                        win32security.ACL_REVISION_DS,
                        # Some types don't support propagation
                        # May need to use 0x0000 instead of None
                        self.ace_prop.get(self.dacl_type, {}).get(applies_to),
                        perm_flag,
                        sid)
                elif access_mode.lower() == 'deny':
                    self.dacl.AddAccessDeniedAceEx(
                        win32security.ACL_REVISION_DS,
                        self.ace_prop.get(self.dacl_type, {}).get(applies_to),
                        perm_flag,
                        sid)
                else:
                    log.exception('Invalid access mode: %s', access_mode)
                    raise HubbleInvocationError(
                        'Invalid access mode: {0}'.format(access_mode))
            except Exception as exc:
                return False, 'Error: {0}'.format(exc)

            return True

        def order_acl(self):
            '''
            Put the ACEs in the ACL in the proper order. This is necessary
            because the add_ace function puts ACEs at the end of the list
            without regard for order. This will cause the following Windows
            Security dialog to appear when viewing the security for the object:

            ``The permissions on Directory are incorrectly ordered, which may
            cause some entries to be ineffective.``

            .. note:: Run this function after adding all your ACEs.

            Proper Orders is as follows:

                1. Implicit Deny
                2. Inherited Deny
                3. Implicit Deny Object
                4. Inherited Deny Object
                5. Implicit Allow
                6. Inherited Allow
                7. Implicit Allow Object
                8. Inherited Allow Object

            Usage:

            .. code-block:: python

                dacl = Dacl(obj_type=obj_type)
                dacl.add_ace(sid, access_mode, applies_to, permission)
                dacl.order_acl()
                dacl.save(obj_name, protected)
            '''
            new_dacl = Dacl()
            deny_dacl = Dacl()
            deny_obj_dacl = Dacl()
            allow_dacl = Dacl()
            allow_obj_dacl = Dacl()

            # Load Non-Inherited ACEs first
            for i in range(0, self.dacl.GetAceCount()):
                ace = self.dacl.GetAce(i)
                if ace[0][1] & win32security.INHERITED_ACE == 0:
                    if ace[0][0] == win32security.ACCESS_DENIED_ACE_TYPE:
                        deny_dacl.dacl.AddAccessDeniedAceEx(
                            win32security.ACL_REVISION_DS,
                            ace[0][1],
                            ace[1],
                            ace[2])
                    elif ace[0][0] == win32security.ACCESS_DENIED_OBJECT_ACE_TYPE:
                        deny_obj_dacl.dacl.AddAccessDeniedAceEx(
                            win32security.ACL_REVISION_DS,
                            ace[0][1],
                            ace[1],
                            ace[2])
                    elif ace[0][0] == win32security.ACCESS_ALLOWED_ACE_TYPE:
                        allow_dacl.dacl.AddAccessAllowedAceEx(
                            win32security.ACL_REVISION_DS,
                            ace[0][1],
                            ace[1],
                            ace[2])
                    elif ace[0][0] == win32security.ACCESS_ALLOWED_OBJECT_ACE_TYPE:
                        allow_obj_dacl.dacl.AddAccessAllowedAceEx(
                            win32security.ACL_REVISION_DS,
                            ace[0][1],
                            ace[1],
                            ace[2])

            # Load Inherited ACEs last
            for i in range(0, self.dacl.GetAceCount()):
                ace = self.dacl.GetAce(i)
                if ace[0][1] & win32security.INHERITED_ACE == \
                        win32security.INHERITED_ACE:
                    ace_prop = ace[0][1] ^ win32security.INHERITED_ACE
                    if ace[0][0] == win32security.ACCESS_DENIED_ACE_TYPE:
                        deny_dacl.dacl.AddAccessDeniedAceEx(
                            win32security.ACL_REVISION_DS,
                            ace_prop,
                            ace[1],
                            ace[2])
                    elif ace[0][0] == win32security.ACCESS_DENIED_OBJECT_ACE_TYPE:
                        deny_obj_dacl.dacl.AddAccessDeniedAceEx(
                            win32security.ACL_REVISION_DS,
                            ace_prop,
                            ace[1],
                            ace[2])
                    elif ace[0][0] == win32security.ACCESS_ALLOWED_ACE_TYPE:
                        allow_dacl.dacl.AddAccessAllowedAceEx(
                            win32security.ACL_REVISION_DS,
                            ace_prop,
                            ace[1],
                            ace[2])
                    elif ace[0][0] == win32security.ACCESS_ALLOWED_OBJECT_ACE_TYPE:
                        allow_obj_dacl.dacl.AddAccessAllowedAceEx(
                            win32security.ACL_REVISION_DS,
                            ace_prop,
                            ace[1],
                            ace[2])

            # Combine ACEs in the proper order
            # Deny, Deny Object, Allow, Allow Object
            # Deny
            for i in range(0, deny_dacl.dacl.GetAceCount()):
                ace = deny_dacl.dacl.GetAce(i)
                new_dacl.dacl.AddAccessDeniedAceEx(
                    win32security.ACL_REVISION_DS,
                    ace[0][1],
                    ace[1],
                    ace[2])

            # Deny Object
            for i in range(0, deny_obj_dacl.dacl.GetAceCount()):
                ace = deny_obj_dacl.dacl.GetAce(i)
                new_dacl.dacl.AddAccessDeniedAceEx(
                    win32security.ACL_REVISION_DS,
                    ace[0][1] ^ win32security.INHERITED_ACE,
                    ace[1],
                    ace[2])

            # Allow
            for i in range(0, allow_dacl.dacl.GetAceCount()):
                ace = allow_dacl.dacl.GetAce(i)
                new_dacl.dacl.AddAccessAllowedAceEx(
                    win32security.ACL_REVISION_DS,
                    ace[0][1],
                    ace[1],
                    ace[2])

            # Allow Object
            for i in range(0, allow_obj_dacl.dacl.GetAceCount()):
                ace = allow_obj_dacl.dacl.GetAce(i)
                new_dacl.dacl.AddAccessAllowedAceEx(
                    win32security.ACL_REVISION_DS,
                    ace[0][1] ^ win32security.INHERITED_ACE,
                    ace[1],
                    ace[2])

            # Set the new dacl
            self.dacl = new_dacl.dacl

        def get_ace(self, principal):
            '''
            Get the ACE for a specific principal.

            Args:

                principal (str):
                    The name of the user or group for which to get the ace. Can
                    also be a SID.

            Returns:
                dict: A dictionary containing the ACEs found for the principal

            Usage:

            .. code-block:: python

                dacl = Dacl(obj_type=obj_type)
                dacl.get_ace()
            '''
            principal = get_name(principal)
            aces = self.list_aces()

            # Filter for the principal
            ret = {}
            for inheritance in aces:
                if principal in aces[inheritance]:
                    ret[inheritance] = {principal: aces[inheritance][principal]}

            return ret

        def list_aces(self):
            '''
            List all Entries in the dacl.

            Returns:
                dict: A dictionary containing the ACEs for the object

            Usage:

            .. code-block:: python

                dacl = Dacl('C:\\Temp')
                dacl.list_aces()
            '''
            ret = {'Inherited': {},
                   'Not Inherited': {}}

            # loop through each ACE in the DACL
            for i in range(0, self.dacl.GetAceCount()):
                ace = self.dacl.GetAce(i)

                # Get ACE Elements
                user, a_type, a_prop, a_perms, inheritance = self._ace_to_dict(ace)

                if user in ret[inheritance]:
                    ret[inheritance][user][a_type] = {
                        'applies to': a_prop,
                        'permissions': a_perms,
                    }
                else:
                    ret[inheritance][user] = {
                        a_type: {
                            'applies to': a_prop,
                            'permissions': a_perms,
                        }}

            return ret

        def _ace_to_dict(self, ace):
            '''
            Helper function for creating the ACE return dictionary
            '''
            # Get the principal from the sid (object sid)
            sid = win32security.ConvertSidToStringSid(ace[2])
            try:
                principal = get_name(sid)
            except CommandExecutionError:
                principal = sid

            # Get the ace type
            ace_type = self.ace_type[ace[0][0]]

            # Is the inherited ace flag present
            inherited = ace[0][1] & win32security.INHERITED_ACE == 16

            # Ace Propagation
            ace_prop = 'NA'

            # Get the ace propagation properties
            if self.dacl_type in ['file', 'registry', 'registry32']:

                ace_prop = ace[0][1]

                # Remove the inherited ace flag and get propagation
                if inherited:
                    ace_prop = ace[0][1] ^ win32security.INHERITED_ACE

                # Lookup the propagation
                try:
                    ace_prop = self.ace_prop[self.dacl_type][ace_prop]
                except KeyError:
                    ace_prop = 'Unknown propagation'

            # Get the object type
            obj_type = 'registry' if self.dacl_type == 'registry32' \
                else self.dacl_type

            # Get the ace permissions
            # Check basic permissions first
            ace_perms = self.ace_perms[obj_type]['basic'].get(ace[1], [])

            # If it didn't find basic perms, check advanced permissions
            if not ace_perms:
                ace_perms = []
                for perm in self.ace_perms[obj_type]['advanced']:
                    # Don't match against the string perms
                    if isinstance(perm, str):
                        continue
                    if ace[1] & perm == perm:
                        ace_perms.append(
                            self.ace_perms[obj_type]['advanced'][perm])
                ace_perms.sort()

            # If still nothing, it must be undefined
            if not ace_perms:
                ace_perms = ['Undefined Permission: {0}'.format(ace[1])]

            return principal, ace_type, ace_prop, ace_perms, \
                   'Inherited' if inherited else 'Not Inherited'

        def rm_ace(self, principal, ace_type='all'):
            '''
            Remove a specific ACE from the DACL.

            Args:

                principal (str):
                    The user whose ACE to remove. Can be the user name or a SID.

                ace_type (str):
                    The type of ACE to remove. If not specified, all ACEs will
                    be removed. Default is 'all'. Valid options are:

                    - 'grant'
                    - 'deny'
                    - 'all'

            Returns:
                list: List of removed aces

            Usage:

            .. code-block:: python

                dacl = Dacl(obj_name='C:\\temp', obj_type='file')
                dacl.rm_ace('Users')
                dacl.save(obj_name='C:\\temp')
            '''
            sid = get_sid(principal)
            offset = 0
            ret = []

            for i in range(0, self.dacl.GetAceCount()):
                ace = self.dacl.GetAce(i - offset)

                # Is the inherited ace flag present
                inherited = ace[0][1] & win32security.INHERITED_ACE == 16

                if ace[2] == sid and not inherited:
                    if self.ace_type[ace[0][0]] == ace_type.lower() or \
                            ace_type == 'all':
                        self.dacl.DeleteAce(i - offset)
                        ret.append(self._ace_to_dict(ace))
                        offset += 1

            if not ret:
                ret = ['ACE not found for {0}'.format(principal)]

            return ret

        def save(self, obj_name, protected=None):
            '''
            Save the DACL

            Args:

                obj_name (str):
                    The object for which to set permissions. This can be the
                    path to a file or folder, a registry key, printer, etc. For
                    more information about how to format the name see:

                    https://msdn.microsoft.com/en-us/library/windows/desktop/aa379593(v=vs.85).aspx

                protected (Optional[bool]):
                    True will disable inheritance for the object. False will
                    enable inheritance. None will make no change. Default is
                    ``None``.

            Returns:
                bool: True if successful, Otherwise raises an exception

            Usage:

            .. code-block:: python

                dacl = Dacl(obj_type='file')
                dacl.save('C:\\Temp', True)
            '''
            sec_info = self.element['dacl']

            if protected is not None:
                if protected:
                    sec_info = sec_info | self.inheritance['protected']
                else:
                    sec_info = sec_info | self.inheritance['unprotected']

            if self.dacl_type in ['registry', 'registry32']:
                obj_name = self.get_reg_name(obj_name)

            try:
                win32security.SetNamedSecurityInfo(
                    obj_name,
                    self.obj_type[self.dacl_type],
                    sec_info,
                    None, None, self.dacl, None)
            except pywintypes.error as exc:
                raise CommandExecutionError(
                    'Failed to set permissions: {0}'.format(obj_name),
                    exc.strerror)

            return True

    return Dacl(obj_name, obj_type)


def get_sid(principal):
    '''
    Converts a username to a sid, or verifies a sid. Required for working with
    the DACL.

    Args:

        principal(str):
            The principal to lookup the sid. Can be a sid or a username.

    Returns:
        PySID Object: A sid

    Usage:

    .. code-block:: python

        # Get a user's sid
        hubblestack.utils.win_dacl.get_sid('jsnuffy')

        # Verify that the sid is valid
        hubblestack.utils.win_dacl.get_sid('S-1-5-32-544')
    '''
    # If None is passed, use the Universal Well-known SID "Null SID"
    if principal is None:
        principal = 'NULL SID'

    # Test if the user passed a sid or a name
    try:
        sid = hubblestack.utils.win_functions.get_sid_from_name(principal)
    except CommandExecutionError:
        sid = principal

    # Test if the SID is valid
    try:
        sid = win32security.ConvertStringSidToSid(sid)
    except pywintypes.error:
        log.exception('Invalid user/group or sid: %s', principal)
        raise CommandExecutionError(
            'Invalid user/group or sid: {0}'.format(principal))
    except TypeError:
        raise CommandExecutionError

    return sid


def copy_security(source,
                  target,
                  obj_type='file',
                  copy_owner=True,
                  copy_group=True,
                  copy_dacl=True,
                  copy_sacl=True):
    r'''
    Copy the security descriptor of the Source to the Target. You can specify a
    specific portion of the security descriptor to copy using one of the
    `copy_*` parameters.

    .. note::
        At least one `copy_*` parameter must be ``True``

    .. note::
        The user account running this command must have the following
        privileges:

        - SeTakeOwnershipPrivilege
        - SeRestorePrivilege
        - SeSecurityPrivilege

    Args:

        source (str):
            The full path to the source. This is where the security info will be
            copied from

        target (str):
            The full path to the target. This is where the security info will be
            applied

        obj_type (str): file
            The type of object to query. This value changes the format of the
            ``obj_name`` parameter as follows:
            - file: indicates a file or directory
                - a relative path, such as ``FileName.txt`` or ``..\FileName``
                - an absolute path, such as ``C:\DirName\FileName.txt``
                - A UNC name, such as ``\\ServerName\ShareName\FileName.txt``
            - service: indicates the name of a Windows service
            - printer: indicates the name of a printer
            - registry: indicates a registry key
                - Uses the following literal strings to denote the hive:
                    - HKEY_LOCAL_MACHINE
                    - MACHINE
                    - HKLM
                    - HKEY_USERS
                    - USERS
                    - HKU
                    - HKEY_CURRENT_USER
                    - CURRENT_USER
                    - HKCU
                    - HKEY_CLASSES_ROOT
                    - CLASSES_ROOT
                    - HKCR
                - Should be in the format of ``HIVE\Path\To\Key``. For example,
                    ``HKLM\SOFTWARE\Windows``
            - registry32: indicates a registry key under WOW64. Formatting is
                the same as it is for ``registry``
            - share: indicates a network share

        copy_owner (bool): True
            ``True`` copies owner information. Default is ``True``

        copy_group (bool): True
            ``True`` copies group information. Default is ``True``

        copy_dacl (bool): True
            ``True`` copies the DACL. Default is ``True``

        copy_sacl (bool): True
            ``True`` copies the SACL. Default is ``True``

    Returns:
        bool: ``True`` if successful

    Raises:
        HubbleInvocationError: When parameters are invalid
        CommandExecutionError: On failure to set security

    Usage:

    .. code-block:: python

        hubblestack.utils.win_dacl.copy_security(
            source='C:\\temp\\source_file.txt',
            target='C:\\temp\\target_file.txt',
            obj_type='file')

        hubblestack.utils.win_dacl.copy_security(
            source='HKLM\\SOFTWARE\\salt\\test_source',
            target='HKLM\\SOFTWARE\\salt\\test_target',
            obj_type='registry',
            copy_owner=False)
    '''
    obj_dacl = dacl(obj_type=obj_type)
    if 'registry' in obj_type.lower():
        source = obj_dacl.get_reg_name(source)
        log.info('Source converted to: %s', source)
        target = obj_dacl.get_reg_name(target)
        log.info('Target converted to: %s', target)

    # Set flags
    try:
        obj_type_flag = flags().obj_type[obj_type.lower()]
    except KeyError:
        raise HubbleInvocationError(
            'Invalid "obj_type" passed: {0}'.format(obj_type))

    security_flags = 0
    if copy_owner:
        security_flags |= win32security.OWNER_SECURITY_INFORMATION
    if copy_group:
        security_flags |= win32security.GROUP_SECURITY_INFORMATION
    if copy_dacl:
        security_flags |= win32security.DACL_SECURITY_INFORMATION
    if copy_sacl:
        security_flags |= win32security.SACL_SECURITY_INFORMATION

    if not security_flags:
        raise HubbleInvocationError(
            'One of copy_owner, copy_group, copy_dacl, or copy_sacl must be '
            'True')

    # To set the owner to something other than the logged in user requires
    # SE_TAKE_OWNERSHIP_NAME and SE_RESTORE_NAME privileges
    # Enable them for the logged in user
    # Setup the privilege set
    new_privs = set()
    luid = win32security.LookupPrivilegeValue('', 'SeTakeOwnershipPrivilege')
    new_privs.add((luid, win32con.SE_PRIVILEGE_ENABLED))
    luid = win32security.LookupPrivilegeValue('', 'SeRestorePrivilege')
    new_privs.add((luid, win32con.SE_PRIVILEGE_ENABLED))
    luid = win32security.LookupPrivilegeValue('', 'SeSecurityPrivilege')
    new_privs.add((luid, win32con.SE_PRIVILEGE_ENABLED))

    # Get the current token
    p_handle = win32api.GetCurrentProcess()
    t_handle = win32security.OpenProcessToken(
        p_handle,
        win32security.TOKEN_ALL_ACCESS | win32con.TOKEN_ADJUST_PRIVILEGES)

    # Enable the privileges
    win32security.AdjustTokenPrivileges(t_handle, 0, new_privs)

    # Load object Security Info from the Source
    sec = win32security.GetNamedSecurityInfo(
        source, obj_type_flag, security_flags)

    # The following return None if the corresponding flag is not set
    sd_sid = sec.GetSecurityDescriptorOwner()
    sd_gid = sec.GetSecurityDescriptorGroup()
    sd_dacl = sec.GetSecurityDescriptorDacl()
    sd_sacl = sec.GetSecurityDescriptorSacl()

    # Set Security info on the target
    try:
        win32security.SetNamedSecurityInfo(
            target, obj_type_flag, security_flags, sd_sid, sd_gid, sd_dacl,
            sd_sacl)
    except pywintypes.error as exc:
        raise CommandExecutionError(
            'Failed to set security info: {0}'.format(exc.strerror))

    return True


def get_name(principal):
    '''
    Gets the name from the specified principal.

    Args:

        principal (str):
            Find the Normalized name based on this. Can be a PySID object, a SID
            string, or a user name in any capitalization.

            .. note::
                Searching based on the user name can be slow on hosts connected
                to large Active Directory domains.

    Returns:
        str: The name that corresponds to the passed principal

    Usage:

    .. code-block:: python

        hubblestack.utils.win_dacl.get_name('S-1-5-32-544')
        hubblestack.utils.win_dacl.get_name('adminisTrators')
    '''
    # If this is a PySID object, use it
    if isinstance(principal, pywintypes.SIDType):
        sid_obj = principal
    else:
        # If None is passed, use the Universal Well-known SID for "Null SID"
        if principal is None:
            principal = 'S-1-0-0'
        # Try Converting String SID to SID Object first as it's least expensive
        try:
            sid_obj = win32security.ConvertStringSidToSid(principal)
        except pywintypes.error:
            # Try Getting the SID Object by Name Lookup last
            # This is expensive, especially on large AD Domains
            try:
                sid_obj = win32security.LookupAccountName(None, principal)[0]
            except pywintypes.error:
                # This is not a PySID object, a SID String, or a valid Account
                # Name. Just pass it and let the LookupAccountSid function try
                # to resolve it
                sid_obj = principal

    # By now we should have a valid PySID object
    try:
        return win32security.LookupAccountSid(None, sid_obj)[0]
    except (pywintypes.error, TypeError) as exc:
        message = 'Error resolving "{0}"'.format(principal)
        if type(exc) == pywintypes.error:
            win_error = win32api.FormatMessage(exc.winerror).rstrip('\n')
            message = '{0}: {1}'.format(message, win_error)
        log.exception(message)
        raise CommandExecutionError(message, exc)