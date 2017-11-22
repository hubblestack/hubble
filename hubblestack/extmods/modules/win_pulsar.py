#win_notify
'''
This will setup your computer to enable auditing for specified folders inputted into a yaml file. It will
then scan the ntfs journal for changes to those folders and report when it finds one.
'''


from __future__ import absolute_import

import collections
import datetime
import fnmatch
import logging
import os
import glob
import yaml
import re

import salt.ext.six
import salt.loader

log = logging.getLogger(__name__)
DEFAULT_MASK = ['ExecuteFile', 'Write', 'Delete', 'DeleteSubdirectoriesAndFiles', 'ChangePermissions',
                'TakeOwnership'] #ExecuteFile Is really chatty
DEFAULT_TYPE = 'all'

__virtualname__ = 'pulsar'
CONFIG = None
CONFIG_STALENESS = 0


def __virtual__():
    if not salt.utils.is_windows():
        return False, 'This module only works on windows'
    return __virtualname__

def process(configfile='salt://hubblestack_pulsar/hubblestack_pulsar_win_config.yaml',
            verbose=False):
    '''
    Watch the confugred files

    Example yaml config on fileserver (targeted by configfile option)

    .. code-block:: yaml
        C:\Users: {}
        C:\Windows:
          mask:
            - 'File Create'
            - 'File Delete'
            - 'Security Change'
          exclude:
            - C:\Windows\System32\*
        C:\temp: {}
        return: splunk_pulsar_return
        batch: True

    Note that if 'batch: True', the configured returner must support receiving a list of events, rather than single one-off events

    the mask list can contain the following events (the default mask is create, delete, and modify):

        1.  Basic Info Change                A user has either changed file or directory attributes, or one or more time stamps
        2.  Close                            The file or directory is closed
        3.  Compression Change               The compression state of the file or directory is changed from or to compressed
        4.  Data Extend                      The file or directory is extended (added to)
        5.  Data Overwrite                   The data in the file or directory is overwritten
        6.  Data Truncation                  The file or directory is truncated
        7.  EA Change                        A user made a change to the extended attributes of a file or directory (These NTFS 
                                                    file system attributes are not accessible to Windows-based applications)
        8.  Encryption Change                The file or directory is encrypted or decrypted
        9.  File Create                      The file or directory is created for the first time
        10. File Delete                      The file or directory is deleted
        11. Hard Link Change                 An NTFS file system hard link is added to or removed from the file or directory
        12. Indexable Change                 A user changes the FILE_ATTRIBUTE_NOT_CONTENT_INDEXED attribute (changes the file 
                                                    or directory from one where content can be indexed to one where content cannot 
                                                    be indexed, or vice versa)
        13. Integrity Change                 A user changed the state of the FILE_ATTRIBUTE_INTEGRITY_STREAM attribute for the given 
                                                    stream (On the ReFS file system, integrity streams maintain a checksum of all 
                                                    data for that stream, so that the contents of the file can be validated during 
                                                    read or write operations)
        14. Named Data Extend                The one or more named data streams for a file are extended (added to)
        15. Named Data Overwrite             The data in one or more named data streams for a file is overwritten
        16. Named Data truncation            The one or more named data streams for a file is truncated
        17. Object ID Change                 The object identifier of a file or directory is changed
        18. Rename New Name                  A file or directory is renamed, and the file name in the USN_RECORD_V2 structure is the 
                                                    new name
        19. Rename Old Name                  The file or directory is renamed, and the file name in the USN_RECORD_V2 structure is
                                                    the previous name
        20. Reparse Point Change             The reparse point that is contained in a file or directory is changed, or a reparse 
                                                    point is added to or deleted from a file or directory
        21. Security Change                  A change is made in the access rights to a file or directory
        22. Stream Change                    A named stream is added to or removed from a file, or a named stream is renamed
        23. Transacted Change                The given stream is modified through a TxF transaction

    exclude:
        Exclude directories or files from triggering events in the watched directory. **Note that the directory excludes shoud
        not have a trailing slash**
    
    :return:
    '''
    config = __salt__['config.get']('hubblestack_pulsar' , {})
    if isinstance(configfile, list):
        config['paths'] = configfile
    else:
        config['paths'] = [configfile]
    config['verbose'] = verbose
    global CONFIG_STALENESS
    global CONFIG
    if config.get('verbose'):
        log.debug('Pulsar module called.')
        log.debug('Pulsar module config from pillar:\n{0}'.format(config))
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
            log.debug('No cached config found for pulsar, retrieving fresh from fileserver.')
        new_config = config
        if isinstance(config.get('paths'), list):
            for path in config['paths']:
                if 'salt://' in path:
                    path = __salt__['cp.cache_file'](path)
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

    # check if cache path contails starting point for 'fsutil usn readjournal'
    cache_path = os.path.join(__opts__['cachedir'], 'win_pulsar_usn')
    # if starting point doesn't exist, create one then finish until next run
    if not os.path.isfile(cache_path):
        queryjournal('C:')
        with open(cache_path, 'w') as f:
            f.write(qj_dict['Next Usn'])
        return ret

    # read in start location and grab all changes since then
    with open(cache_path, 'r') as f:
        nusn = f.read()
    nusn, jitems = readjournal('C:', nusn)

    # create new starting point for next run
    with open(cache_parth, 'w') as f:
        f.write(nusn)

    # filter out unrequested changed
    ret_list = usnfilter(jitems, config)

    # return list of dictionaries
    return ret_list
    
        
def queryjournal(drive):
    '''
    Gets information on the journal prosiding on the drive passed into the method
    returns a dictionary with the following information:
      USN Journal ID
      First USN of the journal
      Next USN to be written to the journal
      Lowest Valid USN of the journal since the biginning of the volume (this will most likely 
                                  not be in the current journal since it only keeys a few days)
      Max USN of the journal (the highest number reachable for a single Journal)
      Maximum Size
      Allocation Delta
      Minimum record version supported
      Maximum record version supported
      Write range tracking (enabled or disabled)
    '''
    qjournal =  (__salt__['cmd.run']('fsutil usn queryjournal {0}'.format(drive))).split('\r\n')
    qj_dict = {}
    #format into dictionary
    if qjournal:
        #remove empty string
        qjournal.pop()
        for item in qjournal:
            qkey, qvalue = item.split(': ')
            qj_dict[qkey.strip()] = qvalue.strip()
    return qj_dict

def readjournal(drive, next_usn=0):
    '''
    Reads the data inside the journal.  Default is to start from the beginning, 
    but you can pass an argument to start from whichever usn you want
    Returns a list of dictionaries with the following information
      list:
        Individual events
    
      dictionary:
        Usn Journal ID (event number)
        File Name
        File name Length
        Reason (what hapened to the file)
        Time Stamp
        File attributes
        File ID
        Parent file ID
        Source Info
        Security ID
        Major version
        Minor version
        Record length
    '''
    jdata = (__salt__['cmd.run']('fsutil usn readjournal {0} startusn={1}'.format(drive, next_usn))).split('\r\n\r\n')
    jd_list = []
    if jdata:
        #prime for next delivery
        jinfo = jdata[0].split('\r\n')
        nusn = jinfo[2].split(' : ')[1]
        #remove first item of list
        jdata.pop(0)
        #format into dictionary
        for dlist in jdata:
            jd_dict = {}
            i_list = dlist.split('\r\n')
            for item in i_list:
                if item == '':
                    continue
                dkey, dvalue = item.split(' : ')
                jd_dict[dkey.strip()] = dvalue.strip()
            jd_dict['Path'] = getfilepath(jd_dict['File ID'], jd_dict['Parent file ID'], jd_dict['File name'])
            jd_list.append(jd_dict)
    return nusn, jd_list


def getfilepath(fid, pfid, fname):
    '''
    Gets file name and path from a File ID
    '''
    try:
        jfullpath = (__salt__['cmd.run']('fsutil file queryfilenamebyid {0} 0x{1}'.format(drive, fid))).replace('?\\', '\r\n')
    except:
        log.debug('Current usn item is not a file')
        return None
    
    if 'Error:' in jfullpath:
        log.debug('Searching for the File ID came back with error.  Trying the parent folder')
        jfullpath = (__salt__['cmd.run']('fsutil file queryfilenamebyid {0} 0x{1}'.format(drive, pfid))).replace('?\\', '\r\n')
        if 'Error:' in jfullpath:
            log.debug('Current usn cannot be queried as file')
            return None
        retpath = jfullpath.split('\r\n')[1] + fname
        return retpath
    retpath = jfullpath.split('\r\n')[1]
    return retpath

def usnfilter(usn_list, config_paths):
    ret_usns = []
    fpath = usn_dict['Path']
    if fpath is None:
        log.debug('The following change made was not a file. {0}'.format(usn_dict))
        return False
    basic_paths = []
    for path in config_paths:
        if path in ['win_notify_interval', 'return', 'batch', 'checksum', 'stats', 'paths', 'verbose']:
            continue
        if not os.path.exists(path):
            log.info('the folder path {} does not exist'.format(path))
            continue
        
        if isinstance(config[path], dict):
            mask = config[path].get('mask', DEFAULT_MASK)
            recurse = config[path].get('recurse', True)
            exclude = config[path].get('exclude', False)

        # iterate through usn_list
        for usn in usn_list:
            fpath = usn['Path']
            if fpath is None:
                log.debug('The following change made was not a file. {0}'.format(usn_dict))
                continue
            # check if base path is in file location
            if path in fpath:
                #check if mask matches
                freason = usn['Reason'].split(': ')[1]
                if freason in mask:
                    throw_away = False
                    for p in exclude:
                        # fnmatch allows for * and ? as wildcards
                        if fnmatch.fnmatch(fpath, p):
                            throw_away = True
                            break
                    if throw_away is True:
                        continue
                    else:
                        ret_usns.append(usn)
                else:
                    continue
            else:
                continue






def canary(change_file=None):
    '''
    Simple module to change a file to trigger a FIM event (daily, etc)

    THE SPECIFIED FILE WILL BE CREATED AND DELETED

    Defaults to CONF_DIR/fim_canary.tmp, i.e. /etc/hubble/fim_canary.tmp
    '''
    if change_file is None:
        conf_dir = os.path.dirname(__opts__['conf_file'])
        change_file = os.path.join(conf_dir, 'fim_canary.tmp')
    __salt__['file.touch'](change_file)
    os.remove(change_file)

