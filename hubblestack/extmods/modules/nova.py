# -*- encoding: utf-8 -*-

import logging
import os
import yaml
import fnmatch

from packaging import version

import salt.loader
import salt.utils

from hubblestack.utils.hubble_error import AuditCheckFailedError
from hubblestack.utils.hubble_error import AuditCheckVersionIncompatibleError
from hubblestack.utils.hubble_error import AuditCheckValdiationError

log = logging.getLogger(__name__)

# base directory of new nova profiles
BASE_DIR_NOVA_PROFILES = 'hubblestack_nova_profiles_v2'
CHECK_STATUS = {
    'Success': 'Success',
    'Failure': 'Failure'
}

__nova__ = None

def audit(audit_files=None,
        tags='*',
        verbose=True,
        results="all"):
    """[summary]

    Keyword Arguments:
        audit_files {str or list} -- Profile to execute. Can have one or more files (python list or comma separated) (default: {None})
        tags {str} -- [description] (default: {'*'})
        verbose {bool} -- [description] (default: {True})
        results {str} -- what type of results to show (success/failure/skipped/error/all) (default: {"all"})
    """

    # categories of results
    result_dict = {
      'Success': [],
      'Failure': [],
      'Error': [],
      'Skipped': [],
    }

    if type(verbose) is str and verbose in ['True', 'False']:
        verbose = verbose == 'True'

    log.info('debug 1')
    # validate and get list of filepaths
    audit_files = __get_audit_files(audit_files)
    if not audit_files:
        return result_dict

    global __nova__
    __nova__ = salt.loader.LazyLoader(salt.loader._module_dirs(__opts__, 'nova_v2_modules'),
                                        __opts__,
                                        tag='nova_v2_modules',
                                        pack={'__salt__': __salt__,
                                              '__grains__': __grains__})
    #
    # Lets start iterating over audit files
    # 
    for audit_file in audit_files:
        # Cache audit file
        log.info('caching file...')
        file_cache_path = __salt__['cp.cache_file'](audit_file)
        log.info(file_cache_path)

        # validate audit file
        # Fileserver will return False if the file is not found
        if not file_cache_path:
            log.error('Could not find audit file %s', audit_file)
            continue

        log.info('Processing %s', audit_file)
        audit_data_dict = __load_and_validate_yaml_file(file_cache_path, audit_file)
        if not audit_data_dict:
            log.error('Audit file: %s could not be loaded', audit_file)
            continue

        ret = __run_audit(audit_data_dict, tags, audit_file, verbose)

def __run_audit(audit_data_dict, tags, audit_file, verbose):
    
    # got data for one audit file
    # lets parse, validate and execute one by one
    for audit_id, audit_data in audit_data_dict.items():
        log.debug('Executing check-id: %s in audit file: %s', audit_id, audit_file)

        audit_impl = __get_matched_implementation(audit_id, audit_data, tags)
        if not audit_impl:
            # no matched impl found
            continue

        if not __validate_audit_data(audit_id, audit_impl):
            continue

        try:
            # version check
            if not __is_audit_check_version_compatible(audit_id, audit_impl):
                # add into skipped section
                raise AuditCheckVersionIncompatibleError('Version not compatible')
        
            # handover to module
            audit_result = __execute_module(audit_id, audit_impl, audit_data, verbose)
        
        except AuditCheckVersionIncompatibleError as version_error:
            log.error(version_error)
        except Exception as exc:
            import traceback
            traceback.print_exc()
            # log.error(exc)

        # parse check
        # get tag and description
        # Make note of sub_check=true/false
        # iterate over implementations
          # Match an implementation by grains match
          # Do version check
          # check if return_no_exec is true. No need to go further
          # get required module
          # Now, initialize respective module

          # module::validate
          # module::execute
          # if verbose=off: call module::get_params_to_log()
          # keep record of results

        # 

def __execute_module(audit_id, audit_impl, audit_data, verbose):
    audit_result = {
        "check_id": audit_id,
        "description": audit_data['description'],
        "tag": audit_data['tag'],
        "check_result": CHECK_STATUS['Success'],
        "module": audit_impl['module'],
        
        "run_config": {
            "filter": audit_impl['filter'],
        }
    }

    # check if return_no_exec is true
    if 'return_no_exec' in audit_impl and audit_impl['return_no_exec']:
        audit_result['run_config']['return_no_exec'] = True
        check_result = CHECK_STATUS['Success']
        if 'invert_result' in audit_data and audit_data['invert_result']:
            audit_result['invert_result'] = True
            check_result = CHECK_STATUS['Failure']
        audit_result['check_result'] = check_result
        return audit_result

    # Check presence of implementation checks
    if 'checks' not in audit_impl:
        raise AuditCheckValdiationError('No checks are present')

    # Execute module validation of params
    validate_param_method = audit_impl['module'] + '.validate_params'
    for audit_check in audit_impl['checks']:
        __nova__[validate_param_method](audit_id, audit_check)

    # validate succeded, lets execute it and prepare result dictionary
    audit_result['run_config']['checks'] = []
    execute_method = audit_impl['module'] + '.execute'
    filtered_log_method = audit_impl['module'] + '.get_filtered_params_to_log'
    for audit_check in audit_impl['checks']:
        module_result_local = __nova__[execute_method](audit_id, audit_check)
        audit_result_local = {}
        if module_result_local['result']:
            audit_result_local['check_result'] = CHECK_STATUS['Success']
        else:
            # if 'failure_reason' in audit_data:
            #     audit_result_local
            audit_result_local['check_result'] = CHECK_STATUS['Failure']
        
        module_logs = {}
        if not verbose:
            log.info('Non verbose mode')
            module_logs = __nova__[filtered_log_method](audit_id, audit_check)
        else:
            log.info('verbose mode')
            module_logs = audit_check

        audit_result_local = {**audit_result_local, **module_logs}
        # add this result
        audit_result['run_config']['checks'].append(audit_result_local)

        

    log.info('~~~~~~~ Result ~~~~~~~~~')
    import json
    log.info(json.dumps(audit_result, sort_keys=False, indent=4))
    # log.info(audit_result)
    log.info('~~~~~~~~~~~~~~~~~~~~~~~~')



def __is_audit_check_version_compatible(audit_check_id, audit_impl):
    """
    Function to check if current hubble version matches with provided values
    :param audit_check_id:
    :param audit_data:
    :return: boolean

    Provided values expect string with operators AND and OR.
    The precedence of AND is greater than OR and for a group of AND or OR, the order of evaluation is from left to right
    Following are the valid comparison operators:
    <,>,<=,>=,==,!=
    The version value after comparison operators should be fixed string. No regex is allowed in this version.
    If any character apart from the allowed values is passed to the provided values, then this function will throw the InvalidSyntax Error
    Some valid string types
    >3.0.0
    <=4.0.0
    >=2.0.0 OR != 4.1.2
    >=1.0.0 AND <=9.1.2 OR >=0.1.1 AND <=0.9.9
    >=2.0.0 AND >3.0.0 AND <=4.0.0 OR ==5.0.0
    >1.0 AND <10.0 AND >=2.0. OR >=4.0 AND <=5.0 OR ==6.0
    """
    log.info("Current hubble version: %s" % __grains__['hubble_version'])
    current_version = version.parse(__grains__['hubble_version'])
    version_str = audit_impl['hubble_version'].upper()
    version_list = [[x.strip() for x in item.split("AND")] for item in version_str.split("OR")]
    #[['>=2.0.0','>3.0.0','<=4.0.0'], ['==5.0.0']]
    expression_result = []
    for expression in version_list: #Outer loop to evaluate OR conditions
        condition_match=True
        for condition in expression: #Inner loop to evaluate AND conditions
            if condition.startswith('<='):
                condition = condition[2:]
                result = current_version <= version.parse(condition)
            elif condition.startswith('>='):
                condition = condition[2:]
                result = current_version >= version.parse(condition)
            elif condition.startswith('<'):
                condition = condition[1:]
                result = current_version < version.parse(condition)
            elif condition.startswith('>'):
                condition = condition[1:]
                result = current_version > version.parse(condition)
            elif condition.startswith('=='):
                condition = condition[2:]
                result = current_version == version.parse(condition)
            elif condition.startswith('!='):
                condition = condition[2:]
                result = current_version != version.parse(condition)
            else:
                # Throw error as unexpected string occurs
                log.error("Invalid syntax in version condition, check_id: %s condition: %s" % (audit_check_id, condition))
            condition_match = condition_match and result
            if not condition_match:
                # Found a false condition. No need to evaluate further for AND conditions
                break
        if condition_match:
            # Found a true condition. No need to evaluate further for OR conditions
            return True
    return False
    
def __validate_audit_data(audit_id, audit_impl):
    if 'module' not in audit_impl:
        log.error('Matched implementation does not have module mentioned, check_id: %s', audit_id)
        return False

    return True

def __get_matched_implementation(audit_check_id, audit_data, tags):
    log.debug('Getting matching implementation')

    # first check if tag passed matches with current check or not
    # if tag is not matched, no need to fetch matched implementation
    audit_check_tag = audit_data.get('tag', audit_check_id)
    if not fnmatch.fnmatch(audit_check_tag, tags):
        log.debug('Not executing audit_check: %s, user passed tag: %s did not match this audit tag: %s', audit_check_id, tags, audit_check_tag)
        return None

    # Lets look for matching implementation based on os.filter grain
    for implementation in audit_data['implementations']:
        target = implementation['filter'].get('grains', '*')

        if __salt__['match.compound'](target):
            return implementation

    log.debug('No target matched for audit_check_id: %s', audit_check_id)
    return None

def __load_and_validate_yaml_file(filepath, audit_filename):
    """
    Load and validate yaml file
    File must be a valid yaml file, and content loaded must form a python-dictionary

    Arguments:
        filepath {str} -- Actual filepath of profile file
        audit_filename {str} -- Filename for logging purpose

    Returns:
        [type] -- [description]
    """
    log.info('Validating yaml file: %s', audit_filename)
    # validating physical file existance
    if not filepath or not os.path.isfile(filepath):
        log.error('Could not find file: %s', filepath)
        return None

    yaml_data = None
    try:
        with open(filepath, 'r') as file_handle:
            yaml_data = yaml.safe_load(file_handle)
    except Exception as exc:
        log.exception('Error loading yaml file: %s, Error: %s', audit_filename, exc)
        return None

    if not yaml_data or not isinstance(yaml_data, dict):
        log.error('yaml data could not be loaded in python dictionary form: %s', audit_filename)
        return None
    return yaml_data
    

def __get_audit_files(audit_files):
    """Get audit files list, if valid

    Arguments:
        audit_files {str or list} -- File lists either in comma-separated or python-list

    Returns:
        list -- List of audit files
    """
    if not audit_files:
        log.warning('nova.audit called without any audit_files')
        return None

    if not isinstance(audit_files, list):
        audit_files = audit_files.split(',')

    # prepare paths
    return ['salt://' + BASE_DIR_NOVA_PROFILES + os.sep + audit_file.replace('.', os.sep) + '.yaml'
                    for audit_file in audit_files]
    
