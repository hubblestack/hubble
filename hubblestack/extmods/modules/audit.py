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
    'Failure': 'Failure',
    'Skipped': 'Skipped',
    'Error': 'Error'
}

__nova__ = None

def run(audit_files=None,
        tags='*',
        labels=None,
        verbose=None,
        show_compliance=None,
        debug=None,
        results="all"):
    """
    :param audit_files: Profile to execute. Can have one or more files (python list or comma separated) (default: {None})
    :param tags: [description] (default: {'*'})
    :param labels: Tests with matching labels are executed. If multiple labels are passed, then tests which have all those labels are executed.
    :param verbose: [description] (default: {True})
    :param show_compliance:
    :param debug:
    :param results: what type of results to show (success/failure/skipped/error/all) (default: {"all"})
    :return:
    """
    if audit_files is None:
        return top(verbose=verbose,
                   show_compliance=show_compliance,
                   labels=labels)
    # categories of results
    result_dict = {
      'Success': [],
      'Failure': [],
      'Error': [],
      'Skipped': [],
    }
    combined_dict = {}
    if type(show_compliance) is str and show_compliance.lower().strip() in ['true', 'false']:
        show_compliance = show_compliance.lower().strip() == 'true'
    if type(verbose) is str and verbose.lower().strip() in ['true', 'false']:
        verbose = verbose.lower().strip() == 'true'
    if labels:
        if not isinstance(labels, list):
            labels = labels.split(',')
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
    for audit_file in audit_files:
        # Cache audit file
        log.debug('caching file...')
        file_cache_path = __salt__['cp.cache_file'](audit_file)

        # validate audit file
        # Fileserver will return False if the file is not found
        if not file_cache_path:
            log.error('Could not find audit file %s', audit_file)
            continue

        log.debug('Processing %s', audit_file)
        audit_data_dict = __load_and_validate_yaml_file(file_cache_path, audit_file)
        if not audit_data_dict:
            log.error('Audit file: %s could not be loaded', audit_file)
            continue

        ret = __run_audit(audit_data_dict, tags, audit_file, verbose, labels)
        combined_dict[audit_file]=ret

    __evaluate_results(result_dict, combined_dict, show_compliance)
    return result_dict

def top(topfile='top.nova',
        verbose=None,
        show_compliance=None,
        labels=None):

    results = {}
    # Will be a combination of strings and single-item dicts. The strings
    # have no tag filters, so we'll treat them as tag filter '*'. If we sort
    # all the data by tag filter we can batch where possible under the same
    # tag.
    data_by_tag = _build_data_by_tag(topfile, results)

    if not data_by_tag:
        return results

    # Run the audits
    for tag, data in data_by_tag.items():
        ret = run(audit_files=data,
                  tags=tag,
                  verbose=verbose,
                  show_compliance=False,
                  labels=labels)

        # Merge in the results
        for key, val in ret.items():
            if key not in results:
                results[key] = []
            results[key].extend(val)

    if show_compliance:
        compliance = _calculate_compliance(results)
        if compliance:
            results['Compliance'] = compliance

    _clean_up_results(results)
    return results

def __run_audit(audit_data_dict, tags, audit_file, verbose, labels):
    
    # got data for one audit file
    # lets parse, validate and execute one by one
    result_list = []
    for audit_id, audit_data in audit_data_dict.items():
        log.debug('Executing check-id: %s in audit file: %s', audit_id, audit_file)

        audit_impl = __get_matched_implementation(audit_id, audit_data, tags, labels)
        if not audit_impl:
            # no matched impl found
            continue

        if not __validate_audit_data(audit_id, audit_impl):
            continue

        try:
            # version check
            if not __is_audit_check_version_compatible(audit_id, audit_impl):
                raise AuditCheckVersionIncompatibleError('Version not compatible')
        
            # handover to module
            audit_result = __execute_module(audit_id, audit_impl, audit_data, verbose)
            result_list.append(audit_result)
        except AuditCheckValdiationError as validation_error:
            # add into error section
            error_dict={}
            error_dict['tag'] = audit_data['tag']
            error_dict['description'] = audit_data['description']
            error_dict['check_result'] = CHECK_STATUS['Error']
            result_list.append(error_dict)
            log.error(validation_error)
        except AuditCheckVersionIncompatibleError as version_error:
            # add into skipped section
            skipped_dict = {}
            skipped_dict['tag'] = audit_data['tag']
            skipped_dict['description'] = audit_data['description']
            skipped_dict['check_result'] = CHECK_STATUS['Skipped']
            result_list.append(skipped_dict)
            log.error(version_error)
        except Exception as exc:
            import traceback
            traceback.print_exc()
            log.error(exc)
    #return list of results for a file
    return result_list

def __execute_module(audit_id, audit_impl, audit_data, verbose):
    audit_result = {
        "check_id": audit_id,
        "description": audit_data['description'],
        "sub_check": audit_data.get('sub_check', False),
        "tag": audit_data['tag'],
        "module": audit_impl['module'],
        "run_config": {
            "filter": audit_impl['filter'],
        }
    }

    failure_reason = audit_data.get('failure_reason', '')
    invert_result = audit_data.get('invert_result', False)
    return_no_exec = audit_impl.get('return_no_exec', False)
    type = audit_impl.get('type', 'and').lower().strip()

    #check for type in check implementation. If not present default is 'and'
    audit_result['type'] = type

    # check if return_no_exec is true
    if return_no_exec:
        audit_result['run_config']['return_no_exec'] = True
        check_result = CHECK_STATUS['Success']
        if invert_result:
            audit_result['invert_result'] = True
            check_result = CHECK_STATUS['Failure']
            audit_result['failure_reason'] = failure_reason
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
    # calculate the check result based on type parameter.
    # If type is 'and', all subchecks should pass for success.
    # If type is 'or', any passed subcheck will result in success.
    overall_result = type=='and'
    failure_reasons = []
    for audit_check in audit_impl['checks']:
        module_result_local = __nova__[execute_method](audit_id, audit_check)
        audit_result_local = {}
        if module_result_local['result']:
            audit_result_local['check_result'] = CHECK_STATUS['Success']
        else:
            audit_result_local['check_result'] = CHECK_STATUS['Failure']
            audit_result_local['failure_reason'] = module_result_local['failure_reason']
            failure_reasons.append(audit_result_local['failure_reason'])
        module_logs = {}
        if not verbose:
            log.debug('Non verbose mode')
            module_logs = __nova__[filtered_log_method](audit_id, audit_check)
        else:
            log.debug('verbose mode')
            module_logs = audit_check

        audit_result_local = {**audit_result_local, **module_logs}
        # add this result
        audit_result['run_config']['checks'].append(audit_result_local)
        if type == 'and':
            overall_result = overall_result and module_result_local['result']
        else:
            overall_result = overall_result or module_result_local['result']

    #Update overall check result based on invert result
    overall_result = overall_result != invert_result

    if overall_result:
        audit_result['check_result'] = CHECK_STATUS['Success']
    else:
        # If check result is failure, fetch failure reason. If it is not present in profile, combine all individual checks reasons.
        audit_result['check_result'] = CHECK_STATUS['Failure']
        if failure_reason:
            audit_result['failure_reason'] = failure_reason
        else:
            if failure_reasons:
                    failure_reasons = set(failure_reasons)
                    audit_result['failure_reason'] = ', '.join(failure_reasons)
            else:
                if invert_result:
                    audit_result['failure_reason'] = 'Check failed due to invert result is set to true'

    return audit_result


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
    >1
    """
    log.debug("Current hubble version: %s" % __grains__['hubble_version'])
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

def __get_matched_implementation(audit_check_id, audit_data, tags, labels):
    log.debug('Getting matching implementation')

    # check if label passed is matching with the check or not.
    # If label is not matched, no need to fetch matched implementation
    if labels:
        check_labels = audit_data.get('labels', [])
        if not set(labels).issubset(check_labels):
            log.debug('Not executing audit_check: %s, user passed label: %s did not match audit labels: %s', audit_check_id, labels, check_labels)
            return None

    # check if tag passed matches with current check or not
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
    log.debug('Validating yaml file: %s', audit_filename)
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
    

def __evaluate_results(result_dict, combined_dict, show_compliance):
    """
    Evaluate the result dictionary to be returned by the audit module
    :param result_dict:
    :param combined_dict:
    :param show_compliance:
    :return:
    """
    for audit_file in combined_dict:
        result_list = combined_dict[audit_file]
        for result in result_list:
            sub_check = result.get('sub_check', False)
            if not sub_check:
                dict={}
                dict[result['tag']]=result['description']
                if result['check_result'] == CHECK_STATUS['Success']:
                    result_dict[CHECK_STATUS['Success']].append(dict)
                elif result['check_result'] == CHECK_STATUS['Failure']:
                    result_dict[CHECK_STATUS['Failure']].append(dict)
                elif result['check_result'] == CHECK_STATUS['Error']:
                    result_dict[CHECK_STATUS['Error']].append(dict)
                elif result['check_result'] == CHECK_STATUS['Skipped']:
                    result_dict[CHECK_STATUS['Skipped']].append(dict)
    if show_compliance:
        compliance = _calculate_compliance(result_dict)
        result_dict['Compliance']=compliance

def _calculate_compliance(result_dict):
    """
    Calculates the compliance number from the given result dictionary
    :param result_dict:
    :return:
    """
    success = len(result_dict[CHECK_STATUS['Success']])
    failure = len(result_dict[CHECK_STATUS['Failure']])
    error = len(result_dict[CHECK_STATUS['Error']])
    # skipped = len(result_dict[CHECK_STATUS['Skipped']])
    total_checks = success + failure + error
    if total_checks > 0:
        compliance = float(success)/total_checks
        compliance = int(compliance * 100)
        compliance = '{0}%'.format(compliance)
        return compliance
    return None

def _build_data_by_tag(topfile, results):
    """
    Helper function that goes over data in top_data and
    aggregate it by tag
    """
    data_by_tag = {}

    # Get a list of yaml to run
    top_data = _get_top_data(topfile)

    for data in top_data:
        if isinstance(data, str):
            if '*' not in data_by_tag:
                data_by_tag['*'] = []
            data_by_tag['*'].append(data)
        elif isinstance(data, dict):
            for key, tag in data.items():
                if tag not in data_by_tag:
                    data_by_tag[tag] = []
                data_by_tag[tag].append(key)
        else:
            if 'Errors' not in results:
                results['Errors'] = {}
            error_log = 'topfile malformed, list entries must be strings or ' \
                        'dicts: {0} | {1}'.format(data, type(data))
            results['Errors'][topfile] = {'error': error_log}
            log.error(error_log)
            continue

    return data_by_tag

def _get_top_data(topfile):
    """
    Helper method to retrieve and parse the nova topfile
    """
    topfile = 'salt://' + BASE_DIR_NOVA_PROFILES + os.sep + topfile;
    log.debug('caching top file...')
    topfile_cache_path = __salt__['cp.cache_file'](topfile)
    if not topfile_cache_path:
        log.error('Could not find top file %s', topfile)
        return None
    try:
        with open(topfile_cache_path) as handle:
            topdata = yaml.safe_load(handle)
    except Exception as exc:
        log.exception('Could not load topfile: {0}'.format(exc))
        return None

    if not isinstance(topdata, dict) or 'nova' not in topdata or \
            (not isinstance(topdata['nova'], dict)):
        log.exception('Nova topfile not formatted correctly')
        return None
    topdata = topdata['nova']
    ret = []
    for match, data in topdata.items():
        if __salt__['match.compound'](match):
            ret.extend(data)
    return ret

def _clean_up_results(results):
    """
    Helper function that cleans up the results by
    removing the keys with empty values, adding an error message if
    results is empty
    """
    for key in list(results.keys()):
        if not results[key]:
            results.pop(key)

    if not results:
        results['Messages'] = 'No audits matched this host in the specified profiles.'