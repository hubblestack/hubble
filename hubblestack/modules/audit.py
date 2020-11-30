# -*- encoding: utf-8 -*-
"""
Audit module
This module is used to run audit checks in Hubble

Checks use a specific audit sub module like 'grep' or 'fdg'
A sample check is defined in yaml as follows:

check_id:
  description: 'dummy test'
  tag: 'ADOBE-1'
  labels:
    - 'sample label 1'
    - 'sample label 2'
  sub_check: true

  failure_reason: 'fail reason'

  invert_result: true

  implementations:
    - filter:
        grains: 'G@osfinger:CentOS*Linux-8'

      hubble_version: '>=4.5'

      return_no_exec: true

      module: stat

      check_eval_logic: and

      checks:
        - path: /etc/ssh/sshd_config.1
          gid: 0
          group: root
          mode: 644
          uid: 0
          user: root
          allow_more_strict: true

The various fields common to checks are defined below:

check_id:
    Unique identifier for a check. Mandatory

description:
    The description of check

tag:
    The tag associated with a check. It can be used to target a check based on tag. Optional

labels:
    The labels associated with a check. We can filter out checks based on labels. Optional

sub_check:
    Flag to execute a check but not report its output in final outcome. Default - false

failure_reason:
    Custom reason to be published in final output if check result is failure. Optional

invert_result:
    Flag to invert the result of check from success to failure or vice versa. Default - false

grains:
    Salt grains to specify on which particular OS/Kernel this check is intended to run. Default - *

hubble_version:
    String to specify version of hubble on which this check is intended to run. Default - *

return_no_exec:
    Flag to specify if a check is not to be executed. The final output is Success in case other flags are not used. Default - false

module:
    Name of audit module that is called for check. Mandatory

check_eval_logic:
    In case there are multiple checks to be run on audit module, the final result is based on the 'check_eval_logic'. Default - and

checks:
    List of params to be passed to each audit sub module. The list of params can be found in the indvidual module documentation. Mandatory

The output of this module is dict containing result of execution of checks. It can be one of following results:
1. Error - An error in execution of a check
2. Skipped - A check is skipped due to check params
3. Success - A check is executed and results in a success
4. Failure - A check is executed and results in failure
There are additional features as verbose logging, compliance and debug which can be passed as flags.
"""

import logging
import os

import yaml

import hubblestack.module_runner.runner_factory as runner_factory
from hubblestack.utils.exceptions import CommandExecutionError
from hubblestack.status import HubbleStatus

log = logging.getLogger(__name__)

hubble_status = HubbleStatus(__name__, 'top', 'run')
BASE_DIR_AUDIT_PROFILES = 'hubblestack_audit_profiles'

CHECK_STATUS = {
    'Success': 'Success',
    'Failure': 'Failure',
    'Skipped': 'Skipped',
    'Error': 'Error'
}


@hubble_status.watch
def run(audit_files=None,
        tags='*',
        labels=None,
        verbose=None,
        show_compliance=None):
    """
    :param audit_files:
        Profile to execute. Can have one or more files
        (python list or comma separated) (default: {None})
    :param tags:
        Can be used to target a subset of tags via glob targeting.
    :param labels:
        Tests with matching labels are executed. If multiple labels are passed,
        then tests which have all those labels are executed.
    :param verbose:
        True by default. If set to False, results will be trimmed to just tags
        and descriptions.
    :param show_compliance:
        Whether to show compliance with results or not
    :return:
        Returns dictionary with Success, Skipped, and Failure keys and the
        results of the checks
    """
    try:
        if audit_files is None:
            return top(verbose=verbose,
                       tags=tags,
                       show_compliance=show_compliance,
                       labels=labels)

        audit_runner = runner_factory.get_audit_runner()

        # categories of results
        result_dict = {
            'Success': [],
            'Failure': [],
            'Error': [],
            'Skipped': [],
        }
        combined_dict = {}

        if verbose is None:
            verbose = __mods__['config.get']('hubblestack:nova:verbose', False)
        if show_compliance is None:
            show_compliance = __mods__['config.get']('hubblestack:nova:show_compliance', True)

        if type(show_compliance) is str and show_compliance.lower().strip() in ['true', 'false']:
            show_compliance = show_compliance.lower().strip() == 'true'
        if type(verbose) is str and verbose.lower().strip() in ['true', 'false']:
            verbose = verbose.lower().strip() == 'true'
        if labels:
            if not isinstance(labels, list):
                labels = labels.split(',')
        # validate and get list of filepaths
        audit_files = _get_audit_files(audit_files)
        if not audit_files:
            return result_dict

        # initialize loader
        audit_runner.init_loader()
        for audit_file in audit_files:
            ret = audit_runner.execute(audit_file, {
                'tags': tags,
                'labels': labels,
                'verbose': verbose
            })
            combined_dict[audit_file] = ret

        _evaluate_results(result_dict, combined_dict, show_compliance, verbose)
    except Exception as e:
        log.error("Error while running audit run method: %s" % e)

    return result_dict


def _get_audit_files(audit_files):
    """Get audit files list, if valid

    Arguments:
        audit_files {str or list} -- File lists either in comma-separated or python-list

    Returns:
        list -- List of audit files
    """
    if not audit_files:
        log.warning('audit.run called without any audit_files')
        return None

    if not isinstance(audit_files, list):
        audit_files = audit_files.split(',')

    # prepare paths
    return ['salt://' + BASE_DIR_AUDIT_PROFILES + os.sep + audit_file.replace('.', os.sep) + '.yaml'
            for audit_file in audit_files]


def _evaluate_results(result_dict, combined_dict, show_compliance, verbose):
    """
    Evaluate the result dictionary to be returned by the audit module
    :param result_dict: Final dictionary to be returned
    :param combined_dict: Initial dictionary with results for all profiles
    :param show_compliance: Param to show compliance percentage
    :param verbose: Create output in verbose manner or not
    :return:
    """
    for audit_file in combined_dict:
        result_list = combined_dict[audit_file]
        for result in result_list:
            sub_check = result.get('sub_check', False)
            if not sub_check:
                dict = {}
                if verbose:
                    dict[result['tag']] = result
                else:
                    dict[result['tag']] = result['description']
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
        result_dict['Compliance'] = compliance


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
        compliance = float(success) / total_checks
        compliance = int(compliance * 100)
        compliance = '{0}%'.format(compliance)
        return compliance
    return None


@hubble_status.watch
def top(topfile='top.audit',
        tags='*',
        verbose=None,
        show_compliance=None,
        labels=None):
    """
    Top function that is called from hubble config file
    :param topfile:
        Path of top file
    :param verbose:
        Verbose flag
    :param show_compliance:
        Whether to show compliance or not
    :param labels:
        Tests with matching labels are executed. If multiple labels are passed,
        then tests which have all those labels are executed.
    :return:
    """
    if verbose is None:
        verbose = __mods__['config.get']('hubblestack:nova:verbose', False)
    if show_compliance is None:
        show_compliance = __mods__['config.get']('hubblestack:nova:show_compliance', True)

    if type(show_compliance) is str and show_compliance.lower().strip() in ['true', 'false']:
        show_compliance = show_compliance.lower().strip() == 'true'
    results = {}
    # Will be a combination of strings and single-item dicts. The strings
    # have no tag filters, so we'll treat them as tag filter '*'. If we sort
    # all the data by tag filter we can batch where possible under the same
    # tag.
    data_by_tag = _build_data_by_tag(topfile, tags, results)

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


def _build_data_by_tag(topfile, tags, results):
    """
    Helper function that goes over data in top_data and
    aggregate it by tag
    """
    data_by_tag = {}

    # Get a list of yaml to run
    top_data = _get_top_data(topfile)

    if top_data:
        for data in top_data:
            if isinstance(data, str):
                if '*' not in data_by_tag:
                    data_by_tag[tags] = []
                data_by_tag[tags].append(data)
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
    Helper method to retrieve and parse the Audit topfile
    """
    topfile = 'salt://' + BASE_DIR_AUDIT_PROFILES + os.sep + topfile
    log.debug('caching top file...')
    topfile_cache_path = __mods__['cp.cache_file'](topfile)
    if not topfile_cache_path:
        log.error('Could not find top file %s', topfile)
        return None
    topfile = __mods__['cp.cache_file'](topfile)
    if not topfile:
        raise CommandExecutionError('Topfile not found.')
    try:
        with open(topfile_cache_path) as handle:
            topdata = yaml.safe_load(handle)
    except Exception as exc:
        log.exception('Could not load topfile: {0}'.format(exc))
        return None
    if not isinstance(topdata, dict) or 'audit' not in topdata or \
            (not isinstance(topdata['audit'], dict)):
        log.exception('Audit topfile not formatted correctly')
        return None
    topdata = topdata['audit']
    ret = []
    for match, data in topdata.items():
        if data is None:
            log.exception('No profiles found for one or more filters in topfile %s', topfile)
            return None
        if __mods__['match.compound'](match):
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
