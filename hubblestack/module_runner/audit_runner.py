import os
import logging
import fnmatch

import hubblestack.module_runner.runner
from hubblestack.module_runner.runner import Caller

import hubblestack.module_runner.comparator

from hubblestack.exceptions import HubbleCheckVersionIncompatibleError
from hubblestack.exceptions import HubbleCheckValidationError

log = logging.getLogger(__name__)
CHECK_STATUS = {
    'Success': 'Success',
    'Failure': 'Failure',
    'Skipped': 'Skipped',
    'Error': 'Error'
}


class AuditRunner(hubblestack.module_runner.runner.Runner):
    """
    Audit runner
    """

    def __init__(self):
        super().__init__(Caller.AUDIT)

    # overridden method
    def _execute(self, audit_data_dict, audit_file, args):
        # got data for one audit file
        # lets parse, validate and execute one by one
        tags = args.get('tags', '*')
        labels = args.get('labels', None)
        verbose = args.get('verbose', None)
        result_list = []
        boolean_expr_check_list = []
        audit_profile = os.path.splitext(os.path.basename(audit_file))[0]
        for audit_id, audit_data in audit_data_dict.items():
            log.debug('Executing check-id: %s in audit profile: %s', audit_id, audit_profile)
            audit_impl = self._get_matched_implementation(audit_id, audit_data, tags, labels)
            if not audit_impl:
                # no matched impl found
                log.debug('No matched implementation found for check-id: %s in audit profile: %s', audit_id,
                          audit_profile)
                continue

            if not self._validate_audit_data(audit_id, audit_impl):
                continue

            try:
                # version check
                if not self._is_hubble_version_compatible(audit_id, audit_impl):
                    raise HubbleCheckVersionIncompatibleError('Version not compatible')

                if self._is_boolean_expression(audit_impl):
                    # Check is boolean expression.
                    # Gather boolean expressions in separate list and evaluate after evaluating all other checks.
                    log.debug('Boolean expression found. Gathering it to evaluate later.')
                    boolean_expr_check_list.append({
                        'check_id': audit_id,
                        'audit_impl': audit_impl,
                        'audit_data': audit_data
                    })
                else:
                    # handover to module
                    audit_result = self._execute_audit(audit_id, audit_impl, audit_data, verbose, audit_profile)
                    result_list.append(audit_result)
            except (HubbleCheckValidationError, HubbleCheckVersionIncompatibleError) as herror:
                # add into error/skipped section
                result_list.append({
                    'check_id': audit_id,
                    'tag': audit_data['tag'],
                    'description': audit_data['description'],
                    'sub_check': audit_data.get('sub_check', False),
                    'check_result': CHECK_STATUS['Error'] if isinstance(herror, HubbleCheckValidationError) else
                    CHECK_STATUS['Skipped'],
                    'audit_profile': audit_profile
                })
                log.error(herror)
            except Exception as exc:
                log.error(exc)

        # Evaluate boolean expressions
        boolean_expr_result_list = self._evaluate_boolean_expression(
            boolean_expr_check_list, verbose, audit_profile, result_list)
        result_list = result_list + boolean_expr_result_list

        # return list of results for a file
        return result_list

    # overridden method
    def _validate_yaml_dictionary(self, yaml_dict):
        return True

    def _get_matched_implementation(self, audit_check_id, audit_data, tags, labels):
        log.debug('Getting matching implementation')

        # check if label passed is matching with the check or not.
        # If label is not matched, no need to fetch matched implementation
        if labels:
            check_labels = audit_data.get('labels', [])
            if not set(labels).issubset(check_labels):
                log.debug('Not executing audit_check: %s, user passed label: %s did not match audit labels: %s',
                          audit_check_id, labels, check_labels)
                return None

        # check if tag passed matches with current check or not
        # if tag is not matched, no need to fetch matched implementation
        audit_check_tag = audit_data.get('tag', audit_check_id)
        if not fnmatch.fnmatch(audit_check_tag, tags):
            log.debug('Not executing audit_check: %s, user passed tag: %s did not match this audit tag: %s',
                      audit_check_id,
                      tags, audit_check_tag)
            return None

        # Lets look for matching implementation based on os.filter grain
        for implementation in audit_data['implementations']:
            target = implementation['filter'].get('grains', '*')

            if __mods__['match.compound'](target):
                return implementation

        log.debug('No target matched for audit_check_id: %s', audit_check_id)
        return None

    def _validate_audit_data(self, audit_id, audit_impl):
        if 'module' not in audit_impl:
            log.error('Matched implementation does not have module mentioned, check_id: %s', audit_id)
            return False

        return True

    def _is_boolean_expression(self, audit_impl):
        return audit_impl.get('module', '') == 'bexpr'

    def _execute_audit(self, audit_id, audit_impl, audit_data, verbose, audit_profile, result_list=None):
        """
        Function to execute the module and return the result
        :param audit_id:
        :param audit_impl:
        :param audit_data:
        :param verbose:
        :param audit_profile:
        :return:
        """
        audit_result = {
            "check_id": audit_id,
            "description": audit_data['description'],
            "audit_profile": audit_profile,
            "sub_check": audit_data.get('sub_check', False),
            "tag": audit_data['tag'],
            "module": audit_impl['module'],
            "run_config": {
                "filter": audit_impl['filter'],
            }
        }

        failure_reason = audit_data.get('failure_reason', '')
        invert_result = audit_data.get('invert_result', False)
        # check if the type of invert_result is boolean
        if not isinstance(invert_result, bool):
            raise HubbleCheckValidationError('value of invert_result is not a boolean in audit_id: {0}'.format(audit_id))

        return_no_exec = audit_impl.get('return_no_exec', False)
        # check if the type of invert_result is boolean
        if not isinstance(return_no_exec, bool):
            raise HubbleCheckValidationError('value of return_no_exec is not a boolean in audit_id: {0}'.format(audit_id))
        check_eval_logic = audit_impl.get('check_eval_logic', 'and')
        if check_eval_logic:
            check_eval_logic = check_eval_logic.lower().strip()

        # check for check_eval_logic in check implementation. If not present default is 'and'
        audit_result['run_config']['check_eval_logic'] = check_eval_logic
        audit_result['invert_result'] = invert_result

        # check if return_no_exec is true
        if return_no_exec:
            audit_result['run_config']['return_no_exec'] = True
            check_result = CHECK_STATUS['Success']
            if invert_result:
                check_result = CHECK_STATUS['Failure']
                audit_result['failure_reason'] = failure_reason
            audit_result['check_result'] = check_result
            return audit_result

        # Check presence of implementation checks
        if 'items' not in audit_impl:
            raise HubbleCheckValidationError('No checks are present in audit_id: {0}'.format(audit_id))
        if check_eval_logic not in ['and', 'or']:
            raise HubbleCheckValidationError(
                "Incorrect value provided for parameter 'check_eval_logic': %s" % check_eval_logic)

        # Execute module validation of params
        for audit_check in audit_impl['items']:
            self._validate_module_params(audit_impl['module'], audit_id, audit_check)

        # validate succeeded, lets execute it and prepare result dictionary
        audit_result['run_config']['items'] = []

        # calculate the check result based on check_eval_logic parameter.
        # If check_eval_logic is 'and', all subchecks should pass for success.
        # If check_eval_logic is 'or', any passed subcheck will result in success.
        overall_result = check_eval_logic == 'and'
        failure_reasons = []
        for audit_check in audit_impl['items']:
            mod_status, module_result_local = self._execute_module(audit_impl['module'], audit_id, audit_check,
                                                                   extra_args=result_list)
            # Invoke Comparator
            comparator_status, comparator_result = hubblestack.module_runner.comparator.run(
                audit_id, audit_check['comparator'], module_result_local, mod_status)

            audit_result_local = {}
            if comparator_status:
                audit_result_local['check_result'] = CHECK_STATUS['Success']
            else:
                audit_result_local['check_result'] = CHECK_STATUS['Failure']
                audit_result_local['failure_reason'] = comparator_result if comparator_result else module_result_local[
                    'error']
                failure_reasons.append(audit_result_local['failure_reason'])
            module_logs = {}
            if not verbose:
                log.debug('Non verbose mode')
                module_logs = self._get_filtered_params_to_log(audit_impl['module'], audit_id, audit_check)
                if not module_logs:
                    module_logs = {}
            else:
                log.debug('verbose mode')
                module_logs = audit_check

            audit_result_local = {**audit_result_local, **module_logs}
            # add this result
            audit_result['run_config']['items'].append(audit_result_local)

            if check_eval_logic == 'and':
                overall_result = overall_result and comparator_status
            else:
                overall_result = overall_result or comparator_status

        # Update overall check result based on invert result
        if invert_result:
            log.debug("Inverting result for check: %s as invert_result is set to True" % audit_id)
            overall_result = not overall_result

        if overall_result:
            audit_result['check_result'] = CHECK_STATUS['Success']
        else:
            audit_result['check_result'] = CHECK_STATUS['Failure']
            # fetch failure reason. If it is not present in profile, combine all individual checks reasons.
            if failure_reason:
                audit_result['failure_reason'] = failure_reason
            else:
                if failure_reasons:
                    failure_reasons = set(failure_reasons)
                    audit_result['failure_reason'] = ', '.join(failure_reasons)
        return audit_result

    def _evaluate_boolean_expression(self, boolean_expr_check_list, verbose, audit_profile, result_list):
        boolean_expr_result_list = []
        if boolean_expr_check_list:
            log.debug("Evaluating boolean expression checks")
            for boolean_expr in boolean_expr_check_list:
                try:
                    check_result = self._execute_audit(boolean_expr['check_id'], boolean_expr['audit_impl'],
                                                       boolean_expr['audit_data'], verbose, audit_profile, result_list)
                    boolean_expr_result_list.append(check_result)
                except (HubbleCheckValidationError, HubbleCheckVersionIncompatibleError) as herror:
                    # add into error section
                    boolean_expr_result_list.append({
                        'check_id': boolean_expr['check_id'],
                        'tag': boolean_expr['audit_data']['tag'],
                        'sub_check': boolean_expr['audit_data'].get('sub_check', False),
                        'description': boolean_expr['audit_data']['description'],
                        'check_result': CHECK_STATUS['Error'] if isinstance(herror, HubbleCheckValidationError) else
                        CHECK_STATUS['Skipped'],
                        'audit_profile': audit_profile
                    })
                    log.error(herror)
                except Exception as exc:
                    log.error(exc)

        return boolean_expr_result_list
