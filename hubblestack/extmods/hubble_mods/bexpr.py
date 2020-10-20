# -*- encoding: utf-8 -*-
"""
Module to evaluate boolean expressions. It can be used only in Audit

Audit Example:
---------------
check_unique_id_1:
  description: 'sample check 1'
  tag: 'ADOBE-01'
  implementations:
    - filter:
        grains: 'G@osfinger:CentOS*Linux-7'
      hubble_version: '>3 AND <7 AND <8'
      module: grep
      items:
        - args:
            path: /etc/ssh/ssh_config
            pattern: '"^host"'
            flags: '-E'
          comparator:
            type: "string"
            match: "host*"
            is_regex: true

check_unique_id_2:
  description: 'sample check 2'
  tag: 'ADOBE-02'
  implementations:
    - filter:
        grains: 'G@osfinger:CentOS*Linux-7'
      hubble_version: '>3 AND <7 AND <8'
      module: stat
      items:
        - args:
            path: /etc/ssh/ssh_config
          comparator:
            type: "dict"
            match:
              gid: 0
              group: "shadow"
              uid: 0
              user: "root"
              mode:
                type: "file_permission"
                match:
                  required_value:  "644"
                  allow_more_strict: true

check_unique_id:
  description: 'bexpr check'
  tag: 'ADOBE-03'
  implementations:
    - filter:
        grains: 'G@osfinger:CentOS*Linux-7'
      hubble_version: '>3 AND <7 AND <8'
      module: bexpr
      items:
        - args:
            expr: check_unique_id_1 AND check_unique_id_2
          comparator:
            type: boolean
            match: True

Mandatory parameters:
    expr - A boolean expression referring other checks in a profile
Multiple expressions can be provided in a single implementation under attribute: "items"

Comparator compatible with this module - boolean

Note: A boolean expression is evaluated in the end after all other checks have been evaluated.
While evaluating boolean expression the result of checks referred is taken into account and no check is actually run.
An expression is a string having following keywords:
    AND, OR and NOT along with parenthesis '(', ')' to group the results

Output of boolean expressions is same as other checks and it is classified in following categories:
1. True - The logical expression of referenced checks evaluated to True
2. False - The logical expression of referenced checks evaluated to False

Sample Output:
'True/False'
"""
import logging

import hubblestack.extmods.module_runner.runner_utils as runner_utils
from hubblestack.extmods.module_runner.runner import Caller
from hubblestack.utils.hubble_error import HubbleCheckValidationError
from pyparsing import infixNotation, opAssoc, Keyword, Word, alphas, ParserElement

log = logging.getLogger(__name__)


def validate_params(block_id, block_dict, extra_args=None):
    """
    Validate all mandatory params required for this module

    :param block_id:
        id of the block
    :param block_dict:
        parameter for this module
    :param extra_args:
        Extra argument dictionary, (If any)
        Example: {'chaining_args': {'result': "True", 'status': True},
                  'caller': 'Audit'}
    Raises:
        HubbleCheckValidationError: For any validation error
    """
    log.debug('Module: bexpr Start validating params for check-id: {0}'.format(block_id))

    error = {}
    # check for calling module. Ony Audit is allowed.
    if extra_args.get('caller') == Caller.FDG:
        error['bexpr'] = 'Module: bexpr called from FDG !!!!'

    # fetch required param
    expr = runner_utils.get_param_for_module(block_id, block_dict, 'expr')
    if not expr:
        error['expr'] = 'Mandatory parameter: expr not found for id: %s' % block_id

    if error:
        raise HubbleCheckValidationError(error)

    log.debug('Validation success for check-id: {0}'.format(block_id))


def execute(block_id, block_dict, extra_args=None):
    """
    Execute the module

    :param block_id:
        id of the block
    :param block_dict:
        parameter for this module
    :param extra_args:
        Extra argument dictionary, (If any)
        Example: {'chaining_args': {'result': "True", 'status': True},
                  'extra_args': [{'check_id': 'ADOBE-01',
                                  'check_status': 'Success'}]
                  'caller': 'Audit'}

    returns:
        tuple of result(value) and status(boolean)
    """
    log.debug('Executing bexpr module for check-id: %s' % block_id)
    result_list = extra_args.get('extra_args')
    keyword_list = ['AND', 'OR', 'NOT', '(', ')']
    operand_list = ['AND', 'OR', 'NOT']
    expression = runner_utils.get_param_for_module(block_id, block_dict, 'expr')
    original_expression = expression
    # Separating keywords on the basis of space
    expression = expression.replace('(', ' ( ')
    expression = expression.replace(')', ' ) ')
    # Parse the expression and evaluate the result
    # Splitting the expression on the basis of spaces
    expr_list = expression.split(" ")
    # Filtering out empty spaces
    expr_list = list(filter(None, expr_list))
    referred_checks_list = []
    referred_checks_result = {}
    operand_present = 0
    for expr in expr_list:
        if expr.upper() not in keyword_list:
            referred_checks_list.append(expr)
        elif expr.upper() in operand_list:
            operand_present += 1
    # Fetch the result of check from result list and store the result of referenced checks
    # In case a check is not present in result list or referred check result is not Success or Failure, raise an Error
    error = {}
    if len(referred_checks_list) == 0:
        error[block_id] = "No checks are referred in the boolean expression: %s" % original_expression
    if len(referred_checks_list) > 1 and operand_present == 0:
        error[
            block_id] = "No operand is present for multiple referred checks in boolean expression: %s" % original_expression

    if error:
        raise HubbleCheckValidationError(error)

    for referred_check_id in referred_checks_list:
        check_found = False
        for result in result_list:
            if result.get('check_id', '') == referred_check_id:
                check_found = True
                check_result = result.get('check_result', '')
                if check_result == "Success":
                    referred_checks_result[referred_check_id] = "True"
                elif check_result == "Failure":
                    referred_checks_result[referred_check_id] = "False"
                else:
                    error[
                        block_id] = "Referred check: %s result is %s. Setting boolean expression check result to error." % (
                        referred_check_id, check_result)
                break

    if not check_found:
        error[block_id] = "Referred check: %s is not available. Please verify correct check is referred." % (
            referred_check_id)
    if error:
        raise HubbleCheckValidationError(error)

    try:
        check_result = _evaluate_expression(expr_list, keyword_list, referred_checks_result)
    except Exception as e:
        error[
            block_id] = "Error in evaluating boolean expression: %s Please verify the expression" % original_expression
        raise HubbleCheckValidationError(error)

    if not bool(check_result):
        log.info("Boolean expression: '%s' evaluated to failure" % original_expression)
        return runner_utils.prepare_positive_result_for_module(block_id, False)

    return runner_utils.prepare_positive_result_for_module(block_id, True)


def get_filtered_params_to_log(block_id, block_dict, extra_args=None):
    """
    For getting params to log, in non-verbose logging

    :param block_id:
        id of the block
    :param block_dict:
        parameter for this module
    :param extra_args:
        Extra argument dictionary, (If any)
        Example: {'chaining_args': {'result': "True", 'status': True},
                  'extra_args': [{'check_id': 'ADOBE-01',
                                  'check_status': 'Success'}]
                  'caller': 'Audit'}
    """
    log.debug('get_filtered_params_to_log for id: {0}'.format(block_id))

    # fetch required param
    expr = runner_utils.get_param_for_module(block_id, block_dict, 'expr')

    return {'expr': expr}


def _evaluate_expression(expr_list, keyword_list, referred_checks_result):
    # Convert the expression now in the format to be parsed by pyparsing module
    parsed_list = []
    for expr in expr_list:
        if expr.upper() not in keyword_list:
            # Check reference is passed. Pass the fetched value instead of original check id
            parsed_list.append(referred_checks_result.get(expr))
        else:
            parsed_list.append(expr.upper())

    parsed_expr = " ".join(parsed_list)

    # Logic to use boolean expression parser using pyparsing library
    # We are passing the boolean expression in the following form:
    # check1 and not (check2 or (check3 and not check4) )
    #   --> check1 and not ( check2 or ( check3 and not check4 )  )
    #       --> True and not ( False or ( True and not False ) )
    ParserElement.enablePackrat()

    TRUE = Keyword("True")
    FALSE = Keyword("False")
    boolOperand = TRUE | FALSE | Word(alphas, max=1)
    boolOperand.setParseAction(BoolOperand)

    boolExpr = infixNotation(
        boolOperand,
        [
            ("NOT", 1, opAssoc.RIGHT, BoolNot),
            ("AND", 2, opAssoc.LEFT, BoolAnd),
            ("OR", 2, opAssoc.LEFT, BoolOr),
        ],
    )
    return boolExpr.parseString(parsed_expr)[0]


class BoolOperand:
    def __init__(self, t):
        self.label = t[0]
        self.value = eval(t[0])

    def __bool__(self):
        return self.value

    def __str__(self):
        return self.label

    __repr__ = __str__


class BoolBinOp:
    def __init__(self, t):
        self.args = t[0][0::2]

    def __str__(self):
        sep = " %s " % self.reprsymbol
        return "(" + sep.join(map(str, self.args)) + ")"

    def __bool__(self):
        return self.evalop(bool(a) for a in self.args)

    __nonzero__ = __bool__


class BoolAnd(BoolBinOp):
    reprsymbol = "AND"
    evalop = all


class BoolOr(BoolBinOp):
    reprsymbol = "OR"
    evalop = any


class BoolNot:
    def __init__(self, t):
        self.arg = t[0][1]

    def __bool__(self):
        v = bool(self.arg)
        return not v

    def __str__(self):
        return "NOT " + str(self.arg)

    __repr__ = __str__
