# -*- encoding: utf-8 -*-
"""
Boolean Expression module to evaluate boolean expressions.
This is a complex check-type where you would want to combine multiple 
check results and evaluate through a boolean expression

Since this type of check involves multiple checks to evaluate boolean expression.
All those checks must be from the same file. You can only refer check-id from the same file.

Note: Now each module just returns its output (As Data gathering)
      For Audit checks, comparison logic is now moved to comparators. 
      See below sections for more understanding

Usable in Modules
-----------------
- Audit (Only)

Common Schema
-------------
- check_unique_id
    Its a unique string within a yaml file.
    It is present on top of a yaml block

- description
    Description of the check

- tag
    Check tag value

- sub_check (Optional, default: false)
    If true, its individual result will not be counted in compliance
    It might be referred in some boolean expression

- failure_reason (Optional)
    By default, module will generate failure reason string at runtime
    If this is passed, this will override module's actual failure reason

- invert_result (Optional, default: false)
    This is used to flip the boolean output from a check

- implementations
    Its an array of implementations, usually for multiple operating systems.
    You can specify multiple implementations here for respective operating system.
    Either one or none will be executed.

- grains (under filter)
    Any grains with and/or/not supported. This is used to filter whether 
    this check can run on the current OS or not.
    To run this check on all OS, put a '*'

    Example:
    G@docker_details:installed:True and G@docker_details:running:True and not G@osfinger:*Flatcar* and not G@osfinger:*CoreOS*

- hubble_version (Optional)
    It acts as a second level filter where you can specify for which Hubble version,
    this check is compatible with. You can specify a boolean expression as well

    Example:
    '>3.0 AND <5.0'

- module
    The name of Hubble module.

- return_no_exec (Optional, Default: false)
    (Applicable only for Audit)
    It takes a boolean (true/false) value.
    If its true, the implementation will not be executed. And true is returned
    
    This can be useful in cases where you don't have any implementation for some OS,
    and you want a result from the block. Else, your meta-check(bexpr) will be failed.

- items
    An array of multiple module implementations. At least one block is necessary.
    Each item in array will result into a boolean value.
    If multiple module implementations exists, final result will be evaluated as 
    boolean AND (default, see parameter: check_eval_logic)

- check_eval_logic (Optional, default: and)
    If there are multiple module implementations in "items" (above parameter), this parameter
    helps in evaluating their result. Default value is "and"
    It accepts only values: and/or

- args
    Arguments specific to a module.

- comparator
    For the purpose of comparing output of module with expected values.
    Parameters depends upon the comparator used.
    For detailed documentation on comparators, 
    read comparator's implementations at (/hubblestack/extmods/comparators/)

Module Arguments
----------------
- expr
    A boolean expression where operands are the check-id from the same file.
    You can specify AND, OR and NOT along with parenthesis '(', ')' to group the results
    Example:
        check_unique_id_1 AND check_unique_id_2

Module Output
-------------
It will always be a boolean value (true/false)

Output: (True, True)
Note: Module returns a tuple
    First value being the status of module
    Second value is the actual output from module

Compatible Comparators
----------------------
- boolean


Audit Example
---------------
boolean_expression_check:
  description: 'bexpr check'
  tag: 'ADOBE-03'
  sub_check: false (Optional, default: false)
  failure_reason: 'a sample failure reason' (Optional)
  invert_result: false (Optional, default: false)
  implementations:
    - filter:
        grains: 'G@osfinger:CentOS*Linux-7'
      hubble_version: '>3 AND <7 AND <8'
      # return_no_exec: true (Optional, default: false)
      check_eval_logic: and (Optional, default: and)
      module: bexpr
      items:
        - args:
            expr: check_unique_id_1 AND check_unique_id_2
          comparator:
            type: boolean
            match: True

check_unique_id_1:
  description: 'sample check 1'
  tag: 'ADOBE-01'
  sub_check: true
  implementations:
    - filter:
        grains: 'G@osfinger:CentOS*Linux-7'
      module: grep
      items:
        - args:
            path: /etc/ssh/ssh_config
            pattern: '"^host"'
            flags: 
                - '-E'
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
      module: stat
      items:
        - args:
            path: /etc/ssh/ssh_config
          comparator:
            type: "dict"
            match:
              gid: 0
              uid: 0
"""
import logging

import hubblestack.module_runner.runner_utils as runner_utils
from hubblestack.module_runner.runner import Caller
from hubblestack.exceptions import HubbleCheckValidationError
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
