"""
Nova module to evaluate boolean expressions

Example of a check
docker_config_file_check:
  tag: ADOBE-00012
  description: Docker config check, if docker is installed and running
  implementations:
    - filter:
        grains: '*'
      module: bexpr
      checks:
        # If docker is not installed OR is not running, we would want result as TRUE
        - expr: NOT (docker_installed AND dockerd_running) OR find_docker_file

Here we are evaluating the boolean expression given in the 'expr' string value
In boolean expressions we refer to the checks present in same profile and evaluate the result based
on the result of those checks.
A boolean expression is evaluated in the end after all other checks have been evaluated.
While evaluating boolean expression the result of checks referred is taken into the account and no
check is actually run.
We can provide a string in expression which consists of following expressions:
AND, OR and NOT along with parenthesis '(', ')' to group the results

The output of boolean expressions is same as other checks and it is classified in following categories:
1. Skipped - If a boolean expression is not executed on the given OS or Hubble version
2. Error - In case there is an error in syntax of bexpr or if any of the referenced check is evaluated as
'Skipped' or 'Error'
3. Success - The logical expression of referenced checks evaluated to Success
4. Failure - The logical expression of referenced checks evaluated to Failure
"""
import logging
from hubblestack.utils.hubble_error import AuditCheckValidationError
from pyparsing import infixNotation, opAssoc, Keyword, Word, alphas, ParserElement

log = logging.getLogger(__name__)


def execute(check_id, audit_check, result_list):
    """
    Execute single check
    :param check_id: Unique check id
    :param audit_check: Dictionary of an individual check implementation
    :param result_list: List of results for other checks in profile
    :return: dict -- dictionary of result status and output
    """
    log.debug('Executing bexpr module for check-id: %s' % (check_id))
    keyword_list = ['AND', 'OR', 'NOT', '(', ')']
    operand_list = ['AND', 'OR', 'NOT']
    expression = audit_check['expr'].strip()
    original_expression = expression
    # Separating keywords on the basis of space
    expression = expression.replace('(', ' ( ')
    expression = expression.replace(')', ' ) ')
    # Parse the expression and evaluate the result
    # Splitting the expression on the basis of spaces
    expr_list = expression.split(" ")
    expr_list = list(filter(None, expr_list))  # Filtering out empty spaces
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
        error[check_id] = "No checks are referred in the boolean expression: %s" % original_expression
    if len(referred_checks_list) > 1 and operand_present == 0:
        error[check_id] = "No operand is present for multiple referred checks in boolean expression: %s" % original_expression

    if error:
        raise AuditCheckValidationError(error)
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
                    error[check_id] = "Referred check: %s result is %s. Setting boolean expression check result to error." % (
                        referred_check_id, check_result)
                break
        if not check_found:
            error[check_id] = "Referred check: %s is not available. Please verify correct check is referred." % (
                referred_check_id)
    if error:
        raise AuditCheckValidationError(error)

    try:
        check_result = _evaluate_expression(expr_list, keyword_list, referred_checks_result)
    except Exception as e:
        error[check_id] = "Error in evaluating boolean expression: %s Please verify the expression" % original_expression
        raise AuditCheckValidationError(error)

    if not bool(check_result):
        return {"result": False,
                "failure_reason": "Boolean expression: '%s' evaluated to failure" % original_expression}
    return {"result": True}


def get_filtered_params_to_log(check_id, audit_check):
    """For getting params to log, in non-verbose logging

    Arguments:
        check_id {str} -- Audit check id
        audit_check {dict} -- Single audit check for this module

    Returns:
        dict -- Dictionary of params to log
    """
    log.debug('Getting filtered parameters to log for check-id: %s' % (check_id))
    return {
        'expr': audit_check['expr']
    }


def validate_params(check_id, audit_check):
    """Validate all mandatory params required for this module

        Arguments:
            check_id {str} -- Audit check id
            audit_check {dict} -- Single audit check for this module

        Raises:
            AuditCheckValidationError: For any validation error
        """
    log.debug('Module: bexpr Start validating params for check-id: %s' % (check_id))
    mandatory_params = ['expr']
    error = {}
    for mandatory_param in mandatory_params:
        if mandatory_param not in audit_check:
            error[mandatory_param] = 'Mandatory parameter: "%s" not found for check-id: %s' % (
                mandatory_param, check_id)
        elif audit_check[mandatory_param] is None:
            error[mandatory_param] = 'Empty value passed for mandatory parameter: "%s" for check-id: %s' % (
                mandatory_param, check_id)

    if error:
        raise AuditCheckValidationError(error)

    log.debug('Validation success for check-id: %s' % (check_id))


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
