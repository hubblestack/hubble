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
In boolean expressions we refer to the checks present in same profile and evaluate the result based on the result of those checks.
A boolean expressio is evaluated in the end after all other checks have been evaluated.
While evaluating boolean expression the result of checks referred is taken into the account and no check is actually run.
We can provide a string in expression which consists of following expressions:
AND, OR and NOT along with parenthesis to group the results
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
    expression = audit_check['expr'].strip()
    #Parse the expression and evaluate the result
    #Splitting the expression on the basis of spaces
    expr_list = expression.split(" ")
    expr_list = list(filter(None, expr_list)) #Filtering out empty spaces
    referred_checks_list = []
    referred_checks_result = {}
    for expr in expr_list:
        if expr.upper() not in keyword_list:
            referred_checks_list.append(expr)

    #Fetch the result of check from result list and store the result of referred checks
    error = {}
    for check in referred_checks_list:
        check_found = False
        for result in result_list:
            if result.get('check_id', '') == check:
                check_found = True
                check_result =  result.get('check_result', '')
                if check_result == "Success":
                    referred_checks_result[check] = "True"
                elif check_result == "Failure":
                    referred_checks_result[check] = "False"
                else:
                    error[check] = "Unable to fetch result of referred check due to errors. Check: %s" % (check)
                break
        if not check_found:
            error[check] = "Referred check: %s is not available. Please verify correct check is referred." % (check)
    if error:
        raise AuditCheckValidationError(error)

    #Convert the expression now in the format to be parsed by pyparsing module
    parsed_list = []
    for expr in expr_list:
        if expr.upper() not in keyword_list:
            #Check reference is passed. Pass the fetched value instead of original check id
            parsed_list.append(referred_checks_result.get(expr))
        else:
            parsed_list.append(expr.upper())

    parsed_expr = " ".join(parsed_list)

    #Logic to use boolean expression parser using pyparsing library
    #We are passing the boolean expression in the following form:
    # True and not ( False or ( True and not False ) )
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
    result = boolExpr.parseString(parsed_expr)[0]
    if not bool(result):
        return {"result": False,
                "failure_reason": "The boolean expression evaluated to failure"}
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
    log.debug('Module: fdg Start validating params for check-id: %s' % (check_id))

    mandatory_params = ['expr']
    error = {}
    for mandatory_param in mandatory_params:
        if mandatory_param not in audit_check:
            error[mandatory_param] = 'Mandatory parameter: "%s" not found for check-id: %s' % (mandatory_param, check_id)

    if error:
        raise AuditCheckValidationError(error)

    log.debug('Validation success for check-id: %s' %(check_id))

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