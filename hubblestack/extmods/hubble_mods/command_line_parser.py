# -*- encoding: utf-8 -*-
"""
This module is used to find the value of a command line parameter.

Audit Example:
---------------
check_unique_id:
  description: 'cmd check'
  tag: 'ADOBE-01'
  implementations:
    - filter:
        grains: 'G@osfinger:CentOS*Linux-7'
      hubble_version: '>3 AND <7 AND <8'
      module: command_line_parser
      items:
        - args:
            cmdline: 'app --config-file=abc test'
            key_aliases: ['config-file']
            delimiter: '='
          comparator:
            type: "string"
            match: abc

FDG Example:
------------
main:
  ...
  ...
  pipe: cmd_parser

cmd_parser:
  description: 'cmd parser check'
  module: command_line_parser
  args:
    key_aliases: ['config-file']
    delimiter: '='

Sample input from chaining:
    {'cmdline': 'app --config-file=abc test'}

Mandatory Params:
    - cmdline
      The command line in which to search for keys.
    - key_aliases
      array of aliases whose value is to be fetched
    - delimiter
      the assignment operator between the key and the value

BASIC EXAMPLES:
Inputs:
    key_aliases = ["config-file"]
    delimiter = "="
    chained = "dockerd --config-file=/etc/docker/daemon.json --log-level=debug"
Output: (True, ["/etc/docker/daemon.json"])

UNIT TESTS:
Check the unit test case file 'test_command_line_parser_new.py' to understand more examples on how this module works.

NOTES:

Understanding the regex(s):
You can copy paste the regex(s) on this webpage - https://regex101.com/ to understand more about the regex.
However, here is a small explanation

regex_base :
    "(?<=(\s|{))-{0,2}\"{0,1}\'{0,1}", key_alias, "\"{0,1}\'{0,1}\s*", delimiter
    This regex primarily focuses on whether the value is embedded inside brackets.

1. '?<=' : denotes a positive lookbehind
2. '\s' : matches the <space> character
3. '{' : matches opening braces
4. (\s|{) : () brackets signify a group. This is the first group in this regex
4. -{0,2} : matches (zero to two) hyphens.
5. \"{0,1}\'{0,1} : matches if any quotes are present.
5. key_alias : matches the given key_alias.
6. /s* : matches 0 or more <space> characters
7. delimiter : matches the input delimiter

regex_pattern
1. openingbracket : is later replaced by one of the three opening bracket types
2. .*? : matches any character lazily.
3. closingbracket : is later replaced by one of the three closing bracket types
4. (?=(\s|$|})) : matches that the end of the pattern must contain either <space> or EOL

regex1 :
    "\s*([\",\']).*?\\2"
    This regex primarily focuses on whether the value is embedded inside double or single quotes

The starting regex is similar to the regex_pattern.
1. ([\", \']) : () brackets signify a group. This is the second group in this regex.
                    [\",\'] inside the () matches either a double-quote or a single-quote.
2. .*? : matches any character lazily.
3. \\2 : matches the second group of the regex.

regex2 :
    "\s*.+?(?=(\s|$|}))"
The starting regex is similar to the regex_pattern.

1. (?=(\s|$)) : matches that the end of the pattern must contain either <space> or EOL
"""

import os
import logging
import re

import hubblestack.extmods.module_runner.runner_utils as runner_utils
from hubblestack.utils.hubble_error import HubbleCheckValidationError

open_bracket_list = ["[", "{", "("]
close_bracket_list = ["]", "}", ")"]
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
        Example: {'chaining_args': {'result': {'cmdline': 'app --config-file=test test'}, 'status': True},
                  'caller': 'Audit'}

    Raises:
        HubbleCheckValidationError: For any validation error
    """
    log.debug('Module: command_line_parser Start validating params for check-id: {0}'.format(block_id))

    error = {}
    command_line = None
    chained_param = runner_utils.get_chained_param(extra_args)
    if chained_param:
        command_line = chained_param.get('cmdline')
    if not command_line:
        # get it from args
        command_line = runner_utils.get_param_for_module(block_id, block_dict, 'cmdline')

    if not command_line:
        error['cmdline'] = 'No cmdline provided in chained params'

    key_aliases = runner_utils.get_param_for_module(block_id, block_dict, 'key_aliases')
    if not key_aliases:
        error['key_aliases'] = 'No key_aliases provided in params'

    delimiter = runner_utils.get_param_for_module(block_id, block_dict, 'delimiter')
    if not delimiter:
        error['delimiter'] = 'No delimiter provided'

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
        Example: {'chaining_args': {'result': {'cmdline': 'app --config-file=test test'}, 'status': True},
                  'caller': 'Audit'}

    returns:
        tuple of result(value) and status(boolean)
    """
    log.debug('Executing command_line_parser module for id: {0}'.format(block_id))

    try:
        command_line = None

        chained_param = runner_utils.get_chained_param(extra_args)
        if chained_param:
            command_line = chained_param.get('cmdline')
        if not command_line:
            # get it from args
            command_line = runner_utils.get_param_for_module(block_id, block_dict, 'cmdline')

        key_aliases = runner_utils.get_param_for_module(block_id, block_dict, 'key_aliases')
        delimiter = runner_utils.get_param_for_module(block_id, block_dict, 'delimiter')

        log.debug("command_line: {0}, key_aliases: {1}, delimeter: {2}".format(command_line, key_aliases, delimiter))
        ret_match_list = []

        for key_alias in key_aliases:
            log.debug("looping with key_alias %s", key_alias)
            key_alias = key_alias.lstrip("-")

            if key_alias not in command_line:
                log.info("key_alias %s not found in command line %s", key_alias, command_line)
                continue

            regex_base = "".join(["(?<=(\s|{))-{0,2}\"{0,1}\'{0,1}", key_alias, "\"{0,1}\'{0,1}\s*", delimiter])
            regex_list = []
            regex_pattern = "".join([regex_base, "\s*openingbracket.*closingbracket(?=(\s|$))"])
            braces_list = [('\[', '\]'), ('\{', '\}'), ('\(', '\)')]
            for item in braces_list:
                regex = re.sub("openingbracket", item[0], regex_pattern)
                regex = re.sub("closingbracket", item[1], regex)
                regex_list.append(regex)
            regex1 = "".join([regex_base, "\s*([\",\']).*?\\2"])
            regex2 = "".join([regex_base, "\s*.+?(?=(\s|$))"])
            regex_list.append(regex1)
            regex_list.append(regex2)

            for regex in regex_list:
                log.debug("looping with regex : %s", regex)
                match_list = _get_match_list(regex, key_alias, command_line, delimiter)
                if match_list:
                    ret_match_list.extend(match_list)
                    break

        return runner_utils.prepare_positive_result_for_module(block_id, ret_match_list)

    except Exception as e:
        log.exception("Some exception occurred in command_line_parser's parse_cmdline function %s", e)
        return runner_utils.prepare_negative_result_for_module(block_id, None)


def _get_match_list(regex, key_alias, command_line, delimiter):
    """

    :param regex: search for this pattern in command_line
    :param key_alias: The key whose value is to be found out
    :param command_line: command_line from where the value is to be fetched
    :param delimiter: assignment operator between key and value
    :return: List of all matching patterns

    This function will fetch all matching patterns of regex in command_line and will then strip the
    matched value to remove the leading and trailing hyphens (-), <spaces> and quotes.
    Since the regex also contains the 'key' and 'delimiter', that is also stripped away to get the final value.
    """
    match_list = []

    matches = re.finditer(regex, command_line)
    for match_num, match in enumerate(matches, start=1):
        log.debug("Match %d was found at %d-%d: %s", match_num, match.start(), match.end(), match.group())
        value = match.group().lstrip("-")
        value = value.replace("".join(["\"", key_alias, "\""]), key_alias)
        value = value.replace("".join(["\'", key_alias, "\'"]), key_alias)
        prefix = "".join([key_alias, "\s*", delimiter, "\s*"])
        value = re.sub(prefix, '', value)
        value = value.rstrip('\"\' ')
        value = value.lstrip('\"\' ')
        if value[0] in open_bracket_list:
            value = _fetch_bracketed_value(value)
            if not value:
                log.error("Unbalanced bracketed value found for match %s, returning empty value", match.group())

        match_list.append(value)

    return match_list


def _fetch_bracketed_value(value):
    """
    Loops over the string value passed and return the first bracket balanced string.
    :param value: input string value
    :return: return a substring that has balanced brackets starting with the first opening bracket
    """
    stack = []
    char_pos = 0
    stacked_once = False
    for i in value:
        if i in open_bracket_list:
            stack.append(i)
            stacked_once = True
        elif i in close_bracket_list:
            pos = close_bracket_list.index(i)
            if ((len(stack) > 0) and
                    (open_bracket_list[pos] == stack[len(stack) - 1])):
                stack.pop()
        if stacked_once and len(stack) == 0:
            return value[:char_pos + 1]
        char_pos += 1

    return None


def get_filtered_params_to_log(block_id, block_dict, extra_args=None):
    """
    For getting params to log, in non-verbose logging

    :param block_id:
        id of the block
    :param block_dict:
        parameter for this module
    :param extra_args:
        Extra argument dictionary, (If any)
        Example: {'chaining_args': {'result': {'cmdline': 'app --config-file=test test'}, 'status': True},
                  'caller': 'Audit'}
    """
    log.debug('get_filtered_params_to_log for id: {0}'.format(block_id))

    chained_param = runner_utils.get_chained_param(extra_args)
    command_line = None
    if chained_param:
        command_line = chained_param.get('cmdline')
    if not command_line:
        # get it from args
        command_line = runner_utils.get_param_for_module(block_id, block_dict, 'cmdline')

    key_aliases = runner_utils.get_param_for_module(block_id, block_dict, 'key_aliases')
    delimiter = runner_utils.get_param_for_module(block_id, block_dict, 'delimiter')

    return {
        'command_line': command_line,
        'key_aliases': key_aliases,
        'delimiter': delimiter
    }
