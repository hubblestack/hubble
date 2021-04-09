# -*- coding: utf-8 -*-
"""
This module contains routines used to verify the matcher against the minions
expected to return
"""

import logging
import re


HAS_RANGE = False
try:
    import seco.range  # pylint: disable=import-error

    HAS_RANGE = True
except ImportError:
    pass

log = logging.getLogger(__name__)

TARGET_REX = re.compile(
    r"""(?x)
        (
            (?P<engine>G|P|I|J|L|N|S|E|R)  # Possible target engines
            (?P<delimiter>(?<=G|P|I|J).)?  # Optional delimiter for specific engines
        @)?                                # Engine+delimiter are separated by a '@'
                                           # character and are optional for the target
        (?P<pattern>.+)$"""  # The pattern passed to the target engine
)


def _nodegroup_regex(nodegroup, words, opers):
    opers_set = set(opers)
    ret = words
    if (set(ret) - opers_set) == set(ret):
        # No compound operators found in nodegroup definition. Check for
        # group type specifiers
        group_type_re = re.compile("^[A-Z]@")
        regex_chars = ["(", "[", "{", "\\", "?", "}", "]", ")"]
        if not [x for x in ret if "*" in x or group_type_re.match(x)]:
            # No group type specifiers and no wildcards.
            # Treat this as an expression.
            if [x for x in ret if x in [x for y in regex_chars if y in x]]:
                joined = "E@" + ",".join(ret)
                log.debug(
                    "Nodegroup '%s' (%s) detected as an expression. "
                    "Assuming compound matching syntax of '%s'",
                    nodegroup,
                    ret,
                    joined,
                )
            else:
                # Treat this as a list of nodenames.
                joined = "L@" + ",".join(ret)
                log.debug(
                    "Nodegroup '%s' (%s) detected as list of nodenames. "
                    "Assuming compound matching syntax of '%s'",
                    nodegroup,
                    ret,
                    joined,
                )
            # Return data must be a list of compound matching components
            # to be fed into compound matcher. Enclose return data in list.
            return [joined]


def parse_target(target_expression):
    """Parse `target_expressing` splitting it into `engine`, `delimiter`,
     `pattern` - returns a dict"""

    match = TARGET_REX.match(target_expression)
    if not match:
        log.warning('Unable to parse target "%s"', target_expression)
        ret = {
            "engine": None,
            "delimiter": None,
            "pattern": target_expression,
        }
    else:
        ret = match.groupdict()
    return ret


def nodegroup_comp(nodegroup, nodegroups, skip=None, first_call=True):
    """
    Recursively expand ``nodegroup`` from ``nodegroups``; ignore nodegroups in ``skip``

    If a top-level (non-recursive) call finds no nodegroups, return the original
    nodegroup definition (for backwards compatibility). Keep track of recursive
    calls via `first_call` argument
    """
    expanded_nodegroup = False
    if skip is None:
        skip = set()
    elif nodegroup in skip:
        log.error(
            'Failed nodegroup expansion: illegal nested nodegroup "%s"', nodegroup
        )
        return ""

    if nodegroup not in nodegroups:
        log.error('Failed nodegroup expansion: unknown nodegroup "%s"', nodegroup)
        return ""

    nglookup = nodegroups[nodegroup]
    if isinstance(nglookup, str):
        words = nglookup.split()
    elif isinstance(nglookup, (list, tuple)):
        words = nglookup
    else:
        log.error(
            "Nodegroup '%s' (%s) is neither a string, list nor tuple",
            nodegroup,
            nglookup,
        )
        return ""

    skip.add(nodegroup)
    ret = []
    opers = ["and", "or", "not", "(", ")"]
    for word in words:
        if not isinstance(word, str):
            word = str(word)
        if word in opers:
            ret.append(word)
        elif len(word) >= 3 and word.startswith("N@"):
            expanded_nodegroup = True
            ret.extend(
                nodegroup_comp(word[2:], nodegroups, skip=skip, first_call=False)
            )
        else:
            ret.append(word)

    if ret:
        ret.insert(0, "(")
        ret.append(")")

    skip.remove(nodegroup)

    log.debug("nodegroup_comp(%s) => %s", nodegroup, ret)
    # Only return list form if a nodegroup was expanded. Otherwise return
    # the original string to conserve backwards compat
    if expanded_nodegroup or not first_call:
        if not first_call:
            joined = _nodegroup_regex(nodegroup, words, opers)
            if joined:
                return joined
        return ret
    else:
        ret = words
        joined = _nodegroup_regex(nodegroup, ret, opers)
        if joined:
            return joined

        log.debug(
            "No nested nodegroups detected. Using original nodegroup " "definition: %s",
            nodegroups[nodegroup],
        )
        return ret
