# -*- coding: utf-8 -*-
"""
Return/control aspects of the grains data

Grains set or altered with this module are stored in the 'grains'
file on the minions. By default, this file is located at: ``/etc/salt/grains``

.. Note::

   This does **NOT** override any grains set in the minion config file.
"""

import collections
import logging
import math

import hubblestack.utils.data
import hubblestack.utils.json
from hubblestack.defaults import (  # pylint: disable=3rd-party-module-not-gated
    DEFAULT_TARGET_DELIM,
)


__proxyenabled__ = ["*"]

# Seed the grains dict so cython will build
__grains__ = {}

# Change the default outputter to make it more readable
__outputter__ = {
    "items": "nested",
    "item": "nested",
    "setval": "nested",
}

# http://stackoverflow.com/a/12414913/127816
_infinitedict = lambda: collections.defaultdict(_infinitedict)

_non_existent_key = "NonExistentValueMagicNumberSpK3hnufdHfeBUXCfqVK"

log = logging.getLogger(__name__)


def _serial_sanitizer(instr):
    """Replaces the last 1/4 of a string with X's"""
    length = len(instr)
    index = int(math.floor(length * 0.75))
    return "{0}{1}".format(instr[:index], "X" * (length - index))


_FQDN_SANITIZER = lambda x: "MINION.DOMAINNAME"
_HOSTNAME_SANITIZER = lambda x: "MINION"
_DOMAINNAME_SANITIZER = lambda x: "DOMAINNAME"


# A dictionary of grain -> function mappings for sanitizing grain output. This
# is used when the 'sanitize' flag is given.
_SANITIZERS = {
    "serialnumber": _serial_sanitizer,
    "domain": _DOMAINNAME_SANITIZER,
    "fqdn": _FQDN_SANITIZER,
    "id": _FQDN_SANITIZER,
    "host": _HOSTNAME_SANITIZER,
    "localhost": _HOSTNAME_SANITIZER,
    "nodename": _HOSTNAME_SANITIZER,
}


def get(key, default="", delimiter=DEFAULT_TARGET_DELIM, ordered=True):
    """
    Attempt to retrieve the named value from grains, if the named value is not
    available return the passed default. The default return is an empty string.

    The value can also represent a value in a nested dict using a ":" delimiter
    for the dict. This means that if a dict in grains looks like this::

        {'pkg': {'apache': 'httpd'}}

    To retrieve the value associated with the apache key in the pkg dict this
    key can be passed::

        pkg:apache


    :param delimiter:
        Specify an alternate delimiter to use when traversing a nested dict.
        This is useful for when the desired key contains a colon. See CLI
        example below for usage.

        .. versionadded:: 2014.7.0

    :param ordered:
        Outputs an ordered dict if applicable (default: True)

        .. versionadded:: 2016.11.0

    CLI Example:

    .. code-block:: bash

        salt '*' grains.get pkg:apache
        salt '*' grains.get abc::def|ghi delimiter='|'
    """
    if ordered is True:
        grains = __grains__
    else:
        grains = hubblestack.utils.json.loads(hubblestack.utils.json.dumps(__grains__))
    return hubblestack.utils.data.traverse_dict_and_list(grains, key, default, delimiter)


def has_value(key):
    """
    Determine whether a key exists in the grains dictionary.

    Given a grains dictionary that contains the following structure::

        {'pkg': {'apache': 'httpd'}}

    One would determine if the apache key in the pkg dict exists by::

        pkg:apache

    CLI Example:

    .. code-block:: bash

        salt '*' grains.has_value pkg:apache
    """
    return (
        hubblestack.utils.data.traverse_dict_and_list(__grains__, key, KeyError)
        is not KeyError
    )


def items(sanitize=False):
    """
    Return all of the minion's grains

    CLI Example:

    .. code-block:: bash

        salt '*' grains.items

    Sanitized CLI Example:

    .. code-block:: bash

        salt '*' grains.items sanitize=True
    """
    if hubblestack.utils.data.is_true(sanitize):
        out = dict(__grains__)
        for key, func in _SANITIZERS.items():
            if key in out:
                out[key] = func(out[key])
        return out
    else:
        return __grains__


def item(*args, **kwargs):
    """
    Return one or more grains

    CLI Example:

    .. code-block:: bash

        salt '*' grains.item os
        salt '*' grains.item os osrelease oscodename

    Sanitized CLI Example:

    .. code-block:: bash

        salt '*' grains.item host sanitize=True
    """
    ret = {}
    default = kwargs.get("default", "")
    delimiter = kwargs.get("delimiter", DEFAULT_TARGET_DELIM)

    try:
        for arg in args:
            ret[arg] = hubblestack.utils.data.traverse_dict_and_list(
                __grains__, arg, default, delimiter
            )
    except KeyError:
        pass

    if hubblestack.utils.data.is_true(kwargs.get("sanitize")):
        for arg, func in _SANITIZERS.items():
            if arg in ret:
                ret[arg] = func(ret[arg])
    return ret


def ls():  # pylint: disable=C0103
    """
    Return a list of all available grains

    CLI Example:

    .. code-block:: bash

        salt '*' grains.ls
    """
    return sorted(__grains__)


def equals(key, value):
    """
    Used to make sure the minion's grain key/value matches.

    Returns ``True`` if matches otherwise ``False``.

    .. versionadded:: 2017.7.0

    CLI Example:

    .. code-block:: bash

        salt '*' grains.equals fqdn <expected_fqdn>
        salt '*' grains.equals systemd:version 219
    """
    return str(value) == str(get(key))


# Provide a jinja function call compatible get aliased as fetch
fetch = get
