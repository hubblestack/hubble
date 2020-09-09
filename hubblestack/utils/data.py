# -*- coding: utf-8 -*-
"""
Functions for manipulating, inspecting, or otherwise working with data types
and data structures.
"""

import fnmatch
import logging
import re

try:
    from collections.abc import Mapping, MutableMapping, Sequence
except ImportError:
    from collections import Mapping, MutableMapping, Sequence

import hubblestack.utils.stringutils
from hubblestack.defaults import (  # pylint: disable=3rd-party-module-not-gated
    DEFAULT_TARGET_DELIM,
)

import hubblestack.utils.yaml
from hubblestack.utils.odict import OrderedDict

log = logging.getLogger(__name__)


class CaseInsensitiveDict(MutableMapping):
    """
    Inspired by requests' case-insensitive dict implementation, but works with
    non-string keys as well.
    """

    def __init__(self, init=None, **kwargs):
        """
        Force internal dict to be ordered to ensure a consistent iteration
        order, irrespective of case.
        """
        self._data = OrderedDict()
        self.update(init or {}, **kwargs)

    def __len__(self):
        return len(self._data)

    def __setitem__(self, key, value):
        # Store the case-sensitive key so it is available for dict iteration
        self._data[to_lowercase(key)] = (key, value)

    def __delitem__(self, key):
        del self._data[to_lowercase(key)]

    def __getitem__(self, key):
        return self._data[to_lowercase(key)][1]

    def __iter__(self):
        return (item[0] for item in iter(self._data.values()))

    def __eq__(self, rval):
        if not isinstance(rval, Mapping):
            # Comparing to non-mapping type (e.g. int) is always False
            return False
        return dict(self.items_lower()) == dict(CaseInsensitiveDict(rval).items_lower())

    def __repr__(self):
        return repr(dict(iter(self.items())))

    def items_lower(self):
        """
        Returns a generator iterating over keys and values, with the keys all
        being lowercase.
        """
        return ((key, val[1]) for key, val in iter(self._data.items()))

    def copy(self):
        """
        Returns a copy of the object
        """
        return CaseInsensitiveDict(iter(self._data.items()))


def decode(data, encoding=None, errors='strict', keep=False,
           normalize=False, preserve_dict_class=False, preserve_tuples=False,
           to_str=False):
    """
    Generic function which will decode whichever type is passed, if necessary.
    Optionally use to_str=True to ensure strings are str types and not unicode
    on Python 2.

    If `strict` is True, and `keep` is False, and we fail to decode, a
    UnicodeDecodeError will be raised. Passing `keep` as True allows for the
    original value to silently be returned in cases where decoding fails. This
    can be useful for cases where the data passed to this function is likely to
    contain binary blobs, such as in the case of cp.recv.

    If `normalize` is True, then unicodedata.normalize() will be used to
    normalize unicode strings down to a single code point per glyph. It is
    recommended not to normalize unless you know what you're doing. For
    instance, if `data` contains a dictionary, it is possible that normalizing
    will lead to data loss because the following two strings will normalize to
    the same value:

    - u'\\u044f\\u0438\\u0306\\u0446\\u0430.txt'
    - u'\\u044f\\u0439\\u0446\\u0430.txt'

    One good use case for normalization is in the test suite. For example, on
    some platforms such as Mac OS, os.listdir() will produce the first of the
    two strings above, in which "й" is represented as two code points (i.e. one
    for the base character, and one for the breve mark). Normalizing allows for
    a more reliable test case.
    """
    _decode_func = hubblestack.utils.stringutils.to_unicode \
        if not to_str \
        else hubblestack.utils.stringutils.to_str
    if isinstance(data, Mapping):
        return decode_dict(data, encoding, errors, keep, normalize,
                           preserve_dict_class, preserve_tuples, to_str)
    elif isinstance(data, list):
        return decode_list(data, encoding, errors, keep, normalize,
                           preserve_dict_class, preserve_tuples, to_str)
    elif isinstance(data, tuple):
        return decode_tuple(data, encoding, errors, keep, normalize,
                            preserve_dict_class, to_str) \
            if preserve_tuples \
            else decode_list(data, encoding, errors, keep, normalize,
                             preserve_dict_class, preserve_tuples, to_str)
    else:
        try:
            data = _decode_func(data, encoding, errors, normalize)
        except TypeError:
            # to_unicode raises a TypeError when input is not a
            # string/bytestring/bytearray. This is expected and simply means we
            # are going to leave the value as-is.
            pass
        except UnicodeDecodeError:
            if not keep:
                raise
        return data


def encode(data, encoding=None, errors='strict', keep=False,
           preserve_dict_class=False, preserve_tuples=False):
    """
    Generic function which will encode whichever type is passed, if necessary

    If `strict` is True, and `keep` is False, and we fail to encode, a
    UnicodeEncodeError will be raised. Passing `keep` as True allows for the
    original value to silently be returned in cases where encoding fails. This
    can be useful for cases where the data passed to this function is likely to
    contain binary blobs.
    """
    if isinstance(data, Mapping):
        return encode_dict(data, encoding, errors, keep,
                           preserve_dict_class, preserve_tuples)
    elif isinstance(data, list):
        return encode_list(data, encoding, errors, keep,
                           preserve_dict_class, preserve_tuples)
    elif isinstance(data, tuple):
        return encode_tuple(data, encoding, errors, keep, preserve_dict_class) \
            if preserve_tuples \
            else encode_list(data, encoding, errors, keep,
                             preserve_dict_class, preserve_tuples)
    else:
        try:
            return hubblestack.utils.stringutils.to_bytes(data, encoding, errors)
        except TypeError:
            # to_bytes raises a TypeError when input is not a
            # string/bytestring/bytearray. This is expected and simply
            # means we are going to leave the value as-is.
            pass
        except UnicodeEncodeError:
            if not keep:
                raise
        return data


def encode_dict(data, encoding=None, errors='strict', keep=False,
                preserve_dict_class=False, preserve_tuples=False):
    """
    Encode all string values to bytes
    """
    rv = data.__class__() if preserve_dict_class else {}
    for key, value in iter(data.items()):
        if isinstance(key, tuple):
            key = encode_tuple(key, encoding, errors, keep, preserve_dict_class) \
                if preserve_tuples \
                else encode_list(key, encoding, errors, keep,
                                 preserve_dict_class, preserve_tuples)
        else:
            try:
                key = hubblestack.utils.stringutils.to_bytes(key, encoding, errors)
            except TypeError:
                # to_bytes raises a TypeError when input is not a
                # string/bytestring/bytearray. This is expected and simply
                # means we are going to leave the value as-is.
                pass
            except UnicodeEncodeError:
                if not keep:
                    raise

        if isinstance(value, list):
            value = encode_list(value, encoding, errors, keep,
                                preserve_dict_class, preserve_tuples)
        elif isinstance(value, tuple):
            value = encode_tuple(value, encoding, errors, keep, preserve_dict_class) \
                if preserve_tuples \
                else encode_list(value, encoding, errors, keep,
                                 preserve_dict_class, preserve_tuples)
        elif isinstance(value, Mapping):
            value = encode_dict(value, encoding, errors, keep,
                                preserve_dict_class, preserve_tuples)
        else:
            try:
                value = hubblestack.utils.stringutils.to_bytes(value, encoding, errors)
            except TypeError:
                # to_bytes raises a TypeError when input is not a
                # string/bytestring/bytearray. This is expected and simply
                # means we are going to leave the value as-is.
                pass
            except UnicodeEncodeError:
                if not keep:
                    raise

        rv[key] = value
    return rv


def encode_list(data, encoding=None, errors='strict', keep=False,
                preserve_dict_class=False, preserve_tuples=False):
    """
    Encode all string values to bytes
    """
    ret_val = []
    for item in data:
        if isinstance(item, list):
            item = encode_list(item, encoding, errors, keep,
                               preserve_dict_class, preserve_tuples)
        elif isinstance(item, tuple):
            item = encode_tuple(item, encoding, errors, keep, preserve_dict_class) \
                if preserve_tuples \
                else encode_list(item, encoding, errors, keep,
                                 preserve_dict_class, preserve_tuples)
        elif isinstance(item, Mapping):
            item = encode_dict(item, encoding, errors, keep,
                               preserve_dict_class, preserve_tuples)
        else:
            try:
                item = hubblestack.utils.stringutils.to_bytes(item, encoding, errors)
            except TypeError:
                # to_bytes raises a TypeError when input is not a
                # string/bytestring/bytearray. This is expected and simply
                # means we are going to leave the value as-is.
                pass
            except UnicodeEncodeError:
                if not keep:
                    raise

        ret_val.append(item)
    return ret_val


def encode_tuple(data, encoding=None, errors='strict', keep=False,
                 preserve_dict_class=False):
    """
    Encode all string values to Unicode
    """
    return tuple(
        encode_list(data, encoding, errors, keep, preserve_dict_class, True))


def decode_dict(data, encoding=None, errors='strict', keep=False,
                normalize=False, preserve_dict_class=False,
                preserve_tuples=False, to_str=False):
    """
    Decode all string values to Unicode. Optionally use to_str=True to ensure
    strings are str types and not unicode on Python 2.
    """
    _decode_func = hubblestack.utils.stringutils.to_unicode \
        if not to_str \
        else hubblestack.utils.stringutils.to_str
    # Make sure we preserve OrderedDicts
    ret_val = data.__class__() if preserve_dict_class else {}
    for key, value in iter(data.items()):
        if isinstance(key, tuple):
            key = decode_tuple(key, encoding, errors, keep, normalize,
                               preserve_dict_class, to_str) \
                if preserve_tuples \
                else decode_list(key, encoding, errors, keep, normalize,
                                 preserve_dict_class, preserve_tuples, to_str)
        else:
            try:
                key = _decode_func(key, encoding, errors, normalize)
            except TypeError:
                # to_unicode raises a TypeError when input is not a
                # string/bytestring/bytearray. This is expected and simply
                # means we are going to leave the value as-is.
                pass
            except UnicodeDecodeError:
                if not keep:
                    raise

        if isinstance(value, list):
            value = decode_list(value, encoding, errors, keep, normalize,
                                preserve_dict_class, preserve_tuples, to_str)
        elif isinstance(value, tuple):
            value = decode_tuple(value, encoding, errors, keep, normalize,
                                 preserve_dict_class, to_str) \
                if preserve_tuples \
                else decode_list(value, encoding, errors, keep, normalize,
                                 preserve_dict_class, preserve_tuples, to_str)
        elif isinstance(value, Mapping):
            value = decode_dict(value, encoding, errors, keep, normalize,
                                preserve_dict_class, preserve_tuples, to_str)
        else:
            try:
                value = _decode_func(value, encoding, errors, normalize)
            except TypeError:
                # to_unicode raises a TypeError when input is not a
                # string/bytestring/bytearray. This is expected and simply
                # means we are going to leave the value as-is.
                pass
            except UnicodeDecodeError:
                if not keep:
                    raise

        ret_val[key] = value
    return ret_val


def decode_list(data, encoding=None, errors='strict', keep=False,
                normalize=False, preserve_dict_class=False,
                preserve_tuples=False, to_str=False):
    """
    Decode all string values to Unicode. Optionally use to_str=True to ensure
    strings are str types and not unicode on Python 2.
    """
    _decode_func = hubblestack.utils.stringutils.to_unicode \
        if not to_str \
        else hubblestack.utils.stringutils.to_str
    ret_val = []
    for item in data:
        if isinstance(item, list):
            item = decode_list(item, encoding, errors, keep, normalize,
                               preserve_dict_class, preserve_tuples, to_str)
        elif isinstance(item, tuple):
            item = decode_tuple(item, encoding, errors, keep, normalize,
                                preserve_dict_class, to_str) \
                if preserve_tuples \
                else decode_list(item, encoding, errors, keep, normalize,
                                 preserve_dict_class, preserve_tuples, to_str)
        elif isinstance(item, Mapping):
            item = decode_dict(item, encoding, errors, keep, normalize,
                               preserve_dict_class, preserve_tuples, to_str)
        else:
            try:
                item = _decode_func(item, encoding, errors, normalize)
            except TypeError:
                # to_unicode raises a TypeError when input is not a
                # string/bytestring/bytearray. This is expected and simply
                # means we are going to leave the value as-is.
                pass
            except UnicodeDecodeError:
                if not keep:
                    raise

        ret_val.append(item)
    return ret_val


def decode_tuple(data, encoding=None, errors='strict', keep=False,
                 normalize=False, preserve_dict_class=False, to_str=False):
    """
    Decode all string values to Unicode. Optionally use to_str=True to ensure
    strings are str types and not unicode on Python 2.
    """
    return tuple(
        decode_list(data, encoding, errors, keep, normalize,
                    preserve_dict_class, True, to_str)
    )


def repack_dictlist(data,
                    strict=False,
                    recurse=False,
                    key_cb=None,
                    val_cb=None):
    """
    Takes a list of one-element dicts (as found in many SLS schemas) and
    repacks into a single dictionary.
    """
    if isinstance(data, str):
        try:
            data = hubblestack.utils.yaml.safe_load(data)
        except hubblestack.utils.yaml.parser.ParserError as err:
            log.error(err)
            return {}

    if key_cb is None:
        key_cb = lambda x: x
    if val_cb is None:
        val_cb = lambda x, y: y

    valid_non_dict = (str, int, float)
    if isinstance(data, list):
        for element in data:
            if isinstance(element, valid_non_dict):
                continue
            elif isinstance(element, dict):
                if len(element) != 1:
                    log.error(
                        'Invalid input for repack_dictlist: key/value pairs '
                        'must contain only one element (data passed: %s).',
                        element
                    )
                    return {}
            else:
                log.error(
                    'Invalid input for repack_dictlist: element %s is '
                    'not a string/dict/numeric value', element
                )
                return {}
    else:
        log.error(
            'Invalid input for repack_dictlist, data passed is not a list '
            '(%s)', data
        )
        return {}

    ret = {}
    for element in data:
        if isinstance(element, valid_non_dict):
            ret[key_cb(element)] = None
        else:
            key = next(iter(element))
            val = element[key]
            if is_dictlist(val):
                if recurse:
                    ret[key_cb(key)] = repack_dictlist(val, recurse=recurse)
                elif strict:
                    log.error(
                        'Invalid input for repack_dictlist: nested dictlist '
                        'found, but recurse is set to False'
                    )
                    return {}
                else:
                    ret[key_cb(key)] = val_cb(key, val)
            else:
                ret[key_cb(key)] = val_cb(key, val)
    return ret


def is_dictlist(data):
    """
    Returns True if data is a list of one-element dicts (as found in many SLS
    schemas), otherwise returns False
    """
    if isinstance(data, list):
        for element in data:
            if isinstance(element, dict):
                if len(element) != 1:
                    return False
            else:
                return False
        return True
    return False


def compare_dicts(old=None, new=None):
    """
    Compare before and after results from various salt functions, returning a
    dict describing the changes that were made.
    """
    ret = {}
    for key in set((new or {})).union((old or {})):
        if key not in old:
            # New key
            ret[key] = {'old': '',
                        'new': new[key]}
        elif key not in new:
            # Key removed
            ret[key] = {'new': '',
                        'old': old[key]}
        elif new[key] != old[key]:
            # Key modified
            ret[key] = {'old': old[key],
                        'new': new[key]}
    return ret


def traverse_dict_and_list(data, key, default=None, delimiter=':'):
    """
    Traverse a dict or list using a colon-delimited (or otherwise delimited,
    using the 'delimiter' param) target string. The target 'foo:bar:0' will
    return data['foo']['bar'][0] if this value exists, and will otherwise
    return the dict in the default argument.
    Function will automatically determine the target type.
    The target 'foo:bar:0' will return data['foo']['bar'][0] if data like
    {'foo':{'bar':['baz']}} , if data like {'foo':{'bar':{'0':'baz'}}}
    then return data['foo']['bar']['0']
    """
    ptr = data
    for each in key.split(delimiter):
        if isinstance(ptr, list):
            try:
                idx = int(each)
            except ValueError:
                embed_match = False
                # Index was not numeric, lets look at any embedded dicts
                for embedded in (x for x in ptr if isinstance(x, dict)):
                    try:
                        ptr = embedded[each]
                        embed_match = True
                        break
                    except KeyError:
                        pass
                if not embed_match:
                    # No embedded dicts matched, return the default
                    return default
            else:
                try:
                    ptr = ptr[idx]
                except IndexError:
                    return default
        else:
            try:
                ptr = ptr[each]
            except (KeyError, TypeError):
                return default
    return ptr


def stringify(data):
    """
    Given an iterable, returns its items as a list, with any non-string items
    converted to unicode strings.
    """
    ret = []
    for item in data:
        if not isinstance(item, str):
            item = str(item)
        elif isinstance(item, str):
            item = hubblestack.utils.stringutils.to_unicode(item)

        ret.append(item)
    return ret


def is_true(value=None):
    """
    Returns a boolean value representing the "truth" of the value passed. The
    rules for what is a "True" value are:

        1. Integer/float values greater than 0
        2. The string values "True" and "true"
        3. Any object for which bool(obj) returns True
    """
    # First, try int/float conversion
    try:
        value = int(value)
    except (ValueError, TypeError):
        pass
    try:
        value = float(value)
    except (ValueError, TypeError):
        pass

    # Now check for truthiness
    if isinstance(value, (int, float)):
        return value > 0
    elif isinstance(value, str):
        return str(value).lower() == 'true'
    else:
        return bool(value)


def __change_case(data, attr, preserve_dict_class=False):
    try:
        return getattr(data, attr)()
    except AttributeError:
        pass

    data_type = data.__class__

    if isinstance(data, Mapping):
        return (data_type if preserve_dict_class else dict)(
            (__change_case(key, attr, preserve_dict_class),
             __change_case(val, attr, preserve_dict_class))
            for key, val in iter(data.items())
        )
    elif isinstance(data, Sequence):
        return data_type(
            __change_case(item, attr, preserve_dict_class) for item in data)
    else:
        return data


def to_lowercase(data, preserve_dict_class=False):
    return __change_case(data, 'lower', preserve_dict_class)


def is_list(value):
    """
    Check if a variable is a list.
    """
    return isinstance(value, list)


def subdict_match(
        data, expr, delimiter=DEFAULT_TARGET_DELIM, regex_match=False, exact_match=False
):
    """
    Check for a match in a dictionary using a delimiter character to denote
    levels of subdicts, and also allowing the delimiter character to be
    matched. Thus, 'foo:bar:baz' will match data['foo'] == 'bar:baz' and
    data['foo']['bar'] == 'baz'. The latter would take priority over the
    former, as more deeply-nested matches are tried first.
    """

    def _match(target, pattern, regex_match=False, exact_match=False):
        # The reason for using six.text_type first and _then_ using
        # to_unicode as a fallback is because we want to eventually have
        # unicode types for comparison below. If either value is numeric then
        # six.text_type will turn it into a unicode string. However, if the
        # value is a PY2 str type with non-ascii chars, then the result will be
        # a UnicodeDecodeError. In those cases, we simply use to_unicode to
        # decode it to unicode. The reason we can't simply use to_unicode to
        # begin with is that (by design) to_unicode will raise a TypeError if a
        # non-string/bytestring/bytearray value is passed.
        try:
            target = str(target).lower()
        except UnicodeDecodeError:
            target = hubblestack.utils.stringutils.to_unicode(target).lower()
        try:
            pattern = str(pattern).lower()
        except UnicodeDecodeError:
            pattern = hubblestack.utils.stringutils.to_unicode(pattern).lower()

        if regex_match:
            try:
                return re.match(pattern, target)
            except Exception:  # pylint: disable=broad-except
                log.error("Invalid regex '%s' in match", pattern)
                return False
        else:
            return (
                target == pattern if exact_match else fnmatch.fnmatch(target, pattern)
            )

    def _dict_match(target, pattern, regex_match=False, exact_match=False):
        ret = False
        wildcard = pattern.startswith("*:")
        if wildcard:
            pattern = pattern[2:]

        if pattern == "*":
            # We are just checking that the key exists
            ret = True
        if not ret and pattern in target:
            # We might want to search for a key
            ret = True
        if not ret and subdict_match(
                target, pattern, regex_match=regex_match, exact_match=exact_match
        ):
            ret = True
        if not ret and wildcard:
            for key in target:
                if isinstance(target[key], dict):
                    if _dict_match(
                            target[key],
                            pattern,
                            regex_match=regex_match,
                            exact_match=exact_match,
                    ):
                        return True
                elif isinstance(target[key], list):
                    for item in target[key]:
                        if _match(
                                item,
                                pattern,
                                regex_match=regex_match,
                                exact_match=exact_match,
                        ):
                            return True
                elif _match(
                        target[key],
                        pattern,
                        regex_match=regex_match,
                        exact_match=exact_match,
                ):
                    return True
        return ret

    splits = expr.split(delimiter)
    num_splits = len(splits)
    if num_splits == 1:
        # Delimiter not present, this can't possibly be a match
        return False

    # If we have 4 splits, then we have three delimiters. Thus, the indexes we
    # want to use are 3, 2, and 1, in that order.
    for idx in range(num_splits - 1, 0, -1):
        key = delimiter.join(splits[:idx])
        if key == "*":
            # We are matching on everything under the top level, so we need to
            # treat the match as the entire data being passed in
            matchstr = expr
            match = data
        else:
            matchstr = delimiter.join(splits[idx:])
            match = traverse_dict_and_list(data, key, {}, delimiter=delimiter)
        log.debug(
            "Attempting to match '%s' in '%s' using delimiter '%s'",
            matchstr,
            key,
            delimiter,
        )
        if match == {}:
            continue
        if isinstance(match, dict):
            if _dict_match(
                    match, matchstr, regex_match=regex_match, exact_match=exact_match
            ):
                return True
            continue
        if isinstance(match, (list, tuple)):
            # We are matching a single component to a single list member
            for member in match:
                if isinstance(member, dict):
                    if _dict_match(
                            member,
                            matchstr,
                            regex_match=regex_match,
                            exact_match=exact_match,
                    ):
                        return True
                if _match(
                        member, matchstr, regex_match=regex_match, exact_match=exact_match
                ):
                    return True
            continue
        if _match(match, matchstr, regex_match=regex_match, exact_match=exact_match):
            return True
    return False
