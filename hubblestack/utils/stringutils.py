# -*- coding: utf-8 -*-
'''
Functions for manipulating or otherwise processing strings
'''

# Import Python libs
import fnmatch
import logging
import re
import unicodedata


log = logging.getLogger(__name__)


def to_unicode(string_to_convert, encoding=None, errors='strict', normalize=False):
    '''
    Given str or unicode, return unicode (str for python 3)
    '''
    if encoding is None:
        # Try utf-8 first, and fall back to detected encoding
        encoding = ('utf-8', __salt_system_encoding__)
    if not isinstance(encoding, (tuple, list)):
        encoding = (encoding,)

    if not encoding:
        raise ValueError('encoding cannot be empty')

    if isinstance(string_to_convert, str):
        return _normalize(string_to_convert, normalize)
    elif isinstance(string_to_convert, (bytes, bytearray)):
        return _normalize(to_str(string_to_convert, encoding, errors), normalize)
    raise TypeError('expected str, bytes, or bytearray')


def to_bytes(string_to_convert, encoding=None, errors='strict'):
    '''
    Given bytes, bytearray, str, or unicode, return bytes
    '''
    if encoding is None:
        # Try utf-8 first, and fall back to detected encoding
        encoding = ('utf-8', __salt_system_encoding__)
    if not isinstance(encoding, (tuple, list)):
        encoding = (encoding,)

    if not encoding:
        raise ValueError('encoding cannot be empty')

    exc = None
    if isinstance(string_to_convert, bytes):
        return string_to_convert
    if isinstance(string_to_convert, bytearray):
        return bytes(string_to_convert)
    if isinstance(string_to_convert, str):
        for enc in encoding:
            try:
                return string_to_convert.encode(enc, errors)
            except UnicodeEncodeError as err:
                exc = err
                continue
        # The only way we get this far is if a UnicodeEncodeError was
        # raised, otherwise we would have already returned (or raised some
        # other exception).
        raise exc  # pylint: disable=raising-bad-type
    raise TypeError('expected bytes, bytearray, or str')


def to_str(string_to_convert, encoding=None, errors='strict', normalize=False):
    '''
    Given str, bytes, bytearray, or unicode (py2), return str
    '''
    if encoding is None:
        # Try utf-8 first, and fall back to detected encoding
        encoding = ('utf-8', __salt_system_encoding__)
    if not isinstance(encoding, (tuple, list)):
        encoding = (encoding,)

    if not encoding:
        raise ValueError('encoding cannot be empty')

    # This shouldn't be six.string_types because if we're on PY2 and we already
    # have a string, we should just return it.
    if isinstance(string_to_convert, str):
        return _normalize(string_to_convert, normalize)

    exc = None
    if isinstance(string_to_convert, (bytes, bytearray)):
        for enc in encoding:
            try:
                return _normalize(string_to_convert.decode(enc, errors), normalize)
            except UnicodeDecodeError as err:
                exc = err
                continue
        # The only way we get this far is if a UnicodeDecodeError was
        # raised, otherwise we would have already returned (or raised some
        # other exception).
        raise exc  # pylint: disable=raising-bad-type
    raise TypeError('expected str, bytes, or bytearray not {}'.format(type(string_to_convert)))


def _normalize(string_to_convert, normalize=False):
    '''
    a utility method for normalizing string
    '''
    try:
        return unicodedata.normalize('NFC', string_to_convert) if normalize else string_to_convert
    except TypeError:
        return string_to_convert


def is_binary(data):
    '''
    Detects if the passed string of data is binary or text
    '''
    if not data or not isinstance(data, (str, bytes)):
        return False

    if isinstance(data, bytes):
        if b'\0' in data:
            return True
    elif str('\0') in data:
        return True

    text_characters = ''.join([chr(x) for x in range(32, 127)] + list('\n\r\t\b'))
    # Get the non-text characters (map each character to itself then use the
    # 'remove' option to get rid of the text characters.)
    if isinstance(data, bytes):
        import hubblestack.utils.data
        nontext = data.translate(None, hubblestack.utils.data.encode(text_characters))
    else:
        trans = ''.maketrans('', '', text_characters)
        nontext = data.translate(trans)

    # If more than 30% non-text characters, then
    # this is considered binary data
    if float(len(nontext)) / len(data) > 0.30:
        return True
    return False


def to_num(text):
    '''
    Convert a string to a number.
    Returns an integer if the string represents an integer, a floating
    point number if the string is a real number, or the string unchanged
    otherwise.
    '''
    try:
        return int(text)
    except ValueError:
        try:
            return float(text)
        except ValueError:
            return text


def get_context(template, line, num_lines=5, marker=None):
    '''
    Returns debugging context around a line in a given string

    Returns:: string
    '''
    template_lines = template.splitlines()
    num_template_lines = len(template_lines)

    # In test mode, a single line template would return a crazy line number like,
    # 357. Do this sanity check and if the given line is obviously wrong, just
    # return the entire template
    if line > num_template_lines:
        return template

    context_start = max(0, line - num_lines - 1)  # subt 1 for 0-based indexing
    context_end = min(num_template_lines, line + num_lines)
    error_line_in_context = line - context_start - 1  # subtr 1 for 0-based idx

    buf = []
    if context_start > 0:
        buf.append('[...]')
        error_line_in_context += 1

    buf.extend(template_lines[context_start:context_end])

    if context_end < num_template_lines:
        buf.append('[...]')

    if marker:
        buf[error_line_in_context] += marker

    return '---\n{0}\n---'.format('\n'.join(buf))


def is_hex(value):
    """
    Returns True if value is a hexadecimal string, otherwise returns False
    """
    try:
        int(value, 16)
        return True
    except (TypeError, ValueError):
        return False


def expr_match(line, expr):
    """
    Checks whether or not the passed value matches the specified expression.
    Tries to match expr first as a glob using fnmatch.fnmatch(), and then tries
    to match expr as a regular expression. Originally designed to match minion
    IDs for whitelists/blacklists.

    Note that this also does exact matches, as fnmatch.fnmatch() will return
    ``True`` when no glob characters are used and the string is an exact match:

    .. code-block:: python

        >>> fnmatch.fnmatch('foo', 'foo')
        True
    """
    try:
        if fnmatch.fnmatch(line, expr):
            return True
        try:
            if re.match(r"\A{0}\Z".format(expr), line):
                return True
        except re.error:
            pass
    except TypeError:
        log.exception("Value %r or expression %r is not a string", line, expr)
    return False


def check_whitelist_blacklist(value, whitelist=None, blacklist=None):
    """
    Check a whitelist and/or blacklist to see if the value matches it.

    value
        The item to check the whitelist and/or blacklist against.

    whitelist
        The list of items that are white-listed. If ``value`` is found
        in the whitelist, then the function returns ``True``. Otherwise,
        it returns ``False``.

    blacklist
        The list of items that are black-listed. If ``value`` is found
        in the blacklist, then the function returns ``False``. Otherwise,
        it returns ``True``.

    If both a whitelist and a blacklist are provided, value membership
    in the blacklist will be examined first. If the value is not found
    in the blacklist, then the whitelist is checked. If the value isn't
    found in the whitelist, the function returns ``False``.
    """
    # Normalize the input so that we have a list
    if blacklist:
        if isinstance(blacklist, str):
            blacklist = [blacklist]
        if not hasattr(blacklist, "__iter__"):
            raise TypeError(
                "Expecting iterable blacklist, but got {0} ({1})".format(
                    type(blacklist).__name__, blacklist
                )
            )
    else:
        blacklist = []

    if whitelist:
        if isinstance(whitelist, str):
            whitelist = [whitelist]
        if not hasattr(whitelist, "__iter__"):
            raise TypeError(
                "Expecting iterable whitelist, but got {0} ({1})".format(
                    type(whitelist).__name__, whitelist
                )
            )
    else:
        whitelist = []

    _blacklist_match = any(expr_match(value, expr) for expr in blacklist)
    _whitelist_match = any(expr_match(value, expr) for expr in whitelist)

    if blacklist and not whitelist:
        # Blacklist but no whitelist
        return not _blacklist_match
    elif whitelist and not blacklist:
        # Whitelist but no blacklist
        return _whitelist_match
    elif blacklist and whitelist:
        # Both whitelist and blacklist
        return not _blacklist_match and _whitelist_match
    else:
        # No blacklist or whitelist passed
        return True


def check_include_exclude(path_str, include_pat=None, exclude_pat=None):
    '''
    Check for glob or regexp patterns for include_pat and exclude_pat in the
    'path_str' string and return True/False conditions as follows.
      - Default: return 'True' if no include_pat or exclude_pat patterns are
        supplied
      - If only include_pat or exclude_pat is supplied: return 'True' if string
        passes the include_pat test or fails exclude_pat test respectively
      - If both include_pat and exclude_pat are supplied: return 'True' if
        include_pat matches AND exclude_pat does not match
    '''
    ret = True  # -- default true
    # Before pattern match, check if it is regexp (E@'') or glob(default)
    if include_pat:
        if re.match('E@', include_pat):
            retchk_include = True if re.search(
                include_pat[2:],
                path_str
            ) else False
        else:
            retchk_include = True if fnmatch.fnmatch(
                path_str,
                include_pat
            ) else False

    if exclude_pat:
        if re.match('E@', exclude_pat):
            retchk_exclude = False if re.search(
                exclude_pat[2:],
                path_str
            ) else True
        else:
            retchk_exclude = False if fnmatch.fnmatch(
                path_str,
                exclude_pat
            ) else True

    # Now apply include/exclude conditions
    if include_pat and not exclude_pat:
        ret = retchk_include
    elif exclude_pat and not include_pat:
        ret = retchk_exclude
    elif include_pat and exclude_pat:
        ret = retchk_include and retchk_exclude
    else:
        ret = True

    return ret