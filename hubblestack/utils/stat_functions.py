"""
These are utility functions used to check 'mode' stat of a file. Currently the stat module in Nova and FDG use these functions
"""

def check_mode(max_permission, given_permission, allow_more_strict):
    """
    Checks whether a file's permission are equal to a given permission or more restrictive.
    Permission is a string of 3 digits [0-7]. 'given_permission' is the actual permission on file,
    'max_permission' is the expected permission on this file. Set 'allow_more_strict' to True,
    to allow more restrictive permissions as well. Example:

    _check_mode('644', '644', False)        returns         True
    _check_mode('644', '600', False)        returns         False
    _check_mode('644', '644', True)         returns         True
    _check_mode('644', '600', True)         returns         True
    _check_mode('644', '655', True)        returns         False

    """

    if given_permission == '0':
        return True

    if not allow_more_strict or max_permission == 'None':
        return max_permission == given_permission

    if (_is_permission_in_limit(max_permission[0], given_permission[0]) and
            _is_permission_in_limit(max_permission[1], given_permission[1]) and
            _is_permission_in_limit(max_permission[2], given_permission[2])):
        return True

    return False


def _is_permission_in_limit(max_permission, given_permission):
    """
    Return true only if given_permission is not more lenient that max_permission. In other words, if
    r or w or x is present in given_permission but absent in max_permission, it should return False
    Takes input two integer values from 0 to 7.
    """
    max_permission = int(max_permission)
    given_permission = int(given_permission)
    allowed_r = False
    allowed_w = False
    allowed_x = False
    given_r = False
    given_w = False
    given_x = False

    if max_permission >= 4:
        allowed_r = True
        max_permission = max_permission - 4
    if max_permission >= 2:
        allowed_w = True
        max_permission = max_permission - 2
    if max_permission >= 1:
        allowed_x = True

    if given_permission >= 4:
        given_r = True
        given_permission = given_permission - 4
    if given_permission >= 2:
        given_w = True
        given_permission = given_permission - 2
    if given_permission >= 1:
        given_x = True

    if given_r and (not allowed_r):
        return False
    if given_w and (not allowed_w):
        return False
    if given_x and (not allowed_x):
        return False

    return True
