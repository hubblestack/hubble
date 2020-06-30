# coding: utf-8

def numbered_file_split_key(x):
    """ for sorting purposes, split filenames like '238048.11', '238048.17',
        '238048.0' into lists of integers.  E.g.:

        for fname in sorted(filenames, key=numbered_file_split_key):
            do_things_ordered_by_integer_sort()
    """
    try:
        return [int(i) for i in x.split('.')]
    except:
        pass
    try:
        return [int(x)]
    except:
        pass
    return list()
