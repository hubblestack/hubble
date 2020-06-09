
from functools import wraps

def memoize(func):
    '''
    Memoize aka cache the return output of a function
    given a specific set of arguments
    '''
    cache = {}

    @wraps(func)
    def _memoize(*args, **kwargs):
        str_args = []
        for arg in args:
            if not isinstance(arg, str):
                str_args.append(str(arg))
            else:
                str_args.append(arg)

        args_ = ','.join(list(str_args) + ['{0}={1}'.format(k, kwargs[k]) for k in sorted(kwargs)])
        if args_ not in cache:
            cache[args_] = func(*args, **kwargs)
        return cache[args_]

    return _memoize
