# -*- coding: utf-8 -*-
'''
In-memory caching
'''
# Import Python libs
import re
import time
import logging

try:
    import msgpack

    HAS_MSGPACK = True
except ImportError:
    HAS_MSGPACK = False

log = logging.getLogger(__name__)


class CacheRegex(object):
    '''
    Create a regular expression object cache for the most frequently
    used patterns to minimize compilation of the same patterns over
    and over again
    '''

    def __init__(self, prepend='', append='', size=1000,
                 keep_fraction=0.8, max_age=3600):
        self.prepend = prepend
        self.append = append
        self.size = size
        self.clear_size = int(size - size * keep_fraction)
        if self.clear_size >= size:
            self.clear_size = int(size / 2) + 1
            if self.clear_size > size:
                self.clear_size = size
        self.max_age = max_age
        self.cache = {}
        self.timestamp = time.time()

    def clear(self):
        '''
        Clear the cache
        '''
        self.cache.clear()

    def sweep(self):
        '''
        Sweep the cache and remove the outdated or least frequently
        used entries
        '''
        if self.max_age < time.time() - self.timestamp:
            self.clear()
            self.timestamp = time.time()
        else:
            paterns = list(self.cache.values())
            paterns.sort()
            for idx in range(self.clear_size):
                del self.cache[paterns[idx][2]]

    def get(self, pattern):
        '''
        Get a compiled regular expression object based on pattern and
        cache it when it is not in the cache already
        '''
        try:
            self.cache[pattern][0] += 1
            return self.cache[pattern][1]
        except KeyError:
            pass
        if len(self.cache) > self.size:
            self.sweep()
        regex = re.compile('{0}{1}{2}'.format(
            self.prepend, pattern, self.append))
        self.cache[pattern] = [1, regex, pattern, time.time()]
        return regex
