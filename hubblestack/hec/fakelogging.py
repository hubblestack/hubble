# -*- encoding: utf-8 -*-

import os
import time

class FakeLog(object):
    ''' teach the hec objects about logging
        in such a way that it can never accidentally go to slunk
        (causing an infinite loop of logging)
    '''
    def __init__(self, name):
        self.file = os.environ.get('HUBBLE_HEC_DEBUG')
        self.name = 'hubblestack.hec.' + name
    def _show(self, level, fmt, *a):
        if not self.file:
            return
        p = os.getpid()
        t = time.ctime()
        with open(self.file, 'a') as fh:
            msg = fmt % a
            for line in msg.splitlines():
                fh.write('{time} {name} [{pid}] {}: {}\n'.format(level, line,
                    time=t, pid=p, name=self.name))
    def debug(self, *a): self._show('debug', *a)
    def  info(self, *a): self._show('info',  *a)
    def error(self, *a): self._show('error', *a)

def getLogger(name):
    return FakeLog(name)
