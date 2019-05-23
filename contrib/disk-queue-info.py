#!/usr/bin/env python

import sys
from hubblestack.hec.dq import DiskQueue

def examine(dirname):
    dq = DiskQueue(dirname)
    return dq.cn, dq.sz

if __name__ == '__main__':
    for d in sys.argv[1:]:
        cn, sz = examine(d)
        print("QUEUE={} ITEMS={} SIZE={}".format(d, cn, sz))
