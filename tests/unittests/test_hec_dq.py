import pytest
import os

from hubblestack.hec.dq import DiskQueue, MemQueue, DiskBackedQueue
from hubblestack.hec.dq import QueueTypeError, QueueCapacityError

TEST_DQ_DIR = os.environ.get('TEST_DQ_DIR', '/tmp/dq.{0}'.format(os.getuid()))

@pytest.fixture
def samp():
    return tuple(b'one two three four five'.split())

@pytest.fixture
def mq():
    return MemQueue(size=100)

@pytest.fixture
def dq():
    return DiskQueue(TEST_DQ_DIR, size=100, fresh=True)

@pytest.fixture
def dbq():
    return DiskBackedQueue(TEST_DQ_DIR, mem_size=100, disk_size=100, fresh=True)

def test_mem_queue(mq):
    borked = False

    mq.put(b'one')
    mq.put(b'two')
    mq.put(b'three')

    assert len(mq) == 13
    assert mq.peek() == b'one'
    assert mq.get() == b'one'
    assert mq.peek() == b'two'
    assert len(mq) == 9

    assert mq.getz() == b'two three'
    assert len(mq) == 0

    mq.put(b'one')
    mq.put(b'two')
    mq.put(b'three')

    assert mq.getz(8) == b'one two'
    assert mq.getz(8) == b'three'

def test_disk_queue(dq):
    borked = False

    dq.put(b'one')
    dq.put(b'two')
    dq.put(b'three')

    assert len(dq) == 13
    assert dq.peek() == b'one'
    assert dq.get() == b'one'
    assert dq.peek() == b'two'
    assert len(dq) == 9

    assert dq.getz() == b'two three'
    assert len(dq) == 0

    dq.put(b'one')
    dq.put(b'two')
    dq.put(b'three')

    assert dq.getz(8) == b'one two'
    assert dq.getz(8) == b'three'

def test_disk_backed_queue(dbq):
    borked = False

    with pytest.raises(QueueCapacityError):
        for i in range(22):
            dbq.put('{0:10}'.format(i).encode())

    assert dbq.mq.sz == 100
    assert dbq.dq.sz == 100

    mr,dr = 100,100
    for i in range(20):
        b = '{0:10}'.format(i).encode()
        assert dbq.get() == b

        if dr:
            dr -= 10
        else:
            mr -= 10

        assert dbq.mq.sz == mr
        assert dbq.dq.sz == dr

    assert dbq.mq.sz == 0
    assert dbq.dq.sz == 0

    compare = list()
    for i in range(15):
        v = '{0:10}'.format(i).encode()
        dbq.put(v)
        compare.append(v)
    assert dbq.mq.sz == 100
    assert dbq.dq.sz == 50
    assert dbq.getz() == dbq.mq.sep.join(compare)

    compare = list()
    for i in range(15):
        v = '{0:10}'.format(i).encode()
        dbq.put(v)
        compare.append(v)
    assert dbq.mq.sz == 100
    assert dbq.dq.sz == 50
    assert dbq.getz(25) == dbq.mq.sep.join(compare[0:2])
    compare = compare[2:]
    assert dbq.mq.sz == 100
    assert dbq.dq.sz == 30


def _test_pop(samp,q):
    for i in samp:
        q.put(i)
    for i in samp:
        assert q.peek() == i
        q.pop()

def test_mq_pop(samp,mq):
    _test_pop(samp,mq)

def test_dq_pop(samp,dq):
    _test_pop(samp,dq)

def test_dbq_pop(dbq):
    samp = tuple( b'test-{i:02x}' for i in range(14) )
    for i in samp:
        dbq.put(i)
    assert dbq.cn == 14
    assert dbq.mq.cn == 8
    assert dbq.dq.cn == 6
    for i in samp:
        assert dbq.peek() == i
        dbq.pop()
        assert dbq.dq.cn + dbq.mq.cn == dbq.cn
