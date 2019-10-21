import pytest
import os

from hubblestack.hec.dq import DiskQueue
from hubblestack.hec.dq import QueueTypeError, QueueCapacityError

TEST_DQ_DIR = os.environ.get('TEST_DQ_DIR', '/tmp/dq.{0}'.format(os.getuid()))

@pytest.fixture
def samp():
    return tuple('one two three four five'.split())

@pytest.fixture
def dq():
    return DiskQueue(TEST_DQ_DIR, size=100, fresh=True)

def test_disk_queue(dq):
    borked = False

    dq.put('one', testinator=3)
    dq.put('two', testinator=4)
    dq.put('three', testinator=5)

    assert len(dq) == 13
    assert dq.peek() == (b'one', {'testinator': 3})
    assert dq.get() == (b'one', {'testinator': 3})
    assert dq.peek() == (b'two', {'testinator': 4})
    assert len(dq) == 9

    assert dq.getz() == ('two three', {'testinator': 5})
    assert len(dq) == 0

    dq.put('one')
    dq.put('two')
    dq.put('three')

    assert dq.getz(8) == ('one two', {})
    assert dq.getz(8) == ('three', {})

def _test_pop(samp,q):
    for i in samp:
        q.put(i)
    for i in samp:
        assert q.peek() == (str.encode(i), {})
        q.pop()

def test_dq_pop(samp,dq):
    _test_pop(samp,dq)

def test_disk_queue_put_estimator():
    dq = DiskQueue(TEST_DQ_DIR, fresh=True)
    for item in ['hi-there-{}'.format(x) for x in range(20)]:
        pre = dq.cn, dq.sz
        dq.put(item)
        post = dq.cn, dq.sz
        assert (pre[0]+1, pre[1]+len(item)) == post
        dq._count()
        more = dq.cn, dq.sz
        assert post == more
