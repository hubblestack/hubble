import pytest
import os

from hubblestack.hec.dq import DiskQueue
from hubblestack.hec.dq import QueueTypeError, QueueCapacityError

TEST_DQ_DIR = os.environ.get('TEST_DQ_DIR', '/tmp/dq.{0}'.format(os.getuid()))

@pytest.fixture
def samp():
    return tuple(b'one two three four five'.split())

@pytest.fixture
def dq():
    return DiskQueue(TEST_DQ_DIR, size=100, fresh=True)

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

def _test_pop(samp,q):
    for i in samp:
        q.put(i)
    for i in samp:
        assert q.peek() == i
        q.pop()

def test_dq_pop(samp,dq):
    _test_pop(samp,dq)
