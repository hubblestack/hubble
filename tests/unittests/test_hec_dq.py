
import pytest
import shutil
import os
from hubblestack.hec.dq import DiskQueue

DQ_LOCATION = os.environ.get('TEST_DQ_LOC', '/tmp/test-dq')

@pytest.fixture(scope='function')
def summon_dq(request):
    def fin():
        if os.path.isdir(DQ_LOCATION):
            shutil.rmtree('/tmp/test-dq')
    fin() # make sure we don't have anything before we get started
    request.addfinalizer(fin) # but also, make sure we clean up when we're done
    def _go(**kw):
        return DiskQueue('/tmp/test-dq', **kw)
    return _go

def test_dq_max_items(summon_dq):
    dq = summon_dq(max_items=100)

    for i in range(200):
        dq.put(i)
    l = list()
    while True:
        item = dq.pull()
        if item is not None:
            l.append(item)
        else:
            break

    assert len(l) == 100
    assert l == list(range(100, 200))

def test_dq_max_size(summon_dq):
    # this is a really small queue size. The journal and other sqlite overhead
    # will eat up a large portion of this small cache space.
    SZ = 100 * 1024

    dq = summon_dq(max_size=SZ)
    for i in range(200):
        dq.put(i)

    # The size is essentially random, due to sqlite overhead
    assert dq.disksize > 0
    assert dq.disksize <= SZ
    assert dq.eventcount == 200

    f = '{:04d} SUPER LONG TEXT TO FILL 100k BUFFER. '
    sz = len((f.format(0) * 10))

    for i in range(200):
        dq.put(f.format(i) * 10)

    at_most = int(SZ/sz)
    # works out to 243 or so, but we'll only find maybe 30ish in the queue

    assert dq.disksize > 0
    assert dq.disksize <= SZ
    assert dq.eventcount < at_most
    assert dq.eventcount > 5 # surely we can fit at least 5
    assert dq[-1].startswith('0199 ')
