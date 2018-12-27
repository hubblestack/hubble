
import pytest
import shutil
import os
from hubblestack.hec.dq import DiskQueue, QueueCapacityError

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

def test_dq_compression0(summon_dq):
    dq = summon_dq(compression=0)

    source_data = ', '.join(['mah data'] * 10000)

    x = dq.compress(source_data)
    assert x == source_data
    assert dq.decompress(x) == source_data

    dq.put('one')
    dq.put('two')
    assert dq.peek() == 'one'
    assert dq.get() == 'one'
    assert dq.get() == 'two'

def test_dq_compression5(summon_dq):
    dq = summon_dq(compression=5)

    source_data = ', '.join(['mah data'] * 10000)

    x = dq.compress(source_data)
    assert x != source_data
    assert x.startswith("BZ")
    assert dq.decompress(x) == source_data

    dq.put('one')
    dq.put('two')
    assert dq.peek() == 'one'
    assert dq.get() == 'one'
    assert dq.get() == 'two'

def test_dq_max_items(summon_dq):
    dq = summon_dq(size=100*10)

    for i in range(200):
        try:
            dq.put('{:010}'.format(i))
        except QueueCapacityError:
            break

    assert dq.cn == 100

    l = list()
    while True:
        item = dq.get()
        if item is not None:
            l.append(item)
        else:
            break

    assert len(l) == 100
    assert l == [ '{:010}'.format(i) for i in range(100) ]

def test_dq_size(summon_dq):
    # this is a really small queue size. The journal and other sqlite overhead
    # will eat up a large portion of this small cache space.
    SZ = 100 * 1024

    dq = summon_dq(size=SZ)
    for i in range(200):
        dq.put(str(i))

    # The size is essentially random, due to sqlite overhead
    assert dq.sz > 0
    assert dq.sz <= SZ
    assert dq.cn == 200

    f = '{:04d} SUPER LONG TEXT TO FILL 100k BUFFER. '
    sz = len(f.format(0))

    for i in range(200):
        dq.put(f.format(i) * 10)

    at_most = int(SZ/sz)

    assert dq.sz > 0
    assert dq.sz <= SZ
    assert dq.cn < at_most
    assert dq.cn > 5 # surely we can fit at least 5
