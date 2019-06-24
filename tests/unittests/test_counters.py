# coding: utf-8

import time
import pytest
import hubblestack.status

def sleep_and_return_time(amount=0.1):
    time.sleep(amount)
    return time.time()

def setup_hubble_status(*a, **kw):
    # completely reset the status stack
    hubblestack.status.HubbleStatus.dat = dict()

    bucket_len = kw.pop('bucket_len', 4e3)
    max_buckets = kw.pop('max_buckets', 1e3)
    namespace = kw.pop('namespace', 'x')
    if kw:
        raise ValueError('unknown arguments: {}', ', '.join(kw.keys()))
    opt = dict(bucket_len=bucket_len, max_buckets=max_buckets)
    hubblestack.status.__opts__['hubble_status'] = opt
    return hubblestack.status.HubbleStatus(namespace, *a)

def test_one_count():
    hubble_status = setup_hubble_status('test1', 'test2')

    t0 = time.time()
    mark1 = hubble_status.mark('test1')
    t1 = sleep_and_return_time()
    mark1.fin()

    s = hubble_status.short()
    assert tuple(s.keys()) == ('x.test1',)
    assert s['x.test1']['count'] == 1
    assert s['x.test1']['dt'] == pytest.approx(0.1, rel=1e2)

    mark1_again = hubble_status.mark('test1')
    assert mark1_again is mark1

    mark2 = hubble_status.mark('test2')
    t2 = sleep_and_return_time()
    mark1_again.fin()
    mark2.fin()

    s = hubble_status.short()
    assert tuple(s.keys()) == ('x.test1', 'x.test2')
    assert s['x.test1']['count'] == 2
    assert s['x.test1']['dt'] == pytest.approx(0.1, rel=1e2)
    assert s['x.test2']['count'] == 1
    assert s['x.test2']['dt'] == pytest.approx(0.1, rel=1e2)

# def test_max_depth():
#     hubble_status = completely_reset_counters(B, N)

#     # some constants
#     t0 = 1553102100
#     N = 100
#     B = 5

#     hubblestack.status.__opts__['hubble_status'] = { 'bucket_len': B, 'max_buckets': 1000 }
#     hubble_status = hubblestack.status.HubbleStatus('x', 'test1')

#     for t in range(t0, t0+N):
#         hubble_status.mark('test1', t=t)

#     b = hubble_status.buckets()
#     assert len(b) == N/B
#     assert b[0] == t0
#     assert b[-2] == t0 + (N-B)

#     c = 0
#     for bucket in b[0:-1]:
#         x = hubble_status.short(bucket)
#         assert x['x.test1']['bucket'] == bucket
#         c += x['x.test1']['count']
#     assert c == N

# def test_buckets():
#     completely_reset_counters()

#     # some constants
#     t0 = 1553102100
#     N = 100
#     B0 = 5
#     B1 = 3

#     hubblestack.status.__opts__['hubble_status'] = { 'bucket_len': B0, 'max_buckets': 1000 }
#     hubble_status = hubblestack.status.HubbleStatus('x', 'test1')

#     for t in range(t0, t0+N):
#         hubble_status.mark('test1', t=t)

#     b1 = hubble_status.buckets()

#     hubblestack.status.__opts__['hubble_status']['max_buckets'] = B1
#     hubble_status.mark('test1', t0 + (N-1))

#     b2 = hubble_status.buckets()

#     assert len(b1) == N/B0
#     assert len(b2) == B1
