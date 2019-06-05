# coding: utf-8

import time
import pytest
import hubblestack.status

def sleep_100ms_and_mark(st=0.1):
    time.sleep(st)
    return time.time()

def test_counts():
    hubble_status = hubblestack.status.HubbleStatus('x', 'test1', 'test2')
    t0 = time.time()
    m = hubble_status.mark('test1')
    t1 = sleep_100ms_and_mark()
    m.fin()
    s1 = hubble_status.short()
    assert s1['x.test1']['count'] == 1
    assert s1['x.test1']['dt'] == pytest.approx(0.1, rel=1e2)

    m1 = hubble_status.mark('test1')
    m2 = hubble_status.mark('test2')
    t2 = sleep_100ms_and_mark()
    m1.fin()
    m2.fin()
    s2 = hubble_status.short()
    assert s2['x.test1']['count'] == 2
    assert s2['x.test1']['dt'] == pytest.approx(0.1, rel=1e2)
    assert s2['x.test2']['count'] == 1
    assert s2['x.test2']['dt'] == pytest.approx(0.1, rel=1e2)


    ########
    t0 = 1553102100
    hubblestack.status.__opts__['hubble_status'] = { 'bucket_len': 5, 'max_buckets': 1000 }
    hubble_status = hubblestack.status.HubbleStatus('x', 'test1')

    for t in range(t0, t0+100):
        hubble_status.mark('test1', t=t)

    b = hubble_status.buckets()
    assert len(b) == 1 + 100/5 # the extra is the bucket for the current time
    assert b[0] == t0
    assert b[-2] == t0+100-5

    c = 0
    for bucket in b[0:-1]:
        x = hubble_status.short(bucket)
        assert x['x.test1']['bucket'] == bucket
        c += x['x.test1']['count']
    assert c == 100


    ########
    t0 = 1553102100
    hubblestack.status.__opts__['hubble_status'] = { 'bucket_len': 5, 'max_buckets': 1000 }
    hubble_status = hubblestack.status.HubbleStatus('x', 'test1')

    for t in range(t0, t0+100):
        hubble_status.mark('test1', t=t)

    b1 = hubble_status.buckets()

    hubblestack.status.__opts__['hubble_status']['max_buckets'] = 3
    hubble_status.mark('test1', t0+99)

    b2 = hubble_status.buckets()
    assert len(b1) == 1 + 100/5
    assert len(b2) == 3
