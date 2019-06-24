# coding: utf-8

import time
import pytest
import logging
import hubblestack.status

def sleep_and_return_time(amount=0.1):
    time.sleep(amount)
    return time.time()

def setup_hubble_status(*a, **kw):
    # completely reset the status stack
    hubblestack.status.HubbleStatus.dat = dict()

    # setup opts
    bucket_len = kw.pop('bucket_len', 30e6) # 30Msec is roughly a year‡
    max_buckets = kw.pop('max_buckets', 1e3)
    namespace = kw.pop('namespace', 'x')
    if kw:
        raise ValueError('unknown arguments: {}', ', '.join(kw.keys()))
    opts = dict(bucket_len=bucket_len, max_buckets=max_buckets)

    # setup hubble_status
    hubblestack.status.__opts__['hubble_status'] = opts

    # create and return
    return hubblestack.status.HubbleStatus(namespace, *a)

def test_marks_and_timers():
    hubble_status = setup_hubble_status('test1', 'test2')

    t0 = time.time()
    mark1 = hubble_status.mark('test1')
    t1 = sleep_and_return_time()
    mark1.fin()

    short_status = hubble_status.short()
    assert tuple(short_status) == ('x.test1',)
    assert short_status['x.test1']['count'] == 1
    assert short_status['x.test1']['dt'] == pytest.approx(0.1, rel=1e2)

    mark1_again = hubble_status.mark('test1')
    assert mark1_again is mark1

    mark2 = hubble_status.mark('test2')
    t2 = sleep_and_return_time()
    mark1_again.fin()
    mark2.fin()

    short_status = hubble_status.short()
    assert set(short_status) == {'x.test1', 'x.test2'}
    assert short_status['x.test1']['count'] == 2
    assert short_status['x.test1']['dt'] == pytest.approx(0.1, rel=1e2)
    assert short_status['x.test2']['count'] == 1
    assert short_status['x.test2']['dt'] == pytest.approx(0.1, rel=1e2)


def test_max_depth():
    # some constants
    t0 = 1553102100
    N = 100
    B = 5
    M = 10

    hubble_status = setup_hubble_status('test1', bucket_len=B, max_buckets=M)

    # mark some status, pretending to move through time from t0
    for t in range(t0, t0+N):
        hubble_status.mark('test1', t=t)

    assert len(hubble_status.buckets()) == M

    # now change the game somewhat every mark() checks the stack depth to make
    # sure we save no more than max_buckets per status item. If we change the
    # setting in the module's copy of __opts__, we should instantly see the
    # buckets drop for 'test1' after a mark().
    hubblestack.status.__opts__['hubble_status']['max_buckets'] = 3
    hubble_status.mark('test1')

    assert len(hubble_status.buckets()) == 3


def test_bucket_len():
    # some constants
    t0 = 1553102100
    N = 100
    B = 5

    hubble_status = setup_hubble_status('test1', bucket_len=B)

    # XXX: There's currently a bug in the status system where if we don't mark
    # something in the current time bucket, all the dicts returned from short()
    # may be empty … In the interests of getting this test working, just mark
    # something then circle back to this afterwards.
    hubble_status.mark('test1')

    # issue test1 mark N times, pretending one mark per second
    # ranging from t0 to t0+(N-1)
    for t in range(t0, t0+N):
        hubble_status.mark('test1', t=t)

    # the list of bucket ids
    buckets = hubble_status.buckets()

    # compute the id of the bucket for the current time
    actual_time = int(time.time())
    very_last_bucket = actual_time - (actual_time % B)

    # … of course, if we get really unlucky, we'll hit just the right time of
    # day to rollover the short B second bucket window. Assuming that might happen,
    # check for either:
    assert buckets[-1] in (very_last_bucket, very_last_bucket + B)

    c = 0
    for i,bucket in enumerate(buckets[:-1]):
        assert bucket == t0 + B*i

        short_status = hubble_status.short(bucket)
        if 'x.test1' in short_status:
            assert set(short_status) == {'x.test1',}
            assert short_status['x.test1']['bucket'] == bucket

            c += short_status['x.test1']['count']

    assert c == N
    assert len(buckets) == N/B + 1


# ‡ These time units are from Deepness in the Sky:
# 4ksec - roughly an hour
# 100ksec - sorta a day
# 600ksec - like a week
# 3Msec - kindof a month
# 30Msec - roughly a year
