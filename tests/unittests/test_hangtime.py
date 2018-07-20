
from hubblestack.hangtime import HangTime, hangtime_wrapper
import time
import signal
import pytest

def test_basic():
    bang = set()

    assert signal.getsignal(signal.SIGALRM) == signal.SIG_DFL

    try:
        with HangTime(timeout=1, tag=10):
            time.sleep(0.5)
    except HangTime as ht:
        bang.add(ht.tag)

    # if we forget to clear the remaining timer
    # we'll alarmclock sys.exit here
    # not a real test, but the tests won't pass if we sys.exit
    time.sleep(1)

    assert bang == set()
    assert signal.getsignal(signal.SIGALRM) == signal.SIG_DFL

    try:
        with HangTime(timeout=1, tag=13):
            time.sleep(1.5)
    except HangTime as ht:
        bang.add(ht.tag)

    assert bang == {13,}
    assert signal.getsignal(signal.SIGALRM) == signal.SIG_DFL

def test_inner_timeout():
    bang = set()

    assert signal.getsignal(signal.SIGALRM) == signal.SIG_DFL

    try:
        with HangTime(timeout=2, tag=10):
            with HangTime(timeout=1, tag=11):
                time.sleep(1.5)
    except HangTime as ht:
        bang.add(ht.tag)

    try:
        with HangTime(timeout=2, tag=12):
            try:
                with HangTime(timeout=1, tag=13):
                    time.sleep(1.5)
            except HangTime as ht:
                bang.add(ht.tag)
    except HangTime as ht:
        bang.add(ht.tag)

    assert bang == {11,13}
    assert signal.getsignal(signal.SIGALRM) == signal.SIG_DFL

def test_outer_timeout():
    bang = set()

    assert signal.getsignal(signal.SIGALRM) == signal.SIG_DFL

    try:
        with HangTime(timeout=1, tag='this-is-tag'):
            with HangTime(timeout=0.7, tag=11):
                time.sleep(0.2)
            time.sleep(1)
    except HangTime as ht:
        bang.add(ht.tag)

    try:
        with HangTime(timeout=1, tag=12):
            try:
                with HangTime(timeout=0.7, tag=13):
                    time.sleep(0.2)
            except HangTime as ht:
                bang.add(ht.tag)
            time.sleep(1)
    except HangTime as ht:
        bang.add(ht.tag)

    assert bang == {'this-is-tag', 12}
    assert signal.getsignal(signal.SIGALRM) == signal.SIG_DFL

def test_wrapper():
    @hangtime_wrapper(timeout=1)
    def blah(a):
        try:
            time.sleep(a)
        except:
            return "timed out"
        return "did not time out"

    assert blah(0.5) == "did not time out"
    assert blah(1.5) == "timed out"


# Salt ends up catching the HangTime exceptions during the grains refreshes.  Any
# attempt to catch them with try/except with wrappers in hubblestack.daemon will
# fail.  This presents two problems:
#
# 1. The grains will appear to die due to a HangTime and will be missing after
#    the refresh
#
# 2. After the HangTime presents an exception, any other hanging grains will
#    continue to hang
#
def test_fake_refresh_grains():
    t1 = time.time()

    @hangtime_wrapper(timeout=0.25, repeats=True)
    def fake_refresh_grains(a,b):
        x = 0
        for i in range(a):
            try:
                time.sleep(b)
            except:
                x += 1
        return x

    x = fake_refresh_grains(5, 2) # five two second sleeps
    target_time = 0.25 * 5 # but each should time out after 0.25s

    t2 = time.time()
    dt = t2-t1
    assert x == 5
    assert dt == pytest.approx(target_time, rel=1e-1)
