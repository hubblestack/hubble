
from hubblestack.hangtime import HangTime, hangtime_wrapper
import time
import signal

def test_basic():
    bang = set()

    assert signal.getsignal(signal.SIGALRM) == signal.SIG_DFL

    try:
        with HangTime(timeout=1, id=10):
            time.sleep(0.5)
    except HangTime as ht:
        bang.add(ht.id)

    assert bang == set()
    assert signal.getsignal(signal.SIGALRM) == signal.SIG_DFL

    try:
        with HangTime(timeout=1, id=13):
            time.sleep(1.5)
    except HangTime as ht:
        bang.add(ht.id)

    assert bang == {13,}
    assert signal.getsignal(signal.SIGALRM) == signal.SIG_DFL

def test_inner_timeout():
    bang = set()

    assert signal.getsignal(signal.SIGALRM) == signal.SIG_DFL

    try:
        with HangTime(timeout=2, id=10):
            with HangTime(timeout=1, id=11):
                time.sleep(1.5)
    except HangTime as ht:
        bang.add(ht.id)

    try:
        with HangTime(timeout=2, id=12):
            try:
                with HangTime(timeout=1, id=13):
                    time.sleep(1.5)
            except HangTime as ht:
                bang.add(ht.id)
    except HangTime as ht:
        bang.add(ht.id)

    assert bang == {11,13}
    assert signal.getsignal(signal.SIGALRM) == signal.SIG_DFL

def test_outer_timeout():
    bang = set()

    assert signal.getsignal(signal.SIGALRM) == signal.SIG_DFL

    try:
        with HangTime(timeout=1, id=10):
            with HangTime(timeout=0.7, id=11):
                time.sleep(0.2)
            time.sleep(1)
    except HangTime as ht:
        bang.add(ht.id)

    try:
        with HangTime(timeout=1, id=12):
            try:
                with HangTime(timeout=0.7, id=13):
                    time.sleep(0.2)
            except HangTime as ht:
                bang.add(ht.id)
            time.sleep(1)
    except HangTime as ht:
        bang.add(ht.id)

    assert bang == {10,12}
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
