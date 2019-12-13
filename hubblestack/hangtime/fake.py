# -*- coding: utf-8 -*-
"""
Defanged fake timer setup that pretends to do all the things HangTime would do
(by arguments); but actually does nothing at all.

The decorator in particular doesn't even attempt to load the HangTime wrapper
around code.
"""

class HangTime(object):
    def __init__(self, msg="hang timeout detected", timeout=300, tag=None, repeats=False, decay=1.0):
        pass

    def __repr__(self):
        return "FakeHT({:0.2f}s, tag={})".format(self.timeout, self.tag)

    def restore(self, ended=False):
        pass

    def fire_timer(self, *sig_param):
        pass

    def __enter__(self):
        return self

    def __exit__(self, e_type, e_obj, e_tb):
        pass


def hangtime_wrapper(**ht_kw):
    def _decorator(actual):
        return actual
    return _decorator
