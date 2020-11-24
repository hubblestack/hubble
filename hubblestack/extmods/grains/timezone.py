# -*- coding: utf-8 -*-
"""
Custom grains for timezone and numerical hours offset
"""


import time


def timezone():
    """
    Generate the timezone code name of the host
    """

    return {'timezone_short': time.strftime('%Z')}


def hours_offset():
    """
    Generate the numerical hour offset for the timezone
    relative to UTC.
    """

    return {'timezone_hours_offset': time.strftime('%z')}
