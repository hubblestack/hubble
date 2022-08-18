#!/usr/bin/env python
# coding: utf-8

import os
import pytest
from unittest.mock import patch, mock_open



from hubblestack.filter.filter_chain import FilterChain

def test_load():
    with patch("builtins.open", mock_open(read_data="""
default:
  sequence:
    label: "seq"
    prefix: "seq_"
""")):
        fc = FilterChain("bob", "default")
    assert fc.filter_config["sequence"] != None
    assert fc.chain[0].filter_name == "sequence"
    assert fc.chain[0].getLabel() == "seq"

    msg = fc.chain[0].filter({"bob": "alice"})
    assert msg["seq"] == "1"


def test_pad():
    with patch("builtins.open", mock_open(read_data="""
default:
  sequence:
    label: "seq"
    prefix: "seq_"
    padding: 5
""")):
        fc = FilterChain("bob", "default")
    assert fc.filter_config["sequence"] != None
    assert fc.chain[0].filter_name == "sequence"
    assert fc.chain[0].getLabel() == "seq"

    msg = fc.chain[0].filter({"bob": "alice"})
    assert msg["seq"] == "00001"







