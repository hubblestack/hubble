#!/usr/bin/env python
# coding: utf-8

import os
from hubblestack.exceptions import CommandExecutionError
import pytest
from unittest.mock import patch, mock_open


import hubblestack.filter.filter_chain as filter_chain
import hubblestack.modules.cp


filter_chain.__opts__ = {}
filter_chain.__context__ = {}


def test_load():

    topfile = 'tests/unittests/resources/filter_chain_load.yaml'

    def cp_cache_file(_):
        ''' pretend salt[cp.cache_file] '''
        return 'tests/unittests/resources/filter_chain_load.yaml'

    filter_chain.__mods__ = {'cp.cache_file': cp_cache_file}

    fc = filter_chain.FilterChain("bob", "default")
    assert fc.config["sequence_id"] != None
    assert fc.chain[0].name == "sequence_id"
    assert fc.chain[0].get_label() == "seq"

    msg = fc.chain[0].filter({"bob": "alice"})
    assert msg["seq"] == "1"


def test_command_exception_one():
    def cp_cache_file(_):
        ''' pretend salt[cp.cache_file] '''
        return 'tests/unittests/resources/filter_chain_ce_01.yaml'

    filter_chain.__mods__ = {'cp.cache_file': cp_cache_file}
    try:
        fc = filter_chain.FilterChain("bob", "default")
    except CommandExecutionError as e:
        ok = True
    else:
        assert 1 == 0

def test_command_exception_two():
    def cp_cache_file(_):
        ''' pretend salt[cp.cache_file] '''
        return 'tests/unittests/resources/filter_chain_ce_02.yaml'

    filter_chain.__mods__ = {'cp.cache_file': cp_cache_file}
    try:
        fc = filter_chain.FilterChain("bob", "default")
    except CommandExecutionError as e:
        ok = True
    else:
        assert 1 == 0


def test_pad():
    def cp_cache_file(_):
        ''' pretend salt[cp.cache_file] '''
        return 'tests/unittests/resources/filter_chain.yaml'

    filter_chain.__mods__ = {'cp.cache_file': cp_cache_file}
    fc = filter_chain.FilterChain("bob", "default")
    assert fc.config["sequence_id"] != None
    assert fc.chain[0].name == "sequence_id"
    assert fc.chain[0].get_label() == "seq"

    msg = fc.chain[0].filter({"bob": "alice"})
    assert msg["seq"] == "00001"













