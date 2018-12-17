from __future__ import absolute_import

import json
import os
import sys
import pytest

myPath = os.path.abspath(os.getcwd())
sys.path.insert(0, myPath)
import hubblestack.extmods.fdg.readfile


class TestReadfile():

    @pytest.fixture(scope="session")
    def json_file(self, tmpdir_factory):
        '''
        Helping function that creates a ``.json`` sample file to test against
        '''
        sample_json = {"id": "file",
                       "value": {"key1": "value1",
                                 "key2": {"key3": "value2"}},
                       "menuitem": ["item1", "item2", "item3"]}
        json_file = tmpdir_factory.mktemp("data").join("json_file.json")
        json_file.write(str(json.dumps(sample_json)))

        return str(json_file)

    def test_json_InvalidPath_EmptyReturn(self):
        '''
        Test that given an invalid path, the json function returns False status
        and an empty return value
        '''
        expected_status, expected_ret = False, None
        status, ret = hubblestack.extmods.fdg.readfile.json('/invalid/path')
        assert expected_status == status
        assert expected_ret == ret

    def test_json_SingleSubkey_ReturnsValue(self, json_file):
        '''
        Test that given a single subkey argument, the function extracts the appropriated value
        '''
        expected_status, expected_ret = True, "file"
        status, ret = hubblestack.extmods.fdg.readfile.json(json_file, subkey='id')
        assert expected_status == status
        assert expected_ret == ret

    def test_json_InvalidSingleSubkey_EmptyReturn(self, json_file):
        '''
        Test that given an invalid single subkey argument,
        the function returns False status and empty value
        '''
        expected_status, expected_ret = False, None
        status, ret = hubblestack.extmods.fdg.readfile.json(json_file, subkey='invalid_key')
        assert expected_status == status
        assert expected_ret == ret

    def test_json_MultipleSubkeys_ReturnsValue(self, json_file):
        '''
        Test that given multiple subkeys, separated by a valid separator,
        the function returns the appropriate value
        '''
        expected_status, expected_ret = True, "value2"
        status, ret = hubblestack.extmods.fdg.readfile.json(
                json_file, subkey='value,key2,key3', sep=',')
        assert expected_status == status
        assert expected_ret == ret

    def test_json_InvalidSep_EmptyReturn(self, json_file):
        '''
        Test that given multiple subkeys separated by an invalid ``sep``,
        the function returns a False status and None value
        '''
        expected_status, expected_ret = False, None
        status, ret = hubblestack.extmods.fdg.readfile.json(
                json_file, subkey='value,key2,key3', sep='/')
        assert expected_status == status
        assert expected_ret == ret

    def test_json_IndexSubkey_ReturnsValue(self, json_file):
        '''
        Test that given an index as subkey, the function returns the appropriate value
        '''
        expected_status, expected_ret = True, "item2"
        status, ret = hubblestack.extmods.fdg.readfile.json(
                json_file, subkey='menuitem,1', sep=',')
        assert expected_status == status
        assert expected_ret == ret

    def test_json_InvalidIndexSubkey_EmptyReturn(self, json_file):
        '''
        Test that given an index as subkey that exceeds the list length,
        the function returns False status and None value
        '''
        expected_status, expected_ret = False, None
        status, ret = hubblestack.extmods.fdg.readfile.json(json_file, subkey='menuitem,15', sep=',')
        assert expected_status == status
        assert expected_ret == ret

    def test_json_EmptyFile_EmptyReturn(self, json_file):
        '''
        Test that given an empty json file, the function returns False status and None value
        '''
        with open(json_file, 'r+') as invalid_file:
            invalid_file.truncate(0)
        expected_status, expected_ret = False, None
        status, ret = hubblestack.extmods.fdg.readfile.json(json_file, subkey='id')
        assert expected_status == status
        assert expected_ret == ret

    def test_json_InvalidJsonFile_EmptyReturn(self, json_file):
        '''
        Test that given an invalid json file, the function returns False status and None value
        '''
        with open(json_file, 'w+') as invalid_file:
            invalid_file.write("invalijson")
        expected_status, expected_ret = False, None
        status, ret = hubblestack.extmods.fdg.readfile.json(json_file, subkey='id')
        assert expected_status == status
        assert expected_ret == ret
