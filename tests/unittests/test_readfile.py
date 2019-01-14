from __future__ import absolute_import

import json
import os
import sys
import yaml
import pytest

myPath = os.path.abspath(os.getcwd())
sys.path.insert(0, myPath)
import hubblestack.extmods.fdg.readfile


class TestReadfile():

    def generate_data(self):
        '''
        Helping function to generate dict data to populate json/yaml files
        '''
        sample_data = {"id": "file",
                       "value": {"key1": "value1",
                                 "key2": {"key3": "value2"}},
                       "menuitem": ["item1", "item2", "item3"]}
        return sample_data
 
    @pytest.fixture(scope="session")
    def json_file(self, tmpdir_factory):
        '''
        Helping function that creates a ``.json`` sample file to test against
        '''
        sample_json = self.generate_data() 
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


    @pytest.fixture(scope="session")
    def yaml_file(self, tmpdir_factory):
        '''
        Helping function that creates a ``.yaml`` sample file to test against
        '''
        sample_yaml= self.generate_data()
        yaml_file = tmpdir_factory.mktemp("data").join("yaml_file.yaml")
        yaml_file.write(str(yaml.dump(sample_yaml)))

        return str(yaml_file)

    def test_yaml_InvalidPath_EmptyReturn(self):
        '''
        Test that given an invalid path, the yaml function returns False status
        and an empty return value
        '''
        expected_status, expected_ret = False, None
        status, ret = hubblestack.extmods.fdg.readfile.yaml('/invalid/path')
        assert expected_status == status
        assert expected_ret == ret

    def test_yaml_SingleSubkey_ReturnsValue(self, yaml_file):
        '''
        Test that given a single subkey argument, the function extracts the appropriated value
        '''
        expected_status, expected_ret = True, "file"
        status, ret = hubblestack.extmods.fdg.readfile.yaml(yaml_file, subkey='id')
        assert expected_status == status
        assert expected_ret == ret

    def test_yaml_InvalidSingleSubkey_EmptyReturn(self, yaml_file):
        '''
        Test that given an invalid single subkey argument,
        the function returns False status and empty value
        '''
        expected_status, expected_ret = False, None
        status, ret = hubblestack.extmods.fdg.readfile.yaml(yaml_file, subkey='invalid_key')
        assert expected_status == status
        assert expected_ret == ret

    def test_yaml_MultipleSubkeys_ReturnsValue(self, yaml_file):
        '''
        Test that given multiple subkeys, separated by a valid separator,
        the function returns the appropriate value
        '''
        expected_status, expected_ret = True, "value2"
        status, ret = hubblestack.extmods.fdg.readfile.yaml(
                yaml_file, subkey='value,key2,key3', sep=',')
        assert expected_status == status
        assert expected_ret == ret

    def test_yaml_InvalidSep_EmptyReturn(self, yaml_file):
        '''
        Test that given multiple subkeys separated by an invalid ``sep``,
        the function returns a False status and None value
        '''
        expected_status, expected_ret = False, None
        status, ret = hubblestack.extmods.fdg.readfile.yaml(
                yaml_file, subkey='value,key2,key3', sep='/')
        assert expected_status == status
        assert expected_ret == ret

    def test_yaml_IndexSubkey_ReturnsValue(self, yaml_file):
        '''
        Test that given an index as subkey, the function returns the appropriate value
        '''
        expected_status, expected_ret = True, "item2"
        status, ret = hubblestack.extmods.fdg.readfile.yaml(
                yaml_file, subkey='menuitem,1', sep=',')
        assert expected_status == status
        assert expected_ret == ret

    def test_yaml_InvalidIndexSubkey_EmptyReturn(self, yaml_file):
        '''
        Test that given an index as subkey that exceeds the list length,
        the function returns False status and None value
        '''
        expected_status, expected_ret = False, None
        status, ret = hubblestack.extmods.fdg.readfile.yaml(yaml_file, subkey='menuitem,15', sep=',')
        assert expected_status == status
        assert expected_ret == ret

    def test_yaml_EmptyFile_EmptyReturn(self, yaml_file):
        '''
        Test that given an empty yaml file, the function returns False status and None value
        '''
        with open(yaml_file, 'r+') as invalid_file:
            invalid_file.truncate(0)
        expected_status, expected_ret = False, None
        status, ret = hubblestack.extmods.fdg.readfile.yaml(yaml_file, subkey='id')
        assert expected_status == status
        assert expected_ret == ret

    def test_yaml_InvalidJsonFile_EmptyReturn(self, yaml_file):
        '''
        Test that given an invalid yaml file, the function returns False status and None value
        '''
        with open(yaml_file, 'w+') as invalid_file:
            invalid_file.write("invalidyaml")
        expected_status, expected_ret = False, None
        status, ret = hubblestack.extmods.fdg.readfile.yaml(yaml_file, subkey='id')
        assert expected_status == status
        assert expected_ret == ret

    def test_checkPattern_EmptyPatternEmptyIgnore_ReturnTrue(self):
        expected_ret = True
        ret = hubblestack.extmods.fdg.readfile._check_pattern('Sample text', None, None)
        assert expected_ret == ret

    def test_checkPattern_EmptyPatternValidIgnore_ReturnFalse(self):
        expected_ret = False
        ret = hubblestack.extmods.fdg.readfile._check_pattern('invalid text', None, 'invalid.*')
        assert expected_ret == ret

    def test_checkPattern_EmptyPatternInvalidIgnore_ReturnTrue(self):
        expected_ret = True
        ret = hubblestack.extmods.fdg.readfile._check_pattern('Sample text', None, 'invalid')
        assert expected_ret == ret

    def test_checkPattern_ValidPatternValidIgnore_ReturnFalse(self):
        expected_ret = False
        line = 'valid and invalid text'
        ret = hubblestack.extmods.fdg.readfile._check_pattern(line, 'valid.*', '.*invalid.*')
        assert expected_ret == ret

    def test_checkPattern_ValidPatternInvalidIgnore_ReturnTrue(self):
        expected_ret = True
        line = 'valid text'
        ret = hubblestack.extmods.fdg.readfile._check_pattern(line, 'valid', 'invalid')
        assert expected_ret == ret

    def test_checkPattern_ValidPatternEmptyIgnore_ReturnTrue(self):
        expected_ret = True
        line = 'valid text'
        ret = hubblestack.extmods.fdg.readfile._check_pattern(line, 'valid', None)
        assert expected_ret == ret

    def test_checkPattern_InvalidPatternInvalidIgnore_ReturnFalse(self):
        expected_ret = False
        line = 'Line with invalid text'
        ret = hubblestack.extmods.fdg.readfile._check_pattern(line, 'bad pattern', 'bad ignore')
        assert expected_ret == ret

    def test_checkPattern_InvalidPatternValidIgnore_ReturnFalse(self):
        expected_ret = False
        line = 'Line with invalid text'
        ret = hubblestack.extmods.fdg.readfile._check_pattern(line, 'bad pattern', '.*invalid.*')
        assert expected_ret == ret

    def test_checkPattern_InvalidPatternEmptyIgnore_ReturnFalse(self):
        expected_ret = False
        line = 'Line with invalid text'
        ret = hubblestack.extmods.fdg.readfile._check_pattern(line, 'bad pattern', None)
        assert expected_ret == ret

    def test_processLine_ValidArguments_ReturnDict(self):
        expected_key, expected_val= 'APP_ATTRIBUTES', {'cluster_role': 'controol', 'provider': 'aws', 'zone': '3'}
        line = "APP_ATTRIBUTES=cluster_role:controol;zone:3;provider:aws" 
        key, val = hubblestack.extmods.fdg.readfile._process_line(line, dictsep='=', valsep=';', subsep=':')
        assert expected_key == key
        assert expected_val == val

    def test_processLine_EmptyDictsep_ReturnLine(self):
        line = "line of text"
        ret, none = hubblestack.extmods.fdg.readfile._process_line(line, None, None, None)
        assert ret == line
        assert none is None

    def test_processLine_ValidDictsepValsepEmptySubsep_ReturnList(self):
        expected_key, expected_val = 'key0', ['key1', 'key2', 'val']
        line = "key0:key1;key2;val"
        key, val = hubblestack.extmods.fdg.readfile._process_line(line, ':', ';', None)
        assert expected_key == key
        assert expected_val == val

    def test_processLine_ValidDictsepInvalidValsep_ReturnList(self):
        expected_key, expected_val = 'key0', ['key1;key2;val']
        line = "key0:key1;key2;val"
        key, val = hubblestack.extmods.fdg.readfile._process_line(line, ':', '-', None)
        assert expected_key == key
        assert expected_val == val

    def test_processLine_ValidDictsepValsepInvalidSubsep_ReturnDict(self):
        expected_key, expected_val = 'APP_ATTRIBUTES', {'cluster_role:controol': None, 'provider:aws': None, 
                                                        'zone:3': None}
        line = "APP_ATTRIBUTES=cluster_role:controol;zone:3;provider:aws"
        key, val = hubblestack.extmods.fdg.readfile._process_line(line, '=', ';', '-')
        assert expected_key == key
        assert expected_val == val

    def test_processLine_ValidDictsepSubsepInvalidValsep_ReturnDict(self):
        expected_key, expected_val = 'key0', {'key1;val': 'val2'}
        line = "key0:key1;val-val2"
        key, val = hubblestack.extmods.fdg.readfile._process_line(line, ':', '.', '-')
        assert expected_key == key
        assert expected_val == val

    def test_processLine_InvalidDictsep_ReturnLine(self):
        line = "key0:key1;val-val2"
        ret, none = hubblestack.extmods.fdg.readfile._process_line(line, '?', '.', '-')
        assert ret == line
        assert none is None
