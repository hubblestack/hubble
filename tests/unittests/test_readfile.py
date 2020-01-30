

import json
import os
import yaml
import pytest

import hubblestack.extmods.fdg.readfile


class TestReadfile():
    """
    Class used to test the functions in ``readfile.py``
    """

    def generate_data(self):
        """
        Helping function to generate dict data to populate json/yaml files
        """
        sample_data = {"id": "file",
                       "value": {"key1": "value1",
                                 "key2": {"key3": "value2"}},
                       "menuitem": ["item1", "item2", "item3"]}
        return sample_data

    @pytest.fixture(scope="session")
    def json_file(self, tmpdir_factory):
        """
        Helping function that creates a ``.json`` sample file to test against
        """
        sample_json = self.generate_data()
        json_file = tmpdir_factory.mktemp("data").join("json_file.json")

        json_file.write(str(json.dumps(sample_json)))

        return str(json_file)

    def test_json_InvalidPath_EmptyReturn(self):
        """
        Test that given an invalid path, the json function returns False status
        and None value
        """
        expected_status, expected_ret = False, None
        status, ret = hubblestack.extmods.fdg.readfile.json('/invalid/path')
        assert expected_status == status
        assert expected_ret == ret

    def test_json_SingleSubkey_ReturnsValue(self, json_file):
        """
        Test that given a single subkey argument, the function extracts the correct value
        """
        expected_status, expected_ret = True, "file"
        status, ret = hubblestack.extmods.fdg.readfile.json(json_file, subkey='id')
        assert expected_status == status
        assert expected_ret == ret

    def test_json_InvalidSingleSubkey_EmptyReturn(self, json_file):
        """
        Test that given an invalid single subkey argument,
        the function returns False status and None value
        """
        expected_status, expected_ret = False, None
        status, ret = hubblestack.extmods.fdg.readfile.json(json_file, subkey='invalid_key')
        assert expected_status == status
        assert expected_ret == ret

    def test_json_MultipleSubkeys_ReturnsValue(self, json_file):
        """
        Test that given multiple subkeys, separated by a valid separator ``sep``,
        the function returns the correct value
        """
        expected_status, expected_ret = True, "value2"
        status, ret = hubblestack.extmods.fdg.readfile.json(
            json_file, subkey='value,key2,key3', sep=',')
        assert expected_status == status
        assert expected_ret == ret

    def test_json_InvalidSep_EmptyReturn(self, json_file):
        """
        Test that given multiple subkeys separated by an invalid separator``sep``,
        the function returns False status and None value
        """
        expected_status, expected_ret = False, None
        status, ret = hubblestack.extmods.fdg.readfile.json(
            json_file, subkey='value,key2,key3', sep='/')
        assert expected_status == status
        assert expected_ret == ret

    def test_json_IndexSubkey_ReturnsValue(self, json_file):
        """
        Test that given an index as subkey, the function returns the correct value
        """
        expected_status, expected_ret = True, "item2"
        status, ret = hubblestack.extmods.fdg.readfile.json(
            json_file, subkey='menuitem,1', sep=',')
        assert expected_status == status
        assert expected_ret == ret

    def test_json_InvalidIndexSubkey_EmptyReturn(self, json_file):
        """
        Test that given an index as subkey that exceeds the list length,
        the function returns False status and None value
        """
        expected_status, expected_ret = False, None
        status, ret = hubblestack.extmods.fdg.readfile.json(
            json_file, subkey='menuitem,15', sep=',')
        assert expected_status == status
        assert expected_ret == ret

    def test_json_EmptyFile_EmptyReturn(self, json_file):
        """
        Test that given an empty json file, the function returns False status and None value
        """
        with open(json_file, 'r+') as invalid_file:
            invalid_file.truncate(0)
        expected_status, expected_ret = False, None
        status, ret = hubblestack.extmods.fdg.readfile.json(json_file, subkey='id')
        assert expected_status == status
        assert expected_ret == ret


    def test_json_InvalidJsonFile_EmptyReturn(self, json_file):
        """
        Test that given an invalid json file, the function returns False status and None value
        """
        with open(json_file, 'w+') as invalid_file:
            invalid_file.write("InvalidJson")
        expected_status, expected_ret = False, None
        status, ret = hubblestack.extmods.fdg.readfile.json(json_file, subkey='id')
        assert expected_status == status
        assert expected_ret == ret


    @pytest.fixture(scope="session")
    def yaml_file(self, tmpdir_factory):
        """
        Helping function that creates a ``.yaml`` sample file to test against
        """
        sample_yaml = self.generate_data()
        yaml_file = tmpdir_factory.mktemp("data").join("yaml_file.yaml")
        yaml_file.write(str(yaml.dump(sample_yaml)))

        return str(yaml_file)

    def test_yaml_InvalidPath_EmptyReturn(self):
        """
        Test that given an invalid path, the yaml function returns False status
        and an empty return value
        """
        expected_status, expected_ret = False, None
        status, ret = hubblestack.extmods.fdg.readfile.yaml('/invalid/path')
        assert expected_status == status
        assert expected_ret == ret

    def test_yaml_SingleSubkey_ReturnsValue(self, yaml_file):
        """
        Test that given a single subkey argument, the function extracts the appropriated value
        """
        expected_status, expected_ret = True, "file"
        status, ret = hubblestack.extmods.fdg.readfile.yaml(yaml_file, subkey='id')
        assert expected_status == status
        assert expected_ret == ret

    def test_yaml_InvalidSingleSubkey_EmptyReturn(self, yaml_file):
        """
        Test that given an invalid single subkey argument,
        the function returns False status and empty value
        """
        expected_status, expected_ret = False, None
        status, ret = hubblestack.extmods.fdg.readfile.yaml(yaml_file, subkey='invalid_key')
        assert expected_status == status
        assert expected_ret == ret

    def test_yaml_MultipleSubkeys_ReturnsValue(self, yaml_file):
        """
        Test that given multiple subkeys, separated by a valid separator,
        the function returns the appropriate value
        """
        expected_status, expected_ret = True, "value2"
        status, ret = hubblestack.extmods.fdg.readfile.yaml(
            yaml_file, subkey='value,key2,key3', sep=',')
        assert expected_status == status
        assert expected_ret == ret

    def test_yaml_InvalidSep_EmptyReturn(self, yaml_file):
        """
        Test that given multiple subkeys separated by an invalid ``sep``,
        the function returns a False status and None value
        """
        expected_status, expected_ret = False, None
        status, ret = hubblestack.extmods.fdg.readfile.yaml(
            yaml_file, subkey='value,key2,key3', sep='/')
        assert expected_status == status
        assert expected_ret == ret

    def test_yaml_IndexSubkey_ReturnsValue(self, yaml_file):
        """
        Test that given an index as subkey, the function returns the appropriate value
        """
        expected_status, expected_ret = True, "item2"
        status, ret = hubblestack.extmods.fdg.readfile.yaml(
            yaml_file, subkey='menuitem,1', sep=',')
        assert expected_status == status
        assert expected_ret == ret

    def test_yaml_InvalidIndexSubkey_EmptyReturn(self, yaml_file):
        """
        Test that given an index as subkey that exceeds the list length,
        the function returns False status and None value
        """
        expected_status, expected_ret = False, None
        status, ret = hubblestack.extmods.fdg.readfile.yaml(
            yaml_file, subkey='menuitem,15', sep=',')
        assert expected_status == status
        assert expected_ret == ret

    def test_yaml_EmptyFile_EmptyReturn(self, yaml_file):
        """
        Test that given an empty yaml file, the function returns False status and None value
        """
        with open(yaml_file, 'r+') as invalid_file:
            invalid_file.truncate(0)
        expected_status, expected_ret = False, None
        status, ret = hubblestack.extmods.fdg.readfile.yaml(yaml_file, subkey='id')
        assert expected_status == status
        assert expected_ret == ret

    def _test_yaml_InvalidJsonFile_EmptyReturn(self, yaml_file):
        """
        Test that given an invalid yaml file, the function returns False status and None value
        """
        with open(yaml_file, 'w+') as invalid_file:
            invalid_file.write("invalidyaml")
        expected_status, expected_ret = False, None
        status, ret = hubblestack.extmods.fdg.readfile.yaml(yaml_file, subkey='id')
        assert expected_status == status
        assert expected_ret == ret

    def test_checkPattern_EmptyPatternEmptyIgnore_ReturnTrue(self):
        """
        Test that given an empty ``pattern`` and empty ``ignore_pattern``, the function returns True
        """
        expected_ret = True
        ret = hubblestack.extmods.fdg.readfile._check_pattern('Sample text', None, None)
        assert expected_ret == ret

    def test_checkPattern_EmptyPatternValidIgnore_ReturnFalse(self):
        """
        Test that given an empty ``pattern`` and a valid ``ignore_pattern``,
        the function returns False
        """
        expected_ret = False
        ret = hubblestack.extmods.fdg.readfile._check_pattern('invalid text', None, 'invalid.*')
        assert expected_ret == ret

    def test_checkPattern_EmptyPatternInvalidIgnore_ReturnTrue(self):
        """
        Test that given an empty ``pattern`` and an invalid ``ignore_pattern``,
        the function returns True
        """
        expected_ret = True
        ret = hubblestack.extmods.fdg.readfile._check_pattern('Sample text', None, 'invalid')
        assert expected_ret == ret

    def test_checkPattern_ValidPatternValidIgnore_ReturnFalse(self):
        """
        Test that given a valid``pattern`` and a valid ``ignore_pattern``,
        the function returns False
        """
        expected_ret = False
        line = 'valid and invalid text'
        ret = hubblestack.extmods.fdg.readfile._check_pattern(line, 'valid.*', '.*invalid.*')
        assert expected_ret == ret

    def test_checkPattern_ValidPatternInvalidIgnore_ReturnTrue(self):
        """
        Test that given a valid``pattern`` and an invalid ``ignore_pattern``,
        the function returns True
        """
        expected_ret = True
        line = 'valid text'
        ret = hubblestack.extmods.fdg.readfile._check_pattern(line, 'valid', 'invalid')
        assert expected_ret == ret

    def test_checkPattern_ValidPatternEmptyIgnore_ReturnTrue(self):
        """
        Test that given a valid``pattern`` and an empty ``ignore_pattern``,
        the function returns True
        """
        expected_ret = True
        line = 'valid text'
        ret = hubblestack.extmods.fdg.readfile._check_pattern(line, 'valid', None)
        assert expected_ret == ret

    def test_checkPattern_InvalidPatternInvalidIgnore_ReturnFalse(self):
        """
        Test that given an invalid``pattern`` and an invalid ``ignore_pattern``,
        the function returns False
        """
        expected_ret = False
        line = 'Line with invalid text'
        ret = hubblestack.extmods.fdg.readfile._check_pattern(line, 'bad pattern', 'bad ignore')
        assert expected_ret == ret

    def test_checkPattern_InvalidPatternValidIgnore_ReturnFalse(self):
        """
        Test that given an invalid``pattern`` and a valid ``ignore_pattern``,
        the function returns False
        """
        expected_ret = False
        line = 'Line with invalid text'
        ret = hubblestack.extmods.fdg.readfile._check_pattern(line, 'bad pattern', '.*invalid.*')
        assert expected_ret == ret

    def test_checkPattern_InvalidPatternEmptyIgnore_ReturnFalse(self):
        """
        Test that given an invalid``pattern`` and an empty ``ignore_pattern``,
        the function returns False
        """
        expected_ret = False
        line = 'Line with invalid text'
        ret = hubblestack.extmods.fdg.readfile._check_pattern(line, 'bad pattern', None)
        assert expected_ret == ret

    def test_processLine_ValidArguments_ReturnDict(self):
        """
        Test that given valid arguments, the function returns a valid dictionary
        """
        expected_key, expected_val = 'APP_ATTRIBUTES', {'cluster_role': 'controol',
                                                        'provider': 'aws',
                                                        'zone': '3'}
        line = "APP_ATTRIBUTES=cluster_role:controol;zone:3;provider:aws"
        key, val = hubblestack.extmods.fdg.readfile._process_line(
            line, dictsep='=', valsep=';', subsep=':')
        assert expected_key == key
        assert expected_val == val

    def test_processLine_ValidArgumentsDuplicateKeys_ReturnDict(self):
        """
        Test that given valid arguments, if the input data contains duplicate keys,
        they will be removed from the return dict
        """
        expected_key, expected_val = 'APP_ATTRIBUTES', {'cluster_role': 'controol',
                                                        'provider': 'aws',
                                                        'zone': '3'}
        line = "APP_ATTRIBUTES=cluster_role:controol;zone:6;provider:aws;zone:3"
        key, val = hubblestack.extmods.fdg.readfile._process_line(
            line, dictsep='=', valsep=';', subsep=':')
        assert expected_key == key
        assert expected_val == val

    def test_processLine_EmptyArguemnts_ReturnLine(self):
        """
        Test that given empty arguments, the line is returned
        """
        line = "line of text"
        ret, none = hubblestack.extmods.fdg.readfile._process_line(line, None, None, None)
        assert ret == line
        assert none is None

    def test_processLine_ValidDictsepValsepEmptySubsep_ReturnList(self):
        """
        Test that given a valid ``dictsep``, a valid ``valsep`` and an empty ``subsep``,
        a list is returned
        """
        expected_key, expected_val = 'key0', ['key1', 'key2', 'val']
        line = "key0:key1;key2;val"
        key, val = hubblestack.extmods.fdg.readfile._process_line(line, ':', ';', None)
        assert expected_key == key
        assert expected_val == val

    def test_processLine_ValidDictsepInvalidValsep_ReturnList(self):
        """
        Test that given a valid ``dictsep`` and an invalid ``valsep``, a list is returned
        """
        expected_key, expected_val = 'key0', ['key1;key2;val']
        line = "key0:key1;key2;val"
        key, val = hubblestack.extmods.fdg.readfile._process_line(line, ':', '-', None)
        assert expected_key == key
        assert expected_val == val

    def test_processLine_ValidDictsepValsepInvalidSubsep_ReturnDict(self):
        """
        Test that given a valid ``dictsep``, a valid ``valsep`` and an invalid ``subsep``,
        a dict is returned
        """
        expected_key, expected_val = 'APP_ATTRIBUTES', {'cluster_role:controol': None,
                                                        'provider:aws': None,
                                                        'zone:3': None}
        line = "APP_ATTRIBUTES=cluster_role:controol;zone:3;provider:aws"
        key, val = hubblestack.extmods.fdg.readfile._process_line(line, '=', ';', '-')
        assert expected_key == key
        assert expected_val == val

    def test_processLine_ValidDictsepSubsepInvalidValsep_ReturnDict(self):
        """
        Test that given a valid ``dictsep``, a valid ``subsep`` and an invalid ``valsep``,
        a dict is returned
        """
        expected_key, expected_val = 'key0', {'key1;val': 'val2'}
        line = "key0:key1;val-val2"
        key, val = hubblestack.extmods.fdg.readfile._process_line(line, ':', '.', '-')
        assert expected_key == key
        assert expected_val == val

    def test_processLine_InvalidDictsep_ReturnLine(self):
        """
        Test that given a valid ``dictsep``, a valid ``subsep`` and an invalid ``valsep``,
        a dict is returned
        """
        line = "key0:key1;val-val2"
        ret, none = hubblestack.extmods.fdg.readfile._process_line(line, '?', '.', '-')
        assert ret == line
        assert none is None

    def generate_config_data(self):
        """
        Sample data to use for testing the ``config`` function
        """
        sample_data = ["APP_ATTRIBUTES=cluster_role:control;zone:3;provider:aws",
                       "APP_ATTRIBUTES=cluster_role:worker;zone:1;provider:aws",
                       "APP_ATTRIBUTES=cluster_role:master;zone:0;provider:aws"]
        return sample_data

    @pytest.fixture(scope="session")
    def config_file(self, tmpdir_factory):
        """
        Helping function that creates a config file to test the ``config`` function against
        """
        sample_data = "\n".join(self.generate_config_data())
        config_file = tmpdir_factory.mktemp("data").join("config_file")
        config_file.write(sample_data)
        return str(config_file)

    def test_config_EmptyArguments_ReturnList(self, config_file):
        """
        Test that given empty arguemtsn, the function returns a list with lines as elements
        """
        expected_status, expected_ret = True, self.generate_config_data()
        status, ret = hubblestack.extmods.fdg.readfile.config(config_file)
        assert expected_status == status
        assert expected_ret == ret

    def test_config_InvalidPath_ReturnNone(self):
        """
        Test that given an invalid ``path``, the function returns ``None``
        """
        expected_status, expected_ret = False, None
        status, ret = hubblestack.extmods.fdg.readfile.config('/invalid/path')
        assert expected_status == status
        assert expected_ret == ret

    def test_config_OnlyDictsep_ReturnDict(self, config_file):
        """
        Test that given a valid ``dictsep`` and empty arguments,
        the function returns a valid ``dict``
        """
        sample_data = self.generate_config_data()
        expected_status, expected_ret = True, {"APP_ATTRIBUTES": [x.split("=")[1]
                                                                  for x in sample_data]}
        status, ret = hubblestack.extmods.fdg.readfile.config(config_file, dictsep="=")
        assert expected_status == status
        assert expected_ret == ret

    def test_config_SamePatternIgnore_ReturnEmptyDict(self, config_file):
        """
        Test that given the same ``pattern`` and ``ignore_pattern``
        """
        expected_status, expected_ret = True, {}
        status, ret = hubblestack.extmods.fdg.readfile.config(
            config_file, pattern="APP_ATTRIBUTES", ignore_pattern="APP_ATTRIBUTES", dictsep="=")
        assert expected_status == status
        assert expected_ret == ret

    def test_config_InvalidDictsep_ReturnDict(self, config_file):
        """
        Test that given an invalid ``dictsep`` and valid arguments,
        the function returns a dict with values of ``None``
        """
        sample_data = self.generate_config_data()
        expected_status, expected_ret = True, {x: None for x in sample_data
                                               if "master" not in x}
        status, ret = hubblestack.extmods.fdg.readfile.config(
            config_file, ignore_pattern=".*master.*", dictsep="?", valsep=';', subsep=':')
        assert expected_status == status
        assert expected_ret == ret

    def test_config_ValidArguments_ReturnDict(self, config_file):
        """
        Test that given valid arguments, the function returns a valid dict
        """
        expected_status, expected_ret = True, {"APP_ATTRIBUTES": {
            "cluster_role": "worker", "zone": "1", "provider":"aws"}}
        status, ret = hubblestack.extmods.fdg.readfile.config(
            config_file, pattern=".*(3|1).*", ignore_pattern=".*3.*",
            dictsep="=", valsep=';', subsep=':')
        assert expected_status == status
        assert expected_ret == ret

    def test_config_EmptyValsep_ReturnDict(self, config_file):
        """
        Test that given valid arguments and an empty ``valsep``,
        the function returns an incomplete dict
        """
        expected_status, expected_ret = True, {"APP_ATTRIBUTES": {
            "cluster_role": "control;zone:3;provider:aws"}}
        status, ret = hubblestack.extmods.fdg.readfile.config(
            config_file, pattern=".*control.*", dictsep="=", subsep=':')
        assert expected_status == status
        assert expected_ret == ret

    def test_config_EmptySubsep_ReturnDict(self, config_file):
        """
        Test that given valid arguments and an empty ``subsep``,
        the function returns a dict with a list as value
        """
        expected_status, expected_ret = True, {"APP_ATTRIBUTES": ["cluster_role:control",
                                                                  "zone:3",
                                                                  "provider:aws"]}
        status, ret = hubblestack.extmods.fdg.readfile.config(
            config_file, ignore_pattern=".*(worker|master).*", dictsep="=", valsep=';')
        assert expected_status == status
        assert expected_ret == ret


    def test_readfileString_InvalidPath_emptyReturn(self):
        """
        Test that given invalid arguments, the function returns False and None.
        """
        expected_status, expected_ret = False, None
        status, ret= hubblestack.extmods.fdg.readfile.readfile_string('/invalid/path')
        assert status == expected_status
        assert ret == expected_ret


    def test_readfileString_ValidPathFalseEncode_returnString(self, json_file):
        """
        Test that given a valid path, the contents are returned as string with no encoding
        """
        with open(json_file, 'w') as jfile:
            jfile.writelines(["First line", "Second line", "Foo bar line"])
        status, ret = hubblestack.extmods.fdg.readfile.readfile_string(json_file)
        assert status == True
        assert ret == "First lineSecond lineFoo bar line"


    def test_readfileString_ValidPathTrueEncode_returnEncodedString(self, json_file):
        """
        Test that given a valid path, the contents are returned as string
        """
        with open(json_file, 'w') as jfile:
            jfile.writelines(["Foo", "bar"])
        status, ret = hubblestack.extmods.fdg.readfile.readfile_string(json_file, encode_b64=True)
        assert status == True
        # encoded Foobar
        assert ret == 'Rm9vYmFy'
