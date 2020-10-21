from unittest import TestCase
import pytest

from hubblestack.extmods.hubble_mods import util
from hubblestack.utils.hubble_error import HubbleCheckValidationError

from collections import defaultdict
from salt.exceptions import ArgumentValueError

class TestProcess():
    """
    Class used to test the functions in ``process.py``
    """

    def test__compare_raises_exception_if_arguments_have_invalid_type(self):
        """
        Test that given invalid ``comp``,
        the function raises an ArgumentValueError exception
        """
        with pytest.raises(ArgumentValueError):
            util._compare('foo', 1, 2)

    def test__compare_returns_correctly_with_ge_comparator(self):
        """
        Test that given correct values, the function outputs the correct result with 'ge' comparator
        ge = greater equal
        """
        ret = util._compare('ge', 1, 2)
        assert ret is False, '1 >= 2'
        ret = util._compare('ge', 2, 2)
        assert ret is True, '2 >= 2'
        ret = util._compare('ge', 2, 1)
        assert ret is True, '2 >= 1'

    def test__compare_returns_correctly_with_gt_comparator(self):
        """
        Test that given correct values, the function outputs the correct result with 'gt' comparator
        gt = greater than
        """
        ret = util._compare('gt', 10, 2)
        assert ret is True, '10 > 2'
        ret = util._compare('gt', 1, 2)
        assert ret is False, '1 > 2'
        ret = util._compare('gt', 2, 2)
        assert ret is False, '2 > 2'

    def test__compare_returns_correctly_with_lt_comparator(self):
        """
        Test that given correct values, the function outputs the correct result with 'lt' comparator
        lt = lower than
        """
        ret = util._compare('lt', 1, 2)
        assert ret is True, '1 < 2'
        ret = util._compare('lt', 2, 2)
        assert ret is False, '2 < 2'
        ret = util._compare('lt', 2, 1)
        ret is False, '2 < 1'

    def test__compare_returns_correctly_with_le_comparator(self):
        """
        Test that given correct values, the function outputs the correct result with 'le' comparator
        le = lower equal
        """
        ret = util._compare('le', 1, 2)
        assert ret is True, '1 <= 2'
        ret = util._compare('le', 2, 2)
        assert ret is True, '2 <= 2'
        ret = util._compare('le', 2, 1)
        assert ret is False, '2 <= 1'

    def test__compare_returns_correctly_with_eq_comparator(self):
        """
        Test that given correct values, the function outputs the correct result with 'eq' comparator
        eq = equal
        """
        ret = util._compare('eq', 1, 2)
        assert ret is False, '1 == 2'
        ret = util._compare('eq', 2, 1)
        assert ret is False, '2 == 1'
        ret = util._compare('eq', 1, 1)
        assert ret is True, '1 == 1'

    def test__compare_returns_correctly_with_ne_comparator(self):
        """
        Test that given correct values, the function outputs the correct result with 'ne' comparator
        ne = not equal
        """
        ret = util._compare('ne', 1, 2)
        assert ret is True, '1 != 2'
        ret = util._compare('ne', 2, 1)
        assert ret is True, '2 != 1'
        ret = util._compare('ne', 1, 1)
        assert ret is False, '1 != 1'

    def test__filter_dict_returns_none_if_filter_values_is_invalid(self):
        """
        Test that given invalid ``filter_values``, the function returns None
        """
        status, ret = util._filter_dict_helper('test',
            dct={1: 'a', 2: 'b'}, filter_values=False, filter_rules={'invalid': 1, 'data': 2})
        assert status is False
        assert ret['error'] == 'invalid_format', 'invalid filter_rules should return None'

    def test__filter_dict_returns_correctly_filtered_dict_by_keys(self):
        """
        Test that given valid ``filter_values``, the function correctly filters a dict by keys
        """
        # keep x if 1 < x <= 4 and x != 3
        expected_ret = {2: 'b', 4: 'd'}
        status, ret = util._filter_dict_helper('test',
            {1: 'a', 2: 'b', 3: 'c', 4: 'd'}, False, {'gt': 1, 'le': 4, 'ne': 3})
        assert status == True
        assert expected_ret == ret['result']
        # keep x if 'a' <= x < 'd' and x != 'c'
        expected_ret = {'a': 1, 'b': 2}
        status, ret = util._filter_dict_helper('test',
            {'a': 1, 'b': 2, 'c': 3, 'd': 4}, False, {'ge': 'a', 'lt': 'd', 'ne': 'c'})
        assert status == True
        assert expected_ret == ret['result']

    def test__filter_dict_returns_correctly_filtered_dict_by_values(self):
        """
        Test that given valid ``filter_values``, the function correctly filters a dict by values
        """
        # keep x if 1 < x <= 4 and x != 3
        expected_ret = {'b': 2, 'd': 4}
        status, ret = util._filter_dict_helper('test',
            {'a': 1, 'b': 2, 'c': 3, 'd': 4}, True, {'gt': 1, 'le': 4, 'ne': 3})
        assert status == True
        assert expected_ret == ret['result']
        # keep x if 'a' <= x < 'd' and x != 'c'
        expected_ret = {1: 'a', 2: 'b'}
        status, ret = util._filter_dict_helper('test',
            {1: 'a', 2: 'b', 3: 'c', 4: 'd'}, True, {'ge': 'a', 'lt': 'd', 'ne': 'c'})
        assert status == True
        assert expected_ret == ret['result']

    def test__filter_dict_returns_unaltered_dict_if_filter_rules_is_empty(self):
        """
        Test that given empty ``filter_rules``, the function leaves the dict intact
        """
        expected_ret = {1: 'a', 2: 'b'}
        status, ret = util._filter_dict_helper('test', {1: 'a', 2: 'b'}, True, {})
        assert status == True
        assert expected_ret == ret['result']

    def test_filter_dict_returns_none_if_dict_is_invalid(self):
        """
        Test that given invalid types for ``starting_dict`` or ``chained``,
        the function returns False and None
        """
        # invalid starting_dict - is type list
        expected_status, expected_ret = False, None
        block_dict = {'args':
            {'starting_dict': [1, 2, 3]}}
        chaining_args = {'chaining_args': {'result': {1: 'a', 2: 'b'}, 'status': True}}
        status, ret = util._filter_dict('test', block_dict, chaining_args)
        assert status is False, 'invalid starting_dict, should return False'
        # invalid chained dict - is type list

        block_dict = {'args':
            {'starting_dict': {1: 'a', 2: 'b'}}}
        chaining_args = {'chaining_args': {'result': [1, 2], 'status': True}}
        status, ret = util._filter_dict('test', block_dict, chaining_args)
        assert status is False, 'invalid chained, should return False'

    def test_filter_dict_correctly_filters_out_keys(self):
        """
        Test that given correct input, the function correctly filters by keys
        """
        expected_ret = {1: 'a', 2: 'b', 4: 'd'}
        block_dict = {'args':
            {'starting_dict': {1: 'a', 2: 'b', 3: 'c'},
            'filter_rules': {'ge':1, 'ne':3}}}
        chaining_args = {'chaining_args': {'result': {1: 'b', 3: 'd', 4: 'd'}, 'status': True}}

        status, ret = util._filter_dict('test', block_dict, chaining_args)
        assert status is True
        assert expected_ret == ret['result']

    def test_filter_dict_correctly_filters_out_values(self):
        """
        Test that given correct input, the function correctly filters by values
        """
        expected_ret = {3: 'c', 4: 'd'}
        block_dict = {'args':
            {'starting_dict': {1: 'a', 2: 'b', 3: 'c'}, 'filter_values': True,
            'filter_rules': {'gt':'a', 'ne':'b', 'le':'d'}}}
        chaining_args = {'chaining_args': {'result': {1: 'b', 3: 'd', 4: 'd'}, 'status': True}}
        status, ret = util._filter_dict('test', block_dict, chaining_args)
        assert status is True
        assert expected_ret == ret['result']

    def test__filter_returns_none_if_input_is_invalid(self):
        """
        Test that given invalid input, the function returns None
        """
        status, ret = util._filter('test', [1, 2, 3], {'foo': 1})
        assert status == False
        assert ret['error'] == 'invalid_format', 'invalid input type should return None'

    def test__filter_correctly_filters_sequence_if_input_is_valid(self):
        """
        Test that given valid arguments of different types,
        the function returns the filtered sequence
        """
        # list
        expected_ret = [2, 4]
        seq = [1, 2, 3, 4]
        status, ret = util._filter('test', seq, {"gt": 1, "ne": 3, "le": 4})
        assert status == True
        assert expected_ret == ret['result']
        # set
        seq = set(seq)
        status, ret = util._filter('test', seq, {"gt": 1, "ne": 3, "le": 4})
        assert status == True
        assert expected_ret == ret['result']
        # string
        seq = "test string"
        expected_ret = ['e', 's', ' ', 's', 'r', 'i', 'n', 'g']
        status, ret = util._filter('test', seq, {"ne": 't'})
        assert status == True
        assert expected_ret == ret['result']

    def test_filter_seq_returns_none_if_input_is_invalid(self):
        """
        Test that given invalid input, the function returns None
        """
        # invalid ``starting_seq``
        chain_args = {'chaining_args': {'result': [2,3,4], 'status': True}}
        block_dict = {'args':{'starting_seq':1, 'filter_rules': {'ge':1, 'lt':4}}}
        status, ret = util._filter_seq('test', block_dict, chain_args)
        assert status is False, 'invalid starting_seq, should return False'
        
        # invalid ``chained``
        chain_args = {'chaining_args': {'result': 4, 'status': True}}
        block_dict = {'args':{'starting_seq':[1,2], 'filter_rules': {'ge':1, 'lt':4}}}
        status, ret = util._filter_seq('test', block_dict, chain_args)
        assert status is False, 'invalid chained, should return False'

    def test_filter_seq_returns_filtered_seq_with_valid_input(self):
        """Test that given valid input of different types,
        the function returns True and the filtered sequence
        """
        # list
        seq = [3, 4]
        chained = [1, 2]
        chain_args = {'chaining_args': {'result': chained, 'status': True}}
        block_dict = {'args':{'starting_seq':seq, 'filter_rules': {'gt':1, 'ne':3, 'le': 4}}}
        expected_ret = [2, 4]
        status, ret = util._filter_seq('test', block_dict, chain_args)
        assert expected_ret == ret['result']
        assert status is True
        # set
        expected_ret = [3]
        seq = set(seq)
        chained = set(chained)
        chain_args = {'chaining_args': {'result': chained, 'status': True}}
        block_dict = {'args':{'starting_seq':seq, 'filter_rules': {'ge':1, 'ne':2, 'lt': 4, 'eq': 3}}}
        status, ret = util._filter_seq('test', block_dict, chain_args)
        assert expected_ret == ret['result']
        assert status is True
        # string
        expected_ret = ['e', 's', ' ', 's', 'r', 'i', 'n', 'g']
        seq = 'test {}'
        chained = 'string'
        chain_args = {'chaining_args': {'result': chained, 'status': True}}
        block_dict = {'args':{'starting_seq':seq, 'filter_rules': {'ne': 't'}}}
        status, ret = util._filter_seq('test', block_dict, chain_args)
        assert expected_ret == ret['result']
        assert status is True

    def test_get_index_returns_none_if_invalid_input(self):
        """
        Test that given invalid arguments, the function returns None
        """
        # invalid ``chained``
        status, ret = util._get_index('test', {'args': {'starting_list':[1, 2, 3]}}, {})
        assert status is False, 'invalid chained, should return False'
        # index out of range
        status, ret = util._get_index('test', {'args': {'index':4}}, 
            {'chaining_args': {'result': [1, 2, 3], 'status': True}})
        assert status is False, 'index 4 out of range, list length is 3, should return False'
        # invalid ``chained`` type
        status, ret = util._get_index('test', {}, 
            {'chaining_args': {'result': set([1, 2, 3]), 'status': True}})
        assert status is False, 'invalid chained type, should return False'

    def test_get_index_returns_correctly_if_valid_input(self):
        """
        Test that given valid arguments,
        the function extracts the correct value
        """
        # return element at index -1 from [3, 4, 1, 2]
        expected_ret = 2
        status, ret = util._get_index('test',
            {'args': {'index': -1, 'starting_list': [1,2]}},
            {'chaining_args': {'result': [3,4], 'status': True}})
        assert status is True
        assert expected_ret == ret['result']
        # default to index 0 from [3, 4, 1, 2]
        expected_ret = 3
        status, ret = util._get_index('test',
            {'args': {'starting_list': [1,2]}},
            {'chaining_args': {'result': [3,4], 'status': True}})
        assert status is True
        assert expected_ret == ret['result']
        # return element at index 2 from [3, 4, 1, 2]
        expected_ret = 1
        status, ret = util._get_index('test',
            {'args': {'index': 2, 'starting_list': [1,2]}},
            {'chaining_args': {'result': [3,4], 'status': True}})
        assert status is True
        assert expected_ret == ret['result']

    def test_get_key_returns_none_if_invalid_input(self):
        """
        Test that given invalid arguments, the function returns None
        """
        # invalid ``chained`` type
        status, ret = util._get_key('test',
            {'args': {'key': '1'}},
            {'chaining_args': {'result': ['a', 'b', 'c'], 'status': True}})
        assert status is False, 'invalid chained type, should return False'
        # invalid key
        status, ret = util._get_key('test',
            {'args': {'key': 'd'}},
            {'chaining_args': {'result': {'a': 1, 'b': 2, 'c': 3}, 'status': True}})
        assert status is False, 'invalid key `d` in dict, should return False'

    def test_get_key_returns_correctly(self):
        """
        Test that given valid arguments,
        the function returns the correct value
        """
        expected_ret = 1
        status, ret = util._get_key('test',
            {'args': {'key': 'b', 'starting_dict':{'b': 1, 'c': 2}}},
            {'chaining_args': {'result': {'a': 1, 'b': 2}, 'status': True}})
        assert status is True
        assert expected_ret == ret['result']

    def test_join_returns_none_if_invalid_arguments(self):
        """
        Test that given invalid arguments,
        the function returns None
        """
        # invalid ``chained``
        status, ret = util._join('test',{},
            {'chaining_args': {'result': 1, 'status': True}})
        assert status is False
        # invalid ``sep``
        status, ret = util._join('test',
            {'args': {'sep': [1,2]}},
            {'chaining_args': {'result': ['foo', 'bar'], 'status': True}})
        assert status is False

    def test_join_returns_correct_string(self):
        """
        Test that given valid arguments,
        the function will return the joined string
        """
        # no ``sep``
        expected_ret = 'testwordstogether'
        status, ret = util._join('test',
            {'args': {'words':'together'}},
            {'chaining_args': {'result': ['test', 'words'], 'status': True}})
        assert status is True
        assert expected_ret == ret['result']
        # valid ``sep``
        expected_ret = 'test-more-words-together'
        status, ret = util._join('test',
            {'args': {'words':['words', 'together'], 'sep': '-'}},
            {'chaining_args': {'result': ['test', 'more'], 'status': True}})
        assert status is True
        assert expected_ret == ret['result']

    def test__sort_returns_none_if_invalid_input(self):
        """
        Test that given invalid arguments, the function returns None
        """
        # invalid ``seq``
        ret = util._sort_helper(seq=1, desc=True, lexico=False)
        assert ret is None
        # invalid ``desc``
        ret = util._sort_helper(seq=[2, 1], desc='yes', lexico=False)
        assert ret is None
        # invalid ``lexico``
        ret = util._sort_helper(seq=[1, 2, 12, 13], desc=False, lexico=True)
        assert ret is None

    def test__sort_returns_sorted_seq(self):
        """
        Test that given valid arguments,
        the function correctly sorts them with different parameters
        """
        expected_ret = ['Z', 'a', 'b']
        ret = util._sort_helper(seq=['b', 'a', 'Z'], desc=False, lexico=False)
        assert expected_ret == ret
        expected_ret = ['b', 'a', 'B']
        ret = util._sort_helper(
            seq={'a': 1, 'b': 2, 'B': 3}, desc=True, lexico=False)
        assert expected_ret == ret
        expected_ret = ['A', 'b', 'C']
        ret = util._sort_helper(
            seq=set(['b', 'A', 'C']), desc=False, lexico=True)
        assert expected_ret == ret

    def test_sort_returns_none_if_invalid_arguments(self):
        """
        Test that given invalid arguments, the function returns None
        """
        # invalid ``chained``
        status, ret = util._sort('test',
            {'args': {'seq': 2}},
            {'chaining_args': {'result': 1, 'status': True}})
        assert status is False
        # invalid ``desc``
        status, ret = util._sort('test',
            {'args': {'desc': 'yes'}},
            {'chaining_args': {'result': [1, 2, 3], 'status': True}})
        assert status is False
        # invalid ``lexico``
        status, ret = util._sort('test',
            {'args': {'lexico': True}},
            {'chaining_args': {'result': [1, 2, 3], 'status': True}})
        assert status is False

    def test_sort_returns_sorted_seq(self):
        """
        Test that given valid arguments,
        the function correctly sorts them with different parameters
        """
        expected_ret = [3, 2, 1]
        # desc list
        status, ret = util._sort('test',
            {'args': {'seq': [1,2],'desc': True}},
            {'chaining_args': {'result': [3], 'status': True}})
        assert status is True
        assert expected_ret == ret['result']
        # dict
        expected_ret = [1, 2, 3]
        status, ret = util._sort('test',
            {},
            {'chaining_args': {'result': {2: 'a', 1: 'b', 3: 'c'}, 'status': True}})
        assert status is True
        assert expected_ret == ret['result']
        # desc set
        expected_ret = ['b', 'a', 'B', 'A']
        status, ret = util._sort('test',
            {'args': {'seq': ['A', 'B'], 'desc': True}},
            {'chaining_args': {'result': set(['a', 'b']), 'status': True}})
        assert status is True
        assert expected_ret == ret['result']
        # lexicographic string
        expected_ret = ['A', 'a', 'b', 'B']
        status, ret = util._sort('test',
            {'args': {'seq': 'A{}B', 'lexico': True}},
            {'chaining_args': {'result': 'ab', 'status': True}})
        assert status is True
        assert expected_ret == ret['result']

    def test__split_returns_none_if_invalid_arguments(self):
        """
        Test that given invalid arguments,
        the function returns None
        """
        ret = util._split_helper(phrase=[1, 2, 3], sep=" ", regex=False)
        assert ret is None, "can't split list, should return None"
        ret = util._split_helper(phrase="foo bar", sep=[1, 2, 3], regex=False)
        assert ret is None, "separator to split by can't be list, should return None"
        ret = util._split_helper(phrase=[1, 2, 3], sep=" ", regex=True)
        assert ret is None, "can't split list, should return None"
        ret = util._split_helper(phrase="foo bar", sep=[1, 2, 3], regex=True)
        assert ret is None, "separator to split by can't be list, should return None"

    def test__split_returns_list_from_string(self):
        """
        Test that given valid arguments,
        the function correctly splits the string into a list
        """
        # simple ``sep``
        expected_ret = ['foo', 'bar']
        ret = util._split_helper("foo bar", " ", False)
        assert expected_ret == ret
        # ``sep`` simple regex
        ret = util._split_helper("foo bar", " ", True)
        assert expected_ret == ret
        # regex
        ret = util._split_helper("foo    bar", r"\s+", True)
        assert expected_ret == ret
        # invalid ``sep``
        expected_ret = ['foo bar']
        ret = util._split_helper("foo bar", "?", False)
        assert expected_ret == ret

    def test_split_returns_none_if_invalid_arguments(self):
        """
        Test that given invalid arguments,
        the function returns None
        """
        # invalid ``words``
        status, ret = util._split('test',
            {'args': {'phrase': [1, 2, 3]}},
            {'chaining_args': {'result': 'ab', 'status': True}})
        assert status is False
        status, ret = util._split('test',
            {'args': {'phrase': {1: 'a', 2: 'b'}}},
            {'chaining_args': {'result': 'ab', 'status': True}})
        assert status is False
        # invalid ``words`` & ``chained``
        status, ret = util._split('test',
            {'args': {'phrase': 1}},
            {'chaining_args': {'result': 12, 'status': True}})
        assert status is False
        status, ret = util._split('test',
            {'args': {'phrase': 'foo bar', 'regex': True}},
            {})
        assert status is False

    def test_split_returns_list_from_string(self):
        """
        Test that given valid arguments, the function correctly splits
        in all scenarios
        """
        expected_ret = ['a', 'b', 'c', 'd']
        # valid regex
        status, ret = util._split('test',
            {'args': {'phrase': 'a1b2c3d', 'sep': r"\d+", 'regex': True}},
            {})
        assert status is True
        assert expected_ret == ret['result']
        # simple sep
        expected_ret = ['a1', 'b2', 'c3', 'd']
        status, ret = util._split('test',
            {'args': {'phrase': "a1 b2 {}", 'sep': " "}},
            {'chaining_args': {'result': 'c3 d', 'status': True}})
        assert status is True
        assert expected_ret == ret['result']
        # no sep
        expected_ret = ['a1', 'b2', 'c3', 'd']
        status, ret = util._split('test',
            {'args': {'phrase': "a1    b2    \n{}"}},
            {'chaining_args': {'result': 'c3 d', 'status': True}})
        assert status is True
        assert expected_ret == ret['result']
        # invalid regex
        expected_ret = ['a1b2c3d']
        status, ret = util._split('test',
            {'args': {'phrase': "a1b2{}", 'sep': r"\d+", 'regex': False}},
            {'chaining_args': {'result': 'c3d', 'status': True}})
        assert status is False

    def test_dict_to_list_returns_none_if_invalid_arguments(self):
        """
        Test that given invalid arguments, the function returns None
        """
        status, ret = util._dict_to_list('test',
            {'args': {'starting_dict':{1: 'a'}}},
            {'chaining_args': {'result': [1,2,3], 'status': True}})
        assert status is False
        status, ret = util._dict_to_list('test',
            {'args': {'starting_dict':'foo'}},
            {'chaining_args': {'result': {1: 'a', 2: 'b'}, 'status': True}})
        assert status is False

    def test_dict_to_list_correctly_returns_list(self):
        """
        Test that given valid arguments, the function outputs a valid list
        """
        # flat dict
        expected_ret = [(1, 'b'), (2, 'c')]
        status, ret = util._dict_to_list('test',
            {'args': {'starting_dict':{1: 'a'}, 'update_chained': False}},
            {'chaining_args': {'result': {1: 'b', 2: 'c'}, 'status': True}})
        assert status is True
        assert expected_ret == ret['result']
        # nested dict
        expected_ret = [(1, 'a'), (2, 'c'), (3, {1: 'a'})]
        status, ret = util._dict_to_list('test',
            {'args': {'starting_dict':{1: 'a', 3: {1: 'a'}}}},
            {'chaining_args': {'result': {1: 'b', 2: 'c'}, 'status': True}})
        assert status is True
        assert expected_ret == ret['result']
        # empty dict
        status, ret = util._dict_to_list('test',{},
            {'chaining_args': {'result': {}, 'status': True}})
        assert status is False

    def test__dict_convert_none_returns_none_if_invalid_arguments(self):
        """
        Test that given invalid arguments, the function returns None
        """
        ret = util._dict_convert_none_helper([1, 2, 3])
        assert ret is None
        ret = util._dict_convert_none_helper(1)
        assert ret is None
        expected_ret = {}
        ret = util._dict_convert_none_helper(defaultdict())
        assert expected_ret == ret

    def test__dict_convert_none_replaces_empty_string_with_none_in_dict(self):
        """
        Test that given valid arguments,
        the function converts empty strings to None in all scenarios
        """
        # flat dict
        expected_ret = {1: None, 2: 'a', 3: "None", 4: None}
        ret = util._dict_convert_none_helper(
            {1: "", 2: 'a', 3: "None", 4: None})
        assert expected_ret == ret
        # nested dicts
        expected_ret = {'a': {'aa': {'aaa': 3, 'bbb': {'bbbb': 4, 'cccc': None},
                                    'ccc': None}, 'bb': None}, 'b': None}
        ret = util._dict_convert_none_helper(
            {'a': {'aa': {'aaa': 3, 'bbb': {'bbbb': 4, 'cccc': ''},
                          'ccc': ''}, 'bb': ''}, 'b': ''})
        assert expected_ret == ret
        # nested dicts & seqs
        expected_ret = {'a': [{'b': [{'c': ['d', {'e': None}], 'f': None}, {'g': None}],
                              'h': None}, 'i'], 'j': None}
        ret = util._dict_convert_none_helper(
            {'a': [{'b': ({'c': ['d', {'e': ''}], 'f': ''}, {'g': ''}),
                    'h': ''}, 'i'], 'j': ''})
        assert expected_ret == ret

    def test__seq_convert_none_returns_none_if_invalid_arguments(self):
        """
        Test that given invalid arguments, the function returns None
        """
        ret = util._seq_convert_none_helper({1: 'a', 2: 'b'})
        assert ret is None
        ret = util._seq_convert_none_helper(1)
        assert ret is None
        ret = util._seq_convert_none_helper(True)
        assert ret is None

    def test__seq_convert_none_replaces_emtpy_strings_with_none(self):
        """
        Test that given valid arguments,
        the function correctly converts empty strings to None in all scenarios
        """
        # flat seq
        expected_ret = ['a', {1: None}, 'b', {1: None}, 'c']
        ret = util._seq_convert_none_helper(
            ['a', {1: ''}, 'b', {1: ''}, 'c'])
        assert expected_ret == ret
        # nested seq & dict
        expected_ret = ['a', [{1: None, 2: [3, [4, {1: None, 2: {3: None}}]]}, 'b'], 'c']
        ret = util._seq_convert_none_helper(
            ('a', [{1: '', 2: [3, (4, {1: '', 2: {3: ''}})]}, 'b'], 'c'))
        assert expected_ret == ret

    def test_dict_convert_none_returns_none_if_invalid_argument(self):
        """
        Test that given invalid arguments, the function returns None
        """
        status, ret = util._dict_convert_none('test',
            {},
            {'chaining_args': {'result': 'foo bar', 'status': True}})
        assert status is False
        status, ret = util._dict_convert_none('test',
            {'args': {'starting_seq':[1, 2]}},
            {'chaining_args': {'result': {1: 'a'}, 'status': True}})
        assert status is False
        status, ret = util._dict_convert_none('test',
            {},
            {'chaining_args': {'result': {}, 'status': True}})
        assert status is False

    def test_dict_convert_none_replaces_empty_string_with_none(self):
        """
        Test that given valid arguments,
        the function returns a valid dict with None instead of empty strings
        """
        # flat dict
        expected_ret = {1: 'a', 2: None, 3: 'b', 4: None}
        status, ret = util._dict_convert_none('test',
            {},
            {'chaining_args': {'result': {1: 'a', 2: '', 3: 'b', 4: ''}, 'status': True}})
        assert expected_ret == ret['result']
        assert status is True
        # nested dict & tuple
        expected_ret = {'a': [{'b': [{'c': {'e': None}, 'f': None}, {'g': None}],
                              'h': None}, 'i'], 'j': None}
        status, ret = util._dict_convert_none('test',
            {'args': {'starting_seq':{'j': ''}}},
            {'chaining_args': {'result': {'a': [{'b': ({'c': {'e': ''}, 'f': ''}, {'g': ''}),
                'h': ''}, 'i']}, 'status': True}})
        assert status is True
        assert expected_ret == ret['result']
        # nested dict, list & tuple
        expected_ret = ['a', [{1: None, 2: [3, [4, {1: None, 2: {3: None}}]]}, 'b'], 'c']
        status, ret = util._dict_convert_none('test',
            {},
            {'chaining_args': {'result': ('a', [{1: '', 2: [3, (4, {1: '', 2: {3: ''}})]}, 'b'], 'c'), 'status': True}})
        assert status is True
        assert expected_ret == ret['result']
        # nested dict & list
        expected_ret = ['a', {1: None}, 'b', {1: None}, 'c']
        status, ret = util._dict_convert_none('test',
            {'args': {'starting_seq': [{1: ''}, 'c']}},
            {'chaining_args': {'result': ['a', {1: ''}, 'b'], 'status': True}})
        assert status is True
        assert expected_ret == ret['result']

    def test_print_string_returns_none_when_invalid_arguments(self):
        """
        Test that given invalid arguments, the function returns None
        """
        status, ret = util._print_string('test',
            {'args': {'starting_string': ['foo', 'bar']}},
            {})
        assert status is False
        status, ret = util._print_string('test',
            {'args': {'starting_string': ''}},
            {})
        assert status is False

    def test_print_string_returns_correct_string(self):
        """
        Test that given valid arguments, the function returns the correct string
        """
        expected_ret = 'foo'
        status, ret = util._print_string('test',
            {'args': {'starting_string': 'foo'}},
            {'chaining_args': {'result': 'bar', 'status': True}})
        assert status is True
        assert expected_ret == ret['result']
        expected_ret = "foo ['b', 'a', 'r']"
        status, ret = util._print_string('test',
            {'args': {'starting_string': 'foo {}'}},
            {'chaining_args': {'result': ['b', 'a', 'r'], 'status': True}})
        assert status is True
        assert expected_ret == ret['result']

    def test__sterilize_dict_returns_none_if_invalid_arguments(self):
        """
        Test that given invalid arguments, the function returns None
        """
        ret = util._sterilize_dict(dictionary=[1, 2])
        assert ret is None
        ret = util._sterilize_dict(dictionary={})
        assert ret == {}
        ret = util._sterilize_dict(dictionary=12)
        assert ret is None

    def test__sterilize_dict_removes_none_values_if_nested_dict(self):
        """
        Test that given valid arguments,
        the function correctly removes keys containing values of None
        """
        # flat dict
        expected_ret = {2: 'a'}
        ret = util._sterilize_dict(
            {1: None, 2: 'a'})
        assert expected_ret == ret
        # nested dicts
        expected_ret = {2: {3: {5: 'a'}, 7: 'b'}, 8: 'c', 9: {}}
        ret = util._sterilize_dict(
            {1: None, 2: {3: {4: None, 5: 'a'}, 6: None, 7: 'b'}, 8: 'c', 9: {10: None}})
        assert expected_ret == ret
        # nested dicts & sequences
        expected_ret = {2: {3: [4, {}], 6: {7: ['b', {}]}}}
        ret = util._sterilize_dict(
            {1: None, 2: {3: [4, {5: None}], 6: {7: ('b', {9: None}), 8: None}}})
        assert expected_ret == ret

    def test__sterilize_seq_returns_none_if_arguments_are_invalid(self):
        """
        Test that given invalid arguments, the function returns None
        """
        ret = util._sterilize_seq(
            {1: 'a', 2: ['b']})
        assert ret is None
        ret = util._sterilize_seq(12)
        assert ret is None
        ret = util._sterilize_seq([])
        assert ret == []

    def test__sterilize_seq_removes_none_values_from_seq(self):
        """
        Test that given valid arguments,
        the function finds nested dicts and removes keys with values of None
        """
        # flat seq
        expected_ret = [1, 2, [1, 2], [1, 2]]
        ret = util._sterilize_seq(
            [1, 2, set([1, 2, 1]), (1, 2)])
        assert expected_ret == ret
        # nested dicts & seq
        expected_ret = [{2: {3: [{5: 'a'}, [None, {7: 'b'}]], 8: 'c', 9: {}}}]
        ret = util._sterilize_seq(
            [{1: None, 2: {3: ({4: None, 5: 'a'}, [None, {6: None, 7: 'b'}]),
                           8: 'c', 9: {10: None}}}])
        assert expected_ret == ret

    def test_remove_dict_none_returns_none_if_invalid_arguments(self):
        """
        Test that given invalid arguments, the function returns None
        """
        # invalid ``starting_seq``
        status, ret = util._dict_remove_none('test',
            {'args': {'starting_seq': [1, 2, 3]}},
            {'chaining_args': {'result': {1: 'a', 2: 'b'}, 'status': True}})
        assert status is False
        # invalid ``chained`` & valid ``starting_seq``
        status, ret = util._dict_remove_none('test',
            {'args': {'starting_seq': [1, 2, 3]}},
            {'chaining_args': {'result': '123', 'status': True}})
        assert status is False
        # invalid ``chained``
        status, ret = util._dict_remove_none('test',
            {},
            {'chaining_args': {'result': '123', 'status': True}})
        assert status is False

    def test_dict_remove_none_returns_valid_sequence(self):
        """
        Test that given valid arguments, the function finds nested dicts
        and removes keys with values of None
        """
        # flat dict
        expected_ret = {2: 'a', 4: 'b'}
        status, ret = util._dict_remove_none('test',
            {},
            {'chaining_args': {'result': {1: None, 2: 'a', 3: None, 4: 'b'}, 'status': True}})
        assert status is True
        assert expected_ret == ret['result']
        # flat seq
        expected_ret = [{}, {2: 'a'}, 5, None, {4: 'b'}]
        status, ret = util._dict_remove_none('test',
            {'args': {'starting_seq':[5, None, {4: 'b'}]}},
            {'chaining_args': {'result': [{1: None}, {2: 'a', 3: None}], 'status': True}})
        assert status is True
        assert expected_ret == ret['result']
        # nested sequences & dicts
        expected_ret = [{9: {11: [1, 2]}}, 11, {2: {3: [{5: 'a'}, [None, {7: 'b'}]], 8: 'c'}}]
        status, ret = util._dict_remove_none('test',
            {'args': {'starting_seq':[{1: None, 2: {3: ({4: None, 5: 'a'},
                                            [None, {6: None, 7: 'b'}]), 8: 'c'}}]}},
            {'chaining_args': {'result': [{9: {10: None, 11: set([1, 2, 1])}}, 11], 'status': True}})
        assert status is True
        assert expected_ret == ret['result']
        # nested dicts & sequences
        expected_ret = {2: {3: [{5: 'a'}, [None, {7: 'b'}]], 8: 'c'}, 9: {11: [1, 2]}}
        status, ret = util._dict_remove_none('test',
            {'args': {'starting_seq':{1: None, 2: {3: ({4: None, 5: 'a'}, [None, {6: None, 7: 'b'}]), 8: 'c'}}}},
            {'chaining_args': {'result': {9: {10: None, 11: set([1, 2, 1])}, 11: None}, 'status': True}})
        assert status is True
        assert expected_ret == ret['result']

    def test_encode_base64_returns_none_if_invalid_arguments_type(self):
        """
        Test that given invalid arguments, the function returns None
        """
        # invalid `starting_string`
        status, ret = util._encode_base64('test',
            {'args': {'starting_string': 123}},
            {'chaining_args': {'result': 'foo', 'status': True}})
        assert status is False
        status, ret = util._encode_base64('test',
            {'args': {'starting_string': ['a', 'c'], 'format_chained': False}},
            {})
        assert status is False
        expected_ret = ''
        status, ret = util._encode_base64('test',
            {'args': {'starting_string': '', 'format_chained': False}},
            {})
        assert status is False

    def test_encode_base64_returns_string_if_valid_arguments(self):
        """
        Test that given valid arguments, the function correctly encodes the string and returns it
        """
        # format chained
        expected_ret = 'Zm9vIGJhcg=='
        status, ret = util._encode_base64('test',
            {'args': {'starting_string': 'foo {}'}},
            {'chaining_args': {'result': 'bar', 'status': True}})
        assert status is True
        assert expected_ret == ret['result']
        # don't format chained
        expected_ret = 'Zm9v'
        status, ret = util._encode_base64('test',
            {'args': {'starting_string': 'foo'}},
            {'chaining_args': {'result': 'bar', 'status': True}})
        assert status is True
        assert expected_ret == ret['result']
        # no chained
        expected_ret = 'Zm9vIHt9'
        status, ret = util._encode_base64('test',
            {'args': {'starting_string': 'foo {}', 'format_chained': False}},
            {'chaining_args': {'result': 'bar', 'status': True}})
        assert status is True
        assert expected_ret == ret['result']