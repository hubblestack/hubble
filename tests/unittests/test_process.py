

import os
import pytest
from collections import defaultdict

from salt.exceptions import ArgumentValueError
import hubblestack.extmods.fdg.process


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
            hubblestack.extmods.fdg.process._compare('foo', 1, 2)

    def test__compare_returns_correctly_with_ge_comparator(self):
        """
        Test that given correct values, the function outputs the correct result with 'ge' comparator
        ge = greater equal
        """
        ret = hubblestack.extmods.fdg.process._compare('ge', 1, 2)
        assert ret is False, '1 >= 2'
        ret = hubblestack.extmods.fdg.process._compare('ge', 2, 2)
        assert ret is True, '2 >= 2'
        ret = hubblestack.extmods.fdg.process._compare('ge', 2, 1)
        assert ret is True, '2 >= 1'

    def test__compare_returns_correctly_with_gt_comparator(self):
        """
        Test that given correct values, the function outputs the correct result with 'gt' comparator
        gt = greater than
        """
        ret = hubblestack.extmods.fdg.process._compare('gt', 10, 2)
        assert ret is True, '10 > 2'
        ret = hubblestack.extmods.fdg.process._compare('gt', 1, 2)
        assert ret is False, '1 > 2'
        ret = hubblestack.extmods.fdg.process._compare('gt', 2, 2)
        assert ret is False, '2 > 2'

    def test__compare_returns_correctly_with_lt_comparator(self):
        """
        Test that given correct values, the function outputs the correct result with 'lt' comparator
        lt = lower than
        """
        ret = hubblestack.extmods.fdg.process._compare('lt', 1, 2)
        assert ret is True, '1 < 2'
        ret = hubblestack.extmods.fdg.process._compare('lt', 2, 2)
        assert ret is False, '2 < 2'
        ret = hubblestack.extmods.fdg.process._compare('lt', 2, 1)
        ret is False, '2 < 1'

    def test__compare_returns_correctly_with_le_comparator(self):
        """
        Test that given correct values, the function outputs the correct result with 'le' comparator
        le = lower equal
        """
        ret = hubblestack.extmods.fdg.process._compare('le', 1, 2)
        assert ret is True, '1 <= 2'
        ret = hubblestack.extmods.fdg.process._compare('le', 2, 2)
        assert ret is True, '2 <= 2'
        ret = hubblestack.extmods.fdg.process._compare('le', 2, 1)
        assert ret is False, '2 <= 1'

    def test__compare_returns_correctly_with_eq_comparator(self):
        """
        Test that given correct values, the function outputs the correct result with 'eq' comparator
        eq = equal
        """
        ret = hubblestack.extmods.fdg.process._compare('eq', 1, 2)
        assert ret is False, '1 == 2'
        ret = hubblestack.extmods.fdg.process._compare('eq', 2, 1)
        assert ret is False, '2 == 1'
        ret = hubblestack.extmods.fdg.process._compare('eq', 1, 1)
        assert ret is True, '1 == 1'

    def test__compare_returns_correctly_with_ne_comparator(self):
        """
        Test that given correct values, the function outputs the correct result with 'ne' comparator
        ne = not equal
        """
        ret = hubblestack.extmods.fdg.process._compare('ne', 1, 2)
        assert ret is True, '1 != 2'
        ret = hubblestack.extmods.fdg.process._compare('ne', 2, 1)
        assert ret is True, '2 != 1'
        ret = hubblestack.extmods.fdg.process._compare('ne', 1, 1)
        assert ret is False, '1 != 1'

    def test__filter_dict_returns_none_if_filter_values_is_invalid(self):
        """
        Test that given invalid ``filter_values``, the function returns None
        """
        ret = hubblestack.extmods.fdg.process._filter_dict(
            dct={1: 'a', 2: 'b'}, filter_values=False, filter_rules={'invalid': 1, 'data': 2})
        assert ret is None, 'invalid filter_rules should return None'

    def test__filter_dict_returns_correctly_filtered_dict_by_keys(self):
        """
        Test that given valid ``filter_values``, the function correctly filters a dict by keys
        """
        # keep x if 1 < x <= 4 and x != 3
        expected_ret = {2: 'b', 4: 'd'}
        ret = hubblestack.extmods.fdg.process._filter_dict(
            {1: 'a', 2: 'b', 3: 'c', 4: 'd'}, False, {'gt': 1, 'le': 4, 'ne': 3})
        assert expected_ret == ret
        # keep x if 'a' <= x < 'd' and x != 'c'
        expected_ret = {'a': 1, 'b': 2}
        ret = hubblestack.extmods.fdg.process._filter_dict(
            {'a': 1, 'b': 2, 'c': 3, 'd': 4}, False, {'ge': 'a', 'lt': 'd', 'ne': 'c'})
        assert expected_ret == ret

    def test__filter_dict_returns_correctly_filtered_dict_by_values(self):
        """
        Test that given valid ``filter_values``, the function correctly filters a dict by values
        """
        # keep x if 1 < x <= 4 and x != 3
        expected_ret = {'b': 2, 'd': 4}
        ret = hubblestack.extmods.fdg.process._filter_dict(
            {'a': 1, 'b': 2, 'c': 3, 'd': 4}, True, {'gt': 1, 'le': 4, 'ne': 3})
        assert expected_ret == ret
        # keep x if 'a' <= x < 'd' and x != 'c'
        expected_ret = {1: 'a', 2: 'b'}
        ret = hubblestack.extmods.fdg.process._filter_dict(
            {1: 'a', 2: 'b', 3: 'c', 4: 'd'}, True, {'ge': 'a', 'lt': 'd', 'ne': 'c'})
        assert expected_ret == ret

    def test__filter_dict_returns_unaltered_dict_if_filter_rules_is_empty(self):
        """
        Test that given empty ``filter_rules``, the function leaves the dict intact
        """
        expected_ret = {1: 'a', 2: 'b'}
        ret = hubblestack.extmods.fdg.process._filter_dict({1: 'a', 2: 'b'}, True, {})
        assert expected_ret == ret

    def test_filter_dict_returns_none_if_dict_is_invalid(self):
        """
        Test that given invalid types for ``starting_dict`` or ``chained``,
        the function returns False and None
        """
        # invalid starting_dict - is type list
        expected_status, expected_ret = False, None
        status, ret = hubblestack.extmods.fdg.process.filter_dict(
            starting_dict=[1, 2, 3], chained={1: 'a', 2: 'b'})
        assert status is False, 'invalid starting_dict, should return False'
        assert ret is None, 'invalid starting_dict, should return None'
        # invalid chained dict - is type list
        status, ret = hubblestack.extmods.fdg.process.filter_dict(
            starting_dict={1: 'a', 2: 'b'}, chained=[1, 2])
        assert status is False, 'invalid chained, should return False'
        assert ret is None, 'invalid chained, should return None'

    def test_filter_dict_correctly_filters_out_keys(self):
        """
        Test that given correct input, the function correctly filters by keys
        """
        expected_ret = {1: 'a', 2: 'b', 4: 'd'}
        status, ret = hubblestack.extmods.fdg.process.filter_dict(
            starting_dict={1: 'a', 2: 'b', 3: 'c'}, chained={1: 'b', 3: 'd', 4: 'd'},
            ge=1, ne=3)
        assert status is True
        assert expected_ret == ret

    def test_filter_dict_correctly_filters_out_values(self):
        """
        Test that given correct input, the function correctly filters by values
        """
        expected_ret = {3: 'c', 4: 'd'}
        status, ret = hubblestack.extmods.fdg.process.filter_dict(
            starting_dict={1: 'a', 2: 'b', 3: 'c'}, filter_values=True,
            chained={1: 'b', 3: 'd', 4: 'd'}, gt='a', ne='b', le='d')
        assert status is True
        assert expected_ret == ret

    def test__filter_returns_none_if_input_is_invalid(self):
        """
        Test that given invalid input, the function returns None
        """
        ret = hubblestack.extmods.fdg.process._filter([1, 2, 3], {'foo': 1})
        assert ret is None, 'invalid input type should return None'

    def test__filter_correctly_filters_sequence_if_input_is_valid(self):
        """
        Test that given valid arguments of different types,
        the function returns the filtered sequence
        """
        # list
        expected_ret = [2, 4]
        seq = [1, 2, 3, 4]
        ret = hubblestack.extmods.fdg.process._filter(seq, {"gt": 1, "ne": 3, "le": 4})
        assert expected_ret == ret
        # set
        seq = set(seq)
        ret = hubblestack.extmods.fdg.process._filter(seq, {"gt": 1, "ne": 3, "le": 4})
        assert expected_ret == ret
        # string
        seq = "test string"
        expected_ret = ['e', 's', ' ', 's', 'r', 'i', 'n', 'g']
        ret = hubblestack.extmods.fdg.process._filter(seq, {"ne": 't'})
        assert expected_ret == ret

    def test_filter_seq_returns_none_if_input_is_invalid(self):
        """
        Test that given invalid input, the function returns None
        """
        # invalid ``starting_seq``
        status, ret = hubblestack.extmods.fdg.process.filter_seq(
            starting_seq=1, chained=[2, 3, 4], ge=1, lt=4)
        assert status is False, 'invalid starting_seq, should return False'
        assert ret is None, 'invalid starting_seq, should return None'
        # invalid ``chained``
        status, ret = hubblestack.extmods.fdg.process.filter_seq(
            starting_seq=[1, 2], chained=4, ge=1, lt=4)
        assert status is False, 'invalid chained, should return False'
        assert ret is None, 'invalid chained, should return None'

    def test_filter_seq_returns_filtered_seq_with_valid_input(self):
        """Test that given valid input of different types,
        the function returns True and the filtered sequence
        """
        # list
        expected_ret = [2, 4]
        chained = [1, 2]
        seq = [3, 4]
        status, ret = hubblestack.extmods.fdg.process.filter_seq(
            starting_seq=seq, chained=chained, gt=1, ne=3, le=4)
        assert expected_ret == ret
        assert status is True
        # set
        expected_ret = [3]
        seq = set(seq)
        chained = set(chained)
        status, ret = hubblestack.extmods.fdg.process.filter_seq(
            starting_seq=seq, chained=chained, ge=1, ne=2, lt=4, eq=3)
        assert expected_ret == ret
        assert status is True
        # string
        expected_ret = ['e', 's', ' ', 's', 'r', 'i', 'n', 'g']
        seq = 'test {}'
        chained = 'string'
        status, ret = hubblestack.extmods.fdg.process.filter_seq(
            starting_seq=seq, chained=chained, ne='t')
        assert expected_ret == ret
        assert status is True

    def test_get_index_returns_none_if_invalid_input(self):
        """
        Test that given invalid arguments, the function returns None
        """
        # invalid ``chained``
        status, ret = hubblestack.extmods.fdg.process.get_index(starting_list=[1, 2, 3])
        assert status is False, 'invalid chained, should return False'
        assert ret is None, 'invalid chained, should return None'
        # index out of range
        status, ret = hubblestack.extmods.fdg.process.get_index(index=4, chained=[1, 2, 3])
        assert status is False, 'index 4 out of range, list length is 3, should return False'
        assert ret is None, 'index 4 out of range, list length is 3, should return None'
        # invalid ``chained`` type
        status, ret = hubblestack.extmods.fdg.process.get_index(chained=set([1, 2, 3]))
        assert status is False, 'invalid chained type, should return False'
        assert ret is None, 'invalid chained type, should return None'

    def test_get_index_returns_correctly_if_valid_input(self):
        """
        Test that given valid arguments,
        the function extracts the correct value
        """
        # return element at index -1 from [3, 4, 1, 2]
        expected_ret = 2
        status, ret = hubblestack.extmods.fdg.process.get_index(
            index=-1, starting_list=[1, 2], chained=[3, 4])
        assert status is True
        assert expected_ret == ret
        # default to index 0 from [3, 4, 1, 2]
        expected_ret = 3
        status, ret = hubblestack.extmods.fdg.process.get_index(
            starting_list=[1, 2], chained=[3, 4])
        assert status is True
        assert expected_ret == ret
        # return element at index 2 from [3, 4, 1, 2]
        expected_ret = 1
        status, ret = hubblestack.extmods.fdg.process.get_index(
            index=2, starting_list=[1, 2], chained=[3, 4])
        assert status is True
        assert expected_ret == ret

    def test_get_key_returns_none_if_invalid_input(self):
        """
        Test that given invalid arguments, the function returns None
        """
        # invalid ``chained`` type
        status, ret = hubblestack.extmods.fdg.process.get_key(key='a', chained=['a', 'b', 'c'])
        assert status is False, 'invalid chained type, should return False'
        assert ret is None, 'invalid chained type, should return None'
        # invalid key
        status, ret = hubblestack.extmods.fdg.process.get_key(
            key='d', chained={'a': 1, 'b': 2, 'c': 3})
        assert status is False, 'invalid key `d` in dict, should return False'
        assert ret is None, 'invalid key `d` in dict, should return None'

    def test_get_key_returns_correctly(self):
        """
        Test that given valid arguments,
        the function returns the correct value
        """
        expected_ret = 1
        status, ret = hubblestack.extmods.fdg.process.get_key(
            key='b', starting_dict={'b': 1, 'c': 2},
            chained={'a': 1, 'b': 2})
        assert status is True
        assert expected_ret == ret

    def test_join_returns_none_if_invalid_arguments(self):
        """
        Test that given invalid arguments,
        the function returns None
        """
        # invalid ``chained``
        status, ret = hubblestack.extmods.fdg.process.join(chained=1)
        assert status is False
        assert ret is None
        # invalid ``sep``
        status, ret = hubblestack.extmods.fdg.process.join(sep=[1, 2], chained=['foo', 'bar'])
        assert status is False
        assert ret is None

    def test_join_returns_correct_string(self):
        """
        Test that given valid arguments,
        the function will return the joined string
        """
        # no ``sep``
        expected_ret = 'testwordstogether'
        status, ret = hubblestack.extmods.fdg.process.join(
            words='together', chained=['test', 'words'])
        assert status is True
        assert expected_ret == ret
        # valid ``sep``
        expected_ret = 'test-more-words-together'
        status, ret = hubblestack.extmods.fdg.process.join(
            words=['words', 'together'], sep='-', chained=['test', 'more'])
        assert status is True
        assert expected_ret == ret

    def test__sort_returns_none_if_invalid_input(self):
        """
        Test that given invalid arguments, the function returns None
        """
        # invalid ``seq``
        ret = hubblestack.extmods.fdg.process._sort(seq=1, desc=True, lexico=False)
        assert ret is None
        # invalid ``desc``
        ret = hubblestack.extmods.fdg.process._sort(seq=[2, 1], desc='yes', lexico=False)
        assert ret is None
        # invalid ``lexico``
        ret = hubblestack.extmods.fdg.process._sort(seq=[1, 2, 12, 13], desc=False, lexico=True)
        assert ret is None

    def test__sort_returns_sorted_seq(self):
        """
        Test that given valid arguments,
        the function correctly sorts them with different parameters
        """
        expected_ret = ['Z', 'a', 'b']
        ret = hubblestack.extmods.fdg.process._sort(seq=['b', 'a', 'Z'], desc=False, lexico=False)
        assert expected_ret == ret
        expected_ret = ['b', 'a', 'B']
        ret = hubblestack.extmods.fdg.process._sort(
            seq={'a': 1, 'b': 2, 'B': 3}, desc=True, lexico=False)
        assert expected_ret == ret
        expected_ret = ['A', 'b', 'C']
        ret = hubblestack.extmods.fdg.process._sort(
            seq=set(['b', 'A', 'C']), desc=False, lexico=True)
        assert expected_ret == ret

    def test_sort_returns_none_if_invalid_arguments(self):
        """
        Test that given invalid arguments, the function returns None
        """
        # invalid ``chained``
        status, ret = hubblestack.extmods.fdg.process.sort(seq=2, chained=1)
        assert status is False
        assert ret is None
        # invalid ``desc``
        status, ret = hubblestack.extmods.fdg.process.sort(chained=[1, 2, 3], desc='yes')
        assert status is False
        assert ret is None
        # invalid ``lexico``
        status, ret = hubblestack.extmods.fdg.process.sort(chained=[1, 2, 3], lexico=True)
        assert status is False
        assert ret is None

    def test_sort_returns_sorted_seq(self):
        """
        Test that given valid arguments,
        the function correctly sorts them with different parameters
        """
        expected_ret = [3, 2, 1]
        # desc list
        status, ret = hubblestack.extmods.fdg.process.sort(
            seq=[1, 2], desc=True, chained=[3])
        assert status is True
        assert expected_ret == ret
        # dict
        expected_ret = [1, 2, 3]
        status, ret = hubblestack.extmods.fdg.process.sort(chained={2: 'a', 1: 'b', 3: 'c'})
        assert status is True
        assert expected_ret == ret
        # desc set
        expected_ret = ['b', 'a', 'B', 'A']
        status, ret = hubblestack.extmods.fdg.process.sort(
            seq=['A', 'B'], chained=set(['a', 'b']), desc=True)
        assert status is True
        assert expected_ret == ret
        # lexicographic string
        expected_ret = ['A', 'a', 'b', 'B']
        status, ret = hubblestack.extmods.fdg.process.sort(
            seq='A{}B', chained='ab', lexico=True)
        assert status is True
        assert expected_ret == ret

    def test__split_returns_none_if_invalid_arguments(self):
        """
        Test that given invalid arguments,
        the function returns None
        """
        ret = hubblestack.extmods.fdg.process._split(phrase=[1, 2, 3], sep=" ", regex=False)
        assert ret is None, "can't split list, should return None"
        ret = hubblestack.extmods.fdg.process._split(phrase="foo bar", sep=[1, 2, 3], regex=False)
        assert ret is None, "separator to split by can't be list, should return None"
        ret = hubblestack.extmods.fdg.process._split(phrase=[1, 2, 3], sep=" ", regex=True)
        assert ret is None, "can't split list, should return None"
        ret = hubblestack.extmods.fdg.process._split(phrase="foo bar", sep=[1, 2, 3], regex=True)
        assert ret is None, "separator to split by can't be list, should return None"

    def test__split_returns_list_from_string(self):
        """
        Test that given valid arguments,
        the function correctly splits the string into a list
        """
        # simple ``sep``
        expected_ret = ['foo', 'bar']
        ret = hubblestack.extmods.fdg.process._split("foo bar", " ", False)
        assert expected_ret == ret
        # ``sep`` simple regex
        ret = hubblestack.extmods.fdg.process._split("foo bar", " ", True)
        assert expected_ret == ret
        # regex
        ret = hubblestack.extmods.fdg.process._split("foo    bar", r"\s+", True)
        assert expected_ret == ret
        # invalid ``sep``
        expected_ret = ['foo bar']
        ret = hubblestack.extmods.fdg.process._split("foo bar", "?", False)
        assert expected_ret == ret

    def test_split_returns_none_if_invalid_arguments(self):
        """
        Test that given invalid arguments,
        the function returns None
        """
        # invalid ``words``
        status, ret = hubblestack.extmods.fdg.process.split([1, 2, 3], chained='ab')
        assert ret is None
        assert status is False
        status, ret = hubblestack.extmods.fdg.process.split({1: 'a', 2: 'b'}, chained='ab')
        assert ret is None
        assert status is False
        # invalid ``words`` & ``chained``
        status, ret = hubblestack.extmods.fdg.process.split(1, chained=12)
        assert ret is None
        assert status is False
        status, ret = hubblestack.extmods.fdg.process.split('foo bar', regex=True)
        assert ret is None
        assert status is False

    def test_split_returns_list_from_string(self):
        """
        Test that given valid arguments, the function correctly splits
        in all scenarios
        """
        expected_ret = ['a', 'b', 'c', 'd']
        # valid regex
        status, ret = hubblestack.extmods.fdg.process.split(
            phrase="a1b2c3d", sep=r"\d+", regex=True)
        assert status is True
        assert expected_ret == ret
        # simple sep
        expected_ret = ['a1', 'b2', 'c3', 'd']
        status, ret = hubblestack.extmods.fdg.process.split(
            phrase="a1 b2 {}", sep=" ", chained='c3 d')
        assert status is True
        assert expected_ret == ret
        # no sep
        expected_ret = ['a1', 'b2', 'c3', 'd']
        status, ret = hubblestack.extmods.fdg.process.split(
            phrase="a1    b2    \n{}", chained='c3 d')
        assert status is True
        assert expected_ret == ret
        # invalid regex
        expected_ret = ['a1b2c3d']
        status, ret = hubblestack.extmods.fdg.process.split(
            phrase="a1b2{}", sep=r"\d+", regex=False, chained='c3d')
        assert status is False
        assert expected_ret == ret

    def test_dict_to_list_returns_none_if_invalid_arguments(self):
        """
        Test that given invalid arguments, the function returns None
        """
        status, ret = hubblestack.extmods.fdg.process.dict_to_list(
            starting_dict={1: 'a'}, chained=[1, 2, 3])
        assert status is False
        assert ret is ret
        status, ret = hubblestack.extmods.fdg.process.dict_to_list(
            starting_dict='foo', chained={1: 'a', 2: 'b'})
        assert status is False
        assert ret is None

    def test_dict_to_list_correctly_returns_list(self):
        """
        Test that given valid arguments, the function outputs a valid list
        """
        # flat dict
        expected_ret = [(1, 'b'), (2, 'c')]
        status, ret = hubblestack.extmods.fdg.process.dict_to_list(
            starting_dict={1: 'a'}, update_chained=False, chained={1: 'b', 2: 'c'})
        assert status is True
        assert expected_ret == ret
        # nested dict
        expected_ret = [(1, 'a'), (2, 'c'), (3, {1: 'a'})]
        status, ret = hubblestack.extmods.fdg.process.dict_to_list(
            starting_dict={1: 'a', 3: {1: 'a'}}, chained={1: 'b', 2: 'c'})
        assert status is True
        assert expected_ret == ret
        # empty dict
        expected_ret = []
        status, ret = hubblestack.extmods.fdg.process.dict_to_list(chained={})
        assert status is False
        assert expected_ret == ret

    def test__dict_convert_none_returns_none_if_invalid_arguments(self):
        """
        Test that given invalid arguments, the function returns None
        """
        ret = hubblestack.extmods.fdg.process._dict_convert_none([1, 2, 3])
        assert ret is None
        ret = hubblestack.extmods.fdg.process._dict_convert_none(1)
        assert ret is None
        expected_ret = {}
        ret = hubblestack.extmods.fdg.process._dict_convert_none(defaultdict())
        assert expected_ret == ret

    def test__dict_convert_none_replaces_empty_string_with_none_in_dict(self):
        """
        Test that given valid arguments,
        the function converts empty strings to None in all scenarios
        """
        # flat dict
        expected_ret = {1: None, 2: 'a', 3: "None", 4: None}
        ret = hubblestack.extmods.fdg.process._dict_convert_none(
            {1: "", 2: 'a', 3: "None", 4: None})
        assert expected_ret == ret
        # nested dicts
        expected_ret = {'a': {'aa': {'aaa': 3, 'bbb': {'bbbb': 4, 'cccc': None},
                                    'ccc': None}, 'bb': None}, 'b': None}
        ret = hubblestack.extmods.fdg.process._dict_convert_none(
            {'a': {'aa': {'aaa': 3, 'bbb': {'bbbb': 4, 'cccc': ''},
                          'ccc': ''}, 'bb': ''}, 'b': ''})
        assert expected_ret == ret
        # nested dicts & seqs
        expected_ret = {'a': [{'b': [{'c': ['d', {'e': None}], 'f': None}, {'g': None}],
                              'h': None}, 'i'], 'j': None}
        ret = hubblestack.extmods.fdg.process._dict_convert_none(
            {'a': [{'b': ({'c': ['d', {'e': ''}], 'f': ''}, {'g': ''}),
                    'h': ''}, 'i'], 'j': ''})
        assert expected_ret == ret

    def test__seq_convert_none_returns_none_if_invalid_arguments(self):
        """
        Test that given invalid arguments, the function returns None
        """
        ret = hubblestack.extmods.fdg.process._seq_convert_none({1: 'a', 2: 'b'})
        assert ret is None
        ret = hubblestack.extmods.fdg.process._seq_convert_none(1)
        assert ret is None
        ret = hubblestack.extmods.fdg.process._seq_convert_none(True)
        assert ret is None

    def test__seq_convert_none_replaces_emtpy_strings_with_none(self):
        """
        Test that given valid arguments,
        the function correctly converts empty strings to None in all scenarios
        """
        # flat seq
        expected_ret = ['a', {1: None}, 'b', {1: None}, 'c']
        ret = hubblestack.extmods.fdg.process._seq_convert_none(
            ['a', {1: ''}, 'b', {1: ''}, 'c'])
        assert expected_ret == ret
        # nested seq & dict
        expected_ret = ['a', [{1: None, 2: [3, [4, {1: None, 2: {3: None}}]]}, 'b'], 'c']
        ret = hubblestack.extmods.fdg.process._seq_convert_none(
            ('a', [{1: '', 2: [3, (4, {1: '', 2: {3: ''}})]}, 'b'], 'c'))
        assert expected_ret == ret

    def test_dict_convert_none_returns_none_if_invalid_argument(self):
        """
        Test that given invalid arguments, the function returns None
        """
        status, ret = hubblestack.extmods.fdg.process.dict_convert_none(chained='foo bar')
        assert status is False
        assert ret is None
        status, ret = hubblestack.extmods.fdg.process.dict_convert_none(
            chained={1: 'a'}, starting_seq=[1, 2])
        assert status is False
        assert ret is None
        expected_ret = []
        status, ret = hubblestack.extmods.fdg.process.dict_convert_none(chained=[])
        assert status is False
        assert expected_ret == ret

    def test_dict_convert_none_replaces_empty_string_with_none(self):
        """
        Test that given valid arguments,
        the function returns a valid dict with None instead of empty strings
        """
        # flat dict
        expected_ret = {1: 'a', 2: None, 3: 'b', 4: None}
        status, ret = hubblestack.extmods.fdg.process.dict_convert_none(
            chained={1: 'a', 2: '', 3: 'b', 4: ''})
        assert expected_ret == ret
        assert status is True
        # nested dict & tuple
        expected_ret = {'a': [{'b': [{'c': {'e': None}, 'f': None}, {'g': None}],
                              'h': None}, 'i'], 'j': None}
        status, ret = hubblestack.extmods.fdg.process.dict_convert_none(
            chained={'a': [{'b': ({'c': {'e': ''}, 'f': ''}, {'g': ''}),
                            'h': ''}, 'i']}, starting_seq={'j': ''})
        assert status is True
        assert expected_ret == ret
        # nested dict, list & tuple
        expected_ret = ['a', [{1: None, 2: [3, [4, {1: None, 2: {3: None}}]]}, 'b'], 'c']
        status, ret = hubblestack.extmods.fdg.process.dict_convert_none(
            chained=('a', [{1: '', 2: [3, (4, {1: '', 2: {3: ''}})]}, 'b'], 'c'))
        assert status is True
        assert expected_ret == ret
        # nested dict & list
        expected_ret = ['a', {1: None}, 'b', {1: None}, 'c']
        status, ret = hubblestack.extmods.fdg.process.dict_convert_none(
            chained=['a', {1: ''}, 'b'], starting_seq=[{1: ''}, 'c'])
        assert status is True
        assert expected_ret == ret

    def test_print_string_returns_none_when_invalid_arguments(self):
        """
        Test that given invalid arguments, the function returns None
        """
        status, ret = hubblestack.extmods.fdg.process.print_string(
            starting_string=['foo', 'bar'])
        assert status is False
        assert ret is None
        expected_ret = ''
        status, ret = hubblestack.extmods.fdg.process.print_string(
            starting_string='')
        assert status is False
        assert expected_ret == ret

    def test_print_string_returns_correct_string(self):
        """
        Test that given valid arguments, the function returns the correct string
        """
        expected_ret = 'foo'
        status, ret = hubblestack.extmods.fdg.process.print_string(
            starting_string='foo', chained='bar')
        assert status is True
        assert expected_ret == ret
        expected_ret = "foo ['b', 'a', 'r']"
        status, ret = hubblestack.extmods.fdg.process.print_string(
            starting_string='foo {}', chained=['b', 'a', 'r'])
        assert status is True
        assert expected_ret == ret

    def test__sterilize_dict_returns_none_if_invalid_arguments(self):
        """
        Test that given invalid arguments, the function returns None
        """
        ret = hubblestack.extmods.fdg.process._sterilize_dict(dictionary=[1, 2])
        assert ret is None
        ret = hubblestack.extmods.fdg.process._sterilize_dict(dictionary={})
        assert ret == {}
        ret = hubblestack.extmods.fdg.process._sterilize_dict(dictionary=12)
        assert ret is None

    def test__sterilize_dict_removes_none_values_if_nested_dict(self):
        """
        Test that given valid arguments,
        the function correctly removes keys containing values of None
        """
        # flat dict
        expected_ret = {2: 'a'}
        ret = hubblestack.extmods.fdg.process._sterilize_dict(
            {1: None, 2: 'a'})
        assert expected_ret == ret
        # nested dicts
        expected_ret = {2: {3: {5: 'a'}, 7: 'b'}, 8: 'c', 9: {}}
        ret = hubblestack.extmods.fdg.process._sterilize_dict(
            {1: None, 2: {3: {4: None, 5: 'a'}, 6: None, 7: 'b'}, 8: 'c', 9: {10: None}})
        assert expected_ret == ret
        # nested dicts & sequences
        expected_ret = {2: {3: [4, {}], 6: {7: ['b', {}]}}}
        ret = hubblestack.extmods.fdg.process._sterilize_dict(
            {1: None, 2: {3: [4, {5: None}], 6: {7: ('b', {9: None}), 8: None}}})
        assert expected_ret == ret

    def test__sterilize_seq_returns_none_if_arguments_are_invalid(self):
        """
        Test that given invalid arguments, the function returns None
        """
        ret = hubblestack.extmods.fdg.process._sterilize_seq(
            {1: 'a', 2: ['b']})
        assert ret is None
        ret = hubblestack.extmods.fdg.process._sterilize_seq(12)
        assert ret is None
        ret = hubblestack.extmods.fdg.process._sterilize_seq([])
        assert ret == []

    def test__sterilize_seq_removes_none_values_from_seq(self):
        """
        Test that given valid arguments,
        the function finds nested dicts and removes keys with values of None
        """
        # flat seq
        expected_ret = [1, 2, [1, 2], [1, 2]]
        ret = hubblestack.extmods.fdg.process._sterilize_seq(
            [1, 2, set([1, 2, 1]), (1, 2)])
        assert expected_ret == ret
        # nested dicts & seq
        expected_ret = [{2: {3: [{5: 'a'}, [None, {7: 'b'}]], 8: 'c', 9: {}}}]
        ret = hubblestack.extmods.fdg.process._sterilize_seq(
            [{1: None, 2: {3: ({4: None, 5: 'a'}, [None, {6: None, 7: 'b'}]),
                           8: 'c', 9: {10: None}}}])
        assert expected_ret == ret

    def test_remove_dict_none_returns_none_if_invalid_arguments(self):
        """
        Test that given invalid arguments, the function returns None
        """
        # invalid ``starting_seq``
        status, ret = hubblestack.extmods.fdg.process.dict_remove_none(
            starting_seq=[1, 2, 3], chained={1: 'a', 2: 'b'})
        assert status is False
        assert ret is None
        # invalid ``chained`` & valid ``starting_seq``
        status, ret = hubblestack.extmods.fdg.process.dict_remove_none(
            starting_seq=[1, 2, 3], chained="123")
        assert status is False
        assert ret is None
        # invalid ``chained``
        status, ret = hubblestack.extmods.fdg.process.dict_remove_none(chained="123")
        assert status is False
        assert ret is None

    def test_dict_remove_none_returns_valid_sequence(self):
        """
        Test that given valid arguments, the function finds nested dicts
        and removes keys with values of None
        """
        # flat dict
        expected_ret = {2: 'a', 4: 'b'}
        status, ret = hubblestack.extmods.fdg.process.dict_remove_none(
            chained={1: None, 2: 'a', 3: None, 4: 'b'})
        assert status is True
        assert expected_ret == ret
        # flat seq
        expected_ret = [{}, {2: 'a'}, 5, None, {4: 'b'}]
        status, ret = hubblestack.extmods.fdg.process.dict_remove_none(
            chained=[{1: None}, {2: 'a', 3: None}],
            starting_seq=[5, None, {4: 'b'}])
        assert status is True
        assert expected_ret == ret
        # nested sequences & dicts
        expected_ret = [{9: {11: [1, 2]}}, 11, {2: {3: [{5: 'a'}, [None, {7: 'b'}]], 8: 'c'}}]
        status, ret = hubblestack.extmods.fdg.process.dict_remove_none(
            starting_seq=[{1: None, 2: {3: ({4: None, 5: 'a'},
                                            [None, {6: None, 7: 'b'}]), 8: 'c'}}],
            chained=[{9: {10: None, 11: set([1, 2, 1])}}, 11])
        assert status is True
        assert expected_ret == ret
        # nested dicts & sequences
        expected_ret = {2: {3: [{5: 'a'}, [None, {7: 'b'}]], 8: 'c'}, 9: {11: [1, 2]}}
        status, ret = hubblestack.extmods.fdg.process.dict_remove_none(
            starting_seq={1: None, 2: {3: ({4: None, 5: 'a'}, [None, {6: None, 7: 'b'}]), 8: 'c'}},
            chained={9: {10: None, 11: set([1, 2, 1])}, 11: None})
        assert status is True
        assert expected_ret == ret

    def test_encode_base64_returns_none_if_invalid_arguments_type(self):
        """
        Test that given invalid arguments, the function returns None
        """
        # invalid `starting_string`
        status, ret = hubblestack.extmods.fdg.process.encode_base64(
            starting_string=123, chained="foo")
        assert status is False
        assert ret is None
        status, ret = hubblestack.extmods.fdg.process.encode_base64(
            starting_string=['a', 'c'], format_chained=False)
        assert status is False
        assert ret is None
        expected_ret = ''
        status, ret = hubblestack.extmods.fdg.process.encode_base64(
            starting_string='', format_chained=False)
        assert status is False
        assert expected_ret == ret

    def test_encode_base64_returns_string_if_valid_arguments(self):
        """
        Test that given valid arguments, the function correctly encodes the string and returns it
        """
        # format chained
        expected_ret = 'Zm9vIGJhcg=='
        status, ret = hubblestack.extmods.fdg.process.encode_base64(
            starting_string="foo {}", chained="bar")
        assert status is True
        assert expected_ret == ret
        # don't format chained
        expected_ret = 'Zm9v'
        status, ret = hubblestack.extmods.fdg.process.encode_base64(
            starting_string="foo", chained="bar")
        assert status is True
        assert expected_ret == ret
        # no chained
        expected_ret = 'Zm9vIHt9'
        status, ret = hubblestack.extmods.fdg.process.encode_base64(
            starting_string="foo {}", format_chained=False, chained="bar")
        assert status is True
        assert expected_ret == ret
