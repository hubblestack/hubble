

import mock
import os

import hubblestack.extmods.fdg.process_status

class TestProcessStatus():
    """
    Class used to test the functions in ``process_status.py``
    """

    @mock.patch('hubblestack.extmods.fdg.process_status._run_query')
    def test_listProcesses_validReturn(self, mock_query):
        """
        Test that the function returns the correct value when the osquery returns a valid value.

        mock_query
            mock function for the `_run_query` function
        """
        mock_query.return_value = {'data': [{'pid': '123', 'name': 'foo'},
                                            {'pid': '321', 'name': 'bar'}],
                                   'result': True}
        status, ret = hubblestack.extmods.fdg.process_status.list_processes()
        assert status
        assert ret == [{'pid': '123', 'name': 'foo'},
                       {'pid': '321', 'name': 'bar'}]

    @mock.patch('hubblestack.extmods.fdg.process_status._run_query')
    def test_listProcesses_invalidReturn(self, mock_query):
        """
        Test that when the osquery call fails, the function returns False, None.

        mock_query
            mock function for the `_run_query` function
        """
        mock_query.return_value = None
        status, ret = hubblestack.extmods.fdg.process_status.list_processes()
        assert status is False
        assert ret is None

    def test__convertToStr_validDict_returnsValidDict(self):
        """
        Test that when passed in valid data, it returns a dict with keys and values converted to string.
        """
        ret = hubblestack.extmods.fdg.process_status._convert_to_str([{'pid': 123}, {'data': [1, 2, 3]}])
        assert ret == [{'pid': '123'}, {'data': '[1, 2, 3]'}]

    def test__convertToStr_invalidArguments_returnsNone(self):
        """
        Test that when passed in an invalid data type, the function returns none
        """
        ret = hubblestack.extmods.fdg.process_status._convert_to_str({'pid': 123, 'data': [1, 2, 3]})
        assert ret is None
        ret = hubblestack.extmods.fdg.process_status._convert_to_str([123, 321, 'foo'])
        assert ret is None
        ret = hubblestack.extmods.fdg.process_status._convert_to_str('foo bar')
        assert ret is None
        ret = hubblestack.extmods.fdg.process_status._convert_to_str(None)
        assert ret is None

    @mock.patch('hubblestack.extmods.fdg.process_status._run_query')
    def test_findProcess_invalidArguments_returnsNone(self, mock_query):
        """
        Test that given invalid arguments, the function returns False, None

        mock_query
            mock function for the `_run_query` function
        """
        mock_query.return_value = None
        status, ret = hubblestack.extmods.fdg.process_status.find_process('foo == bar')
        assert status is False
        assert ret is None
        status, ret = hubblestack.extmods.fdg.process_status.find_process('pid == 123', fields='foo,bar')
        assert status is False
        assert ret is None

    @mock.patch('hubblestack.extmods.fdg.process_status._run_query')
    def test_findProcess_validArguments_returnsListOfDicts(self, mock_query):
        """
        Test that given valid arguments, the function correctly returns the list of filtered processes

        mock_query
            mock function for the `_run_query` function
        """
        mock_query.return_value = {'data': [{'pid': '123', 'name': 'bar'},
                                            {'pid': '321', 'name': 'foo'}],
                                   'result': True}

        status, ret = hubblestack.extmods.fdg.process_status.find_process("state == 'S'")
        assert status
        assert ret == [{'pid': '123', 'name': 'bar'}, {'pid': '321', 'name': 'foo'}]
        mock_query.return_value = {'data': [{'pid': '123', 'name': 'bar', 'parent': '1', 'state': 'S'},
                                            {'pid': '321', 'name': 'foo', 'parent': '1', 'state': 'S'}],
                                   'result': True}
        status, ret = hubblestack.extmods.fdg.process_status.find_process("parent == 1 and state == 'S'",
                                                                          fields='parent,state')
        assert status
        assert ret == [{'pid': '123', 'name': 'bar', 'parent': '1', 'state': 'S'},
                       {'pid': '321', 'name': 'foo', 'parent': '1', 'state': 'S'}]
        mock_query.return_value = {'data': [], 'result': True}
        status, ret = hubblestack.extmods.fdg.process_status.find_process("parent == 1 and state == 'foo'",
                                                                          fields='parent,state')
        assert status is False
        assert ret is None

    @mock.patch('hubblestack.extmods.fdg.process_status._run_query')
    def test_isRunning_invalidArguments_returnsNone(self, mock_query):
        """
        Test that given invalid arguments, the function returns False, None

        mock_query
            mock function for the `_run_query` function
        """
        # error in call (e.g. invalid query)
        mock_query.return_value = None
        status, ret = hubblestack.extmods.fdg.process_status.is_running('foo == bar')
        assert status is False
        assert ret is None
        # multiple processes returned by query
        mock_query.return_value = {'data': [{'state': 'S'}, {'state': 'R'}]}
        status, ret = hubblestack.extmods.fdg.process_status.is_running('parent > 1')
        assert status is False
        assert ret is None
        # no processes returned by query
        mock_query.return_value = {'data': []}
        status, ret = hubblestack.extmods.fdg.process_status.is_running('parent > 1')
        assert status is False
        assert ret is False

    @mock.patch('hubblestack.extmods.fdg.process_status._run_query')
    def test_isRunning_validArguments_validReturn(self, mock_query):
        """
        Test that given valid arguments, the function correctly asserts the process' state

        mock_query
            mock function for the `_run_query` function
        """
        # process is running
        mock_query.return_value = {'data': [{'state': 'R'}]}
        status, ret = hubblestack.extmods.fdg.process_status.is_running('pid == 123')
        assert status
        assert ret
        # process is not running
        mock_query.return_value = {'data': [{'state': 'S'}]}
        status, ret = hubblestack.extmods.fdg.process_status.is_running("name == 'foo'")
        assert status
        assert ret is False

    @mock.patch('hubblestack.extmods.fdg.process_status._run_query')
    def test_findChildren_invalidArguments_returnsNone(self, mock_query):
        """
        Test that given invalid arguments, the function returns False, None

        mock_query
            mock function for the `_run_query` function
        """
        mock_query.return_value = None
        status, ret = hubblestack.extmods.fdg.process_status.find_children("name == 'foo'")
        assert status is False
        assert ret is None
        mock_query.return_value = {'data': [], 'result': True}
        status, ret = hubblestack.extmods.fdg.process_status.find_children("name == 'bar'")
        assert status is False
        assert ret is None


    @mock.patch('hubblestack.extmods.fdg.process_status._run_query')
    def test_findChildren_validArguments_validReturn(self, mock_query):
        """
        Test that given valid arguments for each field, the function returns a valid list of processes

        mock_query
            mock function for the `_run_query` function
        """
        mock_query.return_value = {'data': [{'pid': '123', 'name': 'foo', 'uid': '123'},
                                            {'pid': '321', 'name': 'bar', 'uid': '123'}],
                                   'result': True}
        status, ret = hubblestack.extmods.fdg.process_status.find_children('foo', returned_fields='uid')
        assert status
        assert ret == [{'pid': '123', 'name': 'foo', 'uid': '123'},
                       {'pid': '321', 'name': 'bar', 'uid': '123'}]
        status, ret = hubblestack.extmods.fdg.process_status.find_children('123', parent_field='gid', returned_fields='uid')
        assert status
        assert ret == [{'pid': '123', 'name': 'foo', 'uid': '123'},
                       {'pid': '321', 'name': 'bar', 'uid': '123'}]
