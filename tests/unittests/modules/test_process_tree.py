import mock
import os

import hubblestack.modules.process_tree as process_tree


class TestProcessTree:
    """
    Class used to test the functions in ``process_tree.py``
    """

    @mock.patch("hubblestack.fdg.process_status._run_query")
    def test_tree_valid(self, mock_query):
        """
        Test that the function returns the correct value when the osquery returns a valid value.
        """
        mock_query.return_value = {
            "data": [
                {"ppid": "123", "pname": "foo", "pid": "321", "name": "oof"},
                {"ppid": "123", "pname": "foo", "pid": "213", "name": "ofo"},
                {"ppid": "1", "pname": "bar", "pid": "111", "name": "rab"},
            ],
            "result": True,
        }
        ret = process_tree.tree()
        print(ret)
        expect_events = [
            {"pid": "123", "name": "foo", "children": [{"pid": "321", "name": "oof"}, {"pid": "213", "name": "ofo"}]},
            {"pid": "1", "name": "bar", "children": [{"pid": "111", "name": "rab"}]},
        ]
        assert ret["events"] == expect_events

    @mock.patch("hubblestack.fdg.process_status._run_query")
    def test_tree_invalid(self, mock_query):
        """
        Test that when the osquery call fails, the function returns None.
        """
        mock_query.return_value = None
        ret = process_tree.tree()
        assert ret is None
