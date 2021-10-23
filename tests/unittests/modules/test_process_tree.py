import mock
import os


class TestProcessTree:
    """
    Class used to test the functions in ``process_tree.py``
    """

    @mock.patch("hubblestack.fdg.process_status._run_query")
    def test_tree_valid(self, mock_query, __mods__):
        """
        Test that the function returns the correct value when the osquery returns a valid value.
        """
        proc_d4 = {"pid": "4", "name": "d", "ppid": "3"}
        proc_c3 = {"pid": "3", "name": "c", "ppid": "1"}
        proc_b2 = {"pid": "2", "name": "b", "ppid": "1"}
        proc_a1 = {"pid": "1", "name": "a", "ppid": "0"}
        mock_query.return_value = {
            "data": [proc_a1, proc_b2, proc_c3, proc_d4],
            "result": True,
        }

        def reformat_for_events(pid=None, name=None, ancestors=[], **_):
            if ancestors is None:
                return dict(pid=pid, name=name)
            return dict(pid=pid, name=name, ancestors=[reformat_for_events(**x, ancestors=None) for x in ancestors])

        ret = __mods__["process_tree.tree"]()
        expect_events = [
            reformat_for_events(**proc_a1),
            reformat_for_events(**proc_b2, ancestors=[proc_a1]),
            reformat_for_events(**proc_c3, ancestors=[proc_a1]),
            reformat_for_events(**proc_d4, ancestors=[proc_c3, proc_a1]),
        ]
        assert ret["events"] == expect_events

    @mock.patch("hubblestack.fdg.process_status._run_query")
    def test_tree_invalid(self, mock_query, __mods__):
        """
        Test that when the osquery call fails, the function returns None.
        """
        mock_query.return_value = None
        ret = __mods__["process_tree.tree"]()
        assert ret is None
