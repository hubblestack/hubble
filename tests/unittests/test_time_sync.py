

import mock
import os
import hubblestack.extmods.fdg.time_sync

class TestTimesync():
    '''
    Class used to test the functions in ``time_sync.py``
    '''

    @mock.patch('hubblestack.extmods.fdg.time_sync._query_ntp_server')
    def test_timeCheck_invalidInput_falseReturn(self, mock_offset):
        '''
        Test that given invalid arguments - an error occurred while querying the servers
        and not enough servers are verified, the function returns False, False
        '''
        mock_offset.return_value = None
        status, ret = hubblestack.extmods.fdg.time_sync.time_check(['dummy.ntp.org'],
                                                                   extend_chained=False)
        assert status is False
        assert ret is False

    def test_timeCheck_emptyInputList_emptyReturn(self):
        '''
        Test that given an empty list of NTP servers,
        the function returns False, None
        '''
        status, ret = hubblestack.extmods.fdg.time_sync.time_check([])
        assert status is False
        assert ret is None

    @mock.patch('hubblestack.extmods.fdg.time_sync._query_ntp_server')
    def test_timeCheck_invalidOffset_falseReturn(self, mock_offset):
        '''
        Test that when a server reports an offset that exceeds the limit,
        the function returns True, False
        '''
        mock_offset.return_value = 123
        status, ret = hubblestack.extmods.fdg.time_sync.time_check(
            ntp_servers=['dummy.ntp.org'], max_offset=0.01, nb_servers=1, extend_chained=False)
        assert status is True
        assert ret is False

    @mock.patch('hubblestack.extmods.fdg.time_sync._query_ntp_server')
    def test_timeCheck_invalidNbServers_falseReturn(self, mock_offset):
        '''
        Test that when not enough servers are queried,
        the function returns False, False
        '''
        mock_offset.return_value = 0.001
        status, ret = hubblestack.extmods.fdg.time_sync.time_check(
            ntp_servers=['dummy.ntp.org'], max_offset=1, nb_servers=4, extend_chained=False)
        assert status is False
        assert ret is False

    def test__queryNtpServer_validServer_validReturn(self):
        '''
        Test that when a valid NTP server is passed,
        the query is successful
        '''
        offset = hubblestack.extmods.fdg.time_sync._query_ntp_server('0.pool.ntp.org')
        assert offset is not None
        assert isinstance(offset, float)

    def test__queryNtpServer_invalidServer_emptyReturn(self):
        '''
        Test that when a valid NTP server is passed,
        the query is successful
        '''
        offset = hubblestack.extmods.fdg.time_sync._query_ntp_server('dummy.pool.ntp.org')
        assert offset is None
