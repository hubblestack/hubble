# coding: utf-8

import os
import json
import mock
from hubblestack.hec import HEC

TEST_DQ_DIR = os.environ.get('TEST_DQ_DIR', '/tmp/dq.{0}'.format(os.getuid()))

@mock.patch.object(HEC, '_send')
def test_hec__send_trivially(mock_send):
    hec = HEC('token', 'index', 'server')
    hec.sendEvent({'test': 'test-tacular'})
    assert json.loads(mock_send.call_args.args[0].dat)['test'] == 'test-tacular'

@mock.patch.object(HEC, '_send') # just in case, not actually used
def test_queue_things_with_compression(mock_send, __opts__, __salt__):
    hec = HEC('token', 'index', 'server',
        disk_queue=TEST_DQ_DIR, disk_queue_size=1000,
        disk_queue_compression=9)

    results_of_side_effect = list()
    def side_effect(x):
        results_of_side_effect.append(x)
    mock_send.side_effect = side_effect

    gz = list()
    for i in range(100):
        dat = {f'event{i}': f'test{i}'}
        hec.queueEvent(dat)
        gz.append( json.dumps(dat) )
    hec.flushQueue()
    assert ' '.join(results_of_side_effect) == ' '.join(gz)
