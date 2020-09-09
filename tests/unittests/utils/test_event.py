# -*- coding: utf-8 -*-
'''
    :codeauthor: Pedro Algarvio (pedro@algarvio.me)


    tests.unit.utils.event_test
    ~~~~~~~~~~~~~~~~~~~~~~~~~~~
'''

# Import python libs
from __future__ import absolute_import, unicode_literals, print_function
import os
import time
import zmq.eventloop.ioloop
# support pyzmq 13.0.x, TODO: remove once we force people to 14.0.x
if not hasattr(zmq.eventloop.ioloop, 'ZMQIOLoop'):
    zmq.eventloop.ioloop.ZMQIOLoop = zmq.eventloop.ioloop.IOLoop
from contextlib import contextmanager
from multiprocessing import Process

from tests.support.unit import expectedFailure, skipIf, TestCase

import hubblestack.utils.event
import tests.integration as integration
from hubblestack.utils.process import clean_proc

SOCK_DIR = os.path.join(integration.TMP, 'test-socks')

NO_LONG_IPC = False
if getattr(zmq, 'IPC_PATH_MAX_LEN', 103) <= 103:
    NO_LONG_IPC = True


class EventSender(Process):
    def __init__(self, data, tag, wait):
        super(EventSender, self).__init__()
        self.data = data
        self.tag = tag
        self.wait = wait

    def run(self):
        me = hubblestack.utils.event.MasterEvent(SOCK_DIR, listen=False)
        time.sleep(self.wait)
        me.fire_event(self.data, self.tag)
        # Wait a few seconds before tearing down the zmq context
        if os.environ.get('TRAVIS_PYTHON_VERSION', None) is not None:
            # Travis is slow
            time.sleep(10)
        else:
            time.sleep(2)


@contextmanager
def eventsender_process(data, tag, wait=0):
    proc = EventSender(data, tag, wait)
    proc.start()
    try:
        yield
    finally:
        clean_proc(proc)


@skipIf(NO_LONG_IPC, "This system does not support long IPC paths. Skipping event tests!")
class TestSaltEvent(TestCase):
    def setUp(self):
        if not os.path.exists(SOCK_DIR):
            os.makedirs(SOCK_DIR)

    def assertGotEvent(self, evt, data, msg=None):
        self.assertIsNotNone(evt, msg)
        for key in data:
            self.assertIn(key, evt, '{0}: Key {1} missing'.format(msg, key))
            assertMsg = '{0}: Key {1} value mismatch, {2} != {3}'
            assertMsg = assertMsg.format(msg, key, data[key], evt[key])
            self.assertEqual(data[key], evt[key], assertMsg)

    def test_master_event(self):
        me = hubblestack.utils.event.MasterEvent(SOCK_DIR, listen=False)
        self.assertEqual(
            me.puburi, '{0}'.format(
                os.path.join(SOCK_DIR, 'master_event_pub.ipc')
            )
        )
        self.assertEqual(
            me.pulluri,
            '{0}'.format(
                os.path.join(SOCK_DIR, 'master_event_pull.ipc')
            )
        )