import logging
import threading

import hubblestack.filter.filter
import hubblestack.version

log = logging.getLogger(__name__)

class Filter(hubblestack.filter.filter.Filter):
    """
    A Filter for adding a sequence number 'seq' to each message
    """

    DEFAULT_LABEL = "hubble_version"

    def __init__(self, filter_name, config=None):
        super().__init__(filter_name, self.DEFAULT_LABEL, config)
        self.config = config

    def filter(self, msg):
        """
        add a sequence number if the msg does not have one already
        """
        if self.getLabel() not in msg.keys():
            msg[self.getLabel()] = hubblestack.version.__version__
            log.info(msg)
        return msg

    def getNextValue(self):
        my_cnt = None
        with self.semaphore:
            self.cnt = self.cnt + 1
            my_cnt = self.cnt

        value = str(my_cnt).rjust(self.getPadding(), "0")
        return value

