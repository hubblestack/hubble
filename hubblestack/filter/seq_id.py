import logging
import threading

import hubblestack.filter.filter

log = logging.getLogger(__name__)

class Filter(hubblestack.filter.filter.Filter):
    """
    A Filter for adding a sequence number 'seq' to each message
    """

    DEFAULT_LABEL = "seq"

    def __init__(self, filter_name, config=None):
        super().__init__(filter_name, self.DEFAULT_LABEL, config)
        self.config = config
        self.semaphore = threading.Semaphore(1)

    cnt = 0

    def filter(self, msg):
        """
        add a sequence number if the msg does not have one already
        """
        if self.getLabel() not in msg.keys():
            msg[self.getLabel()] = self.getNextValue()
            log.info(msg)
        return msg

    def getNextValue(self):
        my_cnt = None
        with self.semaphore:
            self.cnt = self.cnt + 1
            my_cnt = self.cnt

        value = str(my_cnt).rjust(self.getPadding(), "0")
        return value

    def getPadding(self):
        if "padding" in self.config:
            return int(self.config["padding"])
        return 0
