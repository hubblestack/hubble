import logging
import threading

from hubblestack.filter.base import BaseFilter

log = logging.getLogger(__name__)

class Filter(BaseFilter):
    """
    A Filter for adding a sequence number 'seq' to each message
    """

    DEFAULT_LABEL = "seq"
    current_seq = 0

    def __init__(self, name, config=None):
        super().__init__(name, self.DEFAULT_LABEL, config)
        self.semaphore = threading.Semaphore(1)

 
    def filter(self, msg):
        """
        add a sequence number if the msg does not have one already
        """
        if self.get_label() not in msg.keys():
            msg[self.get_label()] = self.get_next_value()
            log.info(msg)
        return msg

    def get_next_value(self):
        my_seq = None
        with self.semaphore:
            self.current_seq = self.current_seq + 1
            my_seq = self.current_seq

        value = str(my_seq).rjust(self.get_padding(), "0")
        return value

    def get_padding(self):
        if "padding" in self.config:
            return int(self.config["padding"])
        return 0
