import threading

from hubblestack.filter.base import BaseFilter
import hubblestack.version

class Filter(BaseFilter):
    """
    A Filter for adding a sequence number 'seq' to each message
    """

    DEFAULT_LABEL = "hubble_version"

    def __init__(self, name, config=None):
        super().__init__(name, self.DEFAULT_LABEL, config)

    def filter(self, msg):
        """
        add a sequence number if the msg does not have one already
        """
        if self.get_label() not in msg.keys():
            msg[self.get_label()] = hubblestack.version.__version__
        return msg

    
