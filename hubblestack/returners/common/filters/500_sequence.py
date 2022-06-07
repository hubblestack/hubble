
from .. import filter

class Filter(filter.Filter):
    """
    A Filter for adding a sequence number 'seq' to each message
    """

    cnt = 0

    def filter(self, msg):
        """
           add a sequence number if the msg does not have one already
        """
        if 'seq' not in msg.keys():
          self.cnt = self.cnt + 1 
          msg['seq'] = self.cnt
        return msg

