import hubblestack.filter.filter

class Filter(hubblestack.filter.filter.Filter):
    """
    A Filter for adding a sequence number 'seq' to each message
    """

    def __init__(self, filter_name, config=None):
      super().__init__(filter_name, config)
      self.config = config

    cnt = 0

    def filter(self, msg):
        """
           add a sequence number if the msg does not have one already
        """
        if self.getLabel() not in msg.keys():
          msg[self.getLabel()] = self.getNextValue()
        return msg

    def getNextValue(self):
        self.cnt = self.cnt + 1  # TODO: thread safety
        value = str(self.cnt).rjust(self.getPadding(), "0")
        return value

    def getPadding(self):
      if "padding" in self.config:
        return int(self.config["padding"])
      return 0

