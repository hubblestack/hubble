class Filter:
    """
    Base class for filtering messages before being emitted to logging systems
    """

    def __init__(self, filter_name, default_label, config=None):
        self.filter_name = filter_name
        self.default_label = default_label
        if config != None:
            self.config = config.copy()
        else:
            self.config = {}

    def _process_config(self, config=None):
        if config == None:
            return

    def getLabel(self):
        return self.config.get("label", self.default_label)

    def get_subclass_name(self):
        return self.__class__.__name__
