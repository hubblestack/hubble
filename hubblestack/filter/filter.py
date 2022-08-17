class Filter:
    """
    Base class for filtering messages before being emitted to logging systems
    """

    def __init__(self, filter_name, config=None):
        self._process_config(config)
        self.filter_name = filter_name

    def _process_config(self, config=None):
        if config == None:
            return

        if "label" in config:
            self.label = config["label"]

    def getLabel(self):
        return self.label
