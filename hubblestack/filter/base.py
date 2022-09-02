class BaseFilter:
    """
    Base class for filtering messages before being emitted to logging systems
    """

    def __init__(self, name, default_label, config=None):
        self.name = name
        self.default_label = default_label
        self.config = {} if not config else config.copy()

    def _process_config(self, config=None):
        if config == None:
            return

    def get_label(self):
        return self.config.get("label", self.default_label)

    def get_subclass_name(self):
        return self.__class__.__name__
