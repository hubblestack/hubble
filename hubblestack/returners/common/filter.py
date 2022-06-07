
from os import listdir
from os.path import dirname, isfile, join
import importlib
import logging as log


class MessageFilter:
   _instance = {}

   def __init__(self):
       """
         MessageFilter is to be singleton per flow
       """
       raise RuntimeError('Call instance() instead')

   @classmethod
   def instance(cls, flow):
       """
         Create a get or create a new instance of MessageFilter
       """
       if flow not in cls._instance.keys():
            cls._instance[flow] = cls.__new__(cls)
            cls._instance[flow]._filters = []
       return cls._instance[flow]

   _filters = None



   def _get_filters(self):
        """
          Get the filter objects for this flow
        """

        if len(self._filters) > 0:
            return self._filters

        # TODO: maybe check the filters directory every N minutes for new filters to add

        filters_dir = join(dirname(__file__), 'filters')

        files = [f for f in listdir(filters_dir) if isfile(join(filters_dir, f)) and f.endswith('.py') and '__init__' not in f]

        base_module = 'hubblestack.returners.common.filters.'
        for f in files:
            try:
                # example: hubblestack.returners.common.filters.sequence
                module = base_module + f.split('.')[0] 
                log.info("found module %s" % module)
                _filter = getattr(importlib.import_module(module), "Filter")()
                self._filters.append(_filter)
            except Exception as e:
                log.error(e)

        return self._filters

        

   def filter(self, msg):

        _msg = msg.copy()
        for f in self._get_filters():
            if _msg is not None:
                _msg = f.filter(_msg)
        return _msg


class Filter:
    def filter(self):
        pass
