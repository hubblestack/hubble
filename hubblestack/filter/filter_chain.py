##

import yaml

import hubblestack.filter.seq_id as seq_id

class FilterChain:
    """
    FIlterChain is to loads the filter config from the hubble profile filterchain.yaml
    This configuraiton file will have a default configuration, as well as options for 
    overriding with returner specific filter order
    example:

    default:
      sequence:   # Label
        type: sequence # filter type
        field: "seq" # optional: what field name to add
        prefix: seq_ # a prefix value to add to all.   seq_1, seq_2, seq_3
        digits: 10 # seq: seq_0000000001, seq_0000000002
    """
    def __init__(self, config_path, config_label="default"):
        """
          config_path - path to yaml file defining the configuration for the filter chain
          config_label - the label in the yaml file underwhich the filters and their configurations are located
        """
        self._load_config(config_path, config_label)
        self._initialize_chain()
    
    def _load_config(self, config_path, config_label):
        with open(config_path, 'r') as config_file:
            loaded_config = yaml.safe_load(config_file)
            self.filter_config = loaded_config[config_label]

    def _initialize_chain(self):
      self.chain = []

      for filter_tag in self.filter_config:
        new_fltr = seq_id.Filter(filter_tag, self.filter_config[filter_tag])
        self.chain.append(new_fltr)

