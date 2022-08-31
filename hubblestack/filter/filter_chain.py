##

import importlib
import logging
import yaml

import hubblestack.filter.seq_id as seq_id
from hubblestack.exceptions import CommandExecutionError
import hubblestack.modules.cp

log = logging.getLogger(__name__)

chains = {}

def get_chain(chain_name):
    if chain_name not in chains.keys():
        log.info("REBUILDING CHAINS for %s" % chain_name)
        chains[chain_name] = FilterChain("filter_chain.yaml")
    log.info("GOT CHAIN %s" % chain_name)

    return chains[chain_name]


class FilterChain:
    """
    FilterChain is to loads the filter config from the hubble profile filterchain.yaml
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
        self.config_path = config_path
        self.config_label = config_label
        self.config = {}
        self._load_config()

    def _load_config(self):
        try:
            config_path = "salt://filter_chain.yaml"
            config_path = __mods__['cp.cache_file'](config_path)
            try:
                with open(config_path, 'r') as handle:
                    self.config = yaml.safe_load(handle)
            except Exception as e:
                self.config = {"default": {"filter": { "default": {
                     "sequence_id": { "label": "seq", "type": "hubblestack.filter.seq_id" },
                     "hubble_version": { "label": "hubble_version", "type": "hubblestack.hubble_version"}}}}}
                raise CommandExecutionError('Could not load topfile: {0}'.format(e))


            if not isinstance(self.config, dict) or \
                "filter" not in self.config or \
                not(isinstance(self.config["filter"], dict)) or \
                self.config_label not in self.config["filter"].keys() or \
                not(isinstance(self.config["filter"][self.config_label], dict)):
                raise CommandExecutionError("FilterChain config not formatted correctly")

            self.config = self.config['filter'][self.config_label]

            self._initialize_chain()
        except Exception as e:
            log.error(e)
            self.config = None


    def _initialize_chain(self):
        self.chain = []

        for filter_tag in self.config:
            new_fltr = self._get_filter_class(self.config[filter_tag]["type"])(filter_tag, self.config[filter_tag])
            self.chain.append(new_fltr)

    def filter(self, msg=None):
        if self.config == None:
            self._load_config()
        if self.config != None:
            for filter in self.chain:
                filter.filter(msg)
            log.info("FILTERED")

    def _get_filter_class(self, filter_tag):
        module = importlib.import_module(filter_tag)
        return getattr(module, "Filter")
