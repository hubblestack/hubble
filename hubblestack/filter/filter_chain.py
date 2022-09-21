##

import importlib
import logging
import yaml

import hubblestack.filter.seq_id as seq_id
from hubblestack.exceptions import CommandExecutionError
import hubblestack.modules.cp

log = logging.getLogger(__name__)

chains = {}

class FilterChain:
    """
    FilterChain loads the filter config from the hubble profile filter_chain.yaml
    This configuraiton file will have a default configuration, as well as options for
    overriding with returner specific filter order
    example:

    default:
      sequence:   # Label
        type: "hubblestack.filter.seq_id" # filter type
        label: "seq" # optional: what field name to add
        padding: 10 # seq: 0000000001, 0000000002
    """

    def __init__(self, config_path, config_label="default"):
        """
        config_path - path to yaml file defining the configuration for the filter chain
        config_label - the label in the yaml file underwhich the filters and their configurations are located
        """
        self.config_path = config_path
        self.config_label = config_label

        # force the loading of the config.  # anti-pattern
        self._config = self.config
        self._chain = None

    @property
    def config(self):
        self.cached_path = __mods__["cp.cache_file"](self.config_path)

        try:
            with open(self.cached_path, 'r') as handle:
                yaml_config = yaml.safe_load(handle)
        except Exception as e:
            yaml__config = {"default": {"filter": { "default": {
                 "sequence_id": { "label": "seq", "type": "hubblestack.filter.seq_id" },
                 "hubble_version": { "label": "hubble_version", "type": "hubblestack.filter.hubble_version"},
                 "filter_error": { "label": "load_error", "type": "hubblestack.filter.static_value", "value": "true"}}}}}
            raise CommandExecutionError(f"Could not load filter config: {e}")

        if not isinstance(yaml_config, dict) or \
            "filter" not in yaml_config or \
            not(isinstance(yaml_config["filter"], dict)) or \
            self.config_label not in yaml_config["filter"].keys() or \
            not(isinstance(yaml_config["filter"][self.config_label], dict)):
            raise CommandExecutionError("FilterChain config not formatted correctly")

        yaml_config = yaml_config['filter'][self.config_label]

        return yaml_config

    @property
    def chain(self):
        if self._chain is None or len(self._chain) == 0:
            _chain = []
            for filter_name in self.config:
                new_fltr = self._get_filter_class(self.config[filter_name]["type"])(filter_name, self.config[filter_name])
                _chain.append(new_fltr)
            self._chain = _chain
        return self._chain


    def filter(self, msg=None):
        for filter in self.chain:
            try:
                filter.filter(msg)
            except Exception as e:
                log.error(f"Error processing filters: {e}")
        log.debug(msg)

    def _get_filter_class(self, filter_tag):
        module = importlib.import_module(filter_tag)
        return getattr(module, "Filter")

    @staticmethod
    def get_chain(chain_name, filter_path="salt://filter_chain.yaml"):
        if chain_name not in chains.keys():
            log.info(f"REBUILDING CHAINS for {chain_name}")
            chains[chain_name] = FilterChain(filter_path)
        log.info(f"GOT CHAIN {chain_name}")

        return chains[chain_name]
