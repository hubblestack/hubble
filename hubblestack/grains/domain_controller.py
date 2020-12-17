"""
HubbleStack Domain Controller Grain.
CLI Usage - hubble grains.get domain_controller
Example Output - {u'domain_controller': True}
Author - Devansh Gupta (devagupt@adobe.com)
"""
import logging
import hubblestack.utils.win_reg
import hubblestack.utils.platform

__virtualname__ = "domain_controller"

log = logging.getLogger(__name__)


def __virtual__():
    """
    Load domain controller grain
    """
    if not hubblestack.utils.platform.is_windows():
        return False, "The grain will only run on Windows systems"
    return __virtualname__


def get_domain_controller():
    domain_controller_grain={}
    reg_val = hubblestack.utils.win_reg.read_value(hive="HKLM", key=r"SYSTEM\CurrentControlSet\Control\ProductOptions", vname="ProductType")

    if reg_val['vdata'] == 'LanmanNT':
        domain_controller_grain['domain_controller'] = True
    else:
        domain_controller_grain['domain_controller'] = False
    return domain_controller_grain