from __future__ import annotations
from .libs import utils


def get_mac_address() -> str:
    """
    Retrieve the MAC address of the device.

    Returns:
        str: The MAC address of the device.
    """
    return utils.GetMACAddress()
