# -*- coding: utf-8 -*-

import binascii
from hubblestack.utils.exceptions import HubbleException

try:
    import ipaddress
except ImportError:
    ipaddress = None

try:
    # Python >2.5
    import xml.etree.cElementTree as ElementTree
except Exception:
    try:
        # Python >2.5
        import xml.etree.ElementTree as ElementTree
    except Exception:
        try:
            # normal cElementTree install
            import elementtree.cElementTree as ElementTree
        except Exception:
            try:
                # normal ElementTree install
                import elementtree.ElementTree as ElementTree
            except Exception:
                ElementTree = None

class IPv6AddressScoped(ipaddress.IPv6Address):
    '''
    Represent and manipulate single IPv6 Addresses.
    Scope-aware version
    '''
    def __init__(self, address):
        '''
        Instantiate a new IPv6 address object. Scope is moved to an attribute 'scope'.

        Args:
            address: A string or integer representing the IP

              Additionally, an integer can be passed, so
              IPv6Address('2001:db8::') == IPv6Address(42540766411282592856903984951653826560)
              or, more generally
              IPv6Address(int(IPv6Address('2001:db8::'))) == IPv6Address('2001:db8::')

        Raises:
            AddressValueError: If address isn't a valid IPv6 address.

        :param address:
        '''
        # pylint: disable-all
        if not hasattr(self, '_is_packed_binary'):
            # This method (below) won't be around for some Python 3 versions
            # and we need check this differently anyway
            self._is_packed_binary = lambda p: isinstance(p, bytes)
        # pylint: enable-all
        if isinstance(address, str) and '%' in address:
            buff = address.split('%')
            if len(buff) != 2:
                raise HubbleException('Invalid IPv6 address: "{}"'.format(address))
            address, self.__scope = buff
        else:
            self.__scope = None

        # Python 3.4 fix. Versions higher are simply not affected
        # https://github.com/python/cpython/blob/3.4/Lib/ipaddress.py#L543-L544
        self._version = 6
        self._max_prefixlen = ipaddress.IPV6LENGTH

        # Efficient constructor from integer.
        if isinstance(address, int):
            self._check_int_address(address)
            self._ip = address
        elif self._is_packed_binary(address):
            self._check_packed_address(address, 16)
            self._ip = int(binascii.hexlify(address), 16)
        else:
            address = str(address)
            if '/' in address:
                raise ipaddress.AddressValueError("Unexpected '/' in {}".format(address))
            self._ip = self._ip_int_from_string(address)

    def _is_packed_binary(self, data):
        '''
        Check if data is hexadecimal packed

        :param data:
        :return:
        '''
        packed = False
        if isinstance(data, bytes) and len(data) == 16 and b':' not in data:
            try:
                packed = bool(int(binascii.hexlify(data), 16))
            except ValueError:
                pass

        return packed

    @property
    def scope(self):
        '''
        Return scope of IPv6 address.

        :return:
        '''
        return self.__scope

    def __str__(self):
        return str(self._string_from_ip_int(self._ip) +
                         ('%' + self.scope if self.scope is not None else ''))



if ipaddress:
    ipaddress.IPv6Address = IPv6AddressScoped

if ElementTree is not None:
    if not hasattr(ElementTree, 'ParseError'):
        class ParseError(Exception):
            '''
            older versions of ElementTree do not have ParseError
            '''

        ElementTree.ParseError = ParseError
