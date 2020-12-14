# -*- coding: utf-8 -*-
"""
Define some generic socket functions for network modules
"""

# Import python libs
import os
import re
import logging
import subprocess
import socket
import platform

from hubblestack.utils.versions import LooseVersion
import hubblestack.utils.path
import hubblestack.utils.platform
from hubblestack.utils._compat import ipaddress

# Attempt to import wmi
try:
    import wmi
    import hubblestack.utils.winapi
except ImportError:
    pass

log = logging.getLogger(__name__)

try:
    import ctypes
    import ctypes.util
    libc = ctypes.cdll.LoadLibrary(ctypes.util.find_library("c"))
    res_init = libc.__res_init
except (ImportError, OSError, AttributeError, TypeError):
    pass


def natural_ipv4_netmask(ip, fmt='prefixlen'):
    """
    Returns the "natural" mask of an IPv4 address
    """
    bits = _ipv4_to_bits(ip)

    if bits.startswith('11'):
        mask = '24'
    elif bits.startswith('1'):
        mask = '16'
    else:
        mask = '8'

    if fmt == 'netmask':
        return cidr_to_ipv4_netmask(mask)
    else:
        return '/' + mask


def _ipv4_to_bits(ipaddr):
    """
    Accepts an IPv4 dotted quad and returns a string representing its binary
    counterpart
    """
    return ''.join([bin(int(x))[2:].rjust(8, '0') for x in ipaddr.split('.')])


def cidr_to_ipv4_netmask(cidr_bits):
    """
    Returns an IPv4 netmask
    """
    try:
        cidr_bits = int(cidr_bits)
        if not 1 <= cidr_bits <= 32:
            return ''
    except ValueError:
        return ''

    netmask = ''
    for idx in range(4):
        if idx:
            netmask += '.'
        if cidr_bits >= 8:
            netmask += '255'
            cidr_bits -= 8
        else:
            netmask += '{0:d}'.format(256 - (2 ** (8 - cidr_bits)))
            cidr_bits = 0
    return netmask


def interfaces():
    """
    Return a dictionary of information about all the interfaces on the minion
    """
    if hubblestack.utils.platform.is_windows():
        return win_interfaces()
    elif hubblestack.utils.platform.is_netbsd():
        return netbsd_interfaces()
    else:
        return linux_interfaces()


def win_interfaces():
    """
    Obtain interface information for Windows systems
    """
    with hubblestack.utils.winapi.Com():
        c = wmi.WMI()
        ifaces = {}
        for iface in c.Win32_NetworkAdapterConfiguration(IPEnabled=1):
            ifaces[iface.Description] = dict()
            if iface.MACAddress:
                ifaces[iface.Description]['hwaddr'] = iface.MACAddress
            if iface.IPEnabled:
                ifaces[iface.Description]['up'] = True
                for ip in iface.IPAddress:
                    if '.' in ip:
                        if 'inet' not in ifaces[iface.Description]:
                            ifaces[iface.Description]['inet'] = []
                        item = {'address': ip,
                                'label': iface.Description}
                        if iface.DefaultIPGateway:
                            broadcast = next((i for i in iface.DefaultIPGateway if '.' in i), '')
                            if broadcast:
                                item['broadcast'] = broadcast
                        if iface.IPSubnet:
                            netmask = next((i for i in iface.IPSubnet if '.' in i), '')
                            if netmask:
                                item['netmask'] = netmask
                        ifaces[iface.Description]['inet'].append(item)
                    if ':' in ip:
                        if 'inet6' not in ifaces[iface.Description]:
                            ifaces[iface.Description]['inet6'] = []
                        item = {'address': ip}
                        if iface.DefaultIPGateway:
                            broadcast = next((i for i in iface.DefaultIPGateway if ':' in i), '')
                            if broadcast:
                                item['broadcast'] = broadcast
                        if iface.IPSubnet:
                            netmask = next((i for i in iface.IPSubnet if ':' in i), '')
                            if netmask:
                                item['netmask'] = netmask
                        ifaces[iface.Description]['inet6'].append(item)
            else:
                ifaces[iface.Description]['up'] = False
    return ifaces


def linux_interfaces():
    """
    Obtain interface information for *NIX/BSD variants
    """
    ifaces = dict()
    ip_path = hubblestack.utils.path.which('ip')
    ifconfig_path = None if ip_path else hubblestack.utils.path.which('ifconfig')
    if ip_path:
        cmd1 = subprocess.Popen(
            '{0} link show'.format(ip_path),
            shell=True,
            close_fds=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT).communicate()[0]
        cmd2 = subprocess.Popen(
            '{0} addr show'.format(ip_path),
            shell=True,
            close_fds=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT).communicate()[0]
        ifaces = _interfaces_ip("{0}\n{1}".format(
            hubblestack.utils.stringutils.to_str(cmd1),
            hubblestack.utils.stringutils.to_str(cmd2)))
    elif ifconfig_path:
        cmd = subprocess.Popen(
            '{0} -a'.format(ifconfig_path),
            shell=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT).communicate()[0]
        ifaces = _interfaces_ifconfig(hubblestack.utils.stringutils.to_str(cmd))
    return ifaces


def _interfaces_ip(out):
    """
    Uses ip to return a dictionary of interfaces with various information about
    each (up/down state, ip address, netmask, and hwaddr)
    """
    ret = dict()

    def parse_network(value, cols):
        """
        Return a tuple of ip, netmask, broadcast
        based on the current set of cols
        """
        brd = None
        scope = None
        if '/' in value:  # we have a CIDR in this address
            ip, cidr = value.split('/')  # pylint: disable=C0103
        else:
            ip = value  # pylint: disable=C0103
            cidr = 32

        if type_ == 'inet':
            mask = cidr_to_ipv4_netmask(int(cidr))
            if 'brd' in cols:
                brd = cols[cols.index('brd') + 1]
        elif type_ == 'inet6':
            mask = cidr
            if 'scope' in cols:
                scope = cols[cols.index('scope') + 1]
        return (ip, mask, brd, scope)

    groups = re.compile('\r?\n\\d').split(out)
    for group in groups:
        iface = None
        data = dict()

        for line in group.splitlines():
            if ' ' not in line:
                continue
            match = re.match(r'^\d*:\s+([\w.\-]+)(?:@)?([\w.\-]+)?:\s+<(.+)>', line)
            if match:
                iface, parent, attrs = match.groups()
                if 'UP' in attrs.split(','):
                    data['up'] = True
                else:
                    data['up'] = False
                if parent:
                    data['parent'] = parent
                continue

            cols = line.split()
            if len(cols) >= 2:
                type_, value = tuple(cols[0:2])
                iflabel = cols[-1:][0]
                if type_ in ('inet', 'inet6'):
                    if 'secondary' not in cols:
                        ipaddr, netmask, broadcast, scope = parse_network(value, cols)
                        if type_ == 'inet':
                            if 'inet' not in data:
                                data['inet'] = list()
                            addr_obj = dict()
                            addr_obj['address'] = ipaddr
                            addr_obj['netmask'] = netmask
                            addr_obj['broadcast'] = broadcast
                            addr_obj['label'] = iflabel
                            data['inet'].append(addr_obj)
                        elif type_ == 'inet6':
                            if 'inet6' not in data:
                                data['inet6'] = list()
                            addr_obj = dict()
                            addr_obj['address'] = ipaddr
                            addr_obj['prefixlen'] = netmask
                            addr_obj['scope'] = scope
                            data['inet6'].append(addr_obj)
                    else:
                        if 'secondary' not in data:
                            data['secondary'] = list()
                        ip_, mask, brd, scp = parse_network(value, cols)
                        data['secondary'].append({
                            'type': type_,
                            'address': ip_,
                            'netmask': mask,
                            'broadcast': brd,
                            'label': iflabel,
                        })
                        del ip_, mask, brd, scp
                elif type_.startswith('link'):
                    data['hwaddr'] = value
        if iface:
            ret[iface] = data
            del iface, data
    return ret


def _interfaces_ifconfig(out):
    """
    Uses ifconfig to return a dictionary of interfaces with various information
    about each (up/down state, ip address, netmask, and hwaddr)
    """
    ret = dict()

    piface = re.compile(r'^([^\s:]+)')
    pmac = re.compile('.*?(?:HWaddr|ether|address:|lladdr) ([0-9a-fA-F:]+)')
    if hubblestack.utils.platform.is_sunos():
        pip = re.compile(r'.*?(?:inet\s+)([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+)(.*)')
        pip6 = re.compile('.*?(?:inet6 )([0-9a-fA-F:]+)')
        pmask6 = re.compile(r'.*?(?:inet6 [0-9a-fA-F:]+/(\d+)).*')
    else:
        pip = re.compile(r'.*?(?:inet addr:|inet [^\d]*)(.*?)\s')
        pip6 = re.compile('.*?(?:inet6 addr: (.*?)/|inet6 )([0-9a-fA-F:]+)')
        pmask6 = re.compile(
            r'.*?(?:inet6 addr: [0-9a-fA-F:]+/(\d+)|prefixlen (\d+))(?: Scope:([a-zA-Z]+)| scopeid (0x[0-9a-fA-F]))?')
    pmask = re.compile(r'.*?(?:Mask:|netmask )(?:((?:0x)?[0-9a-fA-F]{8})|([\d\.]+))')
    pupdown = re.compile('UP')
    pbcast = re.compile(r'.*?(?:Bcast:|broadcast )([\d\.]+)')

    groups = re.compile('\r?\n(?=\\S)').split(out)
    for group in groups:
        data = dict()
        iface = ''
        updown = False
        for line in group.splitlines():
            miface = piface.match(line)
            mmac = pmac.match(line)
            mip = pip.match(line)
            mip6 = pip6.match(line)
            mupdown = pupdown.search(line)
            if miface:
                iface = miface.group(1)
            if mmac:
                data['hwaddr'] = mmac.group(1)
                if hubblestack.utils.platform.is_sunos():
                    expand_mac = []
                    for chunk in data['hwaddr'].split(':'):
                        expand_mac.append('0{0}'.format(chunk) if len(chunk) < 2 else '{0}'.format(chunk))
                    data['hwaddr'] = ':'.join(expand_mac)
            if mip:
                if 'inet' not in data:
                    data['inet'] = list()
                addr_obj = dict()
                addr_obj['address'] = mip.group(1)
                mmask = pmask.match(line)
                if mmask:
                    if mmask.group(1):
                        mmask = _number_of_set_bits_to_ipv4_netmask(
                            int(mmask.group(1), 16))
                    else:
                        mmask = mmask.group(2)
                    addr_obj['netmask'] = mmask
                mbcast = pbcast.match(line)
                if mbcast:
                    addr_obj['broadcast'] = mbcast.group(1)
                data['inet'].append(addr_obj)
            if mupdown:
                updown = True
            if mip6:
                if 'inet6' not in data:
                    data['inet6'] = list()
                addr_obj = dict()
                addr_obj['address'] = mip6.group(1) or mip6.group(2)
                mmask6 = pmask6.match(line)
                if mmask6:
                    addr_obj['prefixlen'] = mmask6.group(1) or mmask6.group(2)
                    if not hubblestack.utils.platform.is_sunos():
                        ipv6scope = mmask6.group(3) or mmask6.group(4)
                        addr_obj['scope'] = ipv6scope.lower() if ipv6scope is not None else ipv6scope
                # SunOS sometimes has ::/0 as inet6 addr when using addrconf
                if not hubblestack.utils.platform.is_sunos() \
                        or addr_obj['address'] != '::' \
                        and addr_obj['prefixlen'] != 0:
                    data['inet6'].append(addr_obj)
        data['up'] = updown
        if iface in ret:
            # SunOS optimization, where interfaces occur twice in 'ifconfig -a'
            # output with the same name: for ipv4 and then for ipv6 addr family.
            # Every instance has it's own 'UP' status and we assume that ipv4
            # status determines global interface status.
            #
            # merge items with higher priority for older values
            # after that merge the inet and inet6 sub items for both
            ret[iface] = dict(list(data.items()) + list(ret[iface].items()))
            if 'inet' in data:
                ret[iface]['inet'].extend(x for x in data['inet'] if x not in ret[iface]['inet'])
            if 'inet6' in data:
                ret[iface]['inet6'].extend(x for x in data['inet6'] if x not in ret[iface]['inet6'])
        else:
            ret[iface] = data
        del data
    return ret


def _number_of_set_bits_to_ipv4_netmask(set_bits):  # pylint: disable=C0103
    """
    Returns an IPv4 netmask from the integer representation of that mask.

    Ex. 0xffffff00 -> '255.255.255.0'
    """
    return cidr_to_ipv4_netmask(_number_of_set_bits(set_bits))


def _number_of_set_bits(x):
    """
    Returns the number of bits that are set in a 32bit int
    """
    # Taken from http://stackoverflow.com/a/4912729. Many thanks!
    x -= (x >> 1) & 0x55555555
    x = ((x >> 2) & 0x33333333) + (x & 0x33333333)
    x = ((x >> 4) + x) & 0x0f0f0f0f
    x += x >> 8
    x += x >> 16
    return x & 0x0000003f


def netbsd_interfaces():
    """
    Obtain interface information for NetBSD >= 8 where the ifconfig
    output diverged from other BSD variants (Netmask is now part of the
    address)
    """
    # NetBSD versions prior to 8.0 can still use linux_interfaces()
    if LooseVersion(os.uname()[2]) < LooseVersion('8.0'):
        return linux_interfaces()

    ifconfig_path = hubblestack.utils.path.which('ifconfig')
    cmd = subprocess.Popen(
        '{0} -a'.format(ifconfig_path),
        shell=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT).communicate()[0]
    return _netbsd_interfaces_ifconfig(hubblestack.utils.stringutils.to_str(cmd))


def _netbsd_interfaces_ifconfig(out):
    """
    Uses ifconfig to return a dictionary of interfaces with various information
    about each (up/down state, ip address, netmask, and hwaddr)
    """
    ret = dict()

    piface = re.compile(r'^([^\s:]+)')
    pmac = re.compile('.*?address: ([0-9a-f:]+)')

    pip = re.compile(r'.*?inet [^\d]*(.*?)/([\d]*)\s')
    pip6 = re.compile(r'.*?inet6 ([0-9a-f:]+)%([a-zA-Z0-9]*)/([\d]*)\s')

    pupdown = re.compile('UP')
    pbcast = re.compile(r'.*?broadcast ([\d\.]+)')

    groups = re.compile('\r?\n(?=\\S)').split(out)
    for group in groups:
        data = dict()
        iface = ''
        updown = False
        for line in group.splitlines():
            miface = piface.match(line)
            mmac = pmac.match(line)
            mip = pip.match(line)
            mip6 = pip6.match(line)
            mupdown = pupdown.search(line)
            if miface:
                iface = miface.group(1)
            if mmac:
                data['hwaddr'] = mmac.group(1)
            if mip:
                if 'inet' not in data:
                    data['inet'] = list()
                addr_obj = dict()
                addr_obj['address'] = mip.group(1)
                mmask = mip.group(2)
                if mip.group(2):
                    addr_obj['netmask'] = cidr_to_ipv4_netmask(mip.group(2))
                mbcast = pbcast.match(line)
                if mbcast:
                    addr_obj['broadcast'] = mbcast.group(1)
                data['inet'].append(addr_obj)
            if mupdown:
                updown = True
            if mip6:
                if 'inet6' not in data:
                    data['inet6'] = list()
                addr_obj = dict()
                addr_obj['address'] = mip6.group(1)
                mmask6 = mip6.group(3)
                addr_obj['scope'] = mip6.group(2)
                addr_obj['prefixlen'] = mip6.group(3)
                data['inet6'].append(addr_obj)
        data['up'] = updown
        ret[iface] = data
        del data
    return ret


def get_fqhostname():
    """
    Returns the fully qualified hostname
    """
    l = [socket.getfqdn()]

    # try socket.getaddrinfo
    try:
        addrinfo = socket.getaddrinfo(
            socket.gethostname(), 0, socket.AF_UNSPEC, socket.SOCK_STREAM,
            socket.SOL_TCP, socket.AI_CANONNAME
        )
        for info in addrinfo:
            # info struct [family, socktype, proto, canonname, sockaddr]
            if len(info) >= 4:
                l.append(info[3])
    except socket.gaierror:
        pass

    return l and l[0] or None


def ip_addrs(interface=None, include_loopback=False, interface_data=None):
    """
    Returns a list of IPv4 addresses assigned to the host. 127.0.0.1 is
    ignored, unless 'include_loopback=True' is indicated. If 'interface' is
    provided, then only IP addresses from that interface will be returned.
    """
    return _ip_addrs(interface, include_loopback, interface_data, 'inet')


def _ip_addrs(interface=None, include_loopback=False, interface_data=None, proto='inet'):
    """
    Return the full list of IP adresses matching the criteria

    proto = inet|inet6
    """
    ret = set()

    ifaces = interface_data \
        if isinstance(interface_data, dict) \
        else interfaces()
    if interface is None:
        target_ifaces = ifaces
    else:
        target_ifaces = dict([(k, v) for k, v in iter(ifaces.items())
                              if k == interface])
        if not target_ifaces:
            log.error('Interface %s not found.', interface)
    for ip_info in target_ifaces.values():
        addrs = ip_info.get(proto, [])
        addrs.extend([addr for addr in ip_info.get('secondary', []) if addr.get('type') == proto])

        for addr in addrs:
            addr = ipaddress.ip_address(addr.get('address'))
            if not addr.is_loopback or include_loopback:
                ret.add(addr)
    return [str(addr) for addr in sorted(ret)]


def ip_addrs6(interface=None, include_loopback=False, interface_data=None):
    """
    Returns a list of IPv6 addresses assigned to the host. ::1 is ignored,
    unless 'include_loopback=True' is indicated. If 'interface' is provided,
    then only IP addresses from that interface will be returned.
    """
    return _ip_addrs(interface, include_loopback, interface_data, 'inet6')


def is_ipv6(ip):
    """
    Returns a bool telling if the value passed to it was a valid IPv6 address
    """
    try:
        return ipaddress.ip_address(ip).version == 6
    except ValueError:
        return False


def is_ipv4(ip):
    """
    Returns a bool telling if the value passed to it was a valid IPv4 address
    """
    try:
        return ipaddress.ip_address(ip).version == 4
    except ValueError:
        return False


def refresh_dns():
    """
    issue #21397: force glibc to re-read resolv.conf
    """
    try:
        res_init()
    except NameError:
        # Exception raised loading the library, thus res_init is not defined
        pass


def in_subnet(cidr, addr=None):
    """
    Returns True if host or (any of) addrs is within specified subnet, otherwise False
    """
    try:
        cidr = ipaddress.ip_network(cidr)
    except ValueError:
        log.error("Invalid CIDR '%s'", cidr)
        return False

    if addr is None:
        addr = ip_addrs()
        addr.extend(ip_addrs6())
    elif not isinstance(addr, (list, tuple)):
        addr = (addr,)

    return any(ipaddress.ip_address(item) in cidr for item in addr)


def _generate_minion_id():
    '''
    Get list of possible host names and convention names.

    :return:
    '''
    # There are three types of hostnames:
    # 1. Network names. How host is accessed from the network.
    # 2. Host aliases. They might be not available in all the network or only locally (/etc/hosts)
    # 3. Convention names, an internal nodename.

    class DistinctList(list):
        '''
        List, which allows one to append only distinct objects.
        Needs to work on Python 2.6, because of collections.OrderedDict only since 2.7 version.
        Override 'filter()' for custom filtering.
        '''
        localhost_matchers = [r'localhost.*', r'ip6-.*', r'127[.]\d', r'0\.0\.0\.0',
                              r'::1.*', r'ipv6-.*', r'fe00::.*', r'fe02::.*', r'1.0.0.*.ip6.arpa']

        def append(self, p_object):
            if p_object and p_object not in self and not self.filter(p_object):
                super(self.__class__, self).append(p_object)
            return self

        def extend(self, iterable):
            for obj in iterable:
                self.append(obj)
            return self

        def filter(self, element):
            'Returns True if element needs to be filtered'
            for rgx in self.localhost_matchers:
                if re.match(rgx, element):
                    return True

        def first(self):
            return self and self[0] or None

    hostname = socket.gethostname()

    hosts = DistinctList().append(
        hubblestack.utils.stringutils.to_unicode(socket.getfqdn(hubblestack.utils.stringutils.to_bytes(hostname)))
    ).append(platform.node()).append(hostname)
    if not hosts:
        try:
            for a_nfo in socket.getaddrinfo(hosts.first() or 'localhost', None, socket.AF_INET,
                                            socket.SOCK_RAW, socket.IPPROTO_IP, socket.AI_CANONNAME):
                if len(a_nfo) > 3:
                    hosts.append(a_nfo[3])
        except socket.gaierror:
            log.warning('Cannot resolve address {addr} info via socket: {message}'.format(
                addr=hosts.first() or 'localhost (N/A)', message=socket.gaierror)
            )
    # Universal method for everywhere (Linux, Slowlaris, Windows etc)
    for f_name in ('/etc/hostname', '/etc/nodename', '/etc/hosts',
                   r'{win}\system32\drivers\etc\hosts'.format(win=os.getenv('WINDIR'))):
        try:
            with hubblestack.utils.files.fopen(f_name) as f_hdl:
                for line in f_hdl:
                    line = hubblestack.utils.stringutils.to_unicode(line)
                    hst = line.strip().split('#')[0].strip().split()
                    if hst:
                        if hst[0][:4] in ('127.', '::1') or len(hst) == 1:
                            hosts.extend(hst)
        except IOError:
            pass

    # include public and private ipaddresses
    return hosts.extend([addr for addr in ip_addrs()
                         if not ipaddress.ip_address(addr).is_loopback])


def generate_minion_id():
    '''
    Return only first element of the hostname from all possible list.

    :return:
    '''
    try:
        ret = hubblestack.utils.stringutils.to_unicode(_generate_minion_id().first())
    except TypeError:
        ret = None
    return ret or 'localhost'
