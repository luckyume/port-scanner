import ipaddress
import re
import socket
from concurrent.futures import ThreadPoolExecutor

from common_ports import ports_and_services

# How long to wait for a single connection attempt before calling the port closed.
# Long enough to survive a slow handshake (~0.5s observed) and one SYN retransmit.
CONNECTION_TIMEOUT = 2.0
# Enough parallelism to finish a small range quickly, without flooding the target.
MAX_WORKERS = 10

# Targets made only of digits, dots and colons are treated as IP addresses,
# everything else is treated as a hostname/URL.
IP_ADDRESS_CHARS = re.compile(r"^[0-9.:]+$")


def _resolve(target):
    """Turn the target into an IPv4 address.

    Returns a (ip, error) tuple; exactly one of the two is None.
    """
    if IP_ADDRESS_CHARS.match(target):
        try:
            return str(ipaddress.ip_address(target)), None
        except ValueError:
            return None, "Error: Invalid IP address"

    try:
        return socket.gethostbyname(target), None
    except (socket.gaierror, UnicodeError, OSError):
        return None, "Error: Invalid hostname"


def _scan_port(ip, port):
    """Return the port number if it accepted a connection, otherwise None."""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.settimeout(CONNECTION_TIMEOUT)
        try:
            open_ = sock.connect_ex((ip, port)) == 0
        except OSError:
            open_ = False
    return port if open_ else None


def _get_open_ports(ip, first, last):
    ports = range(first, last + 1)
    with ThreadPoolExecutor(max_workers=min(MAX_WORKERS, len(ports))) as pool:
        results = pool.map(lambda port: _scan_port(ip, port), ports)
    return sorted(port for port in results if port is not None)


def _header(target, ip):
    """Build the first line of the verbose report."""
    if not IP_ADDRESS_CHARS.match(target):
        return "Open ports for {} ({})".format(target, ip)

    try:
        hostname = socket.gethostbyaddr(ip)[0]
    except OSError:
        hostname = None

    if hostname and hostname != ip:
        return "Open ports for {} ({})".format(hostname, ip)
    return "Open ports for {}".format(ip)


def _service_name(port):
    if port in ports_and_services:
        return ports_and_services[port]
    try:
        return socket.getservbyport(port, "tcp")
    except OSError:
        return ""


def get_open_ports(target, port_range, verbose=False):
    """Scan target for open ports inside port_range = [first, last].

    Returns a sorted list of the open ports, or (when verbose is True) a
    formatted report string. Invalid targets return an error string.
    """
    ip, error = _resolve(target)
    if error:
        return error

    first, last = sorted(int(port) for port in port_range)
    first, last = max(first, 1), min(last, 65535)

    open_ports = _get_open_ports(ip, first, last) if first <= last else []

    if not verbose:
        return open_ports

    lines = [_header(target, ip), "PORT     SERVICE"]
    lines += ["{:<9}{}".format(port, _service_name(port)) for port in open_ports]
    return "\n".join(lines)
