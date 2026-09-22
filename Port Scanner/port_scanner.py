import socket
import common_ports


def validateIP(target):
    try:
        socket.inet_aton(target)
        return True
    except socket.error:
        return False


def validateURL(target):
    try:
        socket.gethostbyname(target)
        return True
    except socket.error:
        return False


def checkTarget(target):
    if not validateURL(target):
        if target and target[0].isdigit():
            return "Error: Invalid IP address"
        return "Error: Invalid hostname"
    return False


def portscan(target, port):
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(1)
        result = s.connect_ex((target, port))
        s.close()
        return result == 0
    except socket.error:
        return False


def getService(ports):
    services = {}

    for port in ports:
        if port in common_ports.ports_and_services:
            services[port] = common_ports.ports_and_services[port]

    string = ""

    for k, v in services.items():
        string += str(k) + " " * 5 + v + "\n"

    return string


def get_open_ports(target, port_range, verbose=False):
    error = checkTarget(target)

    if error:
        return error

    open_ports = []

    for port in range(port_range[0], port_range[1] + 1):
        if portscan(target, port):
            open_ports.append(port)

    if verbose:
        if validateIP(target):
            ip = target
            try:
                host = socket.gethostbyaddr(target)[0]
            except socket.herror:
                host = target
        else:
            host = target
            ip = socket.gethostbyname(target)

        return (
            "Open ports for "
            + host
            + " ("
            + ip
            + ")\n"
            + "PORT     SERVICE\n"
            + getService(open_ports)
        )

    return open_ports
