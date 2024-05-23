import ipaddress

def get_prefix_length(cidr):
    return ipaddress.ip_network(cidr).prefixlen

def get_ips(cidr):
    ips = ipaddress.ip_network(cidr)
    return (int(ip) for ip in ips)

def get_std_ips(cidr):
    ips = ipaddress.ip_network(cidr)
    return (str(ip) for ip in ips)

def ip_int_to_str(ip):
    return str(ipaddress.ip_address(ip))

def is_subnet_in_network(subnet, network):
    subnet_obj = ipaddress.ip_network(subnet)
    network_obj = ipaddress.ip_network(network)
    return network_obj.supernet_of(subnet_obj)

def do_networks_overlap(net1, net2):
    net1_obj = ipaddress.ip_network(net1)
    net2_obj = ipaddress.ip_network(net2)
    return net1_obj.overlaps(net2_obj)
