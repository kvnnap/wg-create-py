import ipaddress

from utils.ip import *

class NetGroup:
    def __init__(self, name, subnetConf, mainCidr, ips = None):
        self.name = name
        self.cidr = subnetConf['CIDR']
        self.drop =  subnetConf['Drop'] if 'Drop' in subnetConf else None
        self.mainCidr = mainCidr
        self.ips = ips

        if not is_subnet_in_network(self.cidr, mainCidr):
            raise ValueError(f'cidr error: {self.name} not in main')
        
    def get_ips(self):
        if self.ips:
            return (ip for ip in self.ips)
        mainNet = ipaddress.ip_network(self.mainCidr)
        dIps = {int(mainNet.network_address), int(mainNet.broadcast_address)}
        return (int(ip) for ip in get_ips(self.cidr) if ip not in dIps)

