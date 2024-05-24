import sys
import os
import subprocess
import ipaddress
import qrcode

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from utils.factory import unpack_config
from utils.serialisation import load
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

KEYS_DIR = "keys"

def create_pair(name, gen_pre):
    force_prv = False
    preshared = ""

    path = os.path.join(KEYS_DIR, name, name)
    orig_umask = os.umask(0o077)

    # Create directory
    os.umask(orig_umask)
    os.makedirs(os.path.join(KEYS_DIR, name), exist_ok=True)
    os.umask(0o077)

    # Generate private key if not exists
    private_key_path = f"{path}.private"
    if not os.path.isfile(private_key_path):
        with open(private_key_path, "w") as prv_key_file:
            prv_key_file.write(subprocess.check_output(["wg", "genkey"]).decode())
        force_prv = True

    # Generate public key if force_prv is true or not exists
    public_key_path = f"{path}.public"
    if force_prv or not os.path.isfile(public_key_path):
        os.umask(orig_umask)
        with open(private_key_path, "r") as prv_key_file, open(public_key_path, "w") as pub_key_file:
            pub_key_file.write(subprocess.check_output(["wg", "pubkey"], stdin=prv_key_file).decode())
        os.umask(0o077)

    # Generate preshared key if gen_pre is true and not exists
    if gen_pre and not os.path.isfile(f"{path}.server.preshared"):
        with open(f"{path}.server.preshared", "w") as pre_key_file:
            pre_key_file.write(subprocess.check_output(["wg", "genpsk"]).decode())

    # Read private key, public key, and preshared key
    with open(private_key_path, "r") as prv_key_file, open(public_key_path, "r") as pub_key_file:
        private_key = prv_key_file.read().strip()
        public_key = pub_key_file.read().strip()

    if gen_pre:
        with open(f"{path}.server.preshared", "r") as pre_key_file:
            preshared = pre_key_file.read().strip()

    os.umask(orig_umask)
    return private_key, public_key, preshared

def replace_tokens_in_string(content, token_map):
    for token, mapped_value in token_map.items():
        content = content.replace(token, str(mapped_value))
    return content

def write_to_file(file_path, content):
    with open(file_path, 'w') as file:
        file.write(content)

def read_from_file(file_path):
    with open(file_path, 'r') as file:
        return file.read()

def replace_tokens_in_file(template_file_path, file_path, token_map):
    # Read the content of the file
    content = read_from_file(template_file_path)

    # Replace tokens with mapped values
    content = replace_tokens_in_string(content, token_map)

    # Write the modified content back to the file
    write_to_file(file_path, content)

def main():
    # Load config
    config = load('config.json')

    # Load and check CIDRs
    lan = config['LAN']
    # ip_net_validate(lan)
    mainCidr = config['Network']
    mainIps = list(get_ips(mainCidr))[1:-1]
    ip_start = str(get_network(mainCidr))
    server_host = config['ServerHost']
    prefix_length = get_prefix_length(mainCidr)
    netGroups = {}
    ips = set()
    for name, subnet in config['Subnets'].items():
        netGroup = NetGroup(name, subnet, mainCidr)
        netGroups[name] = netGroup
        for ip in netGroup.get_ips():
            if ip in ips:
                raise ValueError(f'network overlap error: {name} ({ip}) collides with another range')
            ips.add(ip)
    
    mainIps = sorted(set(mainIps) - ips)
    netGroups['main'] = NetGroup('main', {'CIDR': mainCidr}, mainCidr, mainIps)
    peerConfigs = config['PeerConfigs']
    if 'main' not in peerConfigs:
        peerConfigs['main'] = {
            "AllowedIPS": "NETWORK",
            "DNS": ""
        }

    netGroupsUsed = {}
    netGroupsUsed['main'] = netGroups['main'].get_ips()

    # Server
    server_ip = ip_int_to_str(next(netGroupsUsed['main']))
    server_port = config['ServerPort']
    server_private_key, server_public_key, _ = create_pair("server", False)
    server_file = replace_tokens_in_string(read_from_file('templates/server.template'), {
        'SERVER_IP': server_ip,
        'SERVER_PORT': server_port,
        'PREFIX_LENGTH': prefix_length,
        'SERVER_PRIVATE_KEY': server_private_key
    })

    # Clients
    server_peer_template = read_from_file('templates/server-peer.template')
    peer_template = read_from_file('templates/peer.template')
    for device in config['Devices']:
        dev = unpack_config(device)
        name = dev['Name']
        subnet = dev['Subnet']
        peerConfName = dev['PeerConfig']
        if subnet not in netGroups:
            raise ValueError(f'{name} not in defined subnets')
        netGroup = netGroups[subnet]
        if peerConfName not in peerConfigs:
            raise ValueError(f'{peerConfName} not in defined PeerConfigs')
        peerConfig = peerConfigs[peerConfName]
        
        # Init iterator (ip pool)
        if subnet not in netGroupsUsed:
            netGroupsUsed[subnet] = netGroups[subnet].get_ips()

        # Setup peer config specific vars/values
        dns_equals_client_dns = ""
        if 'DNS' in peerConfig and peerConfig['DNS']:
            dns_equals_client_dns = f'DNS = {peerConfig['DNS']}'
        allowed_ips = "IP_START/PREFIX_LENGTH"
        if 'AllowedIPS' in peerConfig:
            allowed_ips = peerConfig['AllowedIPS']

        # Get ip
        ip = ip_int_to_str(next(netGroupsUsed[subnet])) 
        private_key, public_key, preshared_key = create_pair(name, True)
        peer_file = replace_tokens_in_string(peer_template, {
            'CLIENT_NAME': name,
            'ALLOWED_IPS': allowed_ips,
            'NETWORK': 'IP_START/PREFIX_LENGTH',
            'IP_START': ip_start,
            'CLIENT_IP': ip,
            'PREFIX_LENGTH': prefix_length,
            'CLIENT_PRIVATE_KEY': private_key,
            'DNS_EQUALS_CLIENT_DNS': dns_equals_client_dns,
            'SERVER_PUBLIC_KEY': server_public_key,
            'PRESHARED_KEY': preshared_key,
            'SERVER_HOST': server_host,
            'SERVER_PORT': server_port,
            'LAN': lan
        })
        write_to_file(f'{KEYS_DIR}/{name}/{name}.conf', peer_file)
        qrcode.make(peer_file).save(f'{KEYS_DIR}/{name}/{name}.png')
        
        server_file += replace_tokens_in_string(server_peer_template, {
            'CLIENT_NAME': name,
            'CLIENT_PUBLIC_KEY': public_key,
            'PRESHARED_KEY': preshared_key,
            'CLIENT_IP': ip
        })

    # Write iptables rules
    ip_tables_up_template = "iptables -A FORWARD -i %i -d IP_TABLES_DROP -s THIS_NETWORK -j DROP"
    ip_tables_down_template = "iptables -D FORWARD -i %i -d IP_TABLES_DROP -s THIS_NETWORK -j DROP"
    ip_tables = [('iptables -t nat -A POSTROUTING -o eth+ -j MASQUERADE', 'iptables -t nat -D POSTROUTING -o eth+ -j MASQUERADE')]
    for name in netGroupsUsed:
        netGroup = netGroups[name]
        if netGroup.drop:
            filter_dict = { 
                'IP_TABLES_DROP': netGroup.drop,
                'THIS_NETWORK': netGroup.cidr,
                'NETWORK': 'IP_START/PREFIX_LENGTH',
                'IP_START': ip_start,
                'PREFIX_LENGTH': prefix_length,
                'LAN': lan
            }
            ip_tables_up = replace_tokens_in_string(ip_tables_up_template, filter_dict)
            ip_tables_down = replace_tokens_in_string(ip_tables_down_template, filter_dict)
            ip_tables.append((ip_tables_up, ip_tables_down))

    ip_tables_up = '; '.join([s[0] for s in ip_tables])
    ip_tables_down = '; '.join([s[1] for s in ip_tables])

    server_file = replace_tokens_in_string(server_file, {'IP_TABLES_UP': ip_tables_up, 'IP_TABLES_DOWN': ip_tables_down })
    write_to_file(f'{KEYS_DIR}/server/server.conf', server_file)

# The following code block will only execute if this script is run directly,
# not if it's imported as a module in another script.
if __name__ == "__main__":
    main()
