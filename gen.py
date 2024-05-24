import sys
import os
import qrcode

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from utils.factory import unpack_config
from utils.file import *
from utils.ip import *
from utils.wireguard import create_pair
from net_group import NetGroup
from utils.constants import KEYS_DIR

def main():
    # Load config
    config = load_json('config.json')

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

    # Files
    orig_umask = os.umask(0o077)

    # Server
    server_ip = ip_int_to_str(next(netGroupsUsed['main']))
    server_port = config['ServerPort']
    server_private_key, server_public_key, _ = create_pair("server", False, orig_umask)
    server_file = replace_tokens_in_string(read_from_file('templates/server.template'), {
        'SERVER_IP': server_ip,
        'SERVER_PORT': server_port,
        'PREFIX_LENGTH': prefix_length,
        'SERVER_PRIVATE_KEY': server_private_key
    })

    # Clients
    server_peer_template = read_from_file('templates/server-peer.template')
    peer_template = read_from_file('templates/peer.template')
    devNames = set()
    for device in config['Devices']:
        dev = unpack_config(device)
        name, subnet, peerConfName = (dev['Name'], dev['Subnet'], dev['PeerConfig'])
        if name in devNames:
            raise ValueError(f'device {name} already defined')
        if subnet not in netGroups:
            raise ValueError(f'{name} not in defined subnets')
        if peerConfName not in peerConfigs:
            raise ValueError(f'{peerConfName} not in defined PeerConfigs')
        devNames.add(name)
        netGroup = netGroups[subnet]
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
        private_key, public_key, preshared_key = create_pair(name, True, orig_umask)
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
    ip_tables_up_template = "iptables -A FORWARD -i %i -d IP_TABLES_DROP -s THIS_NETWORK -j DROP; iptables -A FORWARD -o %i -s IP_TABLES_DROP -d THIS_NETWORK -j DROP"
    ip_tables_down_template = "iptables -D FORWARD -i %i -d IP_TABLES_DROP -s THIS_NETWORK -j DROP; iptables -D FORWARD -o %i -s IP_TABLES_DROP -d THIS_NETWORK -j DROP"
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

    os.umask(orig_umask)
    os.makedirs('wgsrv/config', exist_ok=True)
    os.umask(0o077)
    write_to_file('wgsrv/config/server.conf', server_file)
    os.umask(orig_umask)


# The following code block will only execute if this script is run directly,
# not if it's imported as a module in another script.
if __name__ == "__main__":
    main()
