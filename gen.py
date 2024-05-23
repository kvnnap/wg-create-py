import sys
import os
import subprocess
import ipaddress

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from utils.serialisation import load
from utils.ip import *

class NetGroup:
    def __init__(self, name, cidr, mainCidr, ips = None):
        self.name = name
        self.cidr = cidr
        self.mainCidr = mainCidr
        self.ips = ips

        if not is_subnet_in_network(cidr, mainCidr):
            raise ValueError(f'cidr error: {name} not in main')
        
    def get_ips(self):
        if self.ips:
            return (ip for ip in self.ips)
        mainNet = ipaddress.ip_network(self.mainCidr)
        dIps = {int(mainNet.network_address), int(mainNet.broadcast_address)}
        return (int(ip) for ip in get_ips(self.cidr) if ip not in dIps)

BASE_DIR = "keys"

def create_pair(name, gen_pre):
    force_prv = False
    preshared = ""

    path = os.path.join(BASE_DIR, name, name)
    orig_umask = os.umask(0o077)

    # Create directory
    os.umask(orig_umask)
    os.makedirs(os.path.join(BASE_DIR, name), exist_ok=True)
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
    mainCidr = config['Network']
    mainIps = list(get_ips(mainCidr))[1:-1]
    prefix_length = get_prefix_length(mainCidr)
    netGroups = {}
    ips = set()
    for subnet in config['Subnets']:
        name = subnet['Name']
        netGroup = NetGroup(name, subnet['CIDR'], mainCidr)
        netGroups[name] = netGroup
        for ip in netGroup.get_ips():
            if ip in ips:
                raise ValueError(f'network overlap error: {name} ({ip}) collides with another range')
            ips.add(ip)
    
    mainIps = sorted(set(mainIps) - ips)
    netGroups['main'] = NetGroup('main', mainCidr, mainCidr, mainIps)

    # Server
    mainIps = netGroups['main'].get_ips()
    server_ip = ip_int_to_str(next(mainIps))
    server_port = config['ServerPort']
    server_private_key, server_public_key, _ = create_pair("server", False)
    # Generate rule for each subnet
    ips = set()
    for subnet in config['Subnets']:
        ips.add(subnet['Drop'])
        
    server_file = replace_tokens_in_string(read_from_file('templates/server.template'), {
        'SERVER_IP': server_ip,
        'SERVER_PORT': server_port,
        'PREFIX_LENGTH': prefix_length,
        'SERVER_PRIVATE_KEY': server_private_key
    })

    pass

# The following code block will only execute if this script is run directly,
# not if it's imported as a module in another script.
if __name__ == "__main__":
    main()
