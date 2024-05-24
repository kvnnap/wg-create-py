import os
import subprocess

from utils.constants import KEYS_DIR

def create_pair(name, gen_pre, orig_umask):
    force_prv = False
    preshared = ""

    path = os.path.join(KEYS_DIR, name, name)

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

    return private_key, public_key, preshared