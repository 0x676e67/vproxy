import ipaddress
import random
import hashlib
import string

def generate_ip_from_cidr(cidr, session_str):
    # Parse the CIDR notation
    network = ipaddress.IPv6Network(cidr)
    network_address = int(network.network_address)
    netmask = int(network.netmask)

    # Combine the CIDR range string and session string
    combined_str = f"{cidr}-{session_str}"

    # Generate a hash value from the combined string to use as a seed
    seed = int(hashlib.sha1(combined_str.encode()).hexdigest(), 16)
    random.seed(seed)

    # Generate a random offset within the network range
    offset = random.randint(0, netmask ^ 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF)

    # Calculate the IP address using the network address and offset
    ip_address_int = network_address + offset
    ip_address = ipaddress.IPv6Address(ip_address_int)

    return ip_address

def session_generator(size, chars=string.ascii_uppercase + string.digits + string.ascii_lowercase):
    random.seed(size)
    return ''.join(random.choice(chars) for _ in range(size))

# Example usage
cidr = "2001:db8::/48"
session_len = 1000
sessions = []

for x in range(session_len):
    sessions.append(session_generator(x))

result = []
for x in sessions:
    result.append(generate_ip_from_cidr(cidr, x))

check = []
for x in sessions:
    check.append(generate_ip_from_cidr(cidr, x))

for x in result:
    if x not in check:
        print(x)
