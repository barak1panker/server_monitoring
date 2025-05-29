import uuid

def get_mac():
    mac = uuid.getnode()
    mac_addr = ':'.join(['{:02x}'.format((mac >> ele) & 0xff) for ele in range(40, -1, -8)])
    return mac_addr

print(get_mac())
