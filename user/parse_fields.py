import re
import struct
import socket

def is_int(check_int):
    try:
        int(check_int)
        return True
    except (Exception, ):
        return False

def is_ip(check_ip):
    # Regular expression to match IP address with mask- from: https://stackoverflow.com/questions/30590193/regex-to-match-ipv4-with-mask 
    ip_pattern = r"^(([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.){3}([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\/(3[0-2]|[1-2]?\d)$"
    if re.match(ip_pattern, check_ip):
        return True
    else:
        return False

def rule_name(rule_name):
    if len(rule_name)>20:
        return False
    rule_name = rule_name.ljust(21, '\0')
    return struct.pack("<21s", rule_name.encode())

def subnet(ip_add):
    if ip_add == "any":
        ip = "10.1.1.1"
        perfix_size = "8"
    elif not is_ip(ip_add):
        return False, False, False
    else:
        ip, perfix_size = ip_add.split("/")
    if perfix_size=="0":
        ip = "10.1.1.1"
        perfix_size = "8"
    perfix_mask = socket.inet_ntoa(struct.pack(">L", (1 << 32) - (1 << 32 >> int(perfix_size))))
    ip = b"".join([int(x).to_bytes(1, 'little') for x in ip.split(".")])
    perfix_mask = b"".join([int(x).to_bytes(1, 'little') for x in perfix_mask.split(".")])
    return ip, perfix_mask, struct.pack("<B", (int(perfix_size)-1))

def ip(ip_string):
    bytes_ip = ip_string.split('.')
    bytes_ip = [int(byte) for byte in bytes_ip]
    return bytes(bytes_ip)

def direction_code(direction):
    if direction == "in":
        return b'\x01'
    elif direction == "out":
        return b'\x02'
    elif direction == "any":
        return b'\x03'
    else:
        return False  # error code

def protocol_code(protocol):
    protocol_num = b'0' #255
    if protocol == "ICMP":
        protocol_num = b'1' #1
    elif protocol == "TCP":
        protocol_num = b'2' #6
    elif protocol == "UDP":
        protocol_num = b'3' #17
    elif protocol == "any":
        protocol_num = b'4' #143
    return protocol_num

def port_code(port):
    if port == ">1023":
        port = 1023
    elif port == "any":
        port =0
    elif not (is_int(port) and 1 <= int(port) and int(port) <= 65535):
        return False
    return struct.pack(">H", int(port))

def ack_code(ack):
    if ack == "yes":
        return b'2'
    elif ack == "no":
        return b'1'
    elif ack == "any":
        return b'3'
    else:
        return False  # error code

def action_code(action):
    if action=="accept":
        return b'1'
    elif action=="drop":
        return b'0'
    else:
        return False