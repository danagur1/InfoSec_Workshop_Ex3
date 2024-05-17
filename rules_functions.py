import socket
import struct
import re

RULES_DEVICE_FILEPATH = "/sys/class/fw/rules/rules"


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
    
def parse_rule_name(rule_name):
    if len(rule_name)>20:
        return False
    rule_name = rule_name.ljust(21, '\0')
    return struct.pack("<21s", rule_name.encode())

def reverse_parse_rule_name(rule_name):
    return struct.unpack('<21s', rule_name)[0].decode().rstrip('\0')

def parse_ip(ip_add):
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


def reverse_parse_ip(ip, perfix_size):
    perfix_size= str(struct.unpack("<B", perfix_size)[0]+1)
    ip = ".".join([str(int(byte)) for byte in ip])
    result = "/".join([ip, perfix_size])
    if result==r"10.0.0.1/8": # this is the meaning of any ip
        return "any"
    return result


def get_direction_code(direction):
    if direction == "in":
        return b'\x01'
    elif direction == "out":
        return b'\x02'
    elif direction == "any":
        return b'\x03'
    else:
        return False  # error code


def reverse_direction(direction_code):
    if direction_code == b'\x01':
        return "in"
    elif direction_code == b'\x02':
        return "out"
    elif direction_code == b'\x03':
        return "any"


def get_protocol_code(protocol):
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


def reverse_protocol(protocol_code):
    if protocol_code == b'1':
        return "ICMP"
    elif protocol_code == b'2':
        return "TCP"
    elif protocol_code == b'3':
        return "UDP"
    elif protocol_code == b'4':
        return "any"
    elif protocol_code == b'0':
        return "OTHER"


def get_port_code(port):
    if port == ">1023":
        port = 1023
    elif port == "any":
        port =0
    elif not (is_int(port) and 1 <= int(port) and int(port) <= 1023):
        return False
    return struct.pack(">H", int(port))


def reverse_port(port_code):
    port = str(struct.unpack(">H", port_code)[0])
    if port=="0":
        return "any" 
    return port


def get_ack_code(ack):
    if ack == "yes":
        return b'2'
    elif ack == "no":
        return b'1'
    elif ack == "any":
        return b'3'
    else:
        return False  # error code


def reverse_ack(ack_code):
    if ack_code == b'1':
        return "yes"
    elif ack_code == b'2':
        return "no"
    elif ack_code == b'3':
        return "any"

def get_action_code(action):
    if action=="accept":
        return b'1'
    elif action=="drop":
        return b'0'
    else:
        return False
    
def reverse_action(action_code):
    if action_code==b'1':
        return "accept"
    elif action_code==b'0':
        return "drop"

def read_rule(rule):
    rule_name = parse_rule_name(rule[0])
    direction = get_direction_code(rule[1])
    src_ip, src_perfix_mask, src_perfix_size = parse_ip(rule[2])
    dst_ip, dst_perfix_mask, dst_perfix_size = parse_ip(rule[3])
    protocol = get_protocol_code(rule[4])
    src_port = get_port_code(rule[5])
    dst_port = get_port_code(rule[6])
    ack = get_ack_code(rule[7])
    action = get_action_code(rule[8])
    if rule_name and src_ip and dst_ip and src_port and dst_port and ack and action:
        return b' '.join([rule_name, direction, src_ip, src_perfix_mask, src_perfix_size, dst_ip, dst_perfix_mask,
                         dst_perfix_size, protocol, src_port, dst_port, ack, action])
    else:
        return False


def write_rule(rule):
    rule_name = reverse_parse_rule_name(rule[0])
    direction = reverse_direction(rule[1])
    src_ip_with_perfix = reverse_parse_ip(rule[2], rule[4])
    dst_ip_with_perfix = reverse_parse_ip(rule[5], rule[7])
    protocol = reverse_protocol(rule[8])
    src_port = reverse_port(rule[9])
    dst_port = reverse_port(rule[10])
    ack = reverse_ack(rule[11])
    action = reverse_action(rule[12])
    return ' '.join([rule_name, direction, src_ip_with_perfix, dst_ip_with_perfix, protocol, src_port, dst_port, ack, action])


def load(rules_file_path):
    try:
        with open(rules_file_path, "r") as rules_file:
            with open(RULES_DEVICE_FILEPATH, "wb") as rules_table_driver:
                rule = rules_file.readline()
                while True:
                    if rule=='':
                        break
                    else:
                        rule= rule.split()
                    parsed_rule = read_rule(rule)
                    if not parsed_rule:
                        return False
                    rules_table_driver.write(parsed_rule+b"\n") # added line terminator to identify end of rule
                    rule = rules_file.readline()
        return True
    except Exception as e:
        print(e)
        return False


def show():
    try:
        with open(RULES_DEVICE_FILEPATH, "rb") as rules_file:
            while True:
                rule = rules_file.read(60)[:-1]
                if rule==b'':
                    break
                rule = rule.split(b' ')
                print(write_rule(rule))
        return True
    except Exception as e:
        print(e)
        return False
