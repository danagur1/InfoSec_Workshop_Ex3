import socket
import struct
import ipaddress

RULES_DEVICE_FILEPATH = "/sys/class/fw/rules/rules"


def is_int(check_int):
    try:
        int(check_int)
        return True
    except (Exception, ):
        return False


def is_ip(check_ip):
    try:
        ipaddress.ip_address(check_ip)
        return True
    except ValueError:
        return False


def parse_ip(ip_add):
    if not is_ip(ip_add):
        return False, False, False
    if ip_add == "any":
        return "10.1.1.1", "255.0.0.0", "8"
    ip, prefix_size = ip_add.split("/")
    prefix_mask = socket.inet_ntoa(struct.pack(">L", (1 << 32) - (1 << 32 >> int(prefix_size))))
    return ip, prefix_mask, prefix_size


def reverse_parse_ip(ip, prefix_size):
    return "/".join(ip, prefix_size)


def get_direction_code(direction):
    if direction == "in":
        return str(1)
    elif direction == "out":
        return str(2)
    elif direction == "any":
        return str(3)
    else:
        return False  # error code


def reverse_direction(direction_code):
    if direction_code == str(1):
        return "in"
    elif direction_code == str(2):
        return "out"
    elif direction_code == str(3):
        return "any"


def get_protocol_code(protocol):
    protocol_num = 255
    if protocol == "ICMP":
        protocol_num = 1
    elif protocol == "TCP":
        protocol_num = 6
    elif protocol == "UDP":
        protocol_num = 17
    elif protocol == "ANY":
        protocol_num = 143
    return str(protocol_num)


def reverse_protocol(protocol_code):
    if protocol_code == str(1):
        return "ICMP"
    elif protocol_code == str(6):
        return "TCP"
    elif protocol_code == str(17):
        return "UDP"
    elif protocol_code == str(143):
        return "ANY"
    elif protocol_code == str(255):
        return "OTHER"


def get_port_code(port):
    if port == ">1023":
        return str(1023)
    elif port == "any":
        return str(0)
    elif is_int(port) and 1 <= port <= 1023:
        return str(port)
    else:
        return False  # error code


def reverse_port(port_code):
    if port_code == str(1023):
        return ">1023"
    elif port_code == str(0):
        return "any"
    else:
        return int(port_code)


def get_ack_code(ack):
    if ack == "yes":
        return str(1)
    elif ack == "no":
        return str(2)
    elif ack == "any":
        return str(3)
    else:
        return False  # error code


def reverse_ack(ack_code):
    if ack_code == str(1):
        return "yes"
    elif ack_code == str(2):
        return "no"
    elif ack_code == str(3):
        return "any"


def read_rule(rule):
    direction = get_direction_code(rule[1])
    src_ip, src_prefix_mask, src_prefix_size = parse_ip(rule[2])
    dst_ip, dst_prefix_mask, dst_prefix_size = parse_ip(rule[3])
    protocol = get_protocol_code(rule[4])
    src_port = get_port_code(rule[5])
    dst_port = get_port_code(rule[6])
    ack = get_ack_code(rule[7])
    if src_ip and dst_ip and src_port and dst_port and ack:
        return ' '.join([rule[0], direction, src_ip, src_prefix_mask, src_prefix_size, dst_ip, dst_prefix_mask,
                         dst_prefix_size, src_port, dst_port, protocol, ack, rule[8]])
    else:
        return False


def write_rule(rule):
    direction = reverse_direction(rule[1])
    src_ip, src_prefix_mask, src_prefix_size = reverse_parse_ip(rule[2])
    dst_ip, dst_prefix_mask, dst_prefix_size = reverse_parse_ip(rule[3])
    protocol = reverse_protocol(rule[4])
    src_port = reverse_port(rule[5])
    dst_port = reverse_port(rule[6])
    ack = reverse_ack(rule[7])
    return ' '.join([rule[0], direction, src_ip, src_prefix_mask, src_prefix_size, dst_ip, dst_prefix_mask,
                         dst_prefix_size, src_port, dst_port, protocol, ack, rule[8]])


def load(rules_file_path):
    with open(rules_file_path, "r") as rules_file:
        with open(RULES_DEVICE_FILEPATH, "w") as rules_table_driver:
            rule = rules_file.readline().split()
            while not rule:
                parsed_rule = read_rule(rule)
                if not parsed_rule:
                    return False
                rules_table_driver.write(parsed_rule)
                rule = rules_file.readline().split()
    return True
    """
    FOR TESTING:
    rule = rules_file.readline().split()
    while rule:
        print(read_rule(rule))
        rule = rules_file.readline().split()"""


def show():
    with open(RULES_DEVICE_FILEPATH, "r") as rules_file:
        rule = rules_file.readline().split()
        while not rule:
            print(write_rule(rule))
    return True


"""load_rules("rules example.txt")"""
