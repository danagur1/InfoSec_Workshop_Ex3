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


def parse_ip(ip_add):
    if ip_add == "any":
        return "10.1.1.1", "255.0.0.0", "8"
    if not is_ip(ip_add):
        return False, False, False
    ip, prefix_size = ip_add.split("/")
    prefix_mask = socket.inet_ntoa(struct.pack(">L", (1 << 32) - (1 << 32 >> int(prefix_size))))
    return ip, prefix_mask, prefix_size


def reverse_parse_ip(ip, prefix_size):
    result = "/".join([ip, prefix_size])
    if result==r"10.0.0.1/8": # this is the meaning of any ip
        return any
    return result


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
    protocol_num = 0 #255
    if protocol == "ICMP":
        protocol_num = 1 #1
    elif protocol == "TCP":
        protocol_num = 2 #6
    elif protocol == "UDP":
        protocol_num = 3 #17
    elif protocol == "any":
        protocol_num = 4 #143
    return str(protocol_num)


def reverse_protocol(protocol_code):
    if protocol_code == str(1):
        return "ICMP"
    elif protocol_code == str(2):
        return "TCP"
    elif protocol_code == str(3):
        return "UDP"
    elif protocol_code == str(4):
        return "any"
    elif protocol_code == str(0):
        return "OTHER"


def get_port_code(port):
    if port == ">1023":
        return str(1023)
    elif port == "any":
        return str(0)
    elif is_int(port) and 1 <= int(port) and int(port) <= 1023:
        return port
    else:
        return False  # error code


def reverse_port(port_code):
    if port_code == str(1023):
        return ">1023"
    elif port_code == str(0):
        return "any"
    else:
        return port_code


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

def get_action_code(action):
    if action=="accept":
        return str(1)
    elif action=="drop":
        return str(0)
    else:
        return False
    
def reverse_action(action_code):
    if action_code=="1":
        return "accept"
    elif action_code=="0":
        return "drop"

def read_rule(rule):
    direction = get_direction_code(rule[1])
    src_ip, src_prefix_mask, src_prefix_size = parse_ip(rule[2])
    dst_ip, dst_prefix_mask, dst_prefix_size = parse_ip(rule[3])
    protocol = get_protocol_code(rule[4])
    src_port = get_port_code(rule[5])
    dst_port = get_port_code(rule[6])
    ack = get_ack_code(rule[7])
    action = get_action_code(rule[8])
    #print("src_ip: "+str(src_ip)+" dst_ip: "+str(dst_ip)+" src_port: "+str(src_port)+" dst_port: "+str(dst_port)+" ack: "+str(ack)+" action: "+str(action))
    if src_ip and dst_ip and src_port and dst_port and ack and action:
        return ' '.join([rule[0], direction, src_ip, src_prefix_mask, src_prefix_size, dst_ip, dst_prefix_mask,
                         dst_prefix_size, protocol, src_port, dst_port, ack, action])
    else:
        return False


def write_rule(rule):
    direction = reverse_direction(rule[1])
    src_ip_with_perfix = reverse_parse_ip(rule[2], rule[4])
    dst_ip_with_perfix = reverse_parse_ip(rule[5], rule[7])
    protocol = reverse_protocol(rule[8])
    src_port = reverse_port(rule[9])
    dst_port = reverse_port(rule[10])
    ack = reverse_ack(rule[11])
    action = reverse_action(rule[12])
    return ' '.join([rule[0], direction, src_ip_with_perfix, dst_ip_with_perfix, protocol, src_port, dst_port, ack, action])


def load(rules_file_path):
    try:
        with open(rules_file_path, "r") as rules_file:
            with open(RULES_DEVICE_FILEPATH, "w") as rules_table_driver:
                rule = rules_file.readline()
                while True:
                    if rule=='':
                        break
                    else:
                        rule= rule.split()
                    parsed_rule = read_rule(rule)
                    if not parsed_rule:
                        return False
                    print(parsed_rule)
                    rules_table_driver.write(parsed_rule+"\n") # added line terminator to identify end of rule
                    rule = rules_file.readline()
        return True
    except Exception as e:
        print(e)
        return False
    """
    FOR TESTING:
    rule = rules_file.readline().split()
    while rule:
        print(read_rule(rule))
        rule = rules_file.readline().split()"""


def show():
    try:
        with open(RULES_DEVICE_FILEPATH, "r") as rules_file:
            rule = rules_file.readline()
            while True:
                if rule=='\n':
                    break
                rule = rule.split()
                print(write_rule(rule))
                rule = rules_file.readline()
        return True
    except (Exception, ):
        return False


"""load_rules("rules example.txt")"""
