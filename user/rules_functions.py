import parse_fields
import reverse_parse_fields

RULES_DEVICE_FILEPATH = "/sys/class/fw/rules/rules"
    

def read_rule(rule):
    rule_name = parse_fields.rule_name(rule[0])
    direction = parse_fields.direction_code(rule[1])
    src_ip, src_perfix_mask, src_perfix_size = parse_fields.subnet(rule[2])
    dst_ip, dst_perfix_mask, dst_perfix_size = parse_fields.subnet(rule[3])
    protocol = parse_fields.protocol_code(rule[4])
    src_port = parse_fields.port_code(rule[5])
    dst_port = parse_fields.port_code(rule[6])
    ack = parse_fields.ack_code(rule[7])
    action = parse_fields.action_code(rule[8])
    if rule_name and src_ip and dst_ip and src_port and dst_port and ack and action:
        return b' '.join([rule_name, direction, src_ip, src_perfix_mask, src_perfix_size, dst_ip, dst_perfix_mask,
                         dst_perfix_size, protocol, src_port, dst_port, ack, action])
    else:
        return False


def write_rule(rule):
    rule_name = reverse_parse_fields.rule_name(rule[0])
    direction = reverse_parse_fields.direction(rule[1])
    src_ip_with_perfix = reverse_parse_fields.subnet(rule[2], rule[4])
    dst_ip_with_perfix = reverse_parse_fields.subnet(rule[5], rule[7])
    protocol = reverse_parse_fields.protocol(rule[8])
    src_port = reverse_parse_fields.port(rule[9])
    dst_port = reverse_parse_fields.port(rule[10])
    ack = reverse_parse_fields.ack(rule[11])
    action = reverse_parse_fields.action(rule[12])
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
