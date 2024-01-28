import ipaddress

def show_rules():
    return

def parse_ip(ip_add):
    if ip_add=="any":
        return "10.1.1.1", "255.0.0.0", "8"
    ip, prefix_mask = ip_add.split("/")
    prefix_size = str(ipaddress.IPv4Network(ip_add).net_mask)
    return ip, prefix_mask, prefix_size

def read_rule(rule):
    if rule[1] == "in":
        direction = 0x01
    if rule[1] == "out":
        direction = 0x02
    if rule[1] == "any":
        direction = 0x01 | 0x02
    src_ip, src_prefix_mask, src_prefix_size = parse_ip(rule[2])
    dst_ip, dst_prefix_mask, dst_prefix_size = parse_ip(rule[3])
    protocol = rule[4]
    src_port = 1023 if rule[5]==">1023" else rule[5]
    dst_port = 1023 if rule[6]==">1023" else rule[6]
    if rule[7] == "yes":
        ack = 0x01
    if rule[7] == "no":
        ack = 0x02
    if rule[7] == "any":
        ack = 0x01 | 0x02
    return ' '.join(rule[0], direction, src_ip, src_prefix_mask, src_prefix_size, dst_ip, dst_prefix_mask, dst_prefix_size, protocol, src_port, dst_port, ack, rule[8])
    

def load_rules(rules_file_path):
    with open(rules_file_path) as rules_file:
        rule = rules_file.readline().split()
        while not rule:
            with open("/sys/class/fw/rules/rules") as rules_table_driver:
                #rules_table_driver.write(read_rule(rule))
                print(read_rule(rule))
                rule = rules_file.readline().split()

load_rules("log example.txt")
