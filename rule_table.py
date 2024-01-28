import socket, struct

def show_rules():
    return

def parse_ip(ip_add):
    if ip_add=="any":
        return "10.1.1.1", "255.0.0.0", "8"
    ip, prefix_size = ip_add.split("/")
    prefix_mask = socket.inet_ntoa(struct.pack(">L", (1<<32) - (1<<32>>int(prefix_size))))
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
    src_port = str(1023) if rule[5]==">1023" else (str(0) if rule[5]=="any" else rule[5])
    dst_port = str(1023) if rule[6]==">1023" else (str(0) if rule[6]=="any" else rule[6])
    if rule[7] == "yes":
        ack = 0x01
    if rule[7] == "no":
        ack = 0x02
    if rule[7] == "any":
        ack = 0x01 | 0x02
    return ' '.join([rule[0], str(direction), src_ip, src_prefix_mask, src_prefix_size, dst_ip, dst_prefix_mask, dst_prefix_size, src_port, dst_port, protocol, str(ack), rule[8]])
    

def load_rules(rules_file_path):
    with open(rules_file_path) as rules_file:
        """
        with open("/sys/class/fw/rules/rules") as rules_table_driver:
            rule = rules_file.readline().split()
            while not rule:
                rules_table_driver.write(read_rule(rule))
                rule = rules_file.readline().split()"""
        rule = rules_file.readline().split()
        while rule:
            print(read_rule(rule))
            rule = rules_file.readline().split()

load_rules("rules example.txt")
