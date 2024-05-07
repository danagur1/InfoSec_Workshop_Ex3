import struct
from datetime import datetime
LOG_SHOW_FILEPATH= "/dev/fw_log"
LOG_CLEAR_FILEPATH= "/sys/class/fw/log/reset"

def parse_timestamp(bytes_timestamp):
    timestamp = struct.unpack("<I", bytes_timestamp)[0]
    formatted_time = datetime.utcfromtimestamp(timestamp)
    return formatted_time.strftime('%m/%d/%Y %H:%M:%S')

def parse_protocol(byte_protocol):
    if chr(byte_protocol)=='0':
        return "other"
    elif chr(byte_protocol)=='1':
        return "icmp"
    elif chr(byte_protocol)=='2':
        return "tcp"
    elif chr(byte_protocol)=='3':
        return "udp"
    else:
        return "any"
    
def parse_action(byte_action):
    if chr(byte_action)=='0':
        return "drop"
    else:
        return "accept"
    
def parse_ip(bytes_ip):
    ip = [str(int(byte)) for byte in bytes_ip]
    return '.'.join(ip)

def parse_port(bytes_port):
    port = str(struct.unpack("<H", bytes_port)[0])
    if port=="0":
        return "any"
    return str(port)

def parse_reason(byte_reason):
    if byte_reason<51:
        return str(byte_reason)
    elif byte_reason==51:
        return "REASON_FW_INACTIVE"
    elif byte_reason==52:
        return "REASON_NO_MATCHING_RULE"
    elif byte_reason==53:
        return "REASON_XMAS_PACKET"
    else:
        return "REASON_ILLEGAL_VALUE"
    
def parse_count(bytes_count):
    count = struct.unpack("<I", bytes_count)[0]
    return str(count)
    
def load():
    try:
        print("timestamp\t\tsrc_ip\t\tdst_ip\t\tsrc_port\t\tdst_port\t\tprotocol\t\taction\t\treason\t\tcount")
        with open(LOG_SHOW_FILEPATH, "rb") as log_show_file:
            validation_bit = log_show_file.read(1)[0]
            while validation_bit==1:
                log = log_show_file.read(23)
                print(parse_timestamp(log[:4]), parse_ip(log[6:10]), parse_ip(log[10:14]), parse_port(log[14:16]), parse_port(log[16:18]), 
                      parse_protocol(log[4]), parse_action(log[5]), parse_reason(log[18]), parse_count(log[19:23]), sep='\t\t')
                validation_bit = log_show_file.read(1)[0]
        return True
    except Exception as e:
        return False

def clear():
    try:
        with open(LOG_CLEAR_FILEPATH, "w") as log_clear_file:
            log_clear_file.write("0")
        return True
    except (Exception, ):
        return False
