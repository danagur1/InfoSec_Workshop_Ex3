import struct
from datetime import datetime

def is_int(check_int):
    try:
        int(check_int)
        return True
    except (Exception, ):
        return False

def rule_name(rule_name):
    return struct.unpack('<21s', rule_name)[0].decode().rstrip('\0')

def subnet(ip, perfix_size):
    perfix_size= str(struct.unpack("<B", perfix_size)[0]+1)
    ip = ".".join([str(int(byte)) for byte in ip])
    result = "/".join([ip, perfix_size])
    if result==r"10.0.0.1/8": # this is the meaning of any ip
        return "any"
    return result

def direction(direction_code):
    if direction_code == b'\x01':
        return "in"
    elif direction_code == b'\x02':
        return "out"
    elif direction_code == b'\x03':
        return "any"

def protocol(protocol_code):
    print("in reverse parse fields protocol got "+str(protocol_code))
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

def port(port_code):
    port = str(struct.unpack(">H", port_code)[0])
    if port=="0":
        return "any" 
    return port

def ack(ack_code):
    if ack_code == b'1':
        return "yes"
    elif ack_code == b'2':
        return "no"
    elif ack_code == b'3':
        return "any"

def action(action_code):
    print("in reverse parse fields action got "+str(action_code))
    if action_code==b'1':
        return "accept"
    elif action_code==b'0':
        return "drop"

def ip(bytes_ip):
    ip = [str(int(byte)) for byte in bytes_ip]
    return '.'.join(ip)

def state(byte_state):
    state_map = {0:"STATE_CLOSED", 1:"STATE_CLOSED", 2:"STATE_SYN_SENT", 3:"STATE_SYN_SENT", 4:"STATE_SYN_SENT", 
                 5:"STATE_SYN_RECEIVED", 6:"STATE_ESTABLISHED", 7:"STATE_ESTABLISHED", 8:"STATE_CLOSE_WAIT", 9:"STATE_LAST_ACK", 
                 10:"STATE_FIN_WAIT_1", 11:"STATE_FIN_WAIT_1", 12:"STATE_FIN_WAIT_2", 13:"STATE_FIN_WAIT_2", 14:"STATE_CLOSING",
                 15: "STATE_TIME_WAIT"}
    return state_map[struct.unpack("<B", byte_state)[0]]

def client_server(byte_client_server):
    #0=client to server, 1=server to client
    return struct.unpack("<B", byte_state)[0]

def timestamp(bytes_timestamp):
    timestamp = struct.unpack("<I", bytes_timestamp)[0]
    formatted_time = datetime.utcfromtimestamp(timestamp)
    return formatted_time.strftime('%m/%d/%Y %H:%M:%S')

def reason(byte_reason):
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

def count(bytes_count):
    count = struct.unpack("<I", bytes_count)[0]
    return str(count)