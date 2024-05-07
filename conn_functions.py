import struct
from datetime import datetime
CONN_SHOW_FILEPATH= "/sys/class/fw/conns/conns"
ROW_OUTPUT_SIZE = 13
    
def parse_ip(bytes_ip):
    ip = [str(int(byte)) for byte in bytes_ip]
    print("parse_ip returning "+'.'.join(ip))
    return '.'.join(ip)

def parse_port(bytes_port):
    port = struct.unpack(">H", bytes_port)[0]
    print("parse_port returning "+str(port))
    return str(port)

def parse_state(byte_state):
    state_map = {0:"STATE_CLOSED", 1:"STATE_LISTEN", 2:"STATE_SYN_SENT", 3:"STATE_SYN_RECEIVED", 4:"STATE_ESTABLISHED", 
                 5:"STATE_CLOSE_WAIT", 6:"STATE_LAST_ACK", 7:"STATE_FIN_WAIT_1", 8:"STATE_FIN_WAIT_2", 9:"STATE_CLOSING", 
                 10:"STATE_TIME_WAIT"}
    print("parse_state returning "+state_map[byte_state])
    return state_map[byte_state]

    
def load():
    try:
        print("src_ip\t\tdst_ip\t\tsrc_port\t\tdst_port\t\tstate")
        with open(CONN_SHOW_FILEPATH, "rb") as conn_show_file:
            validation_bit = conn_show_file.read(1)[0]
            while validation_bit==1:
                conn = conn_show_file.read(ROW_OUTPUT_SIZE-1)
                print(parse_ip(conn[:4]), parse_port(conn[8:10]), parse_ip(conn[4:8]), parse_port(conn[10:12]), parse_state(conn[12:13])
                    , sep='\t\t')
                validation_bit = conn_show_file.read(1)[0]
        return True
    except Exception as e:
        print(e)
        return False
