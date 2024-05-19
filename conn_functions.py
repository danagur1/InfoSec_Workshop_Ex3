import reverse_parse_fields
import parse_fields
CONN_FILEPATH= "/sys/class/fw/conns/conns"
ROW_OUTPUT_SIZE = 19
    
def load():
    try:
        print("src_ip\t\tdst_ip\t\tsrc_port\t\tdst_port\t\tstate")
        with open(CONN_FILEPATH, "rb") as conn_show_file:
            validation_bit = conn_show_file.read(1)[0]
            while validation_bit==1:
                conn = conn_show_file.read(ROW_OUTPUT_SIZE-1)
                print(reverse_parse_fields.ip(conn[:4]), reverse_parse_fields.ip(conn[4:8]), reverse_parse_fields.port(conn[8:10]), 
                reverse_parse_fields.port(conn[10:12]), reverse_parse_fields.state(conn[12:13]),  sep='\t\t')
                validation_bit = conn_show_file.read(1)[0]
        return True
    except Exception as e:
        print(e)
        return False

def get_dst_ip(src_ip, src_port):
    # used for client to server packets
    # return the destination IP of the connection with src_port, src_ip
    try:
        with open(CONN_FILEPATH, "rb") as conn_show_file:
            validation_bit = conn_show_file.read(1)[0]
            while validation_bit==1:
                conn = conn_show_file.read(ROW_OUTPUT_SIZE-1)
                if (src_ip==reverse_parse_fields.ip(conn[:4]) and src_port==reverse_parse_fields.port(conn[8:10]) and 
                reverse_parse_fields.client_server([13])==0 and reverse_parse_fields.port(conn[15:17])=="any"):
                    #reverse_parse_fields.parse_port([15:17])==any means no port is set yet
                    return reverse_parse_fields.ip(conn[4:8]), reverse_parse_fields.port(conn[10:12])
                validation_bit = conn_show_file.read(1)[0]
        return False
    except Exception as e:
        print(e)
        return False

def get_proxy_port_http(src_ip, src_port):
    # used for client to server packets
    # return the destination IP of the connection with src_port, src_ip
    try:
        with open(CONN_FILEPATH, "rb") as conn_show_file:
            validation_bit = conn_show_file.read(1)[0]
            while validation_bit==1:
                conn = conn_show_file.read(ROW_OUTPUT_SIZE-1)
                if (src_ip==reverse_parse_fields.ip(conn[:4]) and src_port==reverse_parse_fields.port(conn[8:10]) and 
                    dst_ip==reverse_parse_fields.ip(conn[4:8]) and src_port==reverse_parse_fields.port(conn[10:12])):
                    #reverse_parse_fields.parse_port([15:17])==any means no port is set yet
                    return reverse_parse_fields.port(conn[14:16])
                validation_bit = conn_show_file.read(1)[0]
        return False
    except Exception as e:
        print(e)
        return False

def get_proxy_port_http(src_ip, src_port):
    # used for client to server packets
    # return the destination IP of the connection with src_port, src_ip
    try:
        with open(CONN_FILEPATH, "rb") as conn_show_file:
            validation_bit = conn_show_file.read(1)[0]
            while validation_bit==1:
                conn = conn_show_file.read(ROW_OUTPUT_SIZE-1)
                if (src_ip==reverse_parse_fields.ip(conn[:4]) and src_port==reverse_parse_fields.port(conn[8:10]) and 
                    dst_ip==reverse_parse_fields.ip(conn[4:8]) and src_port==reverse_parse_fields.port(conn[10:12])):
                    #reverse_parse_fields.parse_port([15:17])==any means no port is set yet
                    return reverse_parse_fields.port(conn[17:19])
                validation_bit = conn_show_file.read(1)[0]
        return False
    except Exception as e:
        print(e)
        return False

def set_proxy_port_http(src_ip, dst_ip, src_port, dst_port, proxy_port):
    try:
        with open(CONN_FILEPATH, "wb") as conn_set_file:
            conn_set_file.write(b"".join(parse_fields.ip(src_ip), parse_fields.ip(dst_ip), parse_fields.port_code(src_port), 
            parse_fields.port_code(dst_port), parse_fields.port_code(proxy_port), b"0"))
    except Exception as e:
        print(e)
        return False

def set_proxy_port_ftp(src_ip, dst_ip, src_port, dst_port, proxy_port):
    try:
        with open(CONN_FILEPATH, "wb") as conn_set_file:
            conn_set_file.write(b"".join(parse_fields.ip(src_ip), parse_fields.ip(dst_ip), parse_fields.port_code(src_port), 
            parse_fields.port_code(dst_port), parse_fields.port_code(proxy_port), b"1"))
    except Exception as e:
        print(e)
        return False
