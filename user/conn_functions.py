import reverse_parse_fields
import parse_fields
CONN_FILEPATH= "/sys/class/fw/conns/conns"
ROW_OUTPUT_SIZE = 19
    
def load():
    try:
        with open(CONN_FILEPATH, "rb") as conn_show_file:
            validation_bit = conn_show_file.read(1)[0]
            while validation_bit==1:
                conn = conn_show_file.read(ROW_OUTPUT_SIZE-1)
                validation_bit = conn_show_file.read(1)[0]
        return True
    except Exception as e:
        return False

def get_dst_and_proxy_port(src_ip, src_port):
    # used for client to server packets
    # return the destination IP of the connection with src_port, src_ip
    try:
        with open(CONN_FILEPATH, "rb") as conn_show_file:
            validation_bit = conn_show_file.read(1)[0]
            while validation_bit==1:
                conn = conn_show_file.read(ROW_OUTPUT_SIZE-1)
                if (src_ip==reverse_parse_fields.ip(conn[:4]) and src_port==reverse_parse_fields.port(conn[8:10]) and 
                reverse_parse_fields.client_server(conn[13:14])=="0" and reverse_parse_fields.port(conn[15:17])=="any"):
                    #reverse_parse_fields.parse_port([15:17])==any means no port is set yet
                    return reverse_parse_fields.ip(conn[4:8]), reverse_parse_fields.port(conn[10:12]), reverse_parse_fields.port(conn[14:16])
                validation_bit = conn_show_file.read(1)[0]
        return False
    except Exception as e:
        return False

def get_proxy_port_ftp(src_ip, src_port):
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
        return False

def set_proxy_port_http(src_ip, dst_ip, src_port, dst_port, proxy_port):
    try:
        with open(CONN_FILEPATH, "wb") as conn_set_file:
            src_ip_parsed = parse_fields.ip(src_ip)
            dst_ip_parsed = parse_fields.ip(dst_ip)
            src_port_parsed = parse_fields.port_code(src_port)
            dst_port_parsed = parse_fields.port_code(dst_port)
            proxy_port_parsed = parse_fields.port_code(proxy_port)
            if src_ip_parsed and dst_ip_parsed and src_port_parsed and dst_port_parsed and proxy_port_parsed:
                conn_set_file.write(b"".join([src_ip_parsed, dst_ip_parsed, src_port_parsed, dst_port_parsed, proxy_port_parsed, b'\x00']))
    except Exception as e:
        return False


def set_proxy_port_ftp(src_ip, dst_ip, src_port, dst_port, proxy_port):
    try:
        with open(CONN_FILEPATH, "wb") as conn_set_file:
            src_ip_parsed = parse_fields.ip(src_ip)
            dst_ip_parsed = parse_fields.ip(dst_ip)
            src_port_parsed = parse_fields.port_code(src_port)
            dst_port_parsed = parse_fields.port_code(dst_port)
            proxy_port_parsed = parse_fields.port_code(proxy_port)
            if src_ip_parsed and dst_ip_parsed and src_port_parsed and dst_port_parsed and proxy_port_parsed:
                conn_set_file.write(b"".join([src_ip_parsed, dst_ip_parsed, src_port_parsed, dst_port_parsed, proxy_port_parsed, b'\x01']))
    except Exception as e:
        return False
