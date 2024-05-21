import socket
import threading
import random
import conn_functions
import re
import 

LISTEN_PORT = 210

def block_ftp_content_types(http_message):
    return True

def generate_unique_port(used_ports):
    while True:
        port = random.randint(33280, 65535)
        if port not in used_ports:
            used_ports.add(port)
            return port

def handle_client(client_socket, address, used_ports):
    src_ip, src_port = address
    dst = conn_functions.get_dst_and_proxy_port(src_ip, str(src_port))
    if dst==False:
        return
    dst_ip, dst_port, my_port = dst
    if my_port=="any": #my port have not been set yet
        my_port = generate_unique_port(used_ports)
        conn_functions.set_proxy_port_http(src_ip, dst_ip, src_port, dst_port, my_port)
    # Receive data from the client
    data = client_socket.recv(4096)
    if not data:
        client_socket.close(address)
        return
    
    # Create a socket with a new source port
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as forward_socket:
        if dlp.accept_packet(data):
            forward_socket.bind(('10.1.2.3', my_port))
            forward_socket.connect((dst_ip, int(dst_port)))
            forward_socket.sendall(data)
    
    client_socket.close()

def start_server():
    used_ports = set()
    
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server_socket:
        server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server_socket.bind(('0.0.0.0', LISTEN_PORT))
        server_socket.listen(5)
        while True:
            client_socket, address = server_socket.accept()
            client_handler = threading.Thread(
                target=handle_client, 
                args=(client_socket, address, used_ports)
            )
            client_handler.start()

if __name__ == "__main__":
    start_server()
