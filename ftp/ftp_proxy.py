import socket
import threading
import random

LISTEN_PORT = 210

def generate_unique_port(used_ports):
    while True:
        port = random.randint(33280, 65535)
        if port not in used_ports:
            used_ports.add(port)
            return port

def handle_client(client_socket, address, used_ports):
    src_ip, src_port = address
    dst_ip, dst_port = get_dst_ip(address)
    my_port = get_proxy_port_ftp(src_ip, dst_ip, src_port, dst_port)
    if my_port=="any": #my port have not been set yet
        my_port = generate_unique_port(used_ports)
        set_proxy_port_ftp(src_ip, dst_ip, src_port, dst_port, my_port)
    # Receive data from the client
    data = client_socket.recv(4096)
    if not data:
        client_socket.close(address)
        return
    
    # Create a socket with a new source port
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as forward_socket:
        forward_socket.bind(('', my_port))
        forward_socket.connect()
        forward_socket.sendall(data)
    
    client_socket.close()

def start_server():
    used_ports = set()
    
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server_socket:
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
