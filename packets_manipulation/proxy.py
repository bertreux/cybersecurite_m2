import sys
import socket
import threading
import time
import re
from http.server import BaseHTTPRequestHandler
from io import BytesIO
from Crypto.Cipher import AES

#The list comprehension gives a printable character representation of the first 256 integers.
HEX_FILTER = ''.join(
    [(len(repr(chr(i))) == 3) and chr(i) or '.' for i in range(256)])

def hexdump(src, length=16, show=True):
    if isinstance(src, bytes):
        src = src.decode()

    results = list()
    for i in range(0, len(src), length):
        word = str(src[i:i+length])
        printable = word.translate(HEX_FILTER)
        hexa = ' '.join([f'{ord(c):02X}' for c in word])
        hexwidth = length*3
        results.append(f'{i:04x} {hexa:<{hexwidth}} {printable}')

    if show:
        for line in results:
            print(line)
    else:
        return results

def receive_from(connection):
    buffer = b""
    connection.settimeout(5)
    try:
        while True:
            data = connection.recv(4096)
            if not data:
                break
            buffer += data
    except Exception as e:
        pass
    return buffer

#################################
# Ajouter du temps a la requete #
#################################

# def request_handler(buffer):
#     # Introduce a 2-second delay
#     time.sleep(2)
#     return buffer
#
# def response_handler(buffer):
#     # Randomly drop packets
#     import random
#     if random.randint(0, 10) < 2:  # 20% chance to drop
#         print("[Dropped Packet]")
#         return b''  # Return empty buffer to simulate packet drop
#     return buffer

#################################
# Ajouter du temps a la requete #
#################################

###################################
# corrompre la date de la requete #
###################################

# def request_handler(buffer):
#     # Let's say you want to corrupt the data being sent
#     buffer = corrupt_data(buffer)
#     return buffer

# def corrupt_data(data):
#     # Flip some bits in the data
#     corrupted = bytearray(data)
#     for i in range(len(corrupted)):
#         corrupted[i] ^= 0xFF  # Invert all bits
#     return bytes(corrupted)

###################################
# corrompre la date de la requete #
###################################

##############################################
# modifier la donnée de a requete avec regex #
##############################################

# def response_handler(buffer):
#     try:
#         buffer_str = buffer.decode('utf-8', errors='ignore')
#     except UnicodeDecodeError:
#         return buffer
#
#     # Remove sensitive information using regex
#     buffer_str = re.sub(r'password=.*?(&|\s)', 'password=******\\1', buffer_str, flags=re.IGNORECASE)
#
#     return buffer_str.encode('utf-8')

##############################################
# modifier la donnée de a requete avec regex #
##############################################

##################################################################################
# modifier structule des protocoles de la données avec des librairies existantes #
##################################################################################

# def request_handler(buffer):
#     class HTTPRequest(BaseHTTPRequestHandler):
#         def __init__(self, request_text):
#             self.rfile = BytesIO(request_text)
#             self.raw_requestline = self.rfile.readline()
#             self.error_code = self.error_message = None
#             self.parse_request()
#
#     request = HTTPRequest(buffer)
#     # Now you can access request.method, request.path, etc.
#     if request.command == 'GET':
#         print(f"Intercepted GET request to {request.path}")
#     # Modify the request as needed
#     # Reconstruct the request back to bytes
#     # (You'll need to manually rebuild the request string)
#     return buffer  # Placeholder

##################################################################################
# modifier structule des protocoles de la données avec des librairies existantes #
##################################################################################

################################
# cripte et decripte la donnée #
################################

# def request_handler(buffer):
#     # Decrypt the payload
#     decrypted_data = decrypt_payload(buffer)
#     # Modify the decrypted data
#     modified_data = decrypted_data.replace('secret', '******')
#     # Re-encrypt the data
#     encrypted_data = encrypt_payload(modified_data)
#     return encrypted_data
#
# def decrypt_payload(data):
#     # Placeholder for decryption logic
#     return data
#
# def encrypt_payload(data):
#     # Placeholder for encryption logic
#     return data

################################
# cripte et decripte la donnée #
################################

################
# log et alert #
################

# def request_handler(buffer):
#     buffer_str = buffer.decode('utf-8', errors='ignore')
#     # Check for SQL injection patterns
#     if re.search(r"(\%27)|(\')|(\-\-)|(\%23)|(#)", buffer_str):
#         print("[Alert] Potential SQL Injection detected")
#         log_alert(buffer_str)
#     return buffer
#
# def log_alert(data):
#     with open('alerts.log', 'a') as f:
#         f.write(f"{datetime.now()} - {data}\n")

################
# log et alert #
################

############################################
# modifier la donnée de la requete (utf-8) #
############################################

# def request_handler(buffer):
#     # Attempt to decode buffer as UTF-8 text
#     try:
#         buffer_str = buffer.decode('utf-8', errors='ignore')
#     except UnicodeDecodeError:
#         return buffer  # Non-text data; return unmodified
#
#     # Check if it's an HTTP request
#     if buffer_str.startswith('GET') or buffer_str.startswith('POST'):
#         # Modify HTTP requests
#         buffer_str = modify_http_request(buffer_str)
#     elif buffer_str.strip().upper().startswith('USER') or buffer_str.strip().upper().startswith('PASS'):
#         # Modify FTP commands
#         buffer_str = modify_ftp_request(buffer_str)
#     else:
#         # Other protocols or data
#         pass
#
#     return buffer_str.encode('utf-8')
#
# def response_handler(buffer):
#     # Similar logic for responses
#     try:
#         buffer_str = buffer.decode('utf-8', errors='ignore')
#     except UnicodeDecodeError:
#         return buffer
#
#     # Check for HTTP response
#     if buffer_str.startswith('HTTP/'):
#         buffer_str = modify_http_response(buffer_str)
#     elif buffer_str.startswith('220') or buffer_str.startswith('230'):
#         buffer_str = modify_ftp_response(buffer_str)
#     else:
#         pass
#
#     return buffer_str.encode('utf-8')
#
# def modify_http_request(request):
#     # Add headers, modify paths, etc.
#     request = request.replace('User-Agent: ', 'User-Agent: MyCustomAgent')
#     return request
#
# def modify_ftp_request(request):
#     # Log credentials, alter commands
#     if request.strip().upper().startswith('PASS'):
#         print(f"[Intercepted Password]: {request.strip()}")
#     return request
#
# def modify_http_response(response):
#     # Inject content, modify status codes
#     if '<body>' in response:
#         response = response.replace('<body>', '<body><h1>Modified by Proxy</h1>')
#     return response
#
# def modify_ftp_response(response):
#     # Change server messages
#     if '230' in response:
#         response = response.replace('230', '230-Welcome to the Proxy Server!')
#     return response

############################################
# modifier la donnée de la requete (utf-8) #
############################################

def request_handler(buffer):
    # Decode the buffer to a string for manipulation
    try:
        buffer_str = buffer.decode('utf-8', errors='ignore')
    except UnicodeDecodeError:
        return buffer  # Return unchanged if decoding fails

    # Log the FTP command
    print(f"[Request] {buffer_str.strip()}")

    # Example 1: Block certain commands (e.g., DELE to prevent file deletion)
    if buffer_str.strip().upper().startswith('DELE '):
        # Replace 'DELE' with 'NOOP' to prevent deletion
        buffer_str = 'NOOP\r\n'
        print("[Modified Request] Blocked DELE command")

    # Example 2: Modify a command parameter (e.g., change directory path)
    if buffer_str.strip().upper().startswith('CWD '):
        # Change the directory to '/home/user'
        buffer_str = 'CWD /home/user\r\n'
        print("[Modified Request] Changed directory to '/home/user'")

    # Example 3: Inject a custom command (e.g., send a NOOP before the actual command)
    buffer_str = 'NOOP\r\n' + buffer_str
    print("[Modified Request] Injected NOOP command before the actual command")

    # Encode the string back to bytes
    return buffer_str.encode('utf-8')

def response_handler(buffer):
    # Decode the buffer to a string for manipulation
    try:
        buffer_str = buffer.decode('utf-8', errors='ignore')
    except UnicodeDecodeError:
        return buffer  # Return unchanged if decoding fails

    # Log the FTP response
    print(f"[Response] {buffer_str.strip()}")

    # Example 1: Modify the welcome message
    if buffer_str.startswith('220'):
        # Append a custom message to the welcome banner
        buffer_str = buffer_str.strip() + '\r\n220-This is a proxy server for educational purposes.\r\n'
        print("[Modified Response] Added custom welcome message")

    # Example 2: Mask server information
    if 'vsftpd' in buffer_str.lower():
        # Replace server software information with generic text
        buffer_str = buffer_str.replace('vsftpd', 'FTP Server')
        print("[Modified Response] Masked server software information")

    # Example 3: Inject a custom response after the original response
    buffer_str += '230-Note: This session is being monitored.\r\n'
    print("[Modified Response] Injected custom response message")

    # Encode the string back to bytes
    return buffer_str.encode('utf-8')

def proxy_handler(client_socket, remote_host, remote_port, receive_first):
    remote_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    remote_socket.connect((remote_host, remote_port))
    #Check if check to make sure we don’t need to first initiate a connection to the remote side and request data before going into the main loop.
    #Some server daemons will expect you to do this (FTP servers typically send a banner first, for example)
    if receive_first:
        remote_buffer = receive_from(remote_socket)
        hexdump(remote_buffer)

    remote_buffer = response_handler(remote_buffer)
    if len(remote_buffer):
        print("[<==] Sending %d bytes to localhost." % len(remote_buffer))
        client_socket.send(remote_buffer)

    while True:
        local_buffer = receive_from(client_socket)
        if len(local_buffer):
            line = "[==>]Received %d bytes from localhost." % len(local_buffer)
            print(line)
            hexdump(local_buffer)
            local_buffer = request_handler(local_buffer)
            remote_socket.send(local_buffer)
            print("[==>] Sent to remote.")

        remote_buffer = receive_from(remote_socket)

        if len(remote_buffer):
            print("[<==] Received %d bytes from remote." % len(remote_buffer))
            hexdump(remote_buffer)
            remote_buffer = response_handler(remote_buffer)
            client_socket.send(remote_buffer)
            print("[<==] Sent to localhost.")
        if not len(local_buffer) or not len(remote_buffer):
            client_socket.close()
            remote_socket.close()
            print("[*] No more data. Closing connections.")
            break

def server_loop(local_host, local_port,
                remote_host, remote_port, receive_first):
    #create socket, bind it to the host then listen
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        server.bind((local_host, local_port))
    except Exception as e:
        print('problem on bind: %r' % e)
        print("[!!] Failed to listen on %s:%d" % (local_host, local_port))
        print("[!!] Check for other listening sockets or correct permissions.")
        sys.exit(0)
    print("[*] Listening on %s:%d" % (local_host, local_port))
    server.listen(5)
    #listen connection --> when comes in start a new thread
    while True:
        client_socket, addr = server.accept()
        # print out the local connection information
        line = "> Received incoming connection from %s:%d" % (addr[0],
addr[1])
        print(line)
        # start a thread to talk to the remote host
        proxy_thread = threading.Thread(
            target=proxy_handler,
            args=(client_socket, remote_host,
            remote_port, receive_first))
        proxy_thread.start()


def main():
    if len(sys.argv[1:]) != 5:
        print("Usage: ./proxy.py [localhost] [localport]", end='')
        print("[remotehost] [remoteport] [receive_first]")
        print("Example: ./proxy.py 127.0.0.1 9000 10.12.132.1 9000 True")
        sys.exit(0)

    local_host = sys.argv[1]
    local_port = int(sys.argv[2])

    remote_host = sys.argv[3]
    remote_port = int(sys.argv[4])

    receive_first = sys.argv[5]
    if "True" in receive_first:
        receive_first = True
    else:
        receive_first = False

    server_loop(local_host, local_port,
        remote_host, remote_port, receive_first)

if __name__ == '__main__':
    main()
