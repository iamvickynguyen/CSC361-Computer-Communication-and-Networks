import socket
import sys

'''
NOTE:
http 2.0: set_alpn_protocols(), ssl
s =  ssl.SSLContext(protocol=ssl.PROTOCOL_TLSv1_3)

password protected: 401 http response
'''

PORT = 80

def main(uri):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect((uri, PORT))
    request = "GET /index.html HTTP/1.0\n\n"
    s.send(request.encode())
    data = s.recv(10000)
    print(data.decode())
    s.close()

if __name__ == "__main__":
    main(sys.argv[1])