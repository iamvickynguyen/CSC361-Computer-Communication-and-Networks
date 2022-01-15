# import socket
# import sys

# uri = input()
# HOST = uri
# PORT = 80

# print('HOST:', HOST)

# try:
#     s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)        
# except socket.error:
#     print("failed to create socket")
#     sys.exit()

# try:
#     ip = socket.gethostbyname(HOST)
# except socket.error:
#     print('failed to get ip')
#     sys.exit()

# try:
#     s.connect((ip, PORT))
#     response = s.recv(4096)
#     print(response)
#     s.close()
# except:
#     print('failed')
#     sys.exit()


import socket
import sys  

host = 'www.pythonprogramminglanguage.com'
port = 80  # web

# create socket
print('# Creating socket')
try:
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
except socket.error:
    print('Failed to create socket')
    sys.exit()

print('# Getting remote IP address') 
try:
    remote_ip = socket.gethostbyname( host )
except socket.gaierror:
    print('Hostname could not be resolved. Exiting')
    sys.exit()

# Connect to remote server
print('# Connecting to server, ' + host + ' (' + remote_ip + ')')
s.connect((remote_ip , port))


# Receive data
print('# Receive data from server')
reply = s.recv(4096)

print(reply )