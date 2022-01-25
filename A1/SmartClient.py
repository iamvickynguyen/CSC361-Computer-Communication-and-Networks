import socket
import sys
import ssl
import re

#https://python-hyper.org/projects/h2/en/stable/negotiating-http2.html

def is_http2_supported(url):
    context = ssl.create_default_context()
    context.set_alpn_protocols(['h2', 'spdy/3', 'http/1.1'])
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        with context.wrap_socket(sock, server_hostname=url) as ssock:
            ssock.connect((url, 443))
            return ssock.selected_alpn_protocol() == "h2"

def get_status(response):
    return int(re.search('(?<=HTTP/1.[0|1]\s*)(\d+)', response).group())

def connect():
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM) 
    s.connect(("www.google.ca",80)) # Connect
    request = "GET /index.html HTTP/1.0\n\n"
    s.send(request.encode()) # Send request 
    data = s.recv(10000).decode() # Get response
    s.close()
    print(data)

def main():
    if len(sys.argv) != 2:
        sys.exit("Error: expected 1 argument")

    url = sys.argv[1]
    print("website:", url)

    # is http2 supported
    print("1. Supports http2:", 'yes' if is_http2_supported(url) else 'no')

    # cookies
    
    print("2. List of Cookies:")

    # password-protected
    print("3. Password-protected:", 'yes' if get_status(response) == 401 else 'no')

    connect()

if __name__ == "__main__":
    main()