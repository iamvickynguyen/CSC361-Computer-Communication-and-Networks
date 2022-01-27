import socket
import sys
import ssl
import re
from urllib.parse import urlparse

#https://python-hyper.org/projects/h2/en/stable/negotiating-http2.html

def is_http2_supported(url):
    context = ssl.create_default_context()
    context.set_alpn_protocols(['h2', 'spdy/3', 'http/1.1'])
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        with context.wrap_socket(sock, server_hostname=url) as ssock:
            ssock.connect((url, 443))
            return ssock.selected_alpn_protocol() == "h2"

def get_status(response):
    return int(re.search(r'(HTTP/1.[01]\s*)(\d+)', response).group(2))

def get_location(response):
    new_location = urlparse(re.search(r'(Location:\s*)([^\r\n]*)', response).group(2))
    location = new_location.netloc
    path = new_location.path or '/'
    is_https = new_location.scheme == "https"
    return location, path, is_https

def connect_http(host, path):
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.connect((host, 80))
        request = f"GET {path} HTTP/1.1\nHost:{host}\r\n\r\n"
        sock.sendall(request.encode())
        response = sock.recv(10000).decode()
        return response

def connect_https(host, path):
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.connect((host, 443))
        sock = ssl.wrap_socket(sock)
        request = f"GET {path} HTTP/1.1\nHost:{host}\r\n\r\n"
        sock.sendall(request.encode())
        response = sock.recv(10000).decode() 
        return response

def connection(location):
    response = connect_http(location, '/')
    for i in range(5):
        status = get_status(response)
        print("STATUS:", status)
        if status != 301 and status != 302:
            return response

        new_location, path, is_https = get_location(response)

        if is_https:
            response = connect_https(new_location, path)
        else:
            response = connect_http(new_location, path)


def get_cookies(host):
    return connection(host)

# def test(host):
#     with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
#         sock.connect((host, 80))
#         request = f"GET / HTTP/1.1\nHost:{host}\nConnection: close\n\n"
#         print(request)
#         sock.sendall(request.encode())
#         response = sock.recv(10000).decode()
#         return response

# def test2(host):
#     s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
#     s.connect((host, 443))
#     # s = ssl.wrap_socket(s, keyfile=None, certfile=None, server_side=False, cert_reqs=ssl.CERT_NONE, ssl_version=ssl.PROTOCOL_SSLv23)
#     s = ssl.wrap_socket(s)
#     request = f"GET / HTTP/1.1\nHost:{host}\nConnection: close\n\n"
#     print(request)
#     s.sendall(request.encode())
#     response = s.recv(10000).decode()
#     return response


def main():
    if len(sys.argv) != 2:
        sys.exit("Error: expected 1 argument")

    url = sys.argv[1]
    print("website:", url)

    # is http2 supported
    print("1. Supports http2:", 'yes' if is_http2_supported(url) else 'no')

    # cookies
    print("2. List of Cookies:")
    # cookies = get_cookies(url)
    response = get_cookies(url)
    # connect_https('www.uvic.ca', '/')
    # response = test2("www.uvic.ca")
    print(response)
    

    # password-protected
    print("3. Password-protected:", 'yes' if get_status(response) == 401 else 'no')

if __name__ == "__main__":
    main()