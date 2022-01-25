import socket
import sys
import ssl

#https://python-hyper.org/projects/h2/en/stable/negotiating-http2.html

def is_http2_supported(url):
    context = ssl.create_default_context()
    context.set_alpn_protocols(['h2', 'spdy/3', 'http/1.1'])
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        with context.wrap_socket(sock, server_hostname=url) as ssock:
            ssock.connect((url, 443))
            return ssock.selected_alpn_protocol() == "h2"

def main():
    if len(sys.argv) != 2:
        sys.exit("Error: expected 1 argument")

    url = sys.argv[1]
    print("website:", url)
    print("1. Supports http2:", 'yes' if is_http2_supported(url) else 'no')

if __name__ == "__main__":
    main()