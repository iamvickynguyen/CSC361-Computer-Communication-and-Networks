import socket
import sys
import re

'''
NOTE:
http 2.0: set_alpn_protocols(), ssl
s =  ssl.SSLContext(protocol=ssl.PROTOCOL_TLSv1_3)

password protected: 401 http response
'''

PORT = 80

def to_cookie_string(cookie):
    s = f"cookie name: {cookie['name'].group().strip()}"
    if cookie['expires']:
        s += f", expires time: {cookie['expires'].group().strip()}"
    if cookie['domain']:
        s += f", domain name: {cookie['domain'].group().strip()}"
    return s

def get_cookies(response):
    cookie_lines = filter(lambda line: line.startswith('Set-Cookie:'), response.split('\n'))
    cookies = map(lambda cookie:
                    {
                        'name': re.search('(?<=Set-Cookie:)([^=]*)(?=\=)', cookie),
                        'expires': re.search('(?<=expires=)([^;]*)', cookie),
                        'domain': re.search('(?<=domain=)([^;]*)', cookie)
                    }, cookie_lines)
    return map(lambda cookie: to_cookie_string(cookie), cookies)

def main(uri):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect((uri, PORT))
    request = "GET /index.html HTTP/1.0\n\n"
    s.send(request.encode())
    response = s.recv(10000).decode()
    s.close()
    
    cookies = get_cookies(response)

    # output
    print("website:", uri)
    print("1. Supports http2:")
    print("2. List of Cookies:")
    for cookie in cookies: print(cookie)
    print("3. Password-protected:")

if __name__ == "__main__":
    main(sys.argv[1])