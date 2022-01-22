from socket import *
import sys
import ssl
import re

'''
NOTE:
http 2.0: set_alpn_protocols(), ssl
s =  ssl.SSLContext(protocol=ssl.PROTOCOL_TLSv1_3)

password protected: 401 http response
'''

PORT = 443

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

def check_401(response):
    return any(filter(lambda line: line.startswith('HTTP/') and '401' in line, response.split('\n')))

def main(uri):
    try:
        ctx = ssl.create_default_context()
        ctx.set_alpn_protocols(['h2'])

        # s = socket(AF_INET, SOCK_STREAM)
        # s.connect((uri, PORT))
        # print("HERE:", is_http2_supported)
        # request = "GET /index.html h2\n\n"
        # s.send(request.encode())
        # response = s.recv(10000).decode()
        # print(response)
        # s.close()

        s = socket(AF_INET, SOCK_STREAM)
        conn = ctx.wrap_socket(s, server_hostname=uri)
        conn.connect((uri, PORT))
        is_http2_supported = conn.selected_alpn_protocol()
        print("HERE:", is_http2_supported)
        request = "GET /index.html h2\n\n"
        conn.send(request.encode())
        response = conn.recv(10000).decode()
        print(response)
        conn.close()
        
        
        cookies = get_cookies(response)
        is_password_protected = check_401(response)

        # output
        print("website:", uri)
        print("1. Supports http2:")
        print("2. List of Cookies:")
        for cookie in cookies: print(cookie)
        print("3. Password-protected:", 'yes' if is_password_protected else 'no')
    except error as e:
        print(e)

if __name__ == "__main__":
    main(sys.argv[1])