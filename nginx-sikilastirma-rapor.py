#!/usr/bin/env python

from nginxparser import load, dumps

class bcolors:
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'

def printok(msg):
    print(bcolors.OKGREEN + msg + bcolors.ENDC)

def printwarn(msg):
    print(bcolors.WARNING + msg + bcolors.ENDC)

def find_http(conf):
    for i in conf:
        if type(i[0]) == list and len(i[0]) == 1 and i[0][0] == 'http':
            return i[1]

def check_server_tokens(conf):
    http = find_http(conf)
    value = 'undefined'
    for i in http:
        if i[0] == 'server_tokens':
            if i[1] == 'off':
                printok('- Server tokens are off.')
                return
            value = i[1]
    printwarn('- Server tokens should be turned off, current value for server_tokens: ' + value)

def check_error_pages(conf):
    http = find_http(conf)
    value = 'undefined'
    for i in http:
        if i[0] == 'error_page':
            if i[1] == '401 403 404 /404.html':
                printok('- Error pages are being redirected to 404.html.')
                return
            value = i[1]
    printwarn('- Error page redirection may need your attention, current value for error_page: ' + value)

def check_buffer_sizes(conf):
    http = find_http(conf)
    check_header = False
    header_size = 'undefined'
    check_body = False
    body_size = 'undefined'
    for i in http:
        if i[0] == 'client_header_buffer_size':
            if i[1] == '1k':
                check_header = True
            else:
                header_size = i[1]
        if i[0] == 'client_body_buffer_size':
            if i[1] == '1k':
                check_body = True
            else:
                body_size = i[1]
    if check_header and check_body:
        printok('- Buffer sizes are small enough.')
        return
    printwarn('- Buffer sizes may need your attention, current values: client_header_buffer_size - ' + header_size + '\tclient_body_buffer_size - ' + body_size)

'''
nginxparser has failed me. it won't parse the file with specific hardening directive inserted. why mate, why?
'''
def check_http_methods(conf):
    pass

def check_x_frame_options(conf):
    http = find_http(conf)
    value = 'undefined'
    for i in http:
        if i[0] == 'add_header':
            if i[1] == 'X-Frame-Options "SAMEORIGIN"':
                printok('- X-Frame-Options header is set to "SAMEORIGIN"')
                return
            elif i[1].find('X-Frame-Options') != -1:
                value = i[1]
    printwarn('- X-Frame-Options header value may need your attention, current value: ' + value)

'''
nginxparser has failed me. again?
'''
def check_x_xss_protection(conf):
    pass
    '''
    http = find_http(conf)
    value = 'undefined'
    for i in http:
        if i[0] == 'add_header':
            if i[1] == 'X-XSS-Protection "1; mode=block";':
                printok('- X-XSS-Protection header is set to "1; mode=block"')
                return
            elif i[1].find('X-XSS-Protection') != -1:
                value = i[1]
    printwarn('- X-XSS-Protection header value may need your attention, current value: ' + value)
    '''

'''
nginxparser has failed me. good lord, I will fix that instead of writing this script.
'''
def check_content_security_policy(conf):
    pass
    '''
    http = find_http(conf)
    value = 'undefined'
    for i in http:
        if i[0] == 'add_header':
            if i[1] == 'Content-Security-Policy "default-src 'self'; script-src 'self'; object-src 'self'; style-src 'self'; img-src 'self'; media-src 'self'; frame-src 'self'; font-src 'self'; connect-src 'self'";':
                printok('- Content-Security-Policy header is set')
                return
            elif i[1].find('Content-Security-Policy') != -1:
                value = i[1]
    printwarn('- Content-Security-Policy header value may need your attention, current value: ' + value)
    '''

def check_diffie_hellman_parameters(conf):
    http = find_http(conf)
    value = 'undefined'
    for i in http:
        if i[0] == 'ssl_dhparam':
            if i[1] == '/etc/nginx/ssl/dhparam.pem':
                printok('- Diffie-Hellman parameters are generated and are being used.')
                return
            value = i[1]
    printwarn('- Did you generate strong Diffie-Hellman parameters? current parameters reside in file: ' + value)

def check_ssl_prefer_server_ciphers(conf):
    http = find_http(conf)
    value = 'undefined'
    for i in http:
        if i[0] == 'ssl_prefer_server_ciphers':
            if i[1] == 'on':
                printok('- Server ciphers are being preferred.')
                return
            value = i[1]
    printwarn('- Server ciphers are not being preferred, current value for ssl_prefer_server_ciphers: ' + value)

def check_ssl_protocols(conf):
    http = find_http(conf)
    value = 'undefined'
    for i in http:
        if i[0] == 'ssl_protocols':
            if i[1] == 'TLSv1 TLSv1.1 TLSv1.2':
                printok('- SSLv3 is not being used, POODLE averted.')
                return
            value = i[1]
    printwarn('- Dangerous SSL versions might be in use, current value for ssl_protocols: ' + value)

def check_ssl_ciphers(conf):
    http = find_http(conf)
    value = 'undefined'
    for i in http:
        if i[0] == 'ssl_ciphers':
            if i[1] == 'ECDHE-RSA-AES256-GCM-SHA384:ECDHE-RSA-AES128-GCM-SHA256:DHE-RSA-AES256-GCM-SHA384:DHE-RSA-AES128-GCM-SHA256:ECDHE-RSA-AES256-SHA384:ECDHE-RSA-AES128-SHA256:ECDHE-RSA-AES256-SHA:ECDHE-RSA-AES128-SHA:DHE-RSA-AES256-SHA256:DHE-RSA-AES128-SHA256:DHE-RSA-AES256-SHA:DHE-RSA-AES128-SHA:ECDHE-RSA-DES-CBC3-SHA:EDH-RSA-DES-CBC3-SHA:AES256-GCM-SHA384:AES128-GCM-SHA256:AES256-SHA256:AES128-SHA256:AES256-SHA:AES128-SHA:DES-CBC3-SHA:HIGH:!aNULL:!eNULL:!EXPORT:!DES:!MD5:!PSK:!RC4':
                printok('- Strict use of strong ciphers are enforced.')
                return
            value = i[1]
    printwarn('- Weak ciphers might be in use, current value for ssl_ciphers: ' + value)

'''
not even going to try this time. I know nginxparser will fail me.
'''
def check_hsts(conf):
    pass

def main():
    with open('/etc/nginx/nginx.conf') as conffile:
        conf = load(conffile)
        check_server_tokens(conf)
        check_error_pages(conf)
        check_buffer_sizes(conf)
        check_http_methods(conf)
        check_x_frame_options(conf)
        check_x_xss_protection(conf)
        check_content_security_policy(conf)
        check_diffie_hellman_parameters(conf)
        check_ssl_prefer_server_ciphers(conf)
        check_ssl_protocols(conf)
        check_ssl_ciphers(conf)
        check_hsts(conf)

if __name__ == '__main__':
    main()
