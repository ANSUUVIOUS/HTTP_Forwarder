#!/usr/bin/env python3


import http.client
import http.server
from http.server import BaseHTTPRequestHandler
import argparse
import netifaces


class ProxyHandler(BaseHTTPRequestHandler):

    destination_host = "example.com"
    destination_port = 443
    unverified_https_site = True

        
    def do_GET(self):
        self.proxy_request()

    def do_POST(self):
        self.proxy_request()

    def proxy_request(self):
        # Destination HTTPS URL

        # Connect to the destination server
        conn = http.client.HTTPSConnection(self.destination_host, self.destination_port)
        conn.request(self.command, self.path, body=self.rfile.read(), headers=self.headers)

        # Get the response from the destination server
        response = conn.getresponse()

        # Send response back to the client
        self.send_response(response.status)
        for header, value in response.getheaders():
            self.send_header(header, value)
        self.end_headers()
        self.wfile.write(response.read())
        conn.close()

def get_local_ip():
    # Get all network interfaces
    interfaces = netifaces.interfaces()

    # Iterate over each interface
    for iface in interfaces:
        # Get the addresses for the interface
        addresses = netifaces.ifaddresses(iface)

        # Check if the interface has IPv4 addresses and is not localhost
        if netifaces.AF_INET in addresses and 'lo' not in iface:
            # Iterate over each address
            for addr_info in addresses[netifaces.AF_INET]:
                # Get the IP address
                ip_address = addr_info['addr']

                # Return the IP address if it's not localhost
                if ip_address != '127.0.0.1':
                    return ip_address

def run_proxy_server():
    parser = argparse.ArgumentParser(description="RDDA HTTP Proxy Server")
    parser.add_argument('--destination-host', '-dh', default="example.com", help="Destination host (ex: HTTPs RD Server Link)")
    parser.add_argument('--source-host', '-sh', default=get_local_ip(), help="Source host to connect to for HTTPs Forwarding")
    parser.add_argument('--source-port', '-sp', type=int, default=8080, help="Source port of HTTP Server")
    parser.add_argument('--verified-site', '-vs', type=bool, default=False, help="Report whether the site is verified or not")
    parser.add_argument('--tokens', nargs='+', required=False, help='RDDA tokens that will be formatted to valid HTTP URLs for usage')

    args = parser.parse_args()
    server_address = (args.source_host, args.source_port)

    httpd = http.server.HTTPServer(server_address, ProxyHandler)
    print(f"Proxy server running on port {args.source_port}")

    if args.tokens is not None and len((args.tokens)) > 0:
        for idx, token in enumerate(args.tokens):
            print(f"[{idx + 1}] http://{args.source_host}:{args.source_port}/index.html?token={token}")
    else:
        token = str(input("Please enter in a token to be used for connection to the RDDA instance: "))
        print(f"[1] http://{args.source_host}:{args.source_port}/index.html?token={token}")

    httpd.destination_host = args.destination_host
    httpd.unverified_https_site = args.verified_site
    httpd.serve_forever()

if __name__ == '__main__':  # Change this to the desired port
    run_proxy_server()
