import logging
import sys
import time
import socket
import socketserver

import sipfullproxy
from sipfullproxy import UDPHandler


def main():
    hostname = socket.gethostname()
    local_ip = socket.gethostbyname(hostname)
    sipfullproxy.HOST, sipfullproxy.PORT = local_ip, 5060
    logging.basicConfig(format='%(asctime)s:%(message)s', filename='proxy.log', level=logging.INFO, datefmt='%H:%M:%S')
    logging.info(time.strftime("DATE : %a, %d %b %Y",))
    hostname = socket.gethostname()
    logging.info("PROXY IP: " + local_ip+"\n")
    ipaddress = local_ip

    sipfullproxy.recordroute = "Record-Route: <sip:%s:%d;lr>" % (ipaddress, sipfullproxy.PORT)
    sipfullproxy.topvia = "Via: SIP/2.0/UDP %s:%d" % (ipaddress, sipfullproxy.PORT)
    server = socketserver.UDPServer((sipfullproxy.HOST, sipfullproxy.PORT), UDPHandler)
    server.serve_forever()


main()
