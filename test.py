#!/usr/bin/python
#! -*-coding:utf-8 -*-
import socket
import select
import time
import struct
import SocketServer
import logging


class socks5TcpHandler(SocketServer.StreamRequestHandler):
	def handle_tcp(self, sock, remote):
		fdset = [sock,remote]
		try:
			while True:
				r, w, e=select.select(fdset,[],[])
				if sock in r:
					data=sock.recv(4096)
					if len(data) > 0:
						remote.send(data)
					else:
						break
				if remote in r:
					data=remote.recv(4096)
					if len(data) > 0:
						sock.send(data)
					else:
						break
		except Exception as e:
			logging.warn(e)
			raise e
		finally:
			remote.close()
			sock.close()
	def handle(self):
		try:
			print "socks connection from {}".format(self.client_address)
			logging.info("socks connection from {}".format(self.client_address))
			s=self.connection
			#1.version
			#self.rfile.read(262)
			s.recv(262)
			#s.send('\x05\x00')
			self.wfile.write('\x05\x00')
			#2.requests
			data=self.rfile.read(4)
			'''
			o  CMD
             o  CONNECT X'01'
             o  BIND X'02'
             o  UDP ASSOCIATE X'03'
			'''
			CMD=ord(data[1])
			'''
			o  ATYP   address type of following address
             o  IP V4 address: X'01'
             o  DOMAINNAME: X'03'
             o  IP V6 address: X'04'
			'''
			ATYP=ord(data[3])
			if ATYP==1:		#ipv4
				addr=socket.inet_ntoa(self.rfile.read(4))
			if ATYP==3:		#domain
				addr = self.rfile.read(ord(self.rfile.read(1)[0]))
				#pass
			port=struct.unpack('>H',self.rfile.read(2))
			'''
			The SOCKS request information is sent by the client as soon as it has
   			established a connection to the SOCKS server, and completed the
   			authentication negotiations.  The server evaluates the request, and
   			returns a reply formed as follows:

        	+----+-----+-------+------+----------+----------+
        	|VER | REP |  RSV  | ATYP | BND.ADDR | BND.PORT |
        	+----+-----+-------+------+----------+----------+
        	| 1  |  1  | X'00' |  1   | Variable |    2     |
        	+----+-----+-------+------+----------+----------+

     		Where:

		      o  VER    protocol version: X'05'
		      o  REP    Reply field:
		         o  X'00' succeeded
		         o  X'01' general SOCKS server failure
		         o  X'02' connection not allowed by ruleset
		         o  X'03' Network unreachable
		         o  X'04' Host unreachable
		         o  X'05' Connection refused
		         o  X'06' TTL expired
		         o  X'07' Command not supported
		         o  X'08' Address type not supported
		         o  X'09' to X'FF' unassigned
		      o  RSV    RESERVED
		      o  ATYP   address type of following address
		      	 o  X'01'
					the address is a version-4 IP address, with a length of 4 octets
				 o  X'03'
					the address field contains a fully-qualified domain name.  The first
   					octet of the address field contains the number of octets of name that
   					follow, there is no terminating NUL octet.
   				 o  X'04'
					the address is a version-6 IP address, with a length of 16 octets.
			'''
			try:
				if CMD==1:
					remote=socket.socket(socket.AF_INET,socket.SOCK_STREAM)
					remote.connect((addr,port[0]))
					reply='\x05\x00\x00\x01'#VER \x05 REP \x01 succeeded
					print 'TCP connect to {}'.format(addr,port[0])
				else:
					reply='\x05\x07\x00\x01'#REP \x07 Command not supported
				remote_addr=remote.getsockname()
				reply+=socket.inet_aton(remote_addr[0])+struct.pack('>H',remote_addr[1])
			except socket.error as e:
				logging.warn(e)
				raise e
				reply='\x05\x05\x00\x01\x00\x00\x00\x00\x00\x00'
			self.wfile.write(reply)
			#s.send(reply)
			if reply[1]=='\x00':
				if CMD==1:
					self.handle_tcp(s,remote)
		except socket.error as e:
			logging.warn(e)
			raise e

if __name__=='__main__':
	logging.basicConfig(filename='socks5server.log',level=logging.DEBUG, format='%(asctime)s %(levelname)-8s %(message)s',
        datefmt='%Y-%m-%d %H:%M:%S', filemode='a+')
	server=SocketServer.ThreadingTCPServer(('',8888),socks5TcpHandler)
	print 'Start server at port 8888'
	logging.info('Start server at port 8888')
	server.serve_forever() #start server
