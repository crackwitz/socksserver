#!/usr/bin/env python2
import os
import sys
import socket
import select
import enum
import time
import threading
import pprint; pp = pprint.pprint

import socks5

# ----------------------------------------------------------------------

def shuffle(src, dst):
	try:
		data = src.recv(2**16)
		if not data:
			return 0
		dst.sendall(data)
		return len(data)
	except socket.error, e:
		print e
		return False

class Association(object):
	def __init__(self, clientconn, remoteconn=None):
		self.client = clientconn
		self.remote = remoteconn
		self.thread = None
		self.closed = False
		self.timeout = 1.0
	
	def __hash__(self):
		return id(self)

	#def __repr__(self): return "<Association #%x>" % (id(self),)

	def close(self):
		if self.closed:
			return
		
		self.closed = True
		
		if hasattr(self, 'server'):
			self.server.remove_assoc(self)

		print "closing assoc", self
		
		if self.client:
			self.client.shutdown(socket.SHUT_RDWR)
			self.client.close()
			self.client = None

		if self.remote:
			self.remote.shutdown(socket.SHUT_RDWR)
			self.remote.close()
			self.remote = None
		
	def authenticate(self):
		# CLIENT AUTH : GET OFFERED METHODS
		offered = socks5.read_methods_offer(self.client)

		if socks5.Method.NO_AUTH in offered['methods']:
			selected = socks5.Method.NO_AUTH
		elif socks5.Method.PASSWORD in offered['methods']:
			selected = socks5.Method.PASSWORD
		else:
			selected = socks5.Method.NONE_ACCEPTED

		# CLIENT AUTH : SELECT METHOD
		socks5.write_method_selected(self.client, selected)

		if selected == socks5.Method.NONE_ACCEPTED:
			self.close()
			return False

		# CLIENT AUTH : AUTHENTICATE...
		if selected == socks5.Method.PASSWORD:
			request = socks5.read_userpass_request(clientconn)
			print "USER, PASSWORD:", request
			socks5.write_userpass_status(clientconn, socks5.Reply.SUCCEEDED)

		return True
	
	def accept_command(self):
		# RECEIVE COMMAND
		request = socks5.read_request(self.client)
		
		if request['command'] != socks5.Command.CONNECT:
			socks5.write_reply(self.client, socks5.Reply.CMD_NOT_SUPPORTED)
			self.close()
			return False
		
		assert request['command'] == socks5.Command.CONNECT

		assert request['atyp'] in (socks5.AddressType.IPV4, socks5.AddressType.DOMAINNAME)

		print "connection to", repr(request['dst_addr']), "port", request['dst_port']

		remoteconn = socket.socket()
		if self.remotebind:
			remoteconn.bind(self.remotebind)
		remoteconn.connect((request['dst_addr'], request['dst_port']))

		(paddr, pport) = remoteconn.getsockname()
		socks5.write_reply(self.client, socks5.Reply.SUCCEEDED,
			socks5.AddressType.IPV4,
			paddr, pport
		)

		self.remote = remoteconn

		return True

	def run(self):
		self.thread = threading.Thread(target=self._thread)
		self.thread.start()

	def _thread(self):
		# 0: closed
		# 1: check read-end
		# 2: check write-end
		# progression 1 -> 2 -> 3:shuffle -> 0 or 1
		
		out_state = 1
		in_state = 1
		
		while (out_state > 0) or (in_state > 0):
			#print "out", out_state, "in", in_state

			if (self.client is None) or (self.remote is None):
				break

			readables = []
			if out_state == 1: readables.append(self.client)
			if  in_state == 1: readables.append(self.remote)
			writables = []
			if out_state == 2: writables.append(self.remote)
			if  in_state == 2: writables.append(self.client)
			
			(rfd,wfd,_) = select.select(readables, writables, [], self.timeout)
			
			if self.client in rfd: out_state = 2
			if self.remote in rfd: in_state = 2
			if self.client in wfd: in_state = 3
			if self.remote in wfd: out_state = 3

			#print "-> out", out_state, "in", in_state
			
			if out_state == 3:
				res = shuffle(self.client, self.remote)
				if not res:
					out_state = 0
					self.remote.shutdown(socket.SHUT_WR)
				else:
					out_state = 1

			if in_state == 3:
				res = shuffle(self.remote, self.client)
				if not res:
					in_state = 0
					self.client.shutdown(socket.SHUT_WR)
				else:
					in_state = 1
		
		#print "done spooling"
		self.close()

class Endpoint(enum.Enum):
	CLIENT = 1
	REMOTE = 2
	
class SocksServer(object):
	def __init__(self, interface):
		self.interface = interface
		self.assocs = set()
		self.remotebind = None
		self.timeout = 1.0
		
	def accept_client(self):
		(clientconn, addr) = self.serversock.accept()
		print "new connection from", addr
		
		assoc = Association(clientconn)
		assoc.remotebind = self.remotebind
		
		if assoc.authenticate() == False:
			assoc.close()
			return
		
		res = assoc.accept_command()
		
		if not res:
			assoc.close()
			return
		
		assert assoc.remote is not None
		
		assoc.server = self
		self.add_assoc(assoc)

		assoc.run()

	def add_assoc(self, assoc):
		self.assocs.add(assoc)
		
	def remove_assoc(self, assoc):
		if assoc in self.assocs:
			self.assocs.remove(assoc)

	def run(self):
		self.serversock = socket.socket()
		self.serversock.bind(self.interface)
		self.serversock.listen(5)
		
		while True:
			rfd = [self.serversock]
			try:
				(rfd,_,_) = select.select(rfd, [], [], self.timeout)
			except KeyboardInterrupt:
				break

			if self.serversock in rfd:
				self.accept_client()
		
		for a in list(self.assocs):
			a.close()

# ----------------------------------------------------------------------

if __name__ == '__main__':
	if len(sys.argv) >= 3:
		clientaddr = sys.argv[1]
		clientport = int(sys.argv[2])
	else:
		clientaddr = '127.0.0.1'
		clientport = 1080
	
	server = SocksServer((clientaddr, clientport))
	
	if len(sys.argv) >= 4:
		server.remotebind = (sys.argv[3], 0)
	
	server.run()
