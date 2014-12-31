import enum
import struct
import socket

# https://tools.ietf.org/html/rfc1928 SOCKS 5
# https://tools.ietf.org/html/rfc1929 user/password auth
# https://tools.ietf.org/html/rfc1961 GSS-API

# ----------------------------------------------------------------------
# AUTH NEGOTIATION

class Method(enum.Enum):
	NO_AUTH       = 0x00
	GSSAPI        = 0x01 # MUST be supported
	PASSWORD      = 0x02 # SHOULD be supported
	# 0x03..0x7f IANA assigned
	# 0x80..0xfe reserved for private methods
	NONE_ACCEPTED = 0xFF

# client writes
def write_methods_offer(sock, *methods):
	version = 0x05
	nmethods = len(methods)
	assert 1 <= len(methods) <= 255
	assert all(isinstance(m, Method) for m in methods)
	
	res = struct.pack("!BB", version, nmethods)
	res += ''.join(struct.pack("!B", method.value) for method in methods)
	
	sock.sendall(res)

# server reads
def read_methods_offer(sock):
	header = sock.recv(2)
	assert len(header) == 2
	(version, nmethods) = struct.unpack("!BB", header)
	
	assert version == 0x05
	assert 1 <= nmethods <= 255
	
	methods = sock.recv(nmethods)
	assert len(methods) == nmethods
	methods = struct.unpack("!" + nmethods * "B", methods)
	methods = map(Method, methods)
	
	return {
		'version': version,
		'methods': methods
	}

# server writes
def write_method_selected(sock, method):
	if method is None:
		method = Method.NONE_ACCEPTED

	assert isinstance(method, Method)
	
	version = 0x05
	
	res = struct.pack("!BB", version, method.value)
	
	sock.sendall(res)

# client reads
def read_method_selected(sock):
	data = sock.recv(2)
	assert len(data) == 2
	
	(version, method) = struct.unpack("!BB", data)

	assert version == 0x05
	method = Method(method)
	
	return method

# ----------------------------------------------------------------------
# USERNAME/PASSWORD

# client writes
def write_userpass_request(sock, username, password):
	assert 1 <= len(username) <= 255
	assert 1 <= len(password) <= 255
	
	res = struct.pack("!BBsBs", version, len(username), username, len(password), password)
	
	sock.sendall(res)

# server reads
def read_userpass_request(sock):
	data = sock.recv(2)
	assert len(data) == 2
	(ver,ulen) = struct.unpack("!BB", data)
	
	assert ver == 0x01 # current version of the subnegotiation

	uname = sock.recv(ulen)
	assert len(uname) == ulen
	
	data = sock.recv(1)
	assert len(data) == 1
	(plen,) = struct.unpack("!BB", data)
	
	passwd = sock.recv(plen)
	assert len(passwd) == plen
	
	return (uname, passwd)

# server sends
def write_userpass_status(sock, statuscode):
	# zero : OK / nonzero : error
	
	assert isinstance(statuscode, Reply)
	
	version = 0x01 # assumed
	res = struct.pack("!BB", version, statuscode.value)
	
	sock.sendall(res)

def read_userpass_status(sock):
	data = sock.recv(2)
	assert len(data) == 2
	
	(version, status) = struct.unpack("!BB", data)
	assert version == 0x01
	
	return status

# ----------------------------------------------------------------------
# REQUESTS

class Command(enum.Enum):
	CONNECT = 0x01
	BIND = 0x02
	UDP_ASSOCIATE = 0x03

class AddressType(enum.Enum):
	IPV4 = 0x01
	# addr length 4
	
	DOMAINNAME = 0x03
	# addr = FQDN, first byte is number of bytes following, no null-termination
	
	IPV6 = 0x04
	# addr length 16
	

# client sends
def write_request(sock, command, atyp, dst_addr, dst_port):
	version = 0x05
	reserved = 0x00
	assert isinstance(command, Command)
	assert isinstance(atyp, AddressType)
	
	if atyp == AddressType.IPV4:
		dst_addr = socket.inet_aton(dst_addr)
	elif atyp == AddressType.IPV6:
		dst_addr = socket.inet_pton(socket.AF_INET6, dst_addr)
	elif atyp == AddressType.DOMAINNAME:
		dst_addr = struct.pack("!B", len(dst_addr)) + dst_addr
	else:
		assert False
	
	data = struct.pack("!BBBB", version, command.value, reserved, atyp.value)
	data += dst_addr
	data += struct.pack("!H", dst_port)
	
	sock.sendall(data)

# server reads
def read_request(sock):
	data = sock.recv(4)
	assert len(data) == 4
	
	(ver, cmd, reserved, atyp) = struct.unpack("!BBBB", data)
	assert ver == 0x05
	cmd = Command(cmd)
	assert reserved == 0x00
	atyp = AddressType(atyp)
	
	if atyp == AddressType.IPV4:
		data = sock.recv(4)
		assert len(data) == 4
		dst_addr = socket.inet_ntoa(data)

	elif atyp == AddressType.IPV6:
		data = sock.recv(16)
		assert len(data) == 16
		dst_addr = socket.inet_ntop(socket.AF_INET6, data)

	elif atyp == AddressType.DOMAINNAME:
		data = sock.recv(1)
		assert len(data) == 1
		(length,) = struct.unpack("!B", data)
		dst_addr = sock.recv(length)
		assert len(dst_addr) == length
	
	data = sock.recv(2)
	assert len(data) == 2
	(dst_port,) = struct.unpack("!H", data)
	
	return {
		'command': cmd,
		'atyp': atyp,
		'dst_addr': dst_addr,
		'dst_port': dst_port
	}

# ----------------------------------------------------------------------
# REPLIES

class Reply(enum.Enum):
	SUCCEEDED = 0x00
	GENERAL_FAILURE = 0x01
	NOT_ALLOWED = 0x02
	NET_UNREACHABLE = 0x03
	HOST_UNREACHABLE = 0x04
	CONN_REFUSED = 0x05
	TTL_EXPIRED = 0x06
	CMD_NOT_SUPPORTED = 0x07
	ADDR_TYPE_NOT_SUPPORTED = 0x08
	# 0x08 .. 0xff unassigned

# server sends
def write_reply(sock, reply, atyp=None, bnd_addr=None, bnd_port=None):
	version = 0x05
	reserved = 0x00
	assert isinstance(reply, Reply)
	
	if (atyp is None) and (bnd_addr is None) and (bnd_port is None):
		atyp = AddressType.DOMAINNAME
		bnd_addr = struct.pack("!B", 0) + ""
		bnd_port = 0
	else:
		assert isinstance(atyp, AddressType)

		if atyp == AddressType.IPV4:
			bnd_addr = socket.inet_aton(bnd_addr)
		elif atyp == AddressType.IPV6:
			bnd_addr = socket.inet_pton(socket.AF_INET6, bnd_addr)
		elif atyp == AddressType.DOMAINNAME:
			bnd_addr = struct.pack("!B", len(bnd_addr)) + bnd_addr
		else:
			assert False
		
	data = struct.pack("!BBBB", version, reply.value, reserved, atyp.value)
	data += bnd_addr
	data += struct.pack("!H", bnd_port)
	
	sock.sendall(data)

# client reads
def read_reply(sock):
	data = sock.recv(4)
	assert len(data) == 4
	
	(ver, reply, reserved, atyp) == struct.unpack("!BBBB", data)
	assert ver == 0x05
	reply = Reply(reply)
	assert reserved == 0x00
	atyp = AddressType(atyp)
	
	if atyp == AddressType.IPV4:
		data = sock.recv(4)
		assert len(data) == 4
		bnd_addr = socket.inet_ntop(socket.AF_INET, data)

	elif atyp == AddressType.IPV6:
		data = sock.recv(16)
		assert len(data) == 16
		bnd_addr = socket.inet_ntop(socket.AF_INET6, data)

	elif atyp == AddressType.DOMAINNAME:
		data = sock.recv(1)
		assert len(data) == 1
		(len,) = struct.unpack("!B", data)
		bnd_addr = sock.recv(len)
		assert len(dst_addr) == len
	
	data = sock.recv(2)
	assert len(data) == 2
	(bnd_port,) = struct.unpack("!H", data)
	
	return {
		'reply': reply,
		'atyp': atyp,
		'bnd_addr': bnd_addr,
		'bnd_port': bnd_port
	}

# ----------------------------------------------------------------------
# here's some speculation

# reply to CONNECT:
#   bnd_addr, bnd_port = public-facing socket of connection to remote host

# replies to BIND:
#   reply #1: bnd_addr, bnd_port = public-facing listening socket
#   reply #2: bnd_addr, bnd_port = source ip+port of connecting remote host (signals incoming connection)

# reply to UDP_ASSOCIATE:
#   bnd_addr, bnd_port = local-facing socket that will forward packets from client to remote host
# request of UDP_ASSOCIATE:
#   ip+port determine target remote host for packets from client
#     proxy may reject packets received from other remote hosts
#   ip+port may be zero, implying client can't send packets, only receive (from any remote host)
