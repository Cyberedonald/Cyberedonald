# Telstra Cyber Task 3
# Firewall Server Handler
 
from http.server import BaseHTTPRequestHandler, HTTPServer
import re
 
host = "localhost"
port = 8000
 
#########
# Handle the response here
def block_request(self):
   print("Blocking request")
   self.send_response(403)
   self.send_header("content-type", "text/plain")
   self.end_headers()
   self.wfile.write(b"Access Denied: Malicious request detected")
 
def handle_request(self):
   self.send_response(200)
   self.send_header("content-type", "application/json")
   self.end_headers()
   self.wfile.write(b'{"status": "success", "message": "Request processed"}')
 
#########
 
class ServerHandler(BaseHTTPRequestHandler):
   # Define malicious patterns to detect
   malicious_patterns = [
       r'class\.module\.classLoader',  # Detects class loader manipulation
       r'getRuntime\(\)\.exec',        # Detects runtime execution attempts
       r'tomcatwar\.jsp',             # Detects specific malicious JSP file
       r'%25%7B.*%7D',               # Detects encoded JSP patterns (%{...})
   ]
 
   def _check_security(self):
       # Get request path and content
       path = self.path.lower()
       
       # Check headers for suspicious patterns
       headers = str(self.headers).lower()
       
       # For POST requests, check the body content
       content = ""
       if self.command == "POST":
           content_length = int(self.headers.get('Content-Length', 0))
           if content_length > 0:
               content = self.rfile.read(content_length).decode('utf-8').lower()
 
       # Check for malicious patterns in path, headers, and content
       full_request = path + headers + content
       for pattern in self.malicious_patterns:
           if re.search(pattern, full_request):
               return False
       
       # Additional specific checks for this attack
       if 'tomcatwar.jsp' in path and 'content-type' in self.headers:
           if 'application/x-www-form-urlencoded' in self.headers['content-type'].lower():
               return False
               
       return True
 
   def do_GET(self):
       if self._check_security():
           handle_request(self)
       else:
           block_request(self)
 
   def do_POST(self):
       if self._check_security():
           handle_request(self)
       else:
           block_request(self)
 
if __name__ == "__main":        
   server = HTTPServer((host, port), ServerHandler)
   print("[+] Firewall Server")
   print("[+] HTTP Web Server running on: %s:%s" % (host, port))
 
   try:
       server.serve_forever()
   except KeyboardInterrupt:
       pass
 
   server.server_close()
   print("[+] Server terminated. Exiting...")
   exit(0)
   
