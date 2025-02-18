from http.server import ThreadingHTTPServer, BaseHTTPRequestHandler
import threading

class SimpleHTTPRequestHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(200)
        self.send_header('Content-type', 'text/html')
        self.end_headers()
        message = f"Hello, World! You requested {self.path}\n"
        self.wfile.write(message.encode('utf-8'))

def run(server_class=ThreadingHTTPServer, handler_class=SimpleHTTPRequestHandler, port=8000):
    server_address = ('', port)
    httpd = server_class(server_address, handler_class)
    print(f"Starting httpd on port {port}...")
    print(f"Running in thread: {threading.current_thread().name}")
    httpd.serve_forever()

if __name__ == '__main__':
    run()