from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import parse_qs, urlparse
from http.cookies import SimpleCookie
import cgi

class WebServer(BaseHTTPRequestHandler):
    @property
    def parsed_url(self):
        return urlparse(self.path)

    @property
    def query_data(self):
        return parse_qs(self.parsed_url.query)

    def read_post_data(self):
        # Récupérer le Content-Type ou utiliser une valeur par défaut
        content_type = self.headers.get('Content-Type')
        if content_type is None:
            content_type = 'application/x-www-form-urlencoded'
        ctype, pdict = cgi.parse_header(content_type)

        content_length = self.headers.get('Content-Length')
        if ctype == 'multipart/form-data':
            if content_length:
                pdict['CONTENT-LENGTH'] = int(content_length)
            # Vérifier que 'boundary' existe dans pdict avant de le convertir en bytes
            if 'boundary' in pdict:
                pdict['boundary'] = bytes(pdict['boundary'], "utf-8")
            post_vars = cgi.parse_multipart(self.rfile, pdict)
        elif ctype == 'application/x-www-form-urlencoded':
            length = int(content_length) if content_length else 0
            post_vars = parse_qs(self.rfile.read(length).decode('utf-8'), keep_blank_values=True)
        else:
            post_vars = {}
        return post_vars

    def cookies(self):
        if "Cookie" in self.headers:
            return SimpleCookie(self.headers["Cookie"])
        else:
            return SimpleCookie()

    def do_GET(self):
        self.send_response(200)
        self.send_header("Content-type", "text/html")
        self.end_headers()
        message = "Handling GET request bro !"
        self.wfile.write(message.encode("utf-8"))
        # Exemple d'utilisation de query_data :
        # query_string = self.query_data.get('key', [''])[0]

    def do_POST(self):
        post_data = self.read_post_data()
        self.send_response(200)
        self.send_header("Content-type", "text/html")
        self.end_headers()
        message = "Handling POST request bro !"
        self.wfile.write(message.encode("utf-8"))
        # Exemple d'utilisation de post_data :
        # post_var = post_data.get('key', [''])[0]

def run(server_class=HTTPServer, handler_class=WebServer, port=8000):
    server_address = ('', port)
    httpd = server_class(server_address, handler_class)
    print(f"Starting httpd on port {port}...")
    httpd.serve_forever()

if __name__ == "__main__":
    run()
