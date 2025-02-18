from http.server import HTTPServer, SimpleHTTPRequestHandler
from ssl import PROTOCOL_TLS_SERVER, SSLContext
from pathlib import Path

chemin_complet = Path(__file__).resolve()
repertoire = chemin_complet.parent

ssl_context = SSLContext(PROTOCOL_TLS_SERVER)
ssl_context.load_cert_chain(repertoire / "cert.pem", repertoire / "private.key")
# change the host address if you want
server = HTTPServer(("0.0.0.0", 443), SimpleHTTPRequestHandler)
server.socket = ssl_context.wrap_socket(server.socket, server_side=True)
server.serve_forever()

# (wsl) openssl req -x509 -nodes -days 365 -newkey rsa:2048 -out cert.pem -keyout private.key