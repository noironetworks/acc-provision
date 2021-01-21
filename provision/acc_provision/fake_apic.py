import threading
import sys
import ssl
import json
if sys.version_info[0] == 3:
    from http.server import HTTPServer, BaseHTTPRequestHandler
    import urllib.parse as urll
else:
    from BaseHTTPServer import HTTPServer, BaseHTTPRequestHandler
    import urllib as urll

fake_gets = {}
fake_deletes = {}
login_data = {
    "imdata": [{"aaaLogin": {"attributes": {"token": "testtoken"}}}]
}
empty_data = {
    "imdata": []
}


class Serv(BaseHTTPRequestHandler):
    def _set_headers(self):
        self.send_response(200)
        self.send_header('Content-type', 'application/json')
        self.end_headers()

    def do_GET(self):
        pp = urll.unquote(self.path)
        if pp in fake_gets.keys():
            self._set_headers()
            self.wfile.write(json.dumps(fake_gets[pp]).encode())
        else:
            print("Error: path {} not found".format(self.path))
            self.send_response(404)

    def do_POST(self):
        if self.path == "/api/aaaLogin.json":
            print("Login detected")
            self._set_headers()
            self.wfile.write(json.dumps(login_data).encode())
            return

        self._set_headers()
        self.wfile.write(json.dumps(empty_data).encode())

    def do_DELETE(self):
        pp = urll.unquote(self.path)
        fake_deletes.pop(pp, None)
        self._set_headers()
        self.wfile.write(json.dumps(empty_data).encode())


def start_fake_apic(port, gets, deletes):
    global fake_gets
    global fake_deletes

    fake_gets = gets
    fake_deletes = deletes
    httpd = HTTPServer(('localhost', port), Serv)
    httpd.socket = ssl.wrap_socket(httpd.socket,
                                   server_side=True,
                                   certfile='localhost.pem',
                                   ssl_version=ssl.PROTOCOL_TLS)
    thread = threading.Thread(target=httpd.serve_forever)
    thread.daemon = True
    thread.start()
    return httpd
