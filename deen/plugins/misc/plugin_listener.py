import sys
import logging
import os
import os.path
import random
import ssl
import tempfile

if sys.version_info.major == 3:
    import http.server
    import socketserver
elif sys.version_info.major < 3:
    import SocketServer
    import BaseHTTPServer
    import SimpleHTTPServer

try:
    import OpenSSL.crypto
    OPENSSL = True
except ImportError:
    OPENSSL = False

from .. import DeenPlugin
from deen.exceptions import MissingDependencyException


class DeenPluginListener(DeenPlugin):
    name = 'listener'
    display_name = 'Listener'
    aliases = ['listen',
               'http',
               'https',
               'tcp',
               'tls',
               'ssl']
    cmd_name = 'listener'
    cmd_help='Listen for HTTP/TCP/SSL/TLS connections.'
    cmd_only = True

    def __init__(self):
        super(DeenPluginListener, self).__init__()
        self.listen_host = b'127.0.0.1'
        self.listen_port = 8000
        self.listen_socket = ()
        self.serving_directory = os.getcwd()
        self.ca_common_name = 'Deen CA'
        self.ca_cert_pem = None
        self.ca_key_pem = None
        self.server_cert_pem = None
        self.server_key_pem = None

    def prerequisites(self):
        try:
            import OpenSSL.crypto
        except ImportError:
            self.log_missing_depdendencies('pyOpenSSL')
            return False
        else:
            return True

    @staticmethod
    def add_argparser(argparser, *args, **kwargs):
        # Python 2 argparse does not support aliases
        if sys.version_info.major < 3 or \
            (sys.version_info.major == 3 and
                sys.version_info.minor < 2):
            parser = argparser.add_parser(DeenPluginListener.cmd_name,
                                          help=DeenPluginListener.cmd_help)
        else:
            parser = argparser.add_parser(DeenPluginListener.cmd_name,
                                          help=DeenPluginListener.cmd_help,
                                          aliases=DeenPluginListener.aliases)
        parser.add_argument('port', nargs='?', type=int, default=8000,
                            help='listening port (default: 8000)')
        parser.add_argument('-d', '--directory', default=os.getcwd(), type=str,
                            metavar='directory', dest='pluginvar_directory')
        parser.add_argument('-b', '--b', help='listening host (default: 0.0.0.0)',
                            type=str, default='0.0.0.0', metavar='host', dest='pluginvar_host')
        parser.add_argument('-t', '--tcp', dest='pluginvar_tcp', default=False,
                            help='open a raw tcp listener',
                            action='store_true')
        parser.add_argument('-s', '--ssl', dest='pluginvar_ssl', default=False,
                            help='use ssl/tls on the listening port',
                            action='store_true')
        parser.add_argument('--server-cert', default=None, type=str,
                            metavar='file', dest='pluginvar_server_cert')
        parser.add_argument('--server-key', default=None, type=str,
                            metavar='file', dest='pluginvar_server_key')

    def process_cli(self, args):
        if not OPENSSL:
            self.error = MissingDependencyException('pyOpenSSL is not available')
            return
        # TODO: check user input
        self.listen_socket = (args.pluginvar_host,
                              args.port)
        self.serving_directory = args.pluginvar_directory
        self.server_cert_file = args.pluginvar_server_cert
        self.server_key_file = args.pluginvar_server_key
        if args.plugin_cmd == 'ssl' or args.plugin_cmd == 'https' \
                or args.pluginvar_ssl:
            if self.server_cert_file and self.server_key_file:
                self._read_cert_and_key_files()
            else:
                self._generate_pki()
        if args.plugin_cmd == 'ssl':
            if args.pluginvar_tcp:
                self.ssl_listen()
            else:
                self.https_listen()
        elif args.plugin_cmd == 'tcp' or args.pluginvar_tcp:
            if args.pluginvar_ssl:
                self.ssl_listen()
            else:
                self.tcp_listen()
        else:
            if args.pluginvar_ssl or args.plugin_cmd =='https':
                self.https_listen()
            else:
                self.http_listen()

    def _read_cert_and_key_files(self):
        """Read the certificate and private key from the
        file paths provided via CLI arguments."""
        if not os.path.isfile(self.server_cert_file) or \
                not os.path.isfile(self.server_key_file):
            return
        with open(self.server_cert_file, 'rb') as f:
            cert = f.read()
            try:
                OpenSSL.crypto.load_certificate(OpenSSL.crypto.FILETYPE_PEM, cert)
            except (OpenSSL.crypto.Error, TypeError) as e:
                self.error = e
                self.log.error(self.error)
                self.log.debug(self.error, exc_info=True)
                return
            else:
                self.server_cert_pem = cert
        with open(self.server_key_file, 'rb') as f:
            key = f.read()
            try:
                OpenSSL.crypto.load_privatekey(OpenSSL.crypto.FILETYPE_PEM, key)
            except OpenSSL.crypto.Error as e:
                self.error = e
                self.log.error(self.error)
                self.log.debug(self.error, exc_info=True)
                return
            else:
                self.server_key_pem = key

    def _generate_pki(self):
        """Generate a random CA certificate and use it to
        sign a randomly generated server certificate. If
        SSL/TLS mode is enabled and no server certificate/
        private key has been supplied via CLI arguments,
        this function will generate temporary certificates
        randomly."""
        ca_key = OpenSSL.crypto.PKey()
        ca_key.generate_key(OpenSSL.crypto.TYPE_RSA, 2048)
        ca_cert = OpenSSL.crypto.X509()
        ca_cert.set_version(2)
        ca_cert.set_serial_number(random.randint(50000000, 100000000))

        ca_subj = ca_cert.get_subject()
        ca_subj.commonName = self.ca_common_name
        ca_cert.add_extensions([
            OpenSSL.crypto.X509Extension(b'subjectKeyIdentifier', False, b'hash', subject=ca_cert),
        ])
        ca_cert.add_extensions([
            OpenSSL.crypto.X509Extension(b'authorityKeyIdentifier', False, b'keyid:always', issuer=ca_cert),
        ])
        ca_cert.add_extensions([
            OpenSSL.crypto.X509Extension(b'basicConstraints', False, b'CA:TRUE'),
            OpenSSL.crypto.X509Extension(b'keyUsage', False, b'keyCertSign, cRLSign'),
        ])
        ca_cert.set_issuer(ca_subj)
        ca_cert.set_pubkey(ca_key)
        ca_cert.sign(ca_key, 'sha256')
        ca_cert.gmtime_adj_notBefore(0)
        ca_cert.gmtime_adj_notAfter(10 * 365 * 24 * 60 * 60)
        self.ca_cert_pem = OpenSSL.crypto.dump_certificate(OpenSSL.crypto.FILETYPE_PEM, ca_cert)
        self.ca_key_pem = OpenSSL.crypto.dump_privatekey(OpenSSL.crypto.FILETYPE_PEM, ca_key)

        # Server cert
        server_key = OpenSSL.crypto.PKey()
        server_key.generate_key(OpenSSL.crypto.TYPE_RSA, 2048)
        server_cert = OpenSSL.crypto.X509()
        server_cert.set_version(2)
        server_cert.set_serial_number(random.randint(50000000, 100000000))
        server_subj = server_cert.get_subject()
        server_subj.commonName = 'deen server'
        server_cert.add_extensions([
            OpenSSL.crypto.X509Extension(b'basicConstraints', False, b'CA:FALSE'),
            OpenSSL.crypto.X509Extension(b'subjectKeyIdentifier', False, b'hash', subject=server_cert),
        ])
        server_cert.add_extensions([
            OpenSSL.crypto.X509Extension(b'authorityKeyIdentifier', False, b'keyid:always', issuer=ca_cert),
            OpenSSL.crypto.X509Extension(b'extendedKeyUsage', False, b'serverAuth'),
            OpenSSL.crypto.X509Extension(b'keyUsage', False, b'digitalSignature'),
        ])
        server_cert.set_issuer(ca_subj)
        server_cert.set_pubkey(server_key)
        server_cert.sign(ca_key, 'sha256')
        server_cert.gmtime_adj_notBefore(0)
        server_cert.gmtime_adj_notAfter(10 * 365 * 24 * 60 * 60)
        self.server_cert_pem = OpenSSL.crypto.dump_certificate(OpenSSL.crypto.FILETYPE_PEM, server_cert)
        self.server_key_pem = OpenSSL.crypto.dump_privatekey(OpenSSL.crypto.FILETYPE_PEM, server_key)

    def tcp_listen(self):
        if sys.version_info.major == 3:
            self.tcp_listen_python3()
        elif sys.version_info.major < 3:
            self.tcp_listen_python2()

    def ssl_listen(self):
        """Wrapper function that takes care
        of either creating or reading keys
        and certificates and opens TCP sockets."""
        if sys.version_info.major == 3:
            self.tcp_listen_python3(listen_ssl=True)
        elif sys.version_info.major < 3:
            self.tcp_listen_python2(listen_ssl=True)

    def tcp_listen_python2(self, listen_ssl=False):
        raise NotImplementedError

    def tcp_listen_python3(self, listen_ssl=False):
        """Open a TCP socket on a given port and print incoming
        data to stdout."""
        class DeenTcpHandler(socketserver.StreamRequestHandler):
            def handle(self):
                self.data = self.rfile.readline().strip()
                print(self.data.decode())
        class TcpServerSsl(socketserver.TCPServer):
            def __init__(self,
                         server_address,
                         RequestHandlerClass,
                         certfile,
                         keyfile,
                         ssl_version=ssl.PROTOCOL_TLS_SERVER,
                         bind_and_activate=True):
                socketserver.TCPServer.__init__(self, server_address,
                                                RequestHandlerClass,
                                                bind_and_activate)
                self.certfile = certfile
                self.keyfile = keyfile
                self.ssl_version = ssl_version

            def get_request(self):
                newsocket, fromaddr = self.socket.accept()
                connstream = ssl.wrap_socket(newsocket,
                                             server_side=True,
                                             certfile=self.certfile,
                                             keyfile=self.keyfile,
                                             ssl_version=self.ssl_version)
                return connstream, fromaddr
        server = None
        if listen_ssl:
            # The certificate chain and private key need to
            # be available as actual files that can be opened
            # with fopen(3).
            with tempfile.TemporaryDirectory() as tmpdirname:
                cert_chain = tmpdirname + '/cert_chain.pem'
                server_key = tmpdirname + '/server_key.pem'
                with open(cert_chain, 'wb') as f:
                    f.write(self.server_cert_pem)
                with open(server_key, 'wb') as f:
                    f.write(self.server_key_pem)
                try:
                    server = TcpServerSsl(self.listen_socket,
                                          DeenTcpHandler,
                                          cert_chain,
                                          server_key)
                except OSError as e:
                    self.error = e
                    self.log.error(self.error)
                    self.log.debug(self.error, exc_info=True)
                    return

        else:
            try:
                server = socketserver.TCPServer(self.listen_socket,
                                                DeenTcpHandler)
            except OSError as e:
                self.error = e
                self.log.error(self.error)
                self.log.debug(self.error, exc_info=True)
                return
        message = 'Listening on TCP port ' + str(self.listen_port)
        if listen_ssl:
            message += ' (SSL)'
        print(message)
        try:
            server.serve_forever()
        except KeyboardInterrupt:
            pass

    def http_listen(self):
        if sys.version_info.major == 3:
            self._http_python3()
        elif sys.version_info.major < 3:
            self._http_python2()

    def https_listen(self):
        if sys.version_info.major == 3:
            self._http_python3(listen_ssl=True)
        elif sys.version_info.major < 3:
            self._http_python2(listen_ssl=True)

    def _http_python2(self, listen_ssl=False):
        """Listen for HTTP connections with Python 2."""
        class ThreadingSimpleServer(SocketServer.ThreadingMixIn,
                                    BaseHTTPServer.HTTPServer):
            pass
        server = ThreadingSimpleServer(self.listen_socket,
                                       SimpleHTTPServer.SimpleHTTPRequestHandler)
        os.chdir(self.serving_directory)
        message = 'Serving HTTP at port ' + str(self.listen_port)
        if listen_ssl:
            message += ' (SSL)'
        print(message)
        try:
            while 1:
                sys.stdout.flush()
                server.handle_request()
        except KeyboardInterrupt:
            pass

    def _http_python3(self, listen_ssl=False):
        """Listen for HTTP connections with Python 3."""
        Handler = http.server.SimpleHTTPRequestHandler
        os.chdir(self.serving_directory)
        try:
            with socketserver.TCPServer(self.listen_socket, Handler) as httpd:
                if listen_ssl:
                    # The certificate chain and private key need to
                    # be available as actual files that can be opened
                    # with fopen(3).
                    with tempfile.TemporaryDirectory() as tmpdirname:
                        cert_chain = tmpdirname + '/cert_chain.pem'
                        server_key = tmpdirname + '/server_key.pem'
                        with open(cert_chain, 'wb') as f:
                            f.write(self.server_cert_pem)
                        with open(server_key, 'wb') as f:
                            f.write(self.server_key_pem)
                        httpd.socket = ssl.wrap_socket(httpd.socket,
                                                       certfile=cert_chain,
                                                       keyfile=server_key,
                                                       server_side=True)
                message = 'Serving HTTP at port ' + str(self.listen_port)
                if listen_ssl:
                    message += ' (SSL)'
                print(message)
                try:
                    httpd.serve_forever()
                except KeyboardInterrupt:
                    pass
        except OSError as e:
            self.error = e
            self.log.error(self.error)
            self.log.debug(self.error, exc_info=True)
