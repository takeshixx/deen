import sys
import hashlib
import logging
import base64
import binascii

try:
    import OpenSSL.crypto
    OPENSSL = True
except ImportError:
    OPENSSL = False

from deen.exceptions import *
from .. import DeenPlugin

LOGGER = logging.getLogger(__name__)


class DeenPluginX509Certificate(DeenPlugin):
    name = 'x509certificate'
    display_name = 'X.509 Certificate'
    aliases = ['x509']
    cmd_name = 'x509certificate'
    cmd_help = ('Print a human-readable representation'
                'of X.509 certificates')

    def __init__(self):
        super(DeenPluginX509Certificate, self).__init__()

    @staticmethod
    def prerequisites():
        try:
            import OpenSSL.crypto
        except ImportError:
            return False
        else:
            return True

    @property
    def certificate(self):
        return self._certificate

    @certificate.setter
    def certificate(self, data):
        if not OPENSSL:
            LOGGER.warning('pyOpenSSL is not available')
            return
        if not b'-----BEGIN' in data or \
            not b'-----END' in data:
            # Check if data is Base64 encoded
            try:
                base64.b64decode(data.replace(b'\n', b''), validate=True)
            except binascii.Error as e:
                LOGGER.error(e)
                # If data is not encoded, encode it
                data = base64.b64encode(data)
        try:
            data = data.decode()
        except UnicodeDecodeError:
            LOGGER.error('Invalid certificate encoding')
            return
        data = data.strip()
        if not '-----BEGIN CERTIFICATE-----' in data:
            LOGGER.warning('Missing certificate prefix')
            data = '-----BEGIN CERTIFICATE-----\n' + data
        if not '-----END CERTIFICATE-----' in data:
            LOGGER.warning('Missing certificate suffix')
            data = data + '\n-----END CERTIFICATE-----'
        self._certificate = OpenSSL.crypto.load_certificate(
            OpenSSL.crypto.FILETYPE_PEM, data)

    def process(self, data):
        super(DeenPluginX509Certificate, self).process(data)
        self.certificate = data
        if not self._certificate:
            self.error = TransformException('Invalid certificate')
            return
        if OPENSSL and self._certificate is not None:
            out = bytearray()
            out.extend(OpenSSL.crypto.dump_certificate(
                OpenSSL.crypto.FILETYPE_TEXT, self.certificate))
            out.extend(b'\n')
            out.extend(OpenSSL.crypto.dump_certificate(
                OpenSSL.crypto.FILETYPE_PEM, self.certificate))
            return out
        elif not OPENSSL:
            LOGGER.warning('pyOpenSSL is not available')
        return data


class DeenPluginX509CertificateCloner(DeenPlugin):
    name = 'x509certificatecloner'
    display_name = 'Clone X.509 Certificate'
    aliases = ['certcloner',
               'x509clone']
    cmd_name = 'x509certificatecloner'
    cmd_help = ('Clone X.509 certificates with a'
                'randomly generated RSA public key')
    cmd_only = True

    def __init__(self):
        super(DeenPluginX509CertificateCloner, self).__init__()

    @staticmethod
    def prerequisites():
        try:
            import OpenSSL.crypto
        except ImportError:
            return False
        else:
            return True

    def process(self, data):
        super(DeenPluginX509CertificateCloner, self).process(data)
        pass

    @staticmethod
    def add_argparser(argparser, *args):
        # Python 2 argparse does not support aliases
        if sys.version_info.major < 3 or \
            (sys.version_info.major == 3 and
                sys.version_info.minor < 2):
            parser = argparser.add_parser(DeenPluginX509CertificateCloner.cmd_name,
                                          help=DeenPluginX509CertificateCloner.cmd_help)
        else:
            parser = argparser.add_parser(DeenPluginX509CertificateCloner.cmd_name,
                                          help=DeenPluginX509CertificateCloner.cmd_help,
                                          aliases=DeenPluginX509CertificateCloner.aliases)
        parser.add_argument('CERT_TO_CLONE')
        parser.add_argument('-o', '--out', help='name of output files (w/o extension)', default='cloned_cert')
        parser.add_argument('-a', '--signature-algorithm', help='hash algorithm for signature', default=None,
                            type=str.lower)
        xor = parser.add_mutually_exclusive_group(required=True)
        xor.add_argument('-s', '--self-signed', action='store_true', dest='self_signed')
        xor.add_argument('CA_CERT', nargs='?')
        parser.add_argument('CA_KEY', nargs='?')

    def process_cli(self, args):
        if args.self_signed and (args.CA_CERT or args.CA_KEY):
            LOGGER.error('-s and CA_* couldn\'t be used together')
            sys.exit(1)
        if (args.CA_CERT and not args.CA_KEY) or (not args.CA_CERT and args.CA_KEY):
            LOGGER.error('CA_CERT and CA_KEY required')
            sys.exit(1)
        with open(args.CERT_TO_CLONE) as f:
            original_cert = f.read()
        original_cert = OpenSSL.crypto.load_certificate(OpenSSL.crypto.FILETYPE_PEM, original_cert)
        if args.signature_algorithm:
            signature_algo = args.signature_algorithm
        else:
            signature_algo = original_cert.get_signature_algorithm().decode()
        new_cert, new_key = self._clone(original_cert, args.self_signed, args.out, signature_algo)
        if args.CA_CERT:
            with open(args.CA_CERT) as f:
                ca_cert = f.read()
            ca_cert = OpenSSL.crypto.load_certificate(OpenSSL.crypto.FILETYPE_PEM, ca_cert)
            new_cert.set_issuer(ca_cert.get_issuer())
            with open(args.CA_KEY) as f:
                ca_pkey = f.read()
            ca_pkey = OpenSSL.crypto.load_privatekey(OpenSSL.crypto.FILETYPE_PEM, ca_pkey)
            new_cert.sign(ca_pkey, signature_algo)
        self._save_to_file(new_cert, new_key, args.out)
        ret = 'Saved new certificate as {}.cert'.format(args.out)
        return ret.encode()

    def _clone(self, original_cert, self_sign, out, signature_algo):
        cert = OpenSSL.crypto.X509()
        cert.set_version(original_cert.get_version())
        cert.set_serial_number(original_cert.get_serial_number())
        cert.set_notBefore(original_cert.get_notBefore())
        cert.set_notAfter(original_cert.get_notAfter())
        pkey = OpenSSL.crypto.PKey()
        pkey.generate_key(OpenSSL.crypto.TYPE_RSA,
                          original_cert.get_pubkey().bits())
        cert.set_pubkey(pkey)
        cert.set_issuer(original_cert.get_issuer())
        cert.set_subject(original_cert.get_subject())
        extensions = []
        for extid in range(original_cert.get_extension_count()):
            extensions.append(original_cert.get_extension(extid))
        cert.add_extensions(extensions)
        if self_sign:
            if not signature_algo:
                signature_algo = original_cert.get_signature_algorithm().decode()
            cert.sign(pkey, signature_algo)
        return cert, pkey

    def _save_to_file(self, cert, pkey, out_file):
        priv_pem = OpenSSL.crypto.dump_privatekey(OpenSSL.crypto.FILETYPE_PEM, pkey)
        cert_pem = OpenSSL.crypto.dump_certificate(OpenSSL.crypto.FILETYPE_PEM, cert)
        with open(out_file, 'wb') as f:
            f.write(priv_pem)
        with open(out_file + '.cert', 'wb') as f:
            f.write(cert_pem)
        with open(out_file + '.pem', 'wb') as f:
            f.write(priv_pem)
            f.write(cert_pem)
