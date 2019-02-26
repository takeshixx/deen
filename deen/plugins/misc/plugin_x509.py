import sys
import base64
import binascii

try:
    import OpenSSL.crypto
    OPENSSL = True
except ImportError:
    OPENSSL = False

from PyQt5 import QtCore, QtWidgets

from deen.exceptions import *
from .. import DeenPlugin


class DeenPluginX509Certificate(DeenPlugin):
    name = 'x509certificate'
    display_name = 'X.509 Certificate'
    aliases = ['x509']
    cmd_name = 'x509certificate'
    cmd_help = ('Print a human-readable representation '
                'of X.509 certificates')

    def __init__(self):
        super(DeenPluginX509Certificate, self).__init__()
        self._certificate = None

    def prerequisites(self):
        try:
            import OpenSSL.crypto
        except ImportError:
            self.log_missing_depdendencies('pyOpenSSL')
            return False
        else:
            return True

    @property
    def certificate(self):
        return self._certificate

    @certificate.setter
    def certificate(self, data):
        if not OPENSSL:
            self.error = MissingDependencyException('pyOpenSSL is not available')
            return
        if not b'-----BEGIN' in data or \
            not b'-----END' in data:
            # Check if data is Base64 encoded
            try:
                base64.b64decode(data.replace(b'\n', b''), validate=True)
            except binascii.Error as e:
                self.log.exception(e)
                # If data is not encoded, encode it
                data = base64.b64encode(data)
        try:
            data = data.decode()
        except UnicodeDecodeError:
            self.error = TransformException('Invalid certificate encoding')
            self.log.error(self.error)
            self.log.debug(self.error, exc_info=True)
            return
        data = data.strip()
        if not '-----BEGIN CERTIFICATE-----' in data:
            self.log.warning('Missing certificate prefix')
            data = '-----BEGIN CERTIFICATE-----\n' + data
        if not '-----END CERTIFICATE-----' in data:
            self.log.warning('Missing certificate suffix')
            data = data + '\n-----END CERTIFICATE-----'
        try:
            self._certificate = OpenSSL.crypto.load_certificate(
                OpenSSL.crypto.FILETYPE_PEM, data)
        except OpenSSL.crypto.Error:
            self.error = TransformException('Invalid certificate encoding')
            return

    def process(self, data):
        super(DeenPluginX509Certificate, self).process(data)
        self.certificate = data
        if not self._certificate:
            if not self.error:
                self.error = TransformException('Invalid certificate')
                self.log.error(self.error)
                self.log.debug(self.error, exc_info=True)
            return data
        if OPENSSL and self._certificate is not None:
            out = bytearray()
            out.extend(OpenSSL.crypto.dump_certificate(
                OpenSSL.crypto.FILETYPE_TEXT, self.certificate))
            out.extend(b'\n')
            out.extend(OpenSSL.crypto.dump_certificate(
                OpenSSL.crypto.FILETYPE_PEM, self.certificate))
            return out
        elif not OPENSSL:
            self.error = MissingDependencyException('pyOpenSSL is not available')
            self.log.error(self.error)
            self.log.debug(self.error, exc_info=True)
        return data


class DeenPluginX509CertificateCloner(DeenPlugin):
    name = 'x509certificatecloner'
    display_name = 'Clone X.509 Certificate'
    aliases = ['certcloner',
               'x509clone']
    cmd_name = 'x509certificatecloner'
    cmd_help = ('Clone X.509 certificates with a '
                'randomly generated RSA public key')

    def __init__(self):
        super(DeenPluginX509CertificateCloner, self).__init__()
        self.parent = None
        self.x509gui = None
        self.file_open_dialog = None
        self.ca_cert = None
        self.ca_key = None

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
            parser = argparser.add_parser(DeenPluginX509CertificateCloner.cmd_name,
                                          help=DeenPluginX509CertificateCloner.cmd_help)
        else:
            parser = argparser.add_parser(DeenPluginX509CertificateCloner.cmd_name,
                                          help=DeenPluginX509CertificateCloner.cmd_help,
                                          aliases=DeenPluginX509CertificateCloner.aliases)
        parser.add_argument('CERT_TO_CLONE')
        parser.add_argument('-o', '--out', help='name of output files (w/o extension)',
                            default='cloned_cert', metavar='filename')
        parser.add_argument('-a', '--signature-algorithm', help='hash algorithm for signature', default=None,
                            type=str.lower, metavar='algorithm')
        xor = parser.add_mutually_exclusive_group(required=True)
        xor.add_argument('-s', '--self-signed', action='store_true', dest='self_signed')
        xor.add_argument('CA_CERT', nargs='?')
        parser.add_argument('CA_KEY', nargs='?')

    def process_cli(self, args):
        if not OPENSSL:
            self.error = MissingDependencyException('pyOpenSSL is not available')
            return
        if args.self_signed and (args.CA_CERT or args.CA_KEY):
            self.log.error('-s and CA_* couldn\'t be used together')
            sys.exit(1)
        if (args.CA_CERT and not args.CA_KEY) or (not args.CA_CERT and args.CA_KEY):
            self.log.error('CA_CERT and CA_KEY required')
            sys.exit(1)
        original_cert = self._load_cert(args.CERT_TO_CLONE)
        if args.signature_algorithm:
            signature_algo = args.signature_algorithm
        else:
            signature_algo = original_cert.get_signature_algorithm().decode()
        new_cert, new_key = self._clone(original_cert, args.self_signed, signature_algo)
        if args.CA_CERT:
            ca_cert = self._load_cert(args.CA_CERT)
            new_cert.set_issuer(ca_cert.get_issuer())
            ca_pkey = self._load_private_key(args.CA_KEY)
            new_cert.sign(ca_pkey, signature_algo)
        self._save_to_file(new_cert, new_key, args.out)
        ret = 'Saved new certificate as {}.cert'.format(args.out)
        return ret.encode()

    def process_gui(self, parent, content):
        """In order to accept multiple input values, we have to create
        an additional GUI element that allows to choose to either selfsign
        certificates or use an existing CA cert and key for signing."""
        self.parent = parent
        self.x509gui = X509CloneGui(self.parent)
        self.file_open_dialog = QtWidgets.QFileDialog(self.x509gui)
        self.x509gui.ui.x509clone_selfsign.toggled.connect(self.x509gui.toggle_selfsign)
        self.x509gui.ui.x509clone_casign.toggled.connect(self.x509gui.toggle_casign)
        self.x509gui.ui.x509clone_load_cacert_button.clicked.connect(self._load_cert_dialog)
        self.x509gui.ui.x509clone_load_cakey_button.clicked.connect(self._load_private_key_dialog)
        if self.x509gui.exec_() == 0:
            # If the plugin GUI is cancelled, just
            # return without doing anything.
            return
        # Decode content because pyOpenSSL fails with bytearrays.
        content = content.decode()
        try:
            original_cert = OpenSSL.crypto.load_certificate(OpenSSL.crypto.FILETYPE_PEM, content)
        except (OpenSSL.crypto.Error, TypeError) as e:
            self.error = Exception('Invalid certificate')
            self.log.error(self.error)
            self.log.debug(e, exc_info=True)
            return
        signature_algo = original_cert.get_signature_algorithm().decode()
        if self.x509gui.ui.x509clone_selfsign.isChecked():
            new_cert, new_key = self._clone(original_cert, True, signature_algo)
        elif self.x509gui.ui.x509clone_casign.isChecked():
            if not self.ca_cert:
                self.error = Exception('Invalid CA cert')
                self.log.error(self.error)
                self.log.debug(self.error, exc_info=True)
                return
            if not self.ca_key:
                self.error = Exception('Invalid CA key')
                self.log.error(self.error)
                self.log.debug(self.error, exc_info=True)
                return
            new_cert, new_key = self._clone(original_cert, False, signature_algo)
            new_cert.set_issuer(self.ca_cert.get_issuer())
            new_cert.sign(self.ca_key, signature_algo)
        else:
            self.error = Exception('No action selected')
            self.log.error(self.error)
            self.log.debug(self.error, exc_info=True)
            return
        content = OpenSSL.crypto.dump_privatekey(OpenSSL.crypto.FILETYPE_PEM, new_key)
        content += OpenSSL.crypto.dump_certificate(OpenSSL.crypto.FILETYPE_PEM, new_cert)
        return content

    def _clone(self, original_cert, self_sign, signature_algo):
        """Create a 1:1 clone of original_cert. If self_sign is False,
        the new_certificate will not yet be signed."""
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

    def _load_cert_dialog(self):
        cert_path = self.file_open_dialog.getOpenFileName(
            self.file_open_dialog, 'Load CA cert from file')[0]
        if not cert_path:
            return
        self.ca_cert = self._load_cert(cert_path)
        if not self.ca_cert:
            self.parent.show_error_msg('Invalid CA cert ' + cert_path, parent=self.x509gui)

    def _load_cert(self, filepath):
        """Read the content of filepath and
        return it an OpenSSL cert object."""
        with open(filepath, 'rb') as f:
            cert = f.read()
        try:
            cert = OpenSSL.crypto.load_certificate(OpenSSL.crypto.FILETYPE_PEM, cert)
        except OpenSSL.crypto.Error as e:
            self.error = Exception('Invalid certificate ' + filepath)
            self.log.error(self.error)
            self.log.debug(self.error, exc_info=True)
            return
        return cert

    def _load_private_key_dialog(self):
        key_path = self.file_open_dialog.getOpenFileName(
            self.file_open_dialog, 'Load CA private key from file')[0]
        if not key_path:
            return
        self.ca_key = self._load_private_key(key_path)
        if not self.ca_key:
            self.parent.show_error_msg('Invalid private key ' + key_path, parent=self.x509gui)

    def _load_private_key(self, filepath):
        """Read the content of filepath and
        return it an OpenSSL private key object."""
        with open(filepath, 'rb') as f:
            key = f.read()
        try:
            key = OpenSSL.crypto.load_privatekey(OpenSSL.crypto.FILETYPE_PEM, key)
        except OpenSSL.crypto.Error:
            self.error = Exception('Invalid private key ' + filepath)
            self.log.error(self.error)
            self.log.debug(self.error, exc_info=True)
            return
        return key

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


class X509CloneGui(QtWidgets.QDialog):
    def __init__(self, parent):
        super(X509CloneGui, self).__init__(parent)
        self.ui = Ui_X509CloneGui()
        self.ui.setupUi(self)
        self.setWindowTitle('Clone X509 Certificate')
        self.parent = parent
        self.ui.x509clone_selfsign.setChecked(True)
        self.ui.x509clone_selfsign_groupbox.setEnabled(True)
        self.ui.x509clone_casign_groupbox.setEnabled(False)

    def toggle_selfsign(self):
        self.ui.x509clone_selfsign_groupbox.setEnabled(True)
        self.ui.x509clone_casign_groupbox.setEnabled(False)

    def toggle_casign(self):
        self.ui.x509clone_selfsign_groupbox.setEnabled(False)
        self.ui.x509clone_casign_groupbox.setEnabled(True)


class Ui_X509CloneGui(object):
    def setupUi(self, X509CloneGui):
        X509CloneGui.setObjectName("X509CloneGui")
        X509CloneGui.resize(597, 398)
        self.gridLayout = QtWidgets.QGridLayout(X509CloneGui)
        self.gridLayout.setObjectName("gridLayout")
        self.x509clone_casign_groupbox = QtWidgets.QGroupBox(X509CloneGui)
        self.x509clone_casign_groupbox.setTitle("")
        self.x509clone_casign_groupbox.setObjectName("x509clone_casign_groupbox")
        self.verticalLayout = QtWidgets.QVBoxLayout(self.x509clone_casign_groupbox)
        self.verticalLayout.setObjectName("verticalLayout")
        self.plainTextEdit_2 = QtWidgets.QPlainTextEdit(self.x509clone_casign_groupbox)
        self.plainTextEdit_2.setObjectName("plainTextEdit_2")
        self.verticalLayout.addWidget(self.plainTextEdit_2)
        self.x509clone_load_cacert_button = QtWidgets.QPushButton(self.x509clone_casign_groupbox)
        self.x509clone_load_cacert_button.setObjectName("x509clone_load_cacert_button")
        self.verticalLayout.addWidget(self.x509clone_load_cacert_button)
        self.x509clone_load_cakey_button = QtWidgets.QPushButton(self.x509clone_casign_groupbox)
        self.x509clone_load_cakey_button.setObjectName("x509clone_load_cakey_button")
        self.verticalLayout.addWidget(self.x509clone_load_cakey_button)
        self.gridLayout.addWidget(self.x509clone_casign_groupbox, 1, 3, 1, 1)
        self.x509clone_ok_button = QtWidgets.QDialogButtonBox(X509CloneGui)
        self.x509clone_ok_button.setOrientation(QtCore.Qt.Horizontal)
        self.x509clone_ok_button.setStandardButtons(QtWidgets.QDialogButtonBox.Cancel|QtWidgets.QDialogButtonBox.Ok)
        self.x509clone_ok_button.setObjectName("x509clone_ok_button")
        self.gridLayout.addWidget(self.x509clone_ok_button, 4, 3, 1, 1)
        self.x509clone_selfsign_groupbox = QtWidgets.QGroupBox(X509CloneGui)
        self.x509clone_selfsign_groupbox.setTitle("")
        self.x509clone_selfsign_groupbox.setObjectName("x509clone_selfsign_groupbox")
        self.verticalLayout_2 = QtWidgets.QVBoxLayout(self.x509clone_selfsign_groupbox)
        self.verticalLayout_2.setObjectName("verticalLayout_2")
        self.plainTextEdit = QtWidgets.QPlainTextEdit(self.x509clone_selfsign_groupbox)
        self.plainTextEdit.setObjectName("plainTextEdit")
        self.verticalLayout_2.addWidget(self.plainTextEdit)
        self.gridLayout.addWidget(self.x509clone_selfsign_groupbox, 1, 2, 1, 1)
        self.x509clone_casign = QtWidgets.QRadioButton(X509CloneGui)
        self.x509clone_casign.setObjectName("x509clone_casign")
        self.gridLayout.addWidget(self.x509clone_casign, 0, 3, 1, 1)
        self.x509clone_selfsign = QtWidgets.QRadioButton(X509CloneGui)
        self.x509clone_selfsign.setObjectName("x509clone_selfsign")
        self.gridLayout.addWidget(self.x509clone_selfsign, 0, 2, 1, 1)

        self.retranslateUi(X509CloneGui)
        self.x509clone_ok_button.accepted.connect(X509CloneGui.accept)
        self.x509clone_ok_button.rejected.connect(X509CloneGui.reject)
        QtCore.QMetaObject.connectSlotsByName(X509CloneGui)

    def retranslateUi(self, X509CloneGui):
        _translate = QtCore.QCoreApplication.translate
        X509CloneGui.setWindowTitle(_translate("X509CloneGui", "Dialog"))
        self.plainTextEdit_2.setPlainText(_translate("X509CloneGui", "Sign the new certificate with an existing CA certificate. The private key of the existing CA must be available."))
        self.x509clone_load_cacert_button.setText(_translate("X509CloneGui", "Load CA certificate"))
        self.x509clone_load_cakey_button.setText(_translate("X509CloneGui", "Load CA private key"))
        self.plainTextEdit.setPlainText(_translate("X509CloneGui", "The new certificate will be self signed."))
        self.x509clone_casign.setText(_translate("X509CloneGui", "Sign wi&th existing CA"))
        self.x509clone_selfsign.setText(_translate("X509CloneGui", "Self si&gned"))
