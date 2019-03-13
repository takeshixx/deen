from __future__ import absolute_import
import sys
import json
import base64
import os
import os.path

from PyQt5 import QtCore, QtWidgets

try:
    from jose import jwt
    from jose import exceptions
    from jose import constants
    JOSE = True
except ImportError:
    JOSE = False

from .. import DeenPlugin
from deen.exceptions import MissingDependencyException, \
                            InvalidFormatException, \
                            InvalidInputFile


class DeenPluginJwt(DeenPlugin):
    name = 'jwt'
    display_name = 'JWT'
    cmd_name = 'jwt'
    cmd_help='Encode/Decode JSON Web Tokens (RFC 7519)'

    def __init__(self):
        super(DeenPluginJwt, self).__init__()
        self.secret = None
        self.key = None

    def prerequisites(self):
        try:
            from jose import jwt
        except ImportError:
            self.log_missing_depdendencies('python-jose')
            return False
        else:
            return True

    def process(self, data, secret=b'', algo='HS256', key=None):
        super(DeenPluginJwt, self).process(data)
        if not JOSE:
            self.error = MissingDependencyException('python-jose module missing')
            return data
        header = None
        try:
            data_dict = json.loads(data)
        except Exception as e:
            self.error = e
            self.log.error(self.error)
            self.log.debug(self.error, exc_info=True)
            return data
        if data_dict and 'data' in data_dict.keys() and \
                'header' in data_dict.keys():
            header = data_dict.get('header')
            data_dict = data_dict.get('data')
        if algo in constants.ALGORITHMS.HMAC:
            # Symmetric signatures
            try:
                data = jwt.encode(data_dict, secret, algorithm=algo)
            except Exception as e:
                self.error = e
                self.log.error(self.error)
                self.log.debug(self.error, exc_info=True)
            else:
                data = data.encode()
        elif algo in constants.ALGORITHMS.RSA or \
                algo in constants.ALGORITHMS.EC:
            # Asymmetric signatures
            try:
                data = jwt.encode(data_dict, key, algorithm=algo)
            except Exception as e:
                self.error = e
                self.log.error(self.error)
                self.log.debug(self.error, exc_info=True)
            else:
                data = data.encode()
        elif algo == 'none':
            # Do not sign JWT token
            if not header:
                header = {'alg': 'none',
                          "typ": "JWT"}
            else:
                header['alg'] = 'none'
            header = json.dumps(header)
            data = base64.b64encode(header.encode()).replace(b'=', b'')
            data += b'.'
            data_dict = json.dumps(data_dict)
            data += base64.b64encode(data_dict.encode()).replace(b'=', b'')
            data += b'.'
        return data

    def unprocess(self, data, secret=b'', verify=False, algo='HS256',
                  key=None):
        super(DeenPluginJwt, self).unprocess(data)
        if not JOSE:
            self.error = MissingDependencyException('python-jose module missing')
            return data
        # Make sure there are no new lines.
        # that could break the padding.
        data = data.strip()
        try:
            _header, payload, signature = data.split(b'.')
            _header = _header
            _header += b'=' * ((4 - len(_header) % 4) % 4)
            _header = base64.urlsafe_b64decode(_header)
            _payload = payload
            _payload += b'=' * ((4 - len(payload) % 4) % 4)
            _payload = base64.urlsafe_b64decode(_payload)
            signature += b'=' * ((4 - len(signature) % 4) % 4)
        except Exception as e:
            self.error = InvalidFormatException('Invalid JWT token format: ' + str(e))
            self.log.error(self.error)
            self.log.debug(self.error, exc_info=True)
            return data
        try:
            algo = json.loads(_header)['alg']
        except KeyError:
            self.error = Exception('alg attribute not found, defaulting to HS256')
            self.log.error(self.error)
            self.log.debug(self.error, exc_info=True)
        except Exception as e:
            self.error = e
            self.log.error(self.error)
            self.log.debug(self.error, exc_info=True)
            return
        if verify:
            options = {'verify_signature': True}
        else:
            options = {'verify_signature': False,
                       'verify_aud': False,
                       'verify_iat': False,
                       'verify_exp': False,
                       'verify_nbf': False,
                       'verify_iss': False,
                       'verify_sub': False,
                       'verify_jti': False,
                       'verify_at_hash': True}
        if algo in constants.ALGORITHMS.RSA or \
             algo in constants.ALGORITHMS.EC:
            # Asymmetric signatures
            secret = key
        try:
            data = jwt.decode(bytes(data).decode(), secret,
                              algorithms=[algo], options=options)
        except exceptions.JWTError as e:
            data = b'Signature valid: False'
            self.error = e
            self.log.error(self.error)
            self.log.debug(self.error, exc_info=True)
        except Exception as e:
            self.error = e
            self.log.error(self.error)
            self.log.debug(self.error, exc_info=True)
        finally:
            data_decoded = json.dumps(data)
            data = b'{"header":' + _header + b', '
            data += b'"data":' + data_decoded.encode() + b','
            data += b'"signature":"' + signature + b'"}'
            if verify:
                data += b'\nSignature valid: True'
        return data

    @staticmethod
    def add_argparser(argparser, cmd_name, cmd_help, cmd_aliases=None,
                      *args, **kwargs):
        if not cmd_aliases:
            cmd_aliases = []
        # Python 2 argparse does not support aliases
        if sys.version_info.major < 3 or \
            (sys.version_info.major == 3 and
                sys.version_info.minor < 2):
            parser = argparser.add_parser(cmd_name, help=cmd_help)
        else:
            parser = argparser.add_parser(cmd_name, help=cmd_help, aliases=cmd_aliases)
        algos = []
        algos.extend(constants.ALGORITHMS.HASHES.keys())
        algos.append('None')
        parser.add_argument('plugindata', action='store',
                            help='input data', nargs='?')
        parser.add_argument('-r', '--revert', action='store_true', dest='revert',
                            default=False, help='revert plugin process')
        parser.add_argument('-f', '--file', dest='plugininfile', default=None,
                            help='file name or - for STDIN', metavar='filename')
        parser.add_argument('-s', '--secret', dest='pluginsecret', default='',
                            help='JWT secret', metavar='secret', type=str)
        parser.add_argument('-k', '--key', dest='pluginkey', default=None,
                            help='key file for asymmetric signatures', metavar='key', type=str)
        parser.add_argument('-m', '--mac', dest='pluginmac', help='JWT MAC algorithm',
                            default='HS256',choices=algos)
        parser.add_argument('-v', '--verify', dest='pluginverify', default=False,
                            help='force signature and claims verification',
                            action='store_true')

    def process_cli(self, args):
        if not self.content:
            if not args.plugindata:
                if not args.plugininfile:
                    self.content = self.read_content_from_file('-')
                else:
                    self.content = self.read_content_from_file(args.plugininfile)
            else:
                self.content = args.plugindata
        if not self.content:
            return
        key_data = None
        if args.pluginkey and os.path.isfile(args.pluginkey) and \
                os.access(args.pluginkey, os.R_OK):
            try:
                with open(args.pluginkey) as f:
                    key_data = f.read()
            except Exception as e:
                self.error = InvalidInputFile('Could not read key file: ' + str(e))
                self.log.error(self.error)
                self.log.debug(self.error, exc_info=True)
                return
        if not args.revert:
            return self.process(self.content, secret=args.pluginsecret,
                                algo=args.pluginmac, key=key_data)
        else:
            return self.unprocess(self.content, secret=args.pluginsecret,
                                  verify=args.pluginverify, algo=args.pluginmac,
                                  key=key_data)

    def process_gui(self, parent, content):
        """Creating JWT tokens requires inputs for the
        secret and signature algorithm values."""
        self.parent = parent
        self.jwtgui = JwtGui(self.parent)
        self.file_open_dialog = QtWidgets.QFileDialog(self.jwtgui)
        self.jwtgui.ui.read_secret_file_button.clicked.connect(self._load_secret_dialog)
        if self.jwtgui.exec_() == 0:
            # If the plugin GUI is cancelled, just
            # return without doing anything.
            return
        algo = self.jwtgui.ui.algo_combo.currentText()
        if self.secret:
            secret = self.secret
        else:
            secret = self.jwtgui.ui.secret_input_field.toPlainText()
            if self.jwtgui.ui.secret_base64_checkbox.isChecked():
                try:
                    secret = base64.b64decode(secret)
                except Exception:
                    pass
        if algo in constants.ALGORITHMS.HMAC:
            return self.process(content, secret=secret, algo=algo)
        elif algo in constants.ALGORITHMS.RSA or \
                algo in constants.ALGORITHMS.EC:
            return self.process(content, key=secret, algo=algo)
        elif algo == 'none':
            return self.process(content, key=secret, algo='none')

    def _load_secret_dialog(self):
        secret_path = self.file_open_dialog.getOpenFileName(
            self.file_open_dialog, 'Load secret from file')[0]
        if not secret_path:
            return
        with open(secret_path, 'rb') as f:
            self.secret = f.read()


class JwtGui(QtWidgets.QDialog):
    def __init__(self, parent):
        super(JwtGui, self).__init__(parent)
        self.ui = Ui_JwtCreateGui()
        self.ui.setupUi(self)
        self.setWindowTitle('Create JWT Token')
        self.parent = parent
        for algo in constants.ALGORITHMS.ALL:
            self.ui.algo_combo.addItem(algo)


class Ui_JwtCreateGui(object):
    def setupUi(self, JwtCreateGui):
        JwtCreateGui.setObjectName("JwtCreateGui")
        JwtCreateGui.resize(351, 461)
        self.dialogButtonBox = QtWidgets.QDialogButtonBox(JwtCreateGui)
        self.dialogButtonBox.setGeometry(QtCore.QRect(-50, 420, 391, 32))
        self.dialogButtonBox.setOrientation(QtCore.Qt.Horizontal)
        self.dialogButtonBox.setStandardButtons(QtWidgets.QDialogButtonBox.Cancel|QtWidgets.QDialogButtonBox.Ok)
        self.dialogButtonBox.setObjectName("dialogButtonBox")
        self.label = QtWidgets.QLabel(JwtCreateGui)
        self.label.setGeometry(QtCore.QRect(10, 20, 141, 18))
        self.label.setObjectName("label")
        self.algo_combo = QtWidgets.QComboBox(JwtCreateGui)
        self.algo_combo.setGeometry(QtCore.QRect(190, 10, 151, 32))
        self.algo_combo.setObjectName("algo_combo")
        self.label_2 = QtWidgets.QLabel(JwtCreateGui)
        self.label_2.setGeometry(QtCore.QRect(10, 70, 261, 18))
        self.label_2.setObjectName("label_2")
        self.read_secret_file_button = QtWidgets.QPushButton(JwtCreateGui)
        self.read_secret_file_button.setGeometry(QtCore.QRect(10, 370, 331, 34))
        self.read_secret_file_button.setObjectName("read_secret_file_button")
        self.secret_base64_checkbox = QtWidgets.QCheckBox(JwtCreateGui)
        self.secret_base64_checkbox.setGeometry(QtCore.QRect(10, 320, 231, 22))
        self.secret_base64_checkbox.setObjectName("secret_base64_checkbox")
        self.secret_input_field = QtWidgets.QTextEdit(JwtCreateGui)
        self.secret_input_field.setGeometry(QtCore.QRect(10, 100, 331, 211))
        self.secret_input_field.setObjectName("secret_input_field")
        self.line = QtWidgets.QFrame(JwtCreateGui)
        self.line.setGeometry(QtCore.QRect(20, 350, 321, 16))
        self.line.setFrameShape(QtWidgets.QFrame.HLine)
        self.line.setFrameShadow(QtWidgets.QFrame.Sunken)
        self.line.setObjectName("line")

        self.retranslateUi(JwtCreateGui)
        self.dialogButtonBox.accepted.connect(JwtCreateGui.accept)
        self.dialogButtonBox.rejected.connect(JwtCreateGui.reject)
        QtCore.QMetaObject.connectSlotsByName(JwtCreateGui)

    def retranslateUi(self, JwtCreateGui):
        _translate = QtCore.QCoreApplication.translate
        JwtCreateGui.setWindowTitle(_translate("JwtCreateGui", "Create JWT Token"))
        self.label.setText(_translate("JwtCreateGui", "Signature algorithm:"))
        self.label_2.setText(_translate("JwtCreateGui", "Secret (symmetric) or Key (asymmetric):"))
        self.read_secret_file_button.setText(_translate("JwtCreateGui", "Read secret from file"))
        self.secret_base64_checkbox.setText(_translate("JwtCreateGui", "secret base64 encoded"))
