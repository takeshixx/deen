#!/usr/bin/env python3
import sys
import base64
import codecs
import binascii
import zlib
import urllib.parse
import hashlib
from PyQt5.QtWidgets import (QWidget, QHBoxLayout, QMainWindow, QAction, QToolButton,
                             QApplication, QMessageBox, QTextEdit, QVBoxLayout, QComboBox,
                             QButtonGroup, QCheckBox)
from PyQt5.QtCore import Qt

ENCODINGS = ['Base64',
             'Hex',
             'URL',
             'Rot13',
             'Punycode']

COMPRESSIONS = ['Gzip',
                'Bz2',]

HASHS = ['MD5',
         'SHA1',
         'SHA224',
         'SHA256',
         'SHA384',
         'SHA512',
         'RIPEMD160',
         'MD4',
         'MDC2',
         'whirlpool']


class Deen(QMainWindow):
    def __init__(self, partent=None):
        super(Deen, self).__init__(partent)
        self.create_menubar()
        self.encoder_widget = EncoderWidget(self)
        self.setCentralWidget(self.encoder_widget)
        self.setWindowTitle("DEEN")
        self.resize(800, 600)
        self.show()

    def create_menubar(self):
        self.main_menu = self.menuBar()
        self.file_menu = self.main_menu.addMenu("File")
        self.quit = QAction("Quit", self)
        self.quit.setShortcut("Alt+F4")
        self.file_menu.addAction(self.quit)
        self.file_menu.triggered[QAction].connect(QApplication.quit)
        self.help_menu = self.main_menu.addMenu("Help")
        self.about = QAction('About', self)
        self.help_menu.addAction(self.about)
        self.help_menu.triggered[QAction].connect(self.show_about)

    def show_about(self):
        about = QMessageBox(self)
        about.setWindowTitle('About')
        about.setText('DEcoderENcoder v0')
        about.show()


class EncoderWidget(QWidget):
    def __init__(self, parent):
        super(EncoderWidget, self).__init__(parent)
        self.incoming = QTextEdit(self)
        self.outgoing = QTextEdit(self)
        self.top1_content = None
        self.top2_content = None
        self.create_incoming()
        self.create_outgoing()
        self.create_panel()
        textfields = QVBoxLayout()
        textfields.addLayout(self.view_panel_top1)
        textfields.addWidget(self.incoming)
        textfields.addLayout(self.view_panel_top2)
        textfields.addWidget(self.outgoing)
        hbox = QHBoxLayout(self)
        hbox.addLayout(textfields)
        hbox.addLayout(self.button_panel)
        self.setLayout(hbox)

    def create_incoming(self):
        top1_text = QCheckBox('Text')
        top1_text.setChecked(True)
        top1_text.stateChanged.connect(self.view_top1_text)
        top1_hex = QCheckBox('Hex')
        top1_hex.setChecked(False)
        top1_hex.stateChanged.connect(self.view_top1_hex)
        view_check_top1 = QButtonGroup(self)
        view_check_top1.addButton(top1_text, 1)
        view_check_top1.addButton(top1_hex, 2)

        self.view_panel_top1 = QHBoxLayout()
        self.view_panel_top1.addWidget(top1_text)
        self.view_panel_top1.addWidget(top1_hex)
        self.view_panel_top1.addStretch()

    def create_outgoing(self):
        top2_text = QCheckBox('Text')
        top2_text.setChecked(True)
        top2_text.stateChanged.connect(self.view_top2_text)
        top2_hex = QCheckBox('Hex')
        top2_hex.setChecked(False)
        top2_hex.stateChanged.connect(self.view_top2_hex)
        view_check_top2 = QButtonGroup(self)
        view_check_top2.addButton(top2_text, 1)
        view_check_top2.addButton(top2_hex, 2)

        flip_button = QToolButton()
        flip_button.setArrowType(Qt.UpArrow)
        flip_button.show()
        flip_button.clicked.connect(self.flip_content)

        self.view_panel_top2 = QHBoxLayout()
        self.view_panel_top2.addWidget(top2_text)
        self.view_panel_top2.addWidget(top2_hex)
        self.view_panel_top2.addStretch()
        self.view_panel_top2.addWidget(flip_button)

    def create_panel(self):
        self.encoding_combo = QComboBox(self)
        self.encoding_combo.addItem('Encode')
        self.encoding_combo.model().item(0).setEnabled(False)
        for encoding in ENCODINGS:
            self.encoding_combo.addItem(encoding)
        self.encoding_combo.currentIndexChanged.connect(self.encode)

        self.decoding_combo = QComboBox(self)
        self.decoding_combo.addItem('Decode')
        self.decoding_combo.model().item(0).setEnabled(False)
        for encoding in ENCODINGS:
            self.decoding_combo.addItem(encoding)
        self.decoding_combo.currentIndexChanged.connect(self.decode)

        self.compress_combo = QComboBox(self)
        self.compress_combo.addItem('Compress')
        self.compress_combo.model().item(0).setEnabled(False)
        for compression in COMPRESSIONS:
            self.compress_combo.addItem(compression)
        self.compress_combo.currentIndexChanged.connect(self.compress)

        self.uncompress_combo = QComboBox(self)
        self.uncompress_combo.addItem('Uncompress')
        self.uncompress_combo.model().item(0).setEnabled(False)
        for compression in COMPRESSIONS:
            self.uncompress_combo.addItem(compression)
        self.uncompress_combo.currentIndexChanged.connect(self.uncompress)

        self.hash_combo = QComboBox(self)
        self.hash_combo.addItem('Hash')
        self.hash_combo.model().item(0).setEnabled(False)
        for hash in HASHS:
            self.hash_combo.addItem(hash)
        self.hash_combo.addItem('ALL')
        self.hash_combo.currentIndexChanged.connect(self.hash)

        self.button_panel = QVBoxLayout()
        self.button_panel.addWidget(self.encoding_combo)
        self.button_panel.addWidget(self.decoding_combo)
        self.button_panel.addWidget(self.compress_combo)
        self.button_panel.addWidget(self.uncompress_combo)
        self.button_panel.addWidget(self.hash_combo)
        self.button_panel.addStretch()

    def flip_content(self):
        self.top1_content = self.outgoing.toPlainText()
        self.incoming.setText(self.top1_content)
        self.outgoing.clear()

    def view_top1_text(self):
        if self.top1_content:
            self.incoming.setText(self.top1_content)

    def view_top1_hex(self):
        if not self.top1_content:
            self.top1_content = self.incoming.toPlainText()
        self.incoming.setText(self.hexdump(self.incoming.toPlainText()))

    def view_top2_text(self):
        if self.top2_content:
            self.outgoing.setText(self.top2_content)

    def view_top2_hex(self):
        if not self.top2_content:
            self.top2_content = self.outgoing.toPlainText()
        self.outgoing.setText(self.hexdump(self.outgoing.toPlainText()))

    def encode(self):
        if not self.top1_content:
            self.top1_content = self.incoming.toPlainText()
        enc = self.encoding_combo.currentText()
        i = self.incoming.toPlainText().encode('utf8')
        if enc == 'Base64':
            output = base64.b64encode(i)
        elif enc == 'Hex':
            output = codecs.encode(i, 'hex')
        elif enc == 'URL':
            output = urllib.parse.quote(i.decode())
        elif enc == 'Gzip':
            output = codecs.encode(i, 'zlib')
        elif enc == 'Bz2':
            output = codecs.encode(i, 'bz2')
        elif enc == 'Punycode':
            output = codecs.encode(i, 'punycode')
        elif enc == 'Rot13':
            output = codecs.encode(codecs.decode(i), 'rot_13')
        else:
            output = i

        if isinstance(output, bytes):
            output = output.decode()
        self.outgoing.clear()
        self.outgoing.setText(output)

    def decode(self):
        if not self.top1_content:
            self.top1_content = self.incoming.toPlainText()
        enc = self.decoding_combo.currentText()
        i = self.incoming.toPlainText().encode('utf8')
        decode_error = None
        if enc == 'Base64':
            try:
                output = base64.b64decode(i)
            except binascii.Error as e:
                decode_error = e
                output = i
        elif enc == 'Hex':
            try:
                output = codecs.decode(i, 'hex')
            except binascii.Error as e:
                decode_error = e
                output = i
        elif enc == 'URL':
            try:
                output = urllib.parse.unquote(i)
            except TypeError as e:
                decode_error = e
                output = i
        elif enc == 'Gzip':
            try:
                output = codecs.decode(i, 'zlib')
            except zlib.error as e:
                decode_error = e
                output = i
        elif enc == 'Bz2':
            try:
                output = codecs.decode(i, 'bz2')
            except OSError as e:
                decode_error = e
                output = i
        elif enc == 'Punycode':
            output = codecs.decode(i, 'punycode')
        elif enc == 'Rot13':
            output = codecs.decode(i, 'rot_13')
        else:
            output = i

        if isinstance(output, bytes):
            output = output.decode()
        if decode_error:
            self.outgoing.setStyleSheet("color: rgb(255, 0, 0);")
        self.outgoing.clear()
        self.outgoing.setText(output)

    def compress(self):
        if not self.top1_content:
            self.top1_content = self.incoming.toPlainText()
        comp = self.compress_combo.currentText()
        i = self.incoming.toPlainText().encode('utf8')
        if comp == 'Gzip':
            output = codecs.encode(i, 'zlib')
        elif comp == 'Bz2':
            output = codecs.encode(i, 'bz2')
        else:
            output = i

        #if isinstance(output, bytes):
        #    output = output.decode()
        self.outgoing.clear()
        self.outgoing.setText(output.decode())

    def uncompress(self):
        if not self.top1_content:
            self.top1_content = self.incoming.toPlainText()
        enc = self.uncompress_combo.currentText()
        i = self.incoming.toPlainText().encode('utf8')
        decode_error = None
        if enc == 'Gzip':
            try:
                output = codecs.decode(i, 'zlib')
            except zlib.error as e:
                decode_error = e
                output = i
        elif enc == 'Bz2':
            try:
                output = codecs.decode(i, 'bz2')
            except OSError as e:
                decode_error = e
                output = i
        else:
            output = i

        if isinstance(output, bytes):
            output = output.decode()
        if decode_error:
            self.outgoing.setStyleSheet("color: rgb(255, 0, 0);")
        self.outgoing.clear()
        self.outgoing.setText(output)

    def hash(self):
        if not self.top1_content:
            self.top1_content = self.incoming.toPlainText()
        hash = self.hash_combo.currentText()
        src = self.incoming.toPlainText().encode('utf8')
        if hash == 'ALL':
            output = ''
            for _hash in HASHS:
                output += '{}:\t'.format(_hash)
                h = hashlib.new(_hash)
                h.update(src)
                output += h.hexdigest()
                output += '\n'
        elif hash in HASHS:
            h = hashlib.new(hash)
            h.update(src)
            output = h.hexdigest()
        else:
            output = src
        self.outgoing.clear()
        self.outgoing.setText(output)

    def hexdump(self, src, length=16):
        FILTER = ''.join([(len(repr(chr(x))) == 3) and chr(x) or '.' for x in range(256)])
        lines = []
        for c in range(0, len(src), length):
            chars = src[c:c + length]
            hex = ' '.join(["%02x" % ord(x) for x in chars])
            printable = ''.join(["%s" % ((ord(x) <= 127 and FILTER[ord(x)]) or '.') for x in chars])
            lines.append("%04x  %-*s  %s\n" % (c, length * 3, hex, printable))
        return ''.join(lines)

        
if __name__ == '__main__':
    app = QApplication(sys.argv)
    ex = Deen()
    sys.exit(app.exec_())
