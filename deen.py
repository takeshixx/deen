#!/usr/bin/env python3
import sys
import base64
import codecs
import binascii
import zlib
import hashlib
import logging
from PyQt5.QtCore import Qt
from PyQt5.QtWidgets import (QWidget, QHBoxLayout, QMainWindow, QAction, QToolButton,
                             QApplication, QMessageBox, QTextEdit, QVBoxLayout, QComboBox,
                             QButtonGroup, QCheckBox, QPushButton)
try:
    import urllib.parse as urllibparse
except ImportError:
    import urllib as urllibparse


LOGGER = logging.getLogger(__name__)
logging.baseConfig(format='[%(lineno)s - %(funcName)20s() ] %(message)s')

ENCODINGS = ['Base64',
             'Hex',
             'URL',
             'Rot13',
             'UTF8',
             'UTF16']

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
        self.widgets = list()
        self.widgets.append(DeenWidget(self))
        self.encoder_layout = QVBoxLayout(self)
        for widget in self.widgets:
            self.encoder_layout.addWidget(widget)
        self.setLayout(self.encoder_layout)


class DeenWidget(QWidget):
    def __init__(self, parent, readonly=False, enable_actions=True):
        super(DeenWidget, self).__init__(parent)
        self.parent = parent
        self.current_pick = None
        self.current_combo = None
        self.field = QTextEdit(self)
        self.field.setReadOnly(readonly)
        self.field.textChanged.connect(self.field_content_changed)
        self.content = None
        self.view_panel = self.create_view_panel()
        self.action_panel = self.create_action_panel(enable_actions)
        if not enable_actions:
            self.action_panel.hide()
        self.h_layout = QHBoxLayout()
        self.h_layout.addWidget(self.field)
        self.h_layout.addWidget(self.action_panel)
        self.v_layout = QVBoxLayout()
        self.v_layout.addWidget(self.view_panel)
        self.v_layout.addLayout(self.h_layout)
        self.setLayout(self.v_layout)

    def previous(self):
        if self.parent.widgets[0] == self:
            return self
        for i, w in enumerate(self.parent.widgets):
            if w == self:
                return self.parent.widgets[i - 1]

    def next(self):
        if self.parent.widgets[-1] == self:
            w = DeenWidget(self.parent, readonly=True, enable_actions=False)
            self.parent.widgets.append(w)
            self.parent.encoder_layout.addWidget(w)
            return w
        for i, w in enumerate(self.parent.widgets):
            if w == self:
                return self.parent.widgets[i + 1]

    def field_content_changed(self):
        if self.action_panel.isHidden():
            self.action_panel.show()
        if self.field.hasFocus():
            self.action()

    def create_view_panel(self):
        text = QCheckBox('Text')
        text.setChecked(True)
        text.stateChanged.connect(self.view_text)
        hex = QCheckBox('Hex')
        hex.setChecked(False)
        hex.stateChanged.connect(self.view_hex)
        clear = QPushButton('Clear')
        clear.clicked.connect(self.clear_content)
        view_group = QButtonGroup(self)
        view_group.addButton(text, 1)
        view_group.addButton(hex, 2)
        view_group.addButton(clear, 3)
        panel = QHBoxLayout()
        panel.addWidget(text)
        panel.addWidget(hex)
        panel.addWidget(clear)
        panel.addStretch()
        widget = QWidget()
        widget.setLayout(panel)
        return widget

    def create_action_panel(self, enable_actions=True):
        self.encoding_combo = QComboBox(self)
        self.encoding_combo.addItem('Encode')
        self.encoding_combo.model().item(0).setEnabled(False)
        for encoding in ENCODINGS:
            self.encoding_combo.addItem(encoding)
        self.encoding_combo.currentIndexChanged.connect(lambda: self.action(self.encoding_combo))

        self.decoding_combo = QComboBox(self)
        self.decoding_combo.addItem('Decode')
        self.decoding_combo.model().item(0).setEnabled(False)
        for encoding in ENCODINGS:
            self.decoding_combo.addItem(encoding)
        self.decoding_combo.currentIndexChanged.connect(lambda: self.action(self.decoding_combo))

        self.compress_combo = QComboBox(self)
        self.compress_combo.addItem('Compress')
        self.compress_combo.model().item(0).setEnabled(False)
        for compression in COMPRESSIONS:
            self.compress_combo.addItem(compression)
        self.compress_combo.currentIndexChanged.connect(lambda: self.action(self.compress_combo))

        self.uncompress_combo = QComboBox(self)
        self.uncompress_combo.addItem('Uncompress')
        self.uncompress_combo.model().item(0).setEnabled(False)
        for compression in COMPRESSIONS:
            self.uncompress_combo.addItem(compression)
        self.uncompress_combo.currentIndexChanged.connect(lambda: self.action(self.uncompress_combo))

        self.hash_combo = QComboBox(self)
        self.hash_combo.addItem('Hash')
        self.hash_combo.model().item(0).setEnabled(False)
        for hash in HASHS:
            self.hash_combo.addItem(hash)
        self.hash_combo.addItem('ALL')
        self.hash_combo.currentIndexChanged.connect(lambda: self.action(self.hash_combo))

        action_panel = QVBoxLayout()
        action_panel.addWidget(self.encoding_combo)
        action_panel.addWidget(self.decoding_combo)
        action_panel.addWidget(self.compress_combo)
        action_panel.addWidget(self.uncompress_combo)
        action_panel.addWidget(self.hash_combo)
        action_panel.addStretch()
        widget = QWidget()
        widget.setLayout(action_panel)
        return widget

    def view_text(self):
        if self.content:
            self.field.setText(self.content)

    def view_hex(self):
        if not self.content:
            self.content = self.field.toPlainText()
        self.field.setText(self.hexdump(self.field.toPlainText()))

    def clear_content(self):
        if self.parent.widgets[0] == self:
            self.field.clear()
        index = self.parent.widgets.index(self)
        while len(self.parent.widgets) != index:
            if len(self.parent.widgets) == 1:
                break
            self.parent.encoder_layout.removeWidget(self.parent.widgets[-1])
            self.parent.widgets[-1].deleteLater()
            self.parent.widgets[-1] = None
            self.parent.widgets.pop()

    def action(self, combo=None):
        if combo and combo.currentText() != combo.model().item(0).text():
            self.current_combo = combo
            self.current_pick = combo.currentText()
        if self.current_pick in ENCODINGS:
            if self.current_combo.model().item(0).text() == 'Encode':
                self.encode(self.current_pick)
            else:
                self.decode(self.current_pick)
        elif self.current_pick in COMPRESSIONS:
            if self.current_combo.model().item(0).text() == 'Compress':
                self.compress(self.current_pick)
            else:
                self.uncompress(self.current_pick)
        elif self.current_pick in HASHS:
            self.hash(self.current_pick)
        if self.current_combo:
            self.current_combo.setCurrentIndex(0)

    def encode(self, enc):
        if not self.content:
            self.content = self.field.toPlainText()
        i = self.field.toPlainText()
        if enc == 'Base64':
            output = base64.b64encode(i.encode())
        elif enc == 'Hex':
            output = codecs.encode(i.encode(), 'hex')
        elif enc == 'URL':
            output = urllibparse.quote_plus(i)
        elif enc == 'Gzip':
            output = codecs.encode(i.encode(), 'zlib')
        elif enc == 'Bz2':
            output = codecs.encode(i.encode(), 'bz2')
        elif enc == 'Rot13':
            output = codecs.encode(i, 'rot_13')
        elif enc == 'UTF8':
            output = codecs.encode(i, 'utf8')
        elif enc == 'UTF16':
            output = codecs.encode(i, 'utf16')
        else:
            output = i

        #if isinstance(output, bytes):
        #    output = output.decode()
        self.next().field.clear()
        self.next().field.setText(output)

    def decode(self, enc):
        if not self.content:
            self.content = self.field.toPlainText()
        i = self.field.toPlainText().encode('utf8')
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
                output = urllibparse.unquote_plus(i)
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
        elif enc == 'Rot13':
            output = codecs.decode(i, 'rot_13')
        else:
            output = i

        if isinstance(output, bytes):
            output = output.decode()
        if decode_error:
            LOGGER.error(decode_error)
            self.next().field.setStyleSheet("color: rgb(255, 0, 0);")
        self.next().field.clear()
        self.next().field.setText(output)

    def compress(self, comp):
        if not self.content:
            self.content = self.field.toPlainText()
        i = self.field.toPlainText().encode('utf8')
        if comp == 'Gzip':
            output = codecs.encode(i, 'zlib')
        elif comp == 'Bz2':
            output = codecs.encode(i, 'bz2')
        else:
            output = i
        self.next().field.clear()
        self.next().field.setText(output.decode())

    def uncompress(self, comp):
        if not self.content:
            self.content = self.field.toPlainText()
        i = self.field.toPlainText().encode('utf8')
        decode_error = None
        if comp == 'Gzip':
            try:
                output = codecs.decode(i, 'zlib')
            except zlib.error as e:
                decode_error = e
                output = i
        elif comp == 'Bz2':
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
            LOGGER.error(decode_error)
            self.outgoing.setStyleSheet("color: rgb(255, 0, 0);")
        self.next().field.clear()
        self.next().field.setText(output)

    def hash(self, hash):
        if not self.content:
            self.content = self.field.toPlainText()
        src = self.field.toPlainText().encode('utf8')
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
        self.next().field.clear()
        self.next().field.setText(output)

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
