#!/usr/bin/env python3
import sys
import base64
import codecs
import binascii
import zlib
import hashlib
import logging
from PyQt5.QtCore import Qt, QTextCodec, QRect
from PyQt5.QtGui import QTextCursor, QTextTableFormat, QTextLength
from PyQt5.QtWidgets import (QWidget, QHBoxLayout, QMainWindow, QAction,QScrollArea, QLabel,
                             QApplication, QMessageBox, QTextEdit, QVBoxLayout, QComboBox,
                             QButtonGroup, QCheckBox, QPushButton, QDialog, QTextBrowser, )
try:
    import urllib.parse as urllibparse
except ImportError:
    import urllib as urllibparse

LOGGER = logging.getLogger()
logging.basicConfig(format='[%(lineno)s - %(funcName)s() ] %(message)s')

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
        self.resize(800, 600)
        self.encoder_widget = EncoderWidget(self)
        self.encoder_widget.setGeometry(QRect(0, 0, 1112, 932))
        self.main_scrollable = QScrollArea(self)
        self.main_scrollable.setWidgetResizable(True)
        self.main_scrollable.setWidget(self.encoder_widget)
        self.setCentralWidget(self.main_scrollable)
        self.setWindowTitle("DEEN")
        self.log = DeenLogger(self)
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
        self.console = QAction('Status Console', self)
        self.help_menu.addAction(self.about)
        self.about.triggered.connect(self.show_about)
        self.help_menu.addAction(self.console)
        self.console.triggered.connect(self.show_status_console)

    def show_about(self):
        about = QMessageBox(self)
        about.setWindowTitle('About')
        about.setText('DEcoderENcoder v0.1')
        about.resize(100, 75)
        about.show()

    def show_status_console(self):
        status = DeenStatusConsole(self)
        status.setWindowTitle('Status Console')
        status.resize(600, 400)
        status.console.show()
        status.show()


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
        self.codec = QTextCodec.codecForName('UTF-8')
        self.content = None
        self.hex_view = False
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
        if not self.field.isReadOnly() and not self.hex_view:
            self.content = bytes(self.codec.fromUnicode(self.field.toPlainText()))
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
        self.hex_view = False
        if self.content:
            self.field.setText(self.codec.toUnicode(self.content))

    def view_hex(self):
        self.hex_view = True
        if not self.content:
            self.content = bytes(self.codec.fromUnicode(self.field.toPlainText()))
        rows = [self.content[i:i+16] for i in range(0, len(self.content), 16)]
        if rows:
            format = QTextTableFormat()
            format.setAlignment(Qt.AlignCenter)
            format.setBorder(0)
            format.setWidth(QTextLength(QTextLength.PercentageLength, 100))
            cursor = self.field.textCursor()
            cursor.select(QTextCursor.Document)
            cursor.removeSelectedText()
            cursor.insertTable(len(rows), len(rows[0]) if len(rows[0]) < 16 else 16, format)
            for r in rows:
                for c in r:
                    cursor.insertText(self.codec.toUnicode(codecs.encode(bytes([c]), 'hex')))
                    cursor.movePosition(QTextCursor.NextCell)

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
        self.next().field.setStyleSheet("color: rgb(0, 0, 0);")
        if not self.content:
            self.content = bytes(self.codec.fromUnicode(self.field.toPlainText()))
        if combo:
            if combo.currentIndex() == 0:
                return
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
        if enc == 'Base64':
            output = base64.b64encode(self.content)
        elif enc == 'Hex':
            output = codecs.encode(self.content, 'hex')
        elif enc == 'URL':
            output = urllibparse.quote_plus(self.content.decode())
        elif enc == 'Gzip':
            output = codecs.encode(self.conent, 'zlib')
        elif enc == 'Bz2':
            output = codecs.encode(self.content, 'bz2')
        elif enc == 'Rot13':
            output = codecs.encode(self.content.decode(), 'rot_13')
        elif enc == 'UTF8':
            output = codecs.encode(self.content.decode(), 'utf8')
        elif enc == 'UTF16':
            output = codecs.encode(self.content.decode(), 'utf16')
        else:
            output = self.content

        if isinstance(output, bytes):
            output = self.codec.toUnicode(output)
        self.next().field.clear()
        self.next().field.setText(output)

    def decode(self, enc):
        decode_error = None
        if enc == 'Base64':
            try:
                output = base64.b64decode(self.content)
            except binascii.Error as e:
                decode_error = e
                output = self.content
        elif enc == 'Hex':
            try:
                output = codecs.decode(self.content, 'hex')
            except binascii.Error as e:
                decode_error = e
                output = self.content
        elif enc == 'URL':
            try:
                output = urllibparse.unquote_plus(self.content.decode())
            except TypeError as e:
                decode_error = e
                output = self.content
        elif enc == 'Gzip':
            try:
                output = codecs.decode(self.content.decode(), 'zlib')
            except zlib.error as e:
                decode_error = e
                output = self.content
        elif enc == 'Bz2':
            try:
                output = codecs.decode(self.content.decode(), 'bz2')
            except OSError as e:
                decode_error = e
                output = self.content
        elif enc == 'Rot13':
            output = codecs.decode(self.content.decode(), 'rot_13')
        else:
            output = self.content

        if isinstance(output, bytes):
            output = self.codec.toUnicode(output)
        if decode_error:
            LOGGER.error(decode_error)
            self.next().field.setStyleSheet("color: rgb(255, 0, 0);")
        self.next().field.clear()
        self.next().field.setText(output)

    def compress(self, comp):
        if comp == 'Gzip':
            output = codecs.encode(self.content, 'zlib')
        elif comp == 'Bz2':
            output = codecs.encode(self.content, 'bz2')
        else:
            output = self.content

        if isinstance(output, bytes):
            output = self.codec.toUnicode(output)
        self.next().field.clear()
        self.next().field.setText(output)

    def uncompress(self, comp):
        decode_error = None
        if comp == 'Gzip':
            try:
                output = codecs.decode(self.content, 'zlib')
            except zlib.error as e:
                decode_error = e
                output = self.content
        elif comp == 'Bz2':
            try:
                output = codecs.decode(self.content, 'bz2')
            except OSError as e:
                decode_error = e
                output = self.content
        else:
            output = self.content

        if isinstance(output, bytes):
            output = self.codec.toUnicode(output)
        if decode_error:
            LOGGER.error(decode_error)
            self.next().field.setStyleSheet("color: rgb(255, 0, 0);")
        self.next().field.clear()
        self.next().field.setText(output)

    def hash(self, hash):
        if hash == 'ALL':
            output = ''
            for _hash in HASHS:
                output += '{}:\t'.format(_hash)
                h = hashlib.new(_hash)
                h.update(self.content)
                output += h.hexdigest()
                output += '\n'
        elif hash in HASHS:
            h = hashlib.new(hash)
            h.update(self.content)
            output = h.hexdigest()
        else:
            output = src
        self.next().field.clear()
        self.next().field.setText(output)


class DeenStatusConsole(QDialog):
    def __init__(self, parent=None):
        super(DeenStatusConsole, self).__init__(parent)
        self.console = parent.log.field
        self.button = QPushButton(self)
        self.button.setText('Close')
        self.layout = QVBoxLayout()
        self.layout.addWidget(self.console)
        self.layout.addWidget(self.button)
        self.setLayout(self.layout)
        self.button.clicked.connect(self.hide)


class DeenLogger(logging.Handler):
    def __init__(self, parent):
        super(DeenLogger, self).__init__()
        self.field = QTextBrowser(parent)
        self.field.setReadOnly(True)
        self.field.hide()
        fmt = logging.Formatter('%(asctime)s : %(message)s')
        self.setFormatter(fmt)

    def emit(self, record):
        self.field.append(self.format(record))

    def write(self, m):
        pass

        
if __name__ == '__main__':
    app = QApplication(sys.argv)
    ex = Deen()
    LOGGER.addHandler(ex.log)
    sys.exit(app.exec_())
