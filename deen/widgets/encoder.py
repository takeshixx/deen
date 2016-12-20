import codecs
import base64
import binascii
import zlib
import hashlib
import logging
import cgi
try:
    import urllib.parse as urllibparse
except ImportError:
    import urllib as urllibparse
try:
    from html.parser import HTMLParser
except ImportError:
    from HTMLParser import HTMLParser

from PyQt5.QtCore import QTextCodec, QRegularExpression
from PyQt5.QtGui import QTextCursor, QTextCharFormat, QBrush, QColor
from PyQt5.QtWidgets import (QWidget, QHBoxLayout, QLabel, QApplication, QVBoxLayout, QComboBox,
                             QButtonGroup, QCheckBox, QPushButton, QLineEdit, QProgressBar,
                             QFileDialog)

from deen.widgets.hex import HexViewWidget
from deen.widgets.text import TextViewWidget
from deen.core import *

LOGGER = logging.getLogger(__name__)


class EncoderWidget(QWidget):
    def __init__(self, parent):
        super(EncoderWidget, self).__init__(parent)
        self.widgets = []
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
        self.text_field = TextViewWidget(self, readonly=readonly)
        self.text_field.textChanged.connect(self.field_content_changed)
        self.hex_field = HexViewWidget(read_only=readonly, parent=self)
        self.hex_field.setHidden(True)
        self.hex_field.bytesChanged.connect(self.field_content_changed)
        self.codec = QTextCodec.codecForName('UTF-8')
        self.content = bytearray()
        self.hex_view = False
        self.view_panel = self.create_view_panel()
        self.action_panel = self.create_action_panel(enable_actions)
        if not enable_actions:
            self.action_panel.hide()
        self.create_search_field()
        self.v_layout = QVBoxLayout()
        self.v_layout.addWidget(self.view_panel)
        self.v_layout.addWidget(self.text_field)
        self.v_layout.addWidget(self.hex_field)
        self.v_layout.addLayout(self.search)
        self.h_layout = QHBoxLayout()
        self.h_layout.addLayout(self.v_layout)
        self.h_layout.addWidget(self.action_panel)
        self.setLayout(self.h_layout)

    def has_previous(self):
        """Determine if the current widget is the root widget."""
        return True if self.parent.widgets[0] != self else False

    def has_next(self):
        """Determine if there are already new widgets created."""
        return True if self.parent.widgets[-1] != self else False

    def previous(self):
        """Return the previous widget. If the current widget
        is the root widget, this function returns the root
        widget (self)."""
        if not self.has_previous() == self:
            return self
        for i, w in enumerate(self.parent.widgets):
            if w == self:
                return self.parent.widgets[i - 1]

    def next(self):
        """Return the next widget. This is most likely the one
        that is supposed to hold the output of action()'s of
        the current widget."""
        if not self.has_next():
            w = DeenWidget(self.parent, readonly=True, enable_actions=False)
            self.parent.widgets.append(w)
            self.parent.encoder_layout.addWidget(w)
            return w
        for i, w in enumerate(self.parent.widgets):
            if w == self:
                return self.parent.widgets[i + 1]

    def field_content_changed(self):
        """The event handler for the textChanged event of the
        current widget. This will be called whenever the text
        of the QTextEdit() will be changed. Whatever will be
        executed here will most likely differ if it will be
        applied on a root widget or any following widget."""
        if self.action_panel.isHidden():
            self.action_panel.show()
        if self.has_next() and not self.text_field.isReadOnly():
            # If widget count is greater then two,
            # remove all widgets after the second.
            self.remove_next_widgets(offset=2)
        if not self.text_field.isReadOnly():
            if not self.hex_view:
                self.content = bytearray(self.text_field.toPlainText(), 'utf8')
            else:
                self.content = self.hex_field.content
        self.update_length_field(self)
        self.update_readonly_field(self)
        if (self.hex_field.hasFocus() or self.text_field.hasFocus()) and self.current_pick:
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
        copy = QPushButton('Copy')
        copy.clicked.connect(self.copy_to_clipboard)
        save = QPushButton('Save')
        save.clicked.connect(self.save_content)
        self.length_field = QLabel()
        self.length_field.setStyleSheet('border: 1px solid lightgrey')
        self.update_length_field(self)
        self.readonly_field = QLabel()
        self.readonly_field.setStyleSheet('border: 1px solid lightgrey')
        self.update_readonly_field(self)
        self.codec_field = QLabel()
        self.codec_field.setStyleSheet('border: 1px solid lightgrey')
        self.codec_field.hide()
        view_group = QButtonGroup(self)
        view_group.addButton(text, 1)
        view_group.addButton(hex, 2)
        view_group.addButton(clear, 3)
        view_group.addButton(save, 4)
        panel = QHBoxLayout()
        panel.addWidget(text)
        panel.addWidget(hex)
        panel.addWidget(self.length_field)
        panel.addWidget(self.readonly_field)
        panel.addWidget(self.codec_field)
        panel.addStretch()
        panel.addWidget(clear)
        panel.addWidget(copy)
        panel.addWidget(save)
        widget = QWidget()
        widget.setLayout(panel)
        return widget

    def create_search_field(self):
        self.search_field = QLineEdit()
        self.search_field.returnPressed.connect(self.search_highlight)
        self.search_field_matches = QLabel()
        self.search_field_matches.hide()
        self.search_field_progress = QProgressBar()
        self.search_field_progress.setGeometry(200, 80, 250, 20)
        self.search_field_progress.hide()
        self.search_bars = QVBoxLayout()
        self.search_bars.addWidget(self.search_field)
        self.search_bars.addWidget(self.search_field_progress)
        self.search = QHBoxLayout()
        self.search.addLayout(self.search_bars)
        self.search.addWidget(self.search_field_matches)

    def search_highlight(self):
        cursor = self.text_field.textCursor()
        b_format = cursor.blockFormat()
        b_format.setBackground(QBrush(QColor('white')))
        cursor.setBlockFormat(b_format)
        format = QTextCharFormat()
        format.setBackground(QBrush(QColor('yellow')))
        regex = QRegularExpression(self.search_field.text())
        matches = regex.globalMatch(self.text_field.toPlainText())
        _matches = []
        while matches.hasNext():
            _matches.append(matches.next())
        self.search_matches = _matches
        self.search_field_matches.setText('Matches: ' + str(len(self.search_matches)))
        self.search_field_matches.show()
        self.search_field_progress.setRange(0, len(self.search_matches))
        if len(self.search_matches) > 100:
            self.search_field_progress.show()
        match_count = 1
        for match in self.search_matches:
            if match_count > 150:
                # TODO: implement proper handling of > 1000 matches
                break
            self.search_field_progress.setValue(match_count)
            match_count += 1
            cursor.setPosition(match.capturedStart())
            cursor.setPosition(match.capturedEnd(), QTextCursor.KeepAnchor)
            cursor.mergeCharFormat(format)
        #self.field.moveCursor(QTextCursor.Start)
        #self.field.moveCursor(F)
        #self.field.ensureCursorVisible()

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
        action_panel.addWidget(self.decoding_combo)
        action_panel.addWidget(self.encoding_combo)
        action_panel.addWidget(self.uncompress_combo)
        action_panel.addWidget(self.compress_combo)
        action_panel.addWidget(self.hash_combo)
        action_panel.addStretch()
        widget = QWidget()
        widget.setLayout(action_panel)
        return widget

    def view_text(self):
        self.hex_view = False
        self.text_field.setHidden(False)
        self.hex_field.setHidden(True)
        if self.content:
            self.text_field.setPlainText(self.codec.toUnicode(self.content))

    def view_hex(self):
        self.hex_view = True
        self.text_field.setHidden(True)
        self.hex_field.setHidden(False)
        self.hex_field._read_only = self.text_field.isReadOnly()
        if not self.content:
            self.content = bytearray(self.text_field.toPlainText(), 'utf8')
        self.hex_field.content = self.content

    def clear_content(self):
        if self.parent.widgets[0] == self:
            self.text_field.clear()
            self.hex_field.content = bytearray()
            self.content = bytearray()
            self.update_length_field(self)
            self.text_field.setReadOnly(False)
            self.update_readonly_field(self)
        self.remove_next_widgets()

    def copy_to_clipboard(self):
        try:
            content = self.content.decode('utf8')
        except UnicodeDecodeError as e:
            LOGGER.error(e)
            LOGGER.error('Cannot copy non-ASCII content to clipboard')
            return
        clipboard = QApplication.clipboard()
        clipboard.setText(content)

    def save_content(self):
        fd = QFileDialog(self)
        name = fd.getSaveFileName(fd, 'Save File')
        if not name or not name[0]:
            return
        with open(name[0], 'wb') as file:
            file.write(self.content)

    def update_length_field(self, widget):
        widget.length_field.setText('Length: ' + str(len(widget.content)))

    def update_readonly_field(self, widget):
        widget.readonly_field.setText('R-' if widget.text_field.isReadOnly() else 'RW')

    def remove_next_widgets(self, offset=0):
        assert isinstance(offset, int)
        index = self.parent.widgets.index(self) + offset
        while len(self.parent.widgets) != index:
            if len(self.parent.widgets) == 1:
                break
            self.parent.encoder_layout.removeWidget(self.parent.widgets[-1])
            self.parent.widgets[-1].deleteLater()
            self.parent.widgets[-1] = None
            self.parent.widgets.pop()

    def set_content(self, content):
        if isinstance(content, str):
            content = codecs.encode(content, 'utf8')
        self.content = bytearray(content)

    def set_content_next(self, content):
        if isinstance(content, bytes):
            self.next().content = bytearray(content)
        elif isinstance(content, str):
            self.next().content = bytearray(content, 'utf8')
        else:
            self.next().content = content
        self.next().text_field.setPlainText(self.codec.toUnicode(self.next().content))
        self.update_length_field(self.next())
        if self.next().hex_view:
            self.next().view_hex()

    def action(self, combo=None):
        self.next().text_field.setStyleSheet('color: rgb(0, 0, 0);')
        if not self.content:
            self.content = bytearray(self.text_field.toPlainText(), 'utf8')
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
        elif self.current_pick in HASHS or self.current_pick == 'ALL':
            self.hash(self.current_pick)
        if self.current_combo:
            self.current_combo.setCurrentIndex(0)
        if self.next().text_field.isReadOnly() and self.current_pick:
            self.next().codec_field.setText('Transformer: ' + self.current_pick)
            self.next().codec_field.show()

    def encode(self, enc):
        if enc == 'Base64':
            output = base64.b64encode(self.content)
        elif enc == 'Hex':
            output = codecs.encode(self.content, 'hex')
        elif enc == 'URL':
            output = urllibparse.quote_plus(self.content.decode())
        elif enc == 'HTML':
            output = cgi.escape(self.content.decode())
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
        self.set_content_next(output)

    def decode(self, enc):
        decode_error = None
        if enc == 'Base64':
            try:
                output = base64.b64decode(self.content.replace(b'\n', b''))
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
        elif enc == 'HTML':
            h = HTMLParser()
            try:
                output = h.unescape(self.content.decode())
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

        if decode_error:
            LOGGER.error(decode_error)
            self.next().text_field.setStyleSheet('color: rgb(255, 0, 0);')
        self.set_content_next(output)

    def compress(self, comp):
        if comp == 'Gzip':
            output = codecs.encode(self.content, 'zlib')
        elif comp == 'Bz2':
            output = codecs.encode(self.content, 'bz2')
        else:
            output = self.content
        self.set_content_next(output)

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

        if decode_error:
            LOGGER.error(decode_error)
            self.next().text_field.setStyleSheet("color: rgb(255, 0, 0);")
        self.set_content_next(output)

    def hash(self, hash):
        if hash == 'ALL':
            output = ''
            for _hash in HASHS:
                output += '{}:\t'.format(_hash)
                h = hashlib.new(_hash.lower())
                h.update(self.content)
                output += h.hexdigest()
                output += '\n'
        elif hash in HASHS:
            h = hashlib.new(hash)
            h.update(self.content)
            output = h.hexdigest()
        else:
            output = hash
        self.set_content_next(output)
