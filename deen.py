#!/usr/bin/env python3
import sys
import base64
import codecs
import binascii
import zlib
import hashlib
import logging
import string
from PyQt5.QtCore import Qt, QTextCodec, QRect, QRegularExpression, pyqtSignal
from PyQt5.QtGui import (QTextCursor, QTextTableFormat, QTextLength, QTextCharFormat, QBrush, QColor)
from PyQt5.QtWidgets import (QWidget, QHBoxLayout, QMainWindow, QAction, QScrollArea, QLabel,
                             QApplication, QMessageBox, QTextEdit, QVBoxLayout, QComboBox,
                             QButtonGroup, QCheckBox, QPushButton, QDialog, QTextBrowser, QLineEdit,
                             QProgressBar, QFileDialog, QTableWidget, QTableWidgetItem, QHeaderView)
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
                'Bz2']

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


class HexDumpWidget(QTableWidget):
    bytesChanged = pyqtSignal()

    def __init__(self, data=b'', bytes_per_line=16, width=1, parent=None):
        super(HexDumpWidget, self).__init__(parent)
        self._bytes_per_line = bytes_per_line
        self._width = width
        self.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch)
        self.data = data

    def _reconstructTable(self):
        try:
            self.itemChanged.disconnect(self._itemChanged)
        except:
            pass
        self.clear()

        rows = []
        for i in range(0, len(self._data), self._bytes_per_line):
            rows.append(self._data[i:i+self._bytes_per_line])

        self.setRowCount(len(rows))
        cols = self._bytes_per_line // self._width + 1 # ascii
        self.setColumnCount(cols)

        header_labels = []
        for i in range(0, self._bytes_per_line, self._width):
            header_labels.append('{:X}'.format(i))
        header_labels.append('ASCII')
        row_labels = []
        for i in range(0, len(self._data), self._bytes_per_line):
            row_labels.append('{:X}'.format(i))
        self.setHorizontalHeaderLabels(header_labels)
        self.setVerticalHeaderLabels(row_labels)

        for y, row in enumerate(rows):
            for x, i in enumerate(range(0, len(row), self._width)):
                block = row[i:i+self._width]
                item = QTableWidgetItem(codecs.encode(block, 'hex').decode())
                item.setBackground(QBrush(QColor('lightgray')))
                item.setData(Qt.UserRole, block)  # store original data
                self.setItem(y, x, item)
            for j in range(x+1, cols):
                item = QTableWidgetItem()
                item.setBackground(QBrush(QColor('gray')))
                item.setFlags(Qt.NoItemFlags)
                self.setItem(y, j, item)

            text = self._bytes2ascii(row)
            item = QTableWidgetItem(text)
            item.setData(Qt.UserRole, row)  # store original data
            item.setBackground(QBrush(QColor('lightblue')))
            self.setItem(y, cols - 1, item)

        self.itemChanged.connect(self._itemChanged)

    def _bytes2ascii(self, data):
        allowed = (set(string.printable.encode()) - set(string.whitespace.encode())) | {b' '}
        return bytes(c if c in allowed else b'.'[0] for c in data).decode()

    def _itemChanged(self, item):
        col = item.column()
        row = item.row()
        text = item.text()
        orig_data = item.data(Qt.UserRole)
        offset = row * self._bytes_per_line
        if col != self.columnCount() - 1:  # hex part
            text = text.strip()
            fmt = "{{:>0{}}}".format(self._width * 2)
            text = fmt.format(text)
            if len(text) != self._width * 2:
                text = codecs.encode(orig_data, 'hex').decode()
                item.setText(text)
                return

            offset += col * self._width
            try:
                value = codecs.decode(text, 'hex')
            except ValueError:
                text = codecs.encode(orig_data, 'hex').decode()
                item.setText(text)
                return
        else:  # ascii part
            if len(orig_data) != len(text):
                text = self._bytes2ascii(orig_data)
                item.setText(text)
                return

            value = bytearray()
            for a, b in zip(orig_data, text.encode()):
                if b == b'.'[0]:
                    value.append(a)
                else:
                    value.append(b)

        self._data[offset:offset+len(value)] = value
        self.bytesChanged.emit()
        self._reconstructTable()

    @property
    def width(self):
        return self._width

    @width.setter
    def width(self, val):
        if val not in (1, 2, 2**2, 2**3, 2**4, 2**5, 2**6):
            raise ValueError('Width not power of 2')
        self._width = val
        self._reconstructTable()

    @property
    def data(self):
        return bytes(self._data)

    @data.setter
    def data(self, val):
        if not isinstance(val, bytes):
            raise TypeError('bytestring required. Got ' + type(val).__name__)
        self._data = bytearray(val)
        if self._data:
            if len(self._data) < self._bytes_per_line:
                self._bytes_per_line = len(self._data)
            elif len(self._data) >= self._bytes_per_line:
                self._bytes_per_line = 16
        self._reconstructTable()

    @property
    def bytes_per_line(self):
        return self._bytes_per_line

    @bytes_per_line.setter
    def bytes_per_line(self, val):
        self._bytes_per_line = val
        self._reconstructTable()

    def to_bytes(self):
        return self.data


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
        about.setText('DEcoderENcoder v0.2.1')
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
        self.hex_field = HexDumpWidget(parent=self)
        self.hex_field.setHidden(True)
        self.hex_field.bytesChanged.connect(self.field_content_changed)
        self.codec = QTextCodec.codecForName('UTF-8')
        self.content = None
        self.hex_view = False
        self.view_panel = self.create_view_panel()
        self.action_panel = self.create_action_panel(enable_actions)
        if not enable_actions:
            self.action_panel.hide()
        self.create_search_field()
        self.v_layout = QVBoxLayout()
        self.v_layout.addWidget(self.view_panel)
        self.v_layout.addWidget(self.field)
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
        if self.has_next() and not self.field.isReadOnly():
            # If widget count is greater then two,
            # remove all widgets after the second.
            self.remove_next_widgets(offset=2)
        if not self.field.isReadOnly():
            if not self.hex_view:
                self.content = bytes(self.codec.fromUnicode(self.field.toPlainText()))
            else:
                self.content = self.hex_field.data
            self.length_field.setText('Length: ' + str(len(self.content)))
        if (self.hex_field.hasFocus() or self.field.hasFocus()) and self.current_pick:
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
        save = QPushButton('Save')
        save.clicked.connect(self.save_content)
        self.length_field = QLabel()
        self.length_field.setStyleSheet('border: 1px solid lightgrey')
        self.length_field.setText('Length: 0')
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
        panel.addWidget(self.codec_field)
        panel.addStretch()
        panel.addWidget(clear)
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
        cursor = self.field.textCursor()
        b_format = cursor.blockFormat()
        b_format.setBackground(QBrush(QColor('white')))
        cursor.setBlockFormat(b_format)
        format = QTextCharFormat()
        format.setBackground(QBrush(QColor('yellow')))
        regex = QRegularExpression(self.search_field.text())
        matches = regex.globalMatch(self.field.toPlainText())
        _matches = list()
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
        self.field.setHidden(False)
        self.hex_field.setHidden(True)
        if self.content:
            self.field.setText(self.codec.toUnicode(self.content))

    def view_hex(self):
        self.hex_view = True
        self.field.setHidden(True)
        self.hex_field.setHidden(False)

        if not self.content:
            self.content = bytes(self.codec.fromUnicode(self.field.toPlainText()))

        self.hex_field.data = self.content

    def clear_content(self):
        if self.parent.widgets[0] == self:
            self.field.clear()
        self.remove_next_widgets()

    def save_content(self):
        fd = QFileDialog(self)
        name = fd.getSaveFileName(fd, 'Save File')
        if not name or not name[0]:
            return
        file = open(name[0], 'wb')
        file.write(self.content)
        file.close()

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
        self.content = content

    def set_content_next(self, content):
        if isinstance(content, bytes):
            self.next().content = content
        else:
            self.next().content = codecs.encode(content, 'utf8')
        self.next().field.clear()
        self.next().field.setText(self.codec.toUnicode(self.next().content))
        self.next().length_field.setText('Length: ' + str(len(self.next().content)))
        if self.next().hex_view:
            self.next().view_hex()

    def action(self, combo=None):
        self.next().field.setStyleSheet('color: rgb(0, 0, 0);')
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
        if self.next().field.isReadOnly() and self.current_pick:
            self.next().codec_field.setText('Transformer: ' + self.current_pick)
            self.next().codec_field.show()

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
            self.next().field.setStyleSheet('color: rgb(255, 0, 0);')
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
            self.next().field.setStyleSheet("color: rgb(255, 0, 0);")
        self.set_content_next(output)

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
            output = hash
        self.set_content_next(output)


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
