try:
    import urllib.parse as urllibparse
except ImportError:
    import urllib as urllibparse

from PyQt5.QtWidgets import QPlainTextEdit


class TextViewWidget(QPlainTextEdit):
    def __init__(self, parent, readonly=False):
        super(TextViewWidget, self).__init__(parent)
        self.parent = parent
        self.setReadOnly(readonly)
        self.codec = self.parent.codec

    @property
    def content(self):
        return bytearray(self.codec.fromUnicode(self.toPlainText()))

    @content.setter
    def content(self, content):
        ctype = type(content).__name__
        assert isinstance(content, bytearray),\
            TypeError('bytearray required. Got ' + ctype)
        self.setPlainText(self.codec.toUnicode(content))
