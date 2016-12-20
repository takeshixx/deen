import codecs
try:
    import urllib.parse as urllibparse
except ImportError:
    import urllib as urllibparse

from PyQt5.QtCore import QTextCodec
from PyQt5.QtWidgets import QPlainTextEdit


class TextViewWidget(QPlainTextEdit):
    def __init__(self, parent, readonly=False):
        super(TextViewWidget, self).__init__(parent)
        self.parent = parent
        self.setReadOnly(readonly)
        self.codec = QTextCodec.codecForName('UTF-8')
