import codecs
try:
    import urllib.parse as urllibparse
except ImportError:
    import urllib as urllibparse

from PyQt5.QtCore import QTextCodec
from PyQt5.QtWidgets import QTextEdit


class TextViewWidget(QTextEdit):
    def __init__(self, parent, readonly=False):
        super(TextViewWidget, self).__init__(parent)
        self.parent = parent
        self.setReadOnly(readonly)
        self.codec = QTextCodec.codecForName('UTF-8')
        self.content = None

    def set_content(self, content):
        if isinstance(content, str):
            content = codecs.encode(content, 'utf8')
        self.content = content
