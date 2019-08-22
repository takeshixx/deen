from PyQt5.QtWidgets import QPlainTextEdit
from PyQt5.QtCore import Qt, pyqtSignal


class TextViewWidget(QPlainTextEdit):
    internallyEdited = pyqtSignal()

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
        self.blockSignals(True)
        self.setPlainText(self.codec.toUnicode(content))
        self.blockSignals(False)
        self.internallyEdited.emit()

    @property
    def selected_data(self):
        cursor = self.textCursor()
        data = cursor.selection().toPlainText()
        data = bytearray(self.codec.fromUnicode(data))
        return data

    @property
    def selection_count(self):
        cursor = self.textCursor()
        data = cursor.selection().toPlainText()
        return len(data)

    def wheelEvent(self, QWheelEvent):
        """Implementes zooming via CTRL+mouse wheel."""
        if QWheelEvent.modifiers() & Qt.ControlModifier:
            if QWheelEvent.angleDelta().y() > 0:
                self.zoomIn(2)
            else:
                self.zoomOut(2)
