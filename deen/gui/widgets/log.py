import logging

from PyQt5.QtWidgets import QVBoxLayout, QPushButton, QDialog, QTextBrowser


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