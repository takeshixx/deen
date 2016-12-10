import logging

from PyQt5.QtCore import QRect
from PyQt5.QtWidgets import (QMainWindow, QAction, QScrollArea, QApplication, QMessageBox, QFileDialog)

from deen.widgets.encoder import EncoderWidget
from deen.widgets.log import DeenLogger, DeenStatusConsole

LOGGER = logging.getLogger(__name__)

class Deen(QMainWindow):
    def __init__(self, parent=None):
        super(Deen, self).__init__(parent)
        self.create_menubar()
        self.resize(800, 600)
        self.encoder_widget = EncoderWidget(self)
        self.encoder_widget.setGeometry(QRect(0, 0, 1112, 932))
        self.main_scrollable = QScrollArea(self)
        self.main_scrollable.setWidgetResizable(True)
        self.main_scrollable.setWidget(self.encoder_widget)
        self.setCentralWidget(self.main_scrollable)
        self.setWindowTitle("deen")
        self.log = DeenLogger(self)
        self.show()

    def create_menubar(self):
        self.main_menu = self.menuBar()
        self.file_menu = self.main_menu.addMenu("File")
        self.quit = QAction("Quit", self)
        self.quit.setShortcut("Alt+F4")
        self.quit.triggered.connect(QApplication.quit)
        self.load_file = QAction("Load from File", self)
        self.load_file.setShortcut("Alt+O")
        self.load_file.triggered.connect(self.load_from_file)
        self.file_menu.addAction(self.load_file)
        self.file_menu.addAction(self.quit)
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
        # TODO: readd __version__ variable
        about.setText('DEcoderENcoder')
        about.resize(100, 75)
        about.show()

    def show_status_console(self):
        status = DeenStatusConsole(self)
        status.setWindowTitle('Status Console')
        status.resize(600, 400)
        status.console.show()
        status.show()

    def load_from_file(self):
        fd = QFileDialog(self)
        name = fd.getOpenFileName(fd, 'Load from File')
        if not name or not name[0]:
            return
        with open(name[0], 'rb') as file:
            content = file.read()
        if content:
            self.encoder_widget.widgets[0].clear_content()
            self.encoder_widget.widgets[0].set_content(content)
            try:
                content = content.decode('utf8')
            except UnicodeDecodeError:
                content = content.decode('utf8', errors='replace')
                self.encoder_widget.widgets[0].text_field.setReadOnly(True)
                LOGGER.warn('Failed to decode file content, root widget will be read only')
            self.encoder_widget.widgets[0].text_field.setText(content)
        self.encoder_widget.widgets[0].hex_field.setHidden(True)
        self.encoder_widget.widgets[0].text_field.setHidden(False)
