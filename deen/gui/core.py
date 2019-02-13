import logging

from PyQt5.QtWidgets import QMainWindow, QApplication, QMessageBox, QFileDialog,\
                            QBoxLayout, QShortcut, QDialog
from PyQt5.QtGui import QKeySequence

import deen.constants
from deen.gui.widgets.log import DeenLogger, DeenStatusConsole
from deen.gui.widgets.ui_deenmainwindow import Ui_MainWindow
from deen.gui.encoder import DeenEncoderWidget
from deen.gui.widgets.ui_deenfuzzysearch import Ui_DeenFuzzySearchWidget

LOGGER = logging.getLogger(__name__)


class FuzzySearchUi(QDialog):
    def __init__(self, parent):
        super(FuzzySearchUi, self).__init__(parent)
        self.ui = Ui_DeenFuzzySearchWidget()
        self.ui.setupUi(self)
        self.parent = parent


class DeenGui(QMainWindow):
    """The main window class that is the core of
    the Deen GUI. If is basically just the main
    window with a central element that includes
    one or more DeenEncoderWidget."""
    def __init__(self, parent=None, plugins=None):
        super(DeenGui, self).__init__(parent)
        self.ui = Ui_MainWindow()
        self.ui.setupUi(self)
        self.plugins = plugins
        self.widgets = []
        self.ui.actionLoad_from_file.triggered.connect(self.load_from_file)
        self.ui.actionQuit.triggered.connect(QApplication.quit)
        self.ui.actionAbout.triggered.connect(self.show_about)
        self.ui.actionStatus_console.triggered.connect(self.show_status_console)
        self.ui.actionTop_to_bottom.triggered.connect(self.set_widget_direction_toptobottom)
        self.ui.actionLeft_to_right.triggered.connect(self.set_widget_direction_lefttoright)
        self.widgets.append(DeenEncoderWidget(self))
        for widget in self.widgets:
            self.ui.encoder_widget_layout.addWidget(widget)
        self.load_from_file_dialog = QFileDialog(self)
        self.setWindowTitle('deen')
        self.log = DeenLogger(self)
        # Start Deen GUI maximized with focus on the text field
        self.showMaximized()
        self.widgets[0].text_field.setFocus(True)
        # Add action fuzzy search
        self.fuzzy_search_ui = FuzzySearchUi(self)
        self.fuzzy_search_action_shortcut = QShortcut(QKeySequence('Ctrl+R'), self)
        self.fuzzy_search_action_shortcut.activated.connect(self.fuzzy_search_action)
        self.clear_current_widget_shortcut = QShortcut(QKeySequence('Ctrl+Q'), self)
        self.clear_current_widget_shortcut.activated.connect(self.clear_current_widget)
        self.hide_search_box_shortcut = QShortcut(QKeySequence('Ctrl+F'), self)
        self.hide_search_box_shortcut.activated.connect(self.toggle_search_box_visibility)
        self.show()

    def fuzzy_search_action(self):
        """Open a dialog for quick access to actions
        with fuzzy search."""
        focussed_widget = QApplication.focusWidget()
        self.fuzzy_search_ui.ui.fuzzy_search_field.setFocus()
        if self.fuzzy_search_ui.exec_() == 0:
            return
        search_data = self.fuzzy_search_ui.ui.fuzzy_search_field.text()
        parent_encoder = self.get_parent_encoder(focussed_widget)
        if parent_encoder:
            parent_encoder.action_fuzzy(search_data)
        else:
            LOGGER.error('Unable to find parent encoder for ' + str(focussed_widget))

    def toggle_search_box_visibility(self):
        """Toggle the search box visibility
        via a shortcut for the current encoder
        widget."""
        focussed_widget = QApplication.focusWidget()
        parent_encoder = self.get_parent_encoder(focussed_widget)
        if parent_encoder:
            parent_encoder.toggle_search_box_visibility()
        else:
            LOGGER.error('Unable to find parent encoder for ' + str(focussed_widget))

    def get_parent_encoder(self, widget):
        """A wrapper function that returns the
        parent encoder widget for a given widget
        retrieved via QApplication.focusWidget().
        Can be used on signal receivers to
        reference the current encoder widget."""
        while not isinstance(widget, DeenEncoderWidget):
            # Builin clases may implement
            # parent() to retrieve the
            # parent object.
            if callable(widget.parent):
                widget = widget.parent()
            else:
                widget = widget.parent
            if isinstance(widget, DeenGui):
                return False
        return widget

    def clear_current_widget(self):
        """Clear and remove the current encoder widget."""
        focussed_widget = QApplication.focusWidget()
        focussed_widget.parent.clear_content()

    def set_root_content(self, data):
        if data:
            if isinstance(data, (str, bytes)):
                data = bytearray(data)
            self.widgets[0].content = data

    def set_widget_direction_toptobottom(self):
        self.ui.encoder_widget_layout.setDirection(QBoxLayout.TopToBottom)

    def set_widget_direction_lefttoright(self):
        self.ui.encoder_widget_layout.setDirection(QBoxLayout.LeftToRight)

    def show_about(self):
        about = QMessageBox(self)
        about.setWindowTitle('About')
        about.setText(deen.constants.about_text)
        about.resize(100, 75)
        about.show()

    def show_status_console(self):
        status = DeenStatusConsole(self)
        status.setWindowTitle('Status Console')
        status.resize(600, 400)
        status.console.show()
        status.show()

    def show_error_msg(self, error_msg, parent=None):
        """Generic message box for displaying any
        kind of error message from GUI elements."""
        widget = parent or self
        dialog = QMessageBox(widget)
        dialog.setIcon(QMessageBox.Critical)
        dialog.setWindowTitle('Error')
        dialog.setText(error_msg)
        dialog.show()

    def load_from_file(self, file_name=None):
        if file_name:
            name = file_name
        else:
            name = self.load_from_file_dialog.getOpenFileName(
                        self.load_from_file_dialog, 'Load from File')
        if not name or not name[0]:
            return
        if isinstance(name, tuple):
            name = name[0]
        with open(name, 'rb') as file:
            content = file.read()
        if content:
            self.widgets[0].clear_content()
            self.widgets[0].content =  bytearray(content)
            try:
                content = content.decode('utf8')
            except UnicodeDecodeError:
                content = content.decode('utf8', errors='replace')
                LOGGER.warning('Failed to decode file content')
            self.widgets[0].text_field.setPlainText(content)
        self.widgets[0].hex_field.setHidden(True)
        self.widgets[0].text_field.setHidden(False)
