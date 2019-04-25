from PyQt5.QtWidgets import QMainWindow, QApplication, QMessageBox, QFileDialog,\
                            QBoxLayout, QShortcut, QDialog, QCompleter
from PyQt5.QtGui import QKeySequence
from PyQt5.QtCore import QStringListModel, Qt

import deen.constants
from deen.gui.widgets.log import DeenLogger, DeenStatusConsole
from deen.gui.widgets.ui_deenmainwindow import Ui_MainWindow
from deen.gui.encoder import DeenEncoderWidget
from deen.gui.widgets.ui_deenfuzzysearch import Ui_DeenFuzzySearchWidget
from deen import logger

LOGGER = logger.DEEN_LOG.getChild('gui.widgets.core')


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
        # Set default direction
        self.set_widget_direction_toptobottom()
        self.ui.actionCopy_to_clipboard.triggered.connect(self.copy_content_to_clipboard)
        self.ui.actionSave_content_to_file.triggered.connect(self.save_widget_content_to_file)
        self.ui.actionSearch.triggered.connect(self.toggle_search_box_visibility)
        self.widgets.append(DeenEncoderWidget(self))
        for widget in self.widgets:
            self.ui.encoder_widget_layout.addWidget(widget)
        self.load_from_file_dialog = QFileDialog(self)
        self.setWindowTitle('deen')
        self.log = DeenLogger(self)
        self.widgets[0].set_field_focus()
        # Add action fuzzy search
        self.fuzzy_search_ui = FuzzySearchUi(self)
        self.fuzzy_search_action_shortcut = QShortcut(QKeySequence(Qt.CTRL | Qt.Key_R), self)
        self.fuzzy_search_action_shortcut.activated.connect(self.fuzzy_search_action)
        self.clear_current_widget_shortcut = QShortcut(QKeySequence(Qt.CTRL | Qt.Key_Q), self)
        self.clear_current_widget_shortcut.activated.connect(self.clear_current_widget)
        self.hide_search_box_shortcut = QShortcut(QKeySequence(Qt.CTRL | Qt.Key_F), self)
        self.hide_search_box_shortcut.activated.connect(self.toggle_search_box_visibility)
        self.next_encoder_widget_shortcut = QShortcut(QKeySequence(Qt.ALT | Qt.Key_Right), self)
        self.next_encoder_widget_shortcut.activated.connect(self.toggle_next_encoder_focus)
        self.prev_encoder_widget_shortcut = QShortcut(QKeySequence(Qt.ALT | Qt.Key_Left), self)
        self.prev_encoder_widget_shortcut.activated.connect(self.toggle_prev_encoder_focus)
        self.show()

    def fuzzy_search_action(self):
        """Open a dialog for quick access to actions
        with fuzzy search."""
        focussed_widget = QApplication.focusWidget()
        self.fuzzy_search_ui.ui.fuzzy_search_field.setFocus()
        def get_data(model):
            plugins = [x[1].name for x in self.plugins.available_plugins]
            for p in self.plugins.codecs + \
                     self.plugins.compressions +\
                     self.plugins.assemblies:
                plugins.append('-' + p[1].name)
                plugins.extend(['-' + x for x in p[1].aliases])
            for p in self.plugins.available_plugins:
                plugins.extend(p[1].aliases)
            model.setStringList(plugins)
        completer = QCompleter()
        self.fuzzy_search_ui.ui.fuzzy_search_field.setCompleter(completer)
        model = QStringListModel()
        completer.setModel(model)
        get_data(model)
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

    def toggle_next_encoder_focus(self):
        """Focus the next encoder widget."""
        focussed_widget = QApplication.focusWidget()
        parent_encoder = self.get_parent_encoder(focussed_widget)
        if parent_encoder:
            if parent_encoder.has_next():
                parent_encoder.next.field.setFocus()
                self.ui.DeenMainWindow.ensureWidgetVisible(parent_encoder.next)
        else:
            LOGGER.error('Unable to find parent encoder for ' + str(focussed_widget))

    def toggle_prev_encoder_focus(self):
        """Focus the previous encoder widget."""
        focussed_widget = QApplication.focusWidget()
        parent_encoder = self.get_parent_encoder(focussed_widget)
        if parent_encoder:
            if parent_encoder.has_previous():
                parent_encoder.previous.field.setFocus()
                self.ui.DeenMainWindow.ensureWidgetVisible(parent_encoder.previous)
        else:
            LOGGER.error('Unable to find parent encoder for ' + str(focussed_widget))

    def clear_current_widget(self):
        """Clear and remove the current encoder widget."""
        focussed_widget = QApplication.focusWidget()
        if not hasattr(focussed_widget, 'parent') or \
                not focussed_widget.parent:
            LOGGER.warning('NO parent for widget found: ' + str(focussed_widget))
            return
        if callable(focussed_widget.parent):
            widget = focussed_widget.parent()
        else:
            widget = focussed_widget.parent
        if isinstance(widget, DeenEncoderWidget):
            widget.clear_content()

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
            self.widgets[0].content = bytearray(content)
            try:
                content = content.decode('utf8')
            except UnicodeDecodeError:
                content = content.decode('utf8', errors='replace')
                LOGGER.warning('Failed to decode file content')
            self.widgets[0].text_field.setPlainText(content)
        self.widgets[0].hex_field.setHidden(True)
        self.widgets[0].text_field.setHidden(False)

    def save_widget_content_to_file(self, file_name=None):
        """Save the content of the current widget
        to a file."""
        focussed_widget = QApplication.focusWidget()
        parent_encoder = self.get_parent_encoder(focussed_widget)
        if not parent_encoder._content:
            return
        fd = QFileDialog(parent_encoder)
        if file_name:
            name = file_name
        else:
            name = fd.getSaveFileName(fd, 'Save File')
        if not name or not name[0]:
            return
        if isinstance(name, tuple):
            name = name[0]
        with open(name, 'wb') as file:
            current_plugin = self.plugins.get_plugin_by_display_name(
                    parent_encoder.ui.current_plugin_label.text().replace('Plugin: ', ''))
            if self.plugins.is_plugin_in_category(current_plugin, 'formatters'):
                # Formatters alter data inplace, so we have to write the
                # data that is currently displayed into the outfile.
                file.write(bytearray(parent_encoder.text_field.toPlainText(), 'utf8'))
            else:
                file.write(parent_encoder._content)

    def copy_content_to_clipboard(self):
        focussed_widget = QApplication.focusWidget()
        parent_encoder = self.get_parent_encoder(focussed_widget)
        if not parent_encoder._content:
            return
        try:
            content = parent_encoder._content.decode('utf8')
        except UnicodeDecodeError as e:
            parent_encoder.log.error('Cannot copy non-ASCII content to clipboard')
            parent_encoder.log.debug(e, exc_info=True)
            return
        clipboard = QApplication.clipboard()
        clipboard.setText(content)
