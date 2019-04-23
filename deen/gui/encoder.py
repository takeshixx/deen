import os
import string

try:
    from OpenSSL import crypto
except ImportError:
    crypto = None

from PyQt5.QtCore import QTextCodec, QRegularExpression, Qt
from PyQt5.QtGui import QTextCursor, QTextCharFormat, QBrush, QColor, QIcon
from PyQt5.QtWidgets import QWidget, QLabel, QApplication, QFileDialog

from deen.gui.widgets.hex import HexViewWidget
from deen.gui.widgets.text import TextViewWidget
from deen.gui.widgets.ui_deenencoderwidget import Ui_DeenEncoderWidget
from deen import logger

MEDIA_PATH = os.path.dirname(os.path.abspath(__file__)) + '/../media/'
LOGGER = logger.DEEN_LOG.getChild('gui.widgets.encoder')


class DeenEncoderWidget(QWidget):
    """For each plugin operation Deen will create
    an instance of this class to represent an
    action. self.parent in instances of this
    class should point to the main window (an
    instance of DeenGui)."""
    def __init__(self, parent, readonly=False):
        super(DeenEncoderWidget, self).__init__(parent)
        self.ui = Ui_DeenEncoderWidget()
        self.ui.setupUi(self)
        self.parent = parent
        self.readonly = readonly
        self.process = False
        self.plugin = None
        self.current_combo = None
        self.search_matches = None
        self._content = bytearray()
        self.formatted_view = False
        self.codec = QTextCodec.codecForName('UTF-8')
        self.hex_view = False
        # TODO: check if printable is enforced
        self.printable = True
        # Assign custom widgets for text_field and hex_field.
        self.text_field = TextViewWidget(self, readonly=self.readonly)
        self.text_field.textChanged.connect(self.field_content_changed)
        self.hex_field = HexViewWidget(read_only=self.readonly, parent=self)
        self.hex_field.setHidden(True)
        # Add connection for selection field
        self.text_field.selectionChanged.connect(self.update_selection_field)
        self.ui.selection_length_label.setText('Selection: 0')
        self.hex_field.bytesChanged.connect(self.field_content_changed)
        self.hex_field.itemSelectionChanged.connect(self.update_selection_field)
        self.ui.content_area_layout.addWidget(self.text_field)
        self.ui.content_area_layout.addWidget(self.hex_field)
        # Configure widget elements
        self.ui.toggle_text_view.setChecked(True)
        self.ui.toggle_text_view.clicked.connect(self.view_text)
        self.ui.toggle_hex_view.setChecked(False)
        self.ui.toggle_hex_view.clicked.connect(self.view_hex)
        # Update labels with proper values
        self.update_length_field()
        # The root widget will not have a plugin label and no "Move to root" button.
        self.ui.current_plugin_label.hide()
        # Disable the first element in all combo boxes.
        for combo in [self.ui.encode_combo, self.ui.decode_combo, self.ui.uncompress_combo,
                      self.ui.compress_combo, self.ui.hash_combo, self.ui.misc_combo,
                      self.ui.format_combo, self.ui.assemble_combo, self.ui.disassemble_combo]:
            combo.model().item(0).setEnabled(False)
        # Add all alvailable plugins to the corresponding combo boxes.
        for encoding in [p[1] for p in self.parent.plugins.codecs
                     if (not getattr(p[1], 'cmd_only', None) or
                        (getattr(p[1], 'cmd_only', None) and not p[1].cmd_only))]:
            self.ui.encode_combo.addItem(encoding.display_name)
            if getattr(encoding, 'cmd_help', None) and encoding.cmd_help:
                index = self.ui.encode_combo.count()
                self.ui.encode_combo.setItemData(index-1, encoding.cmd_help, Qt.ToolTipRole)
        for encoding in [p[1] for p in self.parent.plugins.codecs
                     if (not getattr(p[1], 'cmd_only', None) or
                         (getattr(p[1], 'cmd_only', None) and not p[1].cmd_only))]:
            self.ui.decode_combo.addItem(encoding.display_name)
            if getattr(encoding, 'cmd_help', None) and encoding.cmd_help:
                index = self.ui.decode_combo.count()
                self.ui.decode_combo.setItemData(index-1, encoding.cmd_help, Qt.ToolTipRole)
        for compression in [p[1] for p in self.parent.plugins.compressions
                     if (not getattr(p[1], 'cmd_only', None) or
                         (getattr(p[1], 'cmd_only', None) and not p[1].cmd_only))]:
            self.ui.compress_combo.addItem(compression.display_name)
            if getattr(compression, 'cmd_help', None) and compression.cmd_help:
                index = self.ui.compress_combo.count()
                self.ui.compress_combo.setItemData(index-1, compression.cmd_help, Qt.ToolTipRole)
        for compression in [p[1] for p in self.parent.plugins.compressions
                     if (not getattr(p[1], 'cmd_only', None) or
                         (getattr(p[1], 'cmd_only', None) and not p[1].cmd_only))]:
            self.ui.uncompress_combo.addItem(compression.display_name)
            if getattr(compression, 'cmd_help', None) and compression.cmd_help:
                index = self.ui.uncompress_combo.count()
                self.ui.uncompress_combo.setItemData(index-1, compression.cmd_help, Qt.ToolTipRole)
        for assembly in [p[1] for p in self.parent.plugins.assemblies
                     if (not getattr(p[1], 'cmd_only', None) or
                         (getattr(p[1], 'cmd_only', None) and not p[1].cmd_only))]:
            self.ui.assemble_combo.addItem(assembly.display_name)
            if getattr(assembly, 'cmd_help', None) and assembly.cmd_help:
                index = self.ui.assemble_combo.count()
                self.ui.assemble_combo.setItemData(index-1, assembly.cmd_help, Qt.ToolTipRole)
        for assembly in [p[1] for p in self.parent.plugins.assemblies
                     if (not getattr(p[1], 'cmd_only', None) or
                         (getattr(p[1], 'cmd_only', None) and not p[1].cmd_only))]:
            self.ui.disassemble_combo.addItem(assembly.display_name)
            if getattr(assembly, 'cmd_help', None) and assembly.cmd_help:
                index = self.ui.disassemble_combo.count()
                self.ui.disassemble_combo.setItemData(index-1, assembly.cmd_help, Qt.ToolTipRole)
        for hash in [p[1] for p in self.parent.plugins.hashs
                     if (not getattr(p[1], 'cmd_only', None) or
                         (getattr(p[1], 'cmd_only', None) and not p[1].cmd_only))]:
            self.ui.hash_combo.addItem(hash.display_name)
            if getattr(hash, 'cmd_help', None) and hash.cmd_help:
                index = self.ui.hash_combo.count()
                self.ui.hash_combo.setItemData(index - 1, hash.cmd_help, Qt.ToolTipRole)
        for misc in [p[1] for p in self.parent.plugins.misc
                     if (not getattr(p[1], 'cmd_only', None) or
                         (getattr(p[1], 'cmd_only', None) and not p[1].cmd_only))]:
            self.ui.misc_combo.addItem(misc.display_name)
            if getattr(misc, 'cmd_help', None) and misc.cmd_help:
                index = self.ui.misc_combo.count()
                self.ui.misc_combo.setItemData(index - 1, misc.cmd_help, Qt.ToolTipRole)
        for formatter in [p[1] for p in self.parent.plugins.formatters
                     if (not getattr(p[1], 'cmd_only', None) or
                        (getattr(p[1], 'cmd_only', None) and not p[1].cmd_only))]:
            self.ui.format_combo.addItem(formatter.display_name)
            if getattr(formatter, 'cmd_help', None) and formatter.cmd_help:
                index = self.ui.format_combo.count()
                self.ui.format_combo.setItemData(index - 1, formatter.cmd_help, Qt.ToolTipRole)
        # Add connections for combo boxes
        self.ui.encode_combo.currentIndexChanged.connect(lambda: self.action(self.ui.encode_combo))
        self.ui.decode_combo.currentIndexChanged.connect(lambda: self.action(self.ui.decode_combo))
        self.ui.compress_combo.currentIndexChanged.connect(lambda: self.action(self.ui.compress_combo))
        self.ui.uncompress_combo.currentIndexChanged.connect(lambda: self.action(self.ui.uncompress_combo))
        self.ui.assemble_combo.currentIndexChanged.connect(lambda: self.action(self.ui.assemble_combo))
        self.ui.disassemble_combo.currentIndexChanged.connect(lambda: self.action(self.ui.disassemble_combo))
        self.ui.hash_combo.currentIndexChanged.connect(lambda: self.action(self.ui.hash_combo))
        self.ui.misc_combo.currentIndexChanged.connect(lambda: self.action(self.ui.misc_combo))
        self.ui.format_combo.currentIndexChanged.connect(lambda: self.action(self.ui.format_combo))
        # Configure search widget
        self.ui.search_area.returnPressed.connect(self.search_highlight)
        self.ui.search_button.clicked.connect(self.search_highlight)
        self.ui.search_clear_button.clicked.connect(self.clear_search_highlight)
        self.ui.search_progress_bar.hide()
        self.error_message = QLabel()
        self.error_message.setStyleSheet('border: 2px solid red;')
        self.error_message.hide()
        self.ui.error_message_layout.addWidget(self.error_message)
        self.ui.error_message_layout_widget.hide()
        self.ui.search_group.hide()
        # After adding new widgets, we have to update the max scroll range.
        self.parent.ui.DeenMainWindow.verticalScrollBar().rangeChanged.connect(self.update_vertical_scroll_range)
        self.parent.ui.DeenMainWindow.horizontalScrollBar().rangeChanged.connect(self.update_horizontal_scroll_range)

    @property
    def content(self):
        return self._content

    @content.setter
    def content(self, data):
        assert isinstance(data, (bytearray, bytes))
        if isinstance(data, bytes):
            data = bytearray(data)
        self._content = data
        self.formatted_view = False
        if not all(chr(c) in string.printable for c in self._content):
            # If there are non-printable characters,
            # switch to hex view.
            self.printable = False
            self.ui.toggle_text_view.setEnabled(False)
            self.ui.toggle_hex_view.click()
        else:
            # Prevent the field from overwriting itself with invalid
            # characters.
            self.printable = True
            self.ui.toggle_text_view.setEnabled(True)
            self.ui.toggle_text_view.click()
            self.text_field.moveCursor(QTextCursor.End)
        self.update_length_field()

    def has_previous(self):
        """Determine if the current widget is the root widget."""
        if self.parent.widgets and self.parent.widgets[0] != self:
            return True
        else:
            return False

    def has_next(self):
        """Determine if there are already new widgets created."""
        if self.parent.widgets and self.parent.widgets[-1] != self:
            return True
        else:
            return False

    @property
    def previous(self):
        """Return the previous widget. If the current widget
        is the root widget, this function returns the root
        widget (self)."""
        if not self.has_previous():
            return self
        for i, w in enumerate(self.parent.widgets):
            if w == self:
                return self.parent.widgets[i - 1]

    @property
    def next(self):
        """Return the next widget. This is most likely the one
        that is supposed to hold the output of action()'s of
        the current widget."""
        if not self.has_next():
            w = DeenEncoderWidget(self.parent)
            self.parent.widgets.append(w)
            self.parent.ui.encoder_widget_layout.addWidget(w)
            return w
        for i, w in enumerate(self.parent.widgets):
            if w == self:
                return self.parent.widgets[i + 1]

    @property
    def field(self):
        if self.hex_view:
            return self.hex_field
        else:
            return self.text_field

    def set_field_focus(self):
        """Set the focus of the current
        input field. Checks if hex view
        mode is enabled."""
        self.field.setFocus()

    def get_field_content(self):
        """Return the content of the current
        text or hex field."""
        return self.field.content

    def toggle_search_box_visibility(self):
        """Calling this function will either
        hide or show the search box. By default
        it is hidden and can be made visible
        with the Search button."""
        if self.ui.search_group.isVisible():
            self.ui.search_group.hide()
            self.clear_search_highlight()
            self.set_field_focus()
        else:
            self.ui.search_group.show()
            self.ui.search_area.setFocus()

    def field_content_changed(self):
        """The event handler for the textChanged event of the
        current widget. This will be called whenever the text
        of the QTextEdit() will be changed. Whatever will be
        executed here will most likely differ if it will be
        applied on a root widget or any following widget."""
        if not self.formatted_view:#
            if self.printable:
                # TODO: is there another situation where this could fail?
                self._content = self.get_field_content()
        if self.plugin:
            self._action(self.plugin.name, self.process)
        self.update_length_field()

    def search_highlight(self):
        """The function that will be called whenever the
        search area is submitted. It will search within
        the text_field and highlights matches."""
        cursor = self.text_field.textCursor()
        char_format = QTextCharFormat()
        cursor.select(QTextCursor.Document)
        cursor.mergeCharFormat(char_format)
        cursor.clearSelection()
        char_format.setBackground(QBrush(QColor('yellow')))
        regex = QRegularExpression(self.ui.search_area.text())
        matches = regex.globalMatch(self.text_field.toPlainText())
        _matches = []
        while matches.hasNext():
            _matches.append(matches.next())
        self.search_matches = _matches
        self.ui.search_matches_label.setText('Matches: ' + str(len(self.search_matches)))
        self.ui.search_progress_bar.setRange(0, len(self.search_matches))
        if len(self.search_matches) > 100:
            self.ui.search_progress_bar.show()
        match_count = 1
        for match in self.search_matches:
            if match_count > 1000:
                # TODO: implement proper handling of > 1000 matches
                break
            self.ui.search_progress_bar.setValue(match_count)
            match_count += 1
            cursor.setPosition(match.capturedStart())
            cursor.setPosition(match.capturedEnd(), QTextCursor.KeepAnchor)
            cursor.mergeCharFormat(format)
        self.ui.search_progress_bar.hide()

    def clear_search_highlight(self, widget=None):
        widget = widget or self
        cursor = self.text_field.textCursor()
        cursor.select(QTextCursor.Document)
        char_format = QTextCharFormat()
        cursor.setCharFormat(char_format)
        widget.ui.search_area.clear()
        widget.ui.search_matches_label.setText('Matches: 0')

    def set_error(self, widget=None):
        """If an an error occured during transformation
        this function sets the color of the next widget's
        border to red and removes all following widgets."""
        widget = widget or self
        widget.text_field.setStyleSheet('border: 2px solid red;')
        self.remove_next_widgets(widget=widget, offset=1)

    def set_error_message(self, message, widget=None):
        widget = widget or self
        if not self.ui.error_message_layout_widget.isVisible():
            self.ui.error_message_layout_widget.show()
        widget.error_message.setText('Error: ' + message)
        widget.error_message.setStyleSheet('color: red;')
        widget.error_message.show()

    def clear_error_message(self, widget=None):
        widget = widget or self
        self.ui.error_message_layout_widget.hide()
        widget.error_message.clear()
        widget.error_message.hide()
        widget.text_field.setStyleSheet('')

    def view_text(self):
        self.hex_view = False
        self.text_field.setHidden(False)
        self.hex_field.setHidden(True)
        self.text_field.content = self._content

    def view_hex(self):
        self.hex_view = True
        self.text_field.setHidden(True)
        self.hex_field.setHidden(False)
        self.hex_field.content = self._content

    def clear_content(self, widget=None):
        """Clear the content of widget. If widget
        is not set, clear the content of the current
        widget. This will also remove all widgets
        that follow widget."""
        widget = widget or self
        self.clear_error_message(widget=widget)
        self.clear_search_highlight(widget=widget)
        if self.parent.widgets[0] == widget:
            widget.text_field.clear()
            widget.hex_field.content = bytearray()
            widget._content = bytearray()
            widget.update_length_field()
            widget.ui.current_plugin_label.clear()
            widget.ui.current_plugin_label.hide()
            widget.formatted_view = False
            widget.set_field_focus()
            widget.plugin = None
        else:
            # Remove the current_combo of the previous
            # widget so that the last pick doesn't
            # stuck in the previous widget after deleting
            # one.
            self.previous.current_combo = None
            self.previous.set_field_focus()
            self.previous.plugin = None
        self.remove_next_widgets(widget=widget)

    def update_length_field(self, widget=None):
        widget = widget or self
        widget.ui.content_length_label.setText('Length: ' + str(len(widget.content)))

    def update_selection_field(self):
        self.ui.selection_length_label.setText('Selection: ' + str(self.field.selection_count))

    def update_vertical_scroll_range(self, minimum, maximum):
        """Update the scroll maximum of the main window scroll
        are in order to automatically jump to newly created
        encoder widgets."""
        sb = self.parent.ui.DeenMainWindow.verticalScrollBar()
        sb.setValue(maximum)

    def update_horizontal_scroll_range(self, minimum, maximum):
        """Update the scroll maximum of the main window scroll
        are in order to automatically jump to newly created
        encoder widgets."""
        sb = self.parent.ui.DeenMainWindow.horizontalScrollBar()
        sb.setValue(maximum)

    def remove_next_widgets(self, widget=None, offset=0):
        """Remove all widgets after widget. If widget is not
        set, remove all widgets after the current widget."""
        widget = widget or self
        assert isinstance(offset, int)
        index = self.parent.widgets.index(widget) + offset
        while len(self.parent.widgets) != index:
            if len(self.parent.widgets) == 1:
                break
            self.parent.ui.encoder_widget_layout.removeWidget(self.parent.widgets[-1])
            self.parent.widgets[-1].deleteLater()
            self.parent.widgets[-1] = None
            self.parent.widgets.pop()

    def is_action_process(self, choice):
        """Returns True if the action should call
        process(), False if unprocess() should be
        called. Should only be used for values of
        the combo boxes."""
        if choice == 'Encode' or choice == 'Compress' or \
                choice == 'Hash' or choice == 'Miscellaneous' or \
                choice == 'Assemble':
            return True
        else:
            return False

    def action(self, combo=None):
        """The main function that is responsible for calling plugins
        on input data. It will use self._content as source and puts
        the result of each plugin into the next widget in line via
        the self.set_content_next() function. (except for formatters,
        which will write their output into the same window)"""
        if combo:
            if combo.currentIndex() == 0:
                return
            self.current_combo = combo
            combo_head = self.current_combo.model().item(0).text()
            process = self.is_action_process(combo_head)
            self._action(self.current_combo.currentText(),
                         process)

    def action_fuzzy(self, plugin_name):
        """The main entry point for triggering
        actions via the fuzzy search field."""
        process = True
        if plugin_name.startswith('-'):
            process = False
            plugin_name = plugin_name[1:]
        self._action(plugin_name, process)

    def _action(self, plugin_name, process=True):
        if not self._content:
            self._content = self.text_field.content
        if self.field.selected_data:
            self._content = self.field.selected_data
        if self._content:
            if not self.parent.plugins.plugin_available(plugin_name):
                LOGGER.warning('Plugin {} not found'.format(plugin_name))
                self.parent.show_error_msg('Plugin {} not found'.format(plugin_name))
                return
            else:
                self.plugin = self.parent.plugins.get_plugin_instance(plugin_name)
            data = None
            category = self.parent.plugins.get_category_for_plugin(self.plugin)
            if not category:
                LOGGER.error('Could not determine category for ' + self.plugin.name)
                return
            self.process = process
            process_gui_func = None
            unprocess_gui_func = None
            if process and 'process_gui' in vars(type(self.plugin)):
                # Check if the plugin class implements
                # process_gui() itself, and does not
                # inherit it from DeenPlugin.
                process_gui_func = getattr(self.plugin, 'process_gui', None)
            if not process and 'unprocess_gui' in vars(type(self.plugin)):
                # Check if the plugin class implements
                # unprocess_gui() itself, and does not
                # inherit it from DeenPlugin.
                unprocess_gui_func = getattr(self.plugin, 'unprocess_gui', None)
            if process_gui_func or unprocess_gui_func:
                if process and process_gui_func and \
                        callable(process_gui_func):
                    # For plugins that implement a process_gui() function
                    # that adds additional GUI elements.
                    data = self.plugin.process_gui(self.parent, self._content)
                elif not process and unprocess_gui_func and \
                        callable(unprocess_gui_func):
                    # For plugins that implement a unprocess_gui() function
                    # that adds additional GUI elements.
                    data = self.plugin.unprocess_gui(self.parent, self._content)
                else:
                    LOGGER.error('Invalid path')
                if not data:
                    # plugin.process_gui() returned nothing, so
                    # don't create a new widget.
                    if self.current_combo:
                        self.current_combo.setCurrentIndex(0)
                    if self.plugin.error:
                        self.set_error()
                        self.set_error_message(str(self.plugin.error))
                    return
                if self.plugin.error:
                    self.next.set_error()
                    self.next.set_error_message(str(self.plugin.error))
                self.next.content = data
                self.next.ui.current_plugin_label.setText('Plugin: ' + self.plugin.display_name)
                self.next.ui.current_plugin_label.show()
                # TODO: decide when focus should be set to next widget
                #self.next.set_field_focus()
                if not self.plugin.error:
                    self.next.clear_error_message()
            elif category == 'formatters':
                # Formatters format data in the current window (self)
                data = self.plugin.process(self._content)
                self.formatted_view = True
                self.text_field.setPlainText(
                    self.codec.toUnicode(data))
                self.text_field.moveCursor(QTextCursor.End)
                # After applying formatters the plugin
                # should be displayed, even in the root
                # widget.
                self.ui.current_plugin_label.setText('Plugin: ' + self.plugin.display_name)
                self.ui.current_plugin_label.show()
                if self.plugin.error:
                    self.set_error()
                    self.set_error_message(str(self.plugin.error))
                else:
                    self.clear_error_message()
            else:
                # All other plugins will write their output to a new
                # window (self.next).
                if process:
                    data = self.plugin.process(self._content)
                else:
                    data = self.plugin.unprocess(self._content)
                if self.plugin.error:
                    self.next.set_error()
                    self.next.set_error_message(str(self.plugin.error))
                if data:
                    self.next.content = data
                    self.next.ui.current_plugin_label.setText('Plugin: ' + self.plugin.display_name)
                    self.next.ui.current_plugin_label.show()
                    if not self.plugin.error:
                        self.next.clear_error_message()
                    # TODO: decide when focus should be set to next widget
                    #self.next.set_field_focus()
                else:
                    LOGGER.error('Plugin {} did not return any data'.format(self.plugin.name))
        if self.current_combo:
            self.current_combo.setCurrentIndex(0)
