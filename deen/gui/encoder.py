import os
import logging
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

MEDIA_PATH = os.path.dirname(os.path.abspath(__file__)) + '/../media/'
LOGGER = logging.getLogger(__name__)


class DeenEncoderWidget(QWidget):
    """For each plugin operation Deen will create
    an instance of this class to represent an
    action. self.parent in instances of this
    class should point to the main window (an
    instance of DeenGui)."""
    def __init__(self, parent, readonly=False, enable_actions=True):
        super(DeenEncoderWidget, self).__init__(parent)
        self.ui = Ui_DeenEncoderWidget()
        self.ui.setupUi(self)
        self.parent = parent
        self.readonly = readonly
        self.current_pick = None
        self.current_combo = None
        self._content = bytearray()
        self.formatted_view = False
        self.codec = QTextCodec.codecForName('UTF-8')
        self.hex_view = False
        # Assign custom widgets for text_field and hex_field.
        # TODO: create proper widgets for text and hex widget.
        self.text_field = TextViewWidget(self, readonly=self.readonly)
        self.text_field.textChanged.connect(self.field_content_changed)
        self.hex_field = HexViewWidget(read_only=self.readonly, parent=self)
        self.hex_field.setHidden(True)
        self.hex_field.bytesChanged.connect(self.field_content_changed)
        self.ui.content_area_layout.addWidget(self.text_field)
        self.ui.content_area_layout.addWidget(self.hex_field)
        # Configure widget elements
        self.ui.toggle_text_view.setChecked(True)
        self.ui.toggle_text_view.toggled.connect(self.view_text)
        self.ui.toggle_hex_view.setChecked(False)
        self.ui.toggle_hex_view.toggled.connect(self.view_hex)
        # Set icons based on current theme darkness. Assume dark theme
        # if background color is below 50% brightness.
        if self.palette().color(self.backgroundRole()).value() < 128:
            self.ui.clear_button.setIcon(QIcon(MEDIA_PATH + 'dark/edit-clear.svg'))
            self.ui.save_button.setIcon(QIcon(MEDIA_PATH + 'dark/document-save-as.svg'))
            self.ui.copy_to_clipboard_button.setIcon(QIcon(MEDIA_PATH + 'dark/edit-copy.svg'))
            self.ui.move_to_root_button.setIcon(QIcon(MEDIA_PATH + 'dark/go-up.svg'))
        else:
            self.ui.clear_button.setIcon(QIcon(MEDIA_PATH + 'edit-clear.svg'))
            self.ui.save_button.setIcon(QIcon(MEDIA_PATH + 'document-save-as.svg'))
            self.ui.copy_to_clipboard_button.setIcon(QIcon(MEDIA_PATH + 'edit-copy.svg'))
            self.ui.move_to_root_button.setIcon(QIcon(MEDIA_PATH + 'go-up.svg'))
        # Add connections for the encoder buttons.
        self.ui.clear_button.clicked.connect(self.clear_content)
        self.ui.save_button.clicked.connect(self.save_content)
        self.ui.copy_to_clipboard_button.clicked.connect(self.copy_to_clipboard)
        self.ui.move_to_root_button.clicked.connect(self.move_content_to_root)
        self.ui.hide_side_menu.clicked.connect(self.toggle_side_menu_visibility)
        self.ui.hide_search_box.clicked.connect(self.toggle_search_box_visibility)
        # Update labels with proper values
        self.update_length_field(self)
        self.update_readonly_field(self)
        # The root widget will not have a plugin label and no "Move to root" button.
        self.ui.current_plugin_label.hide()
        if not self.readonly:
            self.ui.move_to_root_button.hide()
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
        if self.hex_view:
            self.hex_field.content = self._content
        elif not self.hex_view and \
                not all(chr(c) in string.printable for c in self._content):
            # If there are non-printable characters,
            # switch to hex view.
            self.text_field.setReadOnly(True)
            self.ui.toggle_hex_view.setChecked(True)
        else:
            # Prevent the field from overwriting itself with invalid
            # characters.
            if not all(chr(c) in string.printable for c in self._content):
                self.text_field.setReadOnly(True)
            self.text_field.setPlainText(self.codec.toUnicode(self._content))
            self.text_field.moveCursor(QTextCursor.End)

    def has_previous(self):
        """Determine if the current widget is the root widget."""
        return True if self.parent.widgets[0] != self else False

    def has_next(self):
        """Determine if there are already new widgets created."""
        return True if self.parent.widgets[-1] != self else False

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
            w = DeenEncoderWidget(self.parent, readonly=True, enable_actions=False)
            self.parent.widgets.append(w)
            self.parent.ui.encoder_widget_layout.addWidget(w)
            return w
        for i, w in enumerate(self.parent.widgets):
            if w == self:
                return self.parent.widgets[i + 1]

    def toggle_side_menu_visibility(self):
        """Calling this function will either
        hide or show the sidebar. Hiding the
        sidebar is a convenient way to make
        larger content more readable."""
        if self.ui.side_menu.isVisible():
            self.ui.side_menu.hide()
        else:
            self.ui.side_menu.show()

    def toggle_search_box_visibility(self):
        """Calling this function will either
        hide or show the search box. By default
        it is hidden and can be made visible
        with the Search button."""
        if self.ui.search_group.isVisible():
            self.ui.search_group.hide()
        else:
            self.ui.search_group.show()

    def field_content_changed(self):
        """The event handler for the textChanged event of the
        current widget. This will be called whenever the text
        of the QTextEdit() will be changed. Whatever will be
        executed here will most likely differ if it will be
        applied on a root widget or any following widget."""
        if self.has_next() and not self.text_field.isReadOnly() \
                and not self.formatted_view:
            # If widget count is greater then two,
            # remove all widgets after the second.
            self.remove_next_widgets(offset=2)
        elif self.has_next() and self.text_field.isReadOnly():
            # If the current widget is not the root
            # but there is at least one next widget.
            self.next.content = self.content
        if not self.text_field.isReadOnly() and not self.formatted_view:
            if not self.hex_view:
                self._content = bytearray(self.text_field.toPlainText(), 'utf8')
            else:
                self._content = self.hex_field.content
        if not self.formatted_view:
            self.update_length_field(self)
            self.update_readonly_field(self)
            if (self.hex_field.hasFocus() or self.text_field.hasFocus()) \
                    and self.current_pick:
                self.action()

    def search_highlight(self):
        """The function that will be called whenever the
        search area is submitted. It will search within
        the text_field and highlights matches."""
        cursor = self.text_field.textCursor()
        format = QTextCharFormat()
        format.setBackground(QBrush(QColor('white')))
        cursor.select(QTextCursor.Document)
        cursor.mergeCharFormat(format)
        cursor.clearSelection()
        format.setBackground(QBrush(QColor('yellow')))
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
        format = QTextCharFormat()
        format.setBackground(QBrush(QColor('white')))
        cursor.mergeCharFormat(format)
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
        widget.text_field.setStyleSheet('border: 1px solid lightgrey;')

    def view_text(self):
        self.hex_view = False
        self.text_field.setHidden(False)
        self.hex_field.setHidden(True)
        if self._content:
            self.text_field.setPlainText(self.codec.toUnicode(self._content))

    def view_hex(self):
        self.hex_view = True
        self.text_field.setHidden(True)
        self.hex_field.setHidden(False)
        self.hex_field._read_only = self.text_field.isReadOnly()
        if not self._content:
            self._content = bytearray(self.text_field.toPlainText(), 'utf8')
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
            widget.update_length_field(self)
            widget.ui.current_plugin_label.clear()
            widget.ui.current_plugin_label.hide()
            widget.text_field.setReadOnly(False)
            widget.update_readonly_field(self)
            widget.current_pick = None
            widget.formatted_view = False
        else:
            # Remove the current_combo and current_pick
            # of the previous widget so that the last
            # pick doesn't stuck in the previous widget
            # after deleting one.
            self.previous.current_combo = None
            self.previous.current_pick = None
        self.remove_next_widgets(widget=widget)

    def copy_to_clipboard(self):
        if not self._content:
            return
        try:
            content = self._content.decode('utf8')
        except UnicodeDecodeError as e:
            LOGGER.error(e)
            LOGGER.error('Cannot copy non-ASCII content to clipboard')
            return
        clipboard = QApplication.clipboard()
        clipboard.setText(content)

    def save_content(self, file_name=None):
        """Save the content of the current widget
        to a file."""
        if not self._content:
            return
        fd = QFileDialog(self)
        if file_name:
            name = file_name
        else:
            name = fd.getSaveFileName(fd, 'Save File')
        if not name or not name[0]:
            return
        if isinstance(name, tuple):
            name = name[0]
        with open(name, 'wb') as file:
            current_plugin = self.parent.plugins.get_plugin_by_display_name(
                    self.ui.current_plugin_label.text().replace('Plugin: ', ''))
            if self.parent.plugins.is_plugin_in_category(current_plugin, 'formatters'):
                # Formatters alter data inplace, so we have to write the
                # data that is currently displayed into the outfile.
                file.write(bytearray(self.text_field.toPlainText(), 'utf8'))
            else:
                file.write(self._content)

    def move_content_to_root(self):
        """Moves the content of the current widget
        to the root widget and removes all widgets
        after the root widget."""
        content = self._content
        self.clear_content(self.parent.widgets[0])
        self.parent.widgets[0].content = content

    def update_length_field(self, widget):
        widget.ui.content_length_label.setText('Length: ' + str(len(widget.content)))

    def update_readonly_field(self, widget):
        widget.ui.widget_mode_label.setText('Mode: Read' if widget.text_field.isReadOnly() else 'Mode: Read/Write')

    def update_vertical_scroll_range(self, min, max):
        """Update the scroll maximum of the main window scroll
        are in order to automatically jump to newly created
        encoder widgets."""
        sb = self.parent.ui.DeenMainWindow.verticalScrollBar()
        sb.setValue(max)

    def update_horizontal_scroll_range(self, min, max):
        """Update the scroll maximum of the main window scroll
        are in order to automatically jump to newly created
        encoder widgets."""
        sb = self.parent.ui.DeenMainWindow.horizontalScrollBar()
        sb.setValue(max)

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
        called."""
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
        if not self._content:
            self._content = bytearray(self.text_field.toPlainText(), 'utf8')
        cursor = self.text_field.textCursor()
        selected_data = cursor.selectedText()
        if selected_data:
            self._content = bytearray(selected_data, 'utf8')
        if combo:
            if combo.currentIndex() == 0:
                return
            self.current_combo = combo
            self.current_pick = combo.currentText()
        if self._content:
            if not self.parent.plugins.plugin_available(self.current_pick):
                LOGGER.warning('Pluging {} not found'.format(self.current_pick))
                return
            else:
                plugin = self.parent.plugins.get_plugin_instance(self.current_pick)
            data = None
            combo_choice = self.current_combo.model().item(0).text()
            process_gui_func = None
            unprocess_gui_func = None
            if self.is_action_process(combo_choice) and \
                    'process_gui' in vars(type(plugin)):
                # Check if the plugin class implements
                # process_gui() itself, and does not
                # inherit it from DeenPlugin.
                process_gui_func = getattr(plugin, 'process_gui', None)
            if not self.is_action_process(combo_choice) and \
                    'unprocess_gui' in vars(type(plugin)):
                # Check if the plugin class implements
                # unprocess_gui() itself, and does not
                # inherit it from DeenPlugin.
                unprocess_gui_func = getattr(plugin, 'unprocess_gui', None)
            if process_gui_func or unprocess_gui_func:
                print(combo_choice)
                if self.is_action_process(combo_choice) and \
                        process_gui_func and callable(process_gui_func):
                    # For plugins that implement a process_gui() function
                    # that adds additional GUI elements.
                    data = plugin.process_gui(self.parent, self._content)
                elif not self.is_action_process(combo_choice) and \
                        unprocess_gui_func and callable(unprocess_gui_func):
                    # For plugins that implement a unprocess_gui() function
                    # that adds additional GUI elements.
                    data = plugin.unprocess_gui(self.parent, self._content)
                else:
                    print('Invalid path')
                if not data:
                    # plugin.process_gui() returned nothing, so
                    # don't create a new widget.
                    self.current_pick = None
                    if self.current_combo:
                        self.current_combo.setCurrentIndex(0)
                    return
                if plugin.error:
                    LOGGER.error(plugin.error)
                    self.next.set_error()
                    self.next.set_error_message(str(plugin.error))
                self.next.content = data
                if self.next.text_field.isReadOnly() and self.current_pick:
                    self.next.ui.current_plugin_label.setText('Plugin: ' + self.current_pick)
                    self.next.ui.current_plugin_label.show()
                if not plugin.error:
                    self.next.clear_error_message()
            elif combo_choice == 'Format':
                # Formatters format data in the current window (self)
                data = plugin.process(self._content)
                self.formatted_view = True
                self.text_field.setPlainText(
                    self.codec.toUnicode(data))
                self.text_field.moveCursor(QTextCursor.End)
                # After applying formatters the plugin
                # should be displayed, even in the root
                # widget.
                self.ui.current_plugin_label.setText('Plugin: ' + self.current_pick)
                self.ui.current_plugin_label.show()
                if plugin.error:
                    LOGGER.error(plugin.error)
                    self.set_error()
                    self.set_error_message(str(plugin.error))
                else:
                    self.clear_error_message()
            else:
                # All other plugins will write their output to a new
                # window (self.next).
                if self.is_action_process(combo_choice):
                    data = plugin.process(self._content)
                else:
                    data = plugin.unprocess(self._content)
                if plugin.error:
                    LOGGER.error(plugin.error)
                    self.next.set_error()
                    self.next.set_error_message(str(plugin.error))
                if data:
                    self.next.content = data
                    if self.next.text_field.isReadOnly() and self.current_pick:
                        self.next.ui.current_plugin_label.setText('Plugin: ' + self.current_pick)
                        self.next.ui.current_plugin_label.show()
                    if not plugin.error:
                        self.next.clear_error_message()
                else:
                    LOGGER.error('Plugin {} did not return any data'.format(plugin.name))
        else:
            self.current_pick = None
        if self.current_combo:
            self.current_combo.setCurrentIndex(0)
