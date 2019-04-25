import os
import string

try:
    from OpenSSL import crypto
except ImportError:
    crypto = None

from PyQt5.QtCore import QTextCodec, QRegularExpression, Qt
from PyQt5.QtGui import QTextCursor, QTextCharFormat, QBrush, QColor, QIcon
from PyQt5.QtWidgets import QWidget, QLabel, QApplication, QFileDialog, QTreeWidgetItem

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
        # Create references for tree view items
        self.plugin_tree_top_decode = self.ui.plugin_tree_view.topLevelItem(0)
        self.plugin_tree_top_encode = self.ui.plugin_tree_view.topLevelItem(1)
        self.plugin_tree_top_uncompress = self.ui.plugin_tree_view.topLevelItem(2)
        self.plugin_tree_top_compress = self.ui.plugin_tree_view.topLevelItem(3)
        self.plugin_tree_top_disassemble = self.ui.plugin_tree_view.topLevelItem(4)
        self.plugin_tree_top_assemble = self.ui.plugin_tree_view.topLevelItem(5)
        self.plugin_tree_top_hash = self.ui.plugin_tree_view.topLevelItem(6)
        self.plugin_tree_top_misc = self.ui.plugin_tree_view.topLevelItem(7)
        self.plugin_tree_top_format = self.ui.plugin_tree_view.topLevelItem(8)
        # Add tree items for the plugin tree view
        for encoding in [p[1] for p in self.parent.plugins.codecs
                if (not getattr(p[1], 'cmd_only', None) or
                    (getattr(p[1], 'cmd_only', None) and not p[1].cmd_only))]:
            self.plugin_tree_top_encode.addChild(QTreeWidgetItem([encoding.display_name]))
        for encoding in [p[1] for p in self.parent.plugins.codecs
                if (not getattr(p[1], 'cmd_only', None) or
                    (getattr(p[1], 'cmd_only', None) and not p[1].cmd_only))]:
            self.plugin_tree_top_decode.addChild(QTreeWidgetItem([encoding.display_name]))
        for compression in [p[1] for p in self.parent.plugins.compressions
                if (not getattr(p[1], 'cmd_only', None) or
                    (getattr(p[1], 'cmd_only', None) and not p[1].cmd_only))]:
            self.plugin_tree_top_compress.addChild(QTreeWidgetItem([compression.display_name]))
        for compression in [p[1] for p in self.parent.plugins.compressions
                if (not getattr(p[1], 'cmd_only', None) or
                    (getattr(p[1], 'cmd_only', None) and not p[1].cmd_only))]:
            self.plugin_tree_top_uncompress.addChild(QTreeWidgetItem([compression.display_name]))
        for assembly in [p[1] for p in self.parent.plugins.assemblies
                if (not getattr(p[1], 'cmd_only', None) or
                    (getattr(p[1], 'cmd_only', None) and not p[1].cmd_only))]:
            self.plugin_tree_top_assemble.addChild(QTreeWidgetItem([assembly.display_name]))
        for assembly in [p[1] for p in self.parent.plugins.assemblies
                if (not getattr(p[1], 'cmd_only', None) or
                    (getattr(p[1], 'cmd_only', None) and not p[1].cmd_only))]:
            self.plugin_tree_top_disassemble.addChild(QTreeWidgetItem([assembly.display_name]))
        for hashalg in [p[1] for p in self.parent.plugins.hashs
                if (not getattr(p[1], 'cmd_only', None) or
                    (getattr(p[1], 'cmd_only', None) and not p[1].cmd_only))]:
            self.plugin_tree_top_hash.addChild(QTreeWidgetItem([hashalg.display_name]))
        for misc in [p[1] for p in self.parent.plugins.misc
                if (not getattr(p[1], 'cmd_only', None) or
                    (getattr(p[1], 'cmd_only', None) and not p[1].cmd_only))]:
            self.plugin_tree_top_misc.addChild(QTreeWidgetItem([misc.display_name]))
        for formatter in [p[1] for p in self.parent.plugins.formatters
                if (not getattr(p[1], 'cmd_only', None) or
                    (getattr(p[1], 'cmd_only', None) and not p[1].cmd_only))]:
            self.plugin_tree_top_format.addChild(QTreeWidgetItem([formatter.display_name]))
        # Connect signal to tree view
        self.ui.plugin_tree_view.itemClicked.connect(self.action)
        self.ui.plugin_tree_view.currentItemChanged.connect(self.action)
        self.ui.plugin_tree_view.setMaximumWidth(self.ui.plugin_tree_view.columnWidth(0) * 2)
        # Hide top level items without any loaded plugins
        for i in range(self.ui.plugin_tree_view.topLevelItemCount()):
            tl_item = self.ui.plugin_tree_view.topLevelItem(i)
            if not tl_item:
                continue
            if tl_item.childCount() < 1:
                tl_item.setHidden(True)
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
        """A property that references
        the currently active field."""
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
        if not self.formatted_view:
            if self.printable:
                # TODO: is there another situation where this could fail?
                self._content = self.get_field_content()
        # Only proceed with live updates if self.plugin
        # is not a formatter plugin.
        if self.plugin and not self.formatted_view:
            self._action()
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
        """Reset any highlights set by the search
        function."""
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
        """A wrapper function that can be
        called to change to the text view
        widget."""
        self.hex_view = False
        self.text_field.setHidden(False)
        self.hex_field.setHidden(True)
        self.text_field.content = self._content

    def view_hex(self):
        """A wrapper function that can be
        called to change to the hex view
        widget."""
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
            widget.formatted_view = False
            widget.set_field_focus()
            widget.plugin = None
            # TODO: move to seperat wrapper function?
            widget.ui.plugin_tree_view.selectionModel().clearSelection()
        else:
            # Remove the current_combo of the previous
            # widget so that the last pick doesn't
            # stuck in the previous widget after deleting
            # one.
            self.previous.current_combo = None
            self.previous.set_field_focus()
            self.previous.plugin = None
            # TODO: move to seperat wrapper function?
            self.previous.ui.plugin_tree_view.selectionModel().clearSelection()
        self.remove_next_widgets(widget=widget)

    def update_length_field(self, widget=None):
        """Update the length field in the encoder widget
        with the count of bytes in the current widget."""
        widget = widget or self
        widget.ui.content_length_label.setText('Length: ' + str(len(widget.content)))

    def update_selection_field(self):
        """Update the selection field in the encoder widget
        with the count of selected bytes."""
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

    def get_tree_tl_label_for_plugin(self, plugin=None, process=None):
        """Return the top level item label for a plugin."""
        plugin = plugin or self.plugin
        process = process or self.process
        category = self.parent.plugins.get_category_for_plugin(plugin)
        if not category:
            LOGGER.error('Could not determine category for ' + plugin.name)
            return
        tl_label = ''
        if category == 'codecs':
            tl_label = 'Encode' if process else 'Decode'
        elif category == 'compressions':
            tl_label = 'Compress' if process else 'Uncompress'
        elif category == 'assemblies':
            tl_label = 'Assemble' if process else 'Disassemble'
        elif category == 'hashs':
            tl_label = 'Hash'
        elif category == 'misc':
            tl_label = 'Miscellaneous'
        elif category == 'formatters':
            tl_label = 'Format'
        else:
            LOGGER.warning('Could not determine top level label')
            return
        return tl_label

    def get_tree_item_for_plugin(self, plugin=None, process=None):
        """Return the tree view item of a plugin."""
        plugin = plugin or self.plugin
        process = process or self.process
        tl_label = self.get_tree_tl_label_for_plugin(plugin, process)
        for i in range(self.ui.plugin_tree_view.topLevelItemCount()):
            tl_item = self.ui.plugin_tree_view.topLevelItem(i)
            if not tl_item:
                continue
            # Find the top level item for the current label
            if tl_item.text(0) == tl_label:
                for j in range(tl_item.childCount()):
                    tl_child = tl_item.child(j)
                    if plugin.display_name == tl_child.text(0):
                        return tl_child

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

    def action(self, tree_item, **args):
        """The main function that will call plugins via the tree view."""
        if not tree_item.parent():
            return
        self.process = self.is_action_process(tree_item.parent().text(0))
        self.plugin = self.parent.plugins.get_plugin_instance(tree_item.text(0))
        self._action()

    def action_fuzzy(self, plugin_name):
        """The main entry point for triggering
        actions via the fuzzy search field. This
        function determines if the current action
        should process or unprocess data. It then
        tries to find appropriate plugin and select
        it in the plugin tree view."""
        self.process = True
        if plugin_name.startswith('-'):
            self.process = False
            plugin_name = plugin_name[1:]
        if not self._content:
            return
        if self.parent.plugins.plugin_available(plugin_name):
            self.plugin = self.parent.plugins.get_plugin_instance(plugin_name)
        else:
            LOGGER.warning('Plugin {} not found'.format(plugin_name))
            self.parent.show_error_msg('Plugin {} not found'.format(plugin_name))
            return
        tl_label = self.get_tree_tl_label_for_plugin()
        # Clear all selected items first
        for i in self.ui.plugin_tree_view.selectedItems():
            i.setSelected(False)
        for i in range(self.ui.plugin_tree_view.topLevelItemCount()):
            tl_item = self.ui.plugin_tree_view.topLevelItem(i)
            if not tl_item:
                continue
            # Find the top level item for the current label
            if tl_item.text(0) == tl_label:
                if not tl_item.isExpanded():
                    tl_item.setExpanded(True)
                for j in range(tl_item.childCount()):
                    tl_child = tl_item.child(j)
                    if self.plugin.display_name == tl_child.text(0):
                        tl_child.setSelected(True)
                        self.ui.plugin_tree_view.scrollToItem(tl_child)
            else:
                # Collapse all other top level items
                if tl_item.isExpanded():
                    tl_item.setExpanded(False)
        self._action()

    def _action(self, process=None):
        if process != None:
            self.process = process
        # Update self._content with data from
        # the current field.
        self._content = self.field.content
        if self.field.selected_data:
            self._content = self.field.selected_data
        if self._content and self.plugin:
            # Reset plugin errors
            self.plugin.error = None
            data = None
            category = self.parent.plugins.get_category_for_plugin(self.plugin)
            if not category:
                LOGGER.error('Could not determine category for ' + self.plugin.name)
                return
            process_gui_func = None
            unprocess_gui_func = None
            if self.process and 'process_gui' in vars(type(self.plugin)):
                # Check if the plugin class implements
                # process_gui() itself, and does not
                # inherit it from DeenPlugin.
                process_gui_func = getattr(self.plugin, 'process_gui', None)
            if not self.process and 'unprocess_gui' in vars(type(self.plugin)):
                # Check if the plugin class implements
                # unprocess_gui() itself, and does not
                # inherit it from DeenPlugin.
                unprocess_gui_func = getattr(self.plugin, 'unprocess_gui', None)
            if process_gui_func or unprocess_gui_func:
                if self.process and process_gui_func and \
                        callable(process_gui_func):
                    # For plugins that implement a process_gui() function
                    # that adds additional GUI elements.
                    data = self.plugin.process_gui(self.parent, self._content)
                elif not self.process and unprocess_gui_func and \
                        callable(unprocess_gui_func):
                    # For plugins that implement a unprocess_gui() function
                    # that adds additional GUI elements.
                    data = self.plugin.unprocess_gui(self.parent, self._content)
                else:
                    LOGGER.error('Invalid path')
                if not data:
                    # plugin.process_gui() returned nothing, so
                    # don't create a new widget.
                    if self.plugin.error:
                        self.set_error()
                        self.set_error_message(str(self.plugin.error))
                    return
                if self.plugin.error:
                    self.next.set_error()
                    self.next.set_error_message(str(self.plugin.error))
                self.next.content = data
                # TODO: decide when focus should be set to next widget
                #self.next.set_field_focus()
                if not self.plugin.error:
                    self.next.clear_error_message()
            elif category == 'formatters':
                # Formatters format data in the current window (self)
                data = self.plugin.process(self._content)
                self.formatted_view = True
                if data:
                    self.text_field.setPlainText(
                        self.codec.toUnicode(data))
                    self.text_field.moveCursor(QTextCursor.End)
                if self.plugin.error:
                    self.set_error()
                    self.set_error_message(str(self.plugin.error))
                else:
                    self.clear_error_message()
            else:
                # All other plugins will write their output to a new
                # window (self.next).
                if self.process:
                    data = self.plugin.process(self._content)
                else:
                    data = self.plugin.unprocess(self._content)
                if self.plugin.error:
                    self.next.set_error()
                    self.next.set_error_message(str(self.plugin.error))
                if data:
                    self.next.content = data
                    if not self.plugin.error:
                        self.next.clear_error_message()
                else:
                    LOGGER.error('Plugin {} did not return any data'.format(self.plugin.name))
        # Ensure that the selected plugins are visible
        # in all widget plugin tree views.
        for w in self.parent.widgets:
            selected = w.ui.plugin_tree_view.selectedItems()
            if selected:
                w.ui.plugin_tree_view.scrollToItem(selected[0])
