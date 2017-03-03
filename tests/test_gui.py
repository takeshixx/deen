import sys
import os
import unittest
import tempfile
import hashlib
import random
import string
import codecs
import base64

from PyQt5.QtWidgets import QApplication
from PyQt5.QtCore import Qt
from PyQt5.QtTest import QTest

from deen.constants import *
from deen.widgets.core import Deen

app = QApplication(sys.argv)


class TestGui(unittest.TestCase):
    def setUp(self):
        self.deen = Deen()
        # The list of sub-widgets
        self.widgets = self.deen.encoder_widget.widgets

    def _random_str(self, length=16):
        return ''.join(random.choice(string.ascii_uppercase + string.digits)
                       for _ in range(length))

    def _random_bytes(self, length=16):
        return os.urandom(length)

    def test_quit_app(self):
        self.deen.quit.trigger()

    def test_load_frome_file(self):
        test_file = '/bin/id'
        hasher = hashlib.new('sha256')
        with open(test_file, 'rb') as temp_file:
            hasher.update(temp_file.read())
        test_file_hash = hasher.digest()
        self.deen.load_from_file(file_name=test_file)
        hasher = hashlib.new('sha256')
        hasher.update(self.widgets[0].content)
        self.assertEqual(test_file_hash, hasher.digest())

    def test_save_to_file(self):
        data_str = self._random_str(1024)
        hasher = hashlib.new('sha256')
        hasher.update(data_str.encode())
        data_str_hash = hasher.digest()
        self.widgets[0].text_field.setPlainText(data_str)
        file_name = self._random_str(32)
        with tempfile.TemporaryDirectory() as tmpdirname:
            temp_file = tmpdirname + '/' + file_name
            self.widgets[0].save_content(file_name=temp_file)
            hasher = hashlib.new('sha256')
            with open(temp_file, 'rb') as temp_file:
                hasher.update(temp_file.read())
                temp_file_hash = hasher.digest()
        self.assertEqual(data_str_hash, temp_file_hash)

    def test_save_to_file_binary(self):
        test_file = '/bin/id'
        hasher = hashlib.new('sha256')
        with open(test_file, 'rb') as temp_file:
            hasher.update(temp_file.read())
        input_file_hash = hasher.digest()
        self.deen.load_from_file(file_name=test_file)
        file_name = self._random_str(32)
        with tempfile.TemporaryDirectory() as tmpdirname:
            temp_file = tmpdirname + '/' + file_name
            self.widgets[0].save_content(file_name=temp_file)
            hasher = hashlib.new('sha256')
            with open(temp_file, 'rb') as temp_file:
                hasher.update(temp_file.read())
                temp_file_hash = hasher.digest()
        self.assertEqual(input_file_hash, temp_file_hash)

    def test_empty_input(self):
        """Check if an error happens when any of the
        transformers or formatters are called without
        any input."""
        root_widget = self.widgets[0]
        for index in range(root_widget.encoding_combo.count()):
            root_widget.encoding_combo.setCurrentIndex(index)
        for index in range(root_widget.decoding_combo.count()):
            root_widget.decoding_combo.setCurrentIndex(index)
        for index in range(root_widget.compress_combo.count()):
            root_widget.compress_combo.setCurrentIndex(index)
        for index in range(root_widget.uncompress_combo.count()):
            root_widget.uncompress_combo.setCurrentIndex(index)
        for index in range(root_widget.hash_combo.count()):
            root_widget.hash_combo.setCurrentIndex(index)
        for index in range(root_widget.misc_combo.count()):
            root_widget.misc_combo.setCurrentIndex(index)
        for index in range(root_widget.format_combo.count()):
            root_widget.format_combo.setCurrentIndex(index)

    def test_encodings_hex(self):
        data_bytes = self._random_bytes(256)
        data_bytes_encoded = codecs.encode(data_bytes, 'hex')
        self.widgets[0].text_field.setPlainText(
            data_bytes_encoded.decode())
        self.widgets[0].decoding_combo.setCurrentText('Hex')
        self.assertEqual(data_bytes,
                         self.widgets[1].content)
        self.widgets[1].encoding_combo.setCurrentText('Hex')
        self.assertEqual(data_bytes_encoded,
                         self.widgets[2].content)

    def test_encodings_base64(self):
        data_bytes = self._random_bytes(256)
        data_bytes_encoded = base64.b64encode(data_bytes)
        self.widgets[0].text_field.setPlainText(
            data_bytes_encoded.decode())
        self.widgets[0].decoding_combo.setCurrentText('Base64')
        self.assertEqual(data_bytes,
                         self.widgets[1].content)
        self.widgets[1].encoding_combo.setCurrentText('Base64')
        self.assertEqual(data_bytes_encoded.strip(),
                         self.widgets[2].content)

    def test_hashing_str(self):
        data_str = self._random_str(256)
        hasher = hashlib.new('sha256')
        hasher.update(data_str.encode())
        self.widgets[0].text_field.setPlainText(data_str)
        self.assertEqual(data_str.encode(),
                         self.widgets[0].content)
        self.widgets[0].hash_combo.setCurrentText('SHA256')
        self.assertEqual(hasher.hexdigest().encode(),
                         self.widgets[1].content)
        self.widgets[1].decoding_combo.setCurrentText('Hex')
        self.assertEqual(hasher.digest(),
                         self.widgets[2].content)


if __name__ == '__main__':
    unittest.main()