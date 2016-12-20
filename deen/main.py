import sys
import logging
import os.path
import argparse

from PyQt5.QtWidgets import QApplication
from PyQt5.QtGui import QIcon

from deen.widgets.core import Deen

ICON = os.path.dirname(os.path.abspath(__file__)) + '/icon.png'
LOGGER = logging.getLogger()
logging.basicConfig(format='[%(lineno)s - %(funcName)s() ] %(message)s')

ARGS = argparse.ArgumentParser()
ARGS.add_argument('infile', nargs='?', default=None)
ARGS.add_argument('outfile', nargs='?', default=None)


def main():
    args = ARGS.parse_args()
    content = None
    if args.infile:
        if args.infile == '-':
            try:
                stdin = sys.stdin.buffer
            except AttributeError:
                stdin = sys.stdin
            content = stdin.read()
        else:
            with open(args.infile, 'rb') as f:
                content = f.read()
    app = QApplication(sys.argv)
    ex = Deen()
    if content:
        ex.encoder_widget.set_root_content(content)
    ex.setWindowIcon(QIcon(ICON))
    LOGGER.addHandler(ex.log)
    return app.exec_()
