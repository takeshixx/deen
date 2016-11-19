import sys
import logging
import pathlib

from PyQt5.QtWidgets import QApplication
from PyQt5.QtGui import QIcon

from deen.widgets.core import Deen

ICON = str(pathlib.PurePath(__file__).parent / 'icon.png')
LOGGER = logging.getLogger()
logging.basicConfig(format='[%(lineno)s - %(funcName)s() ] %(message)s')


def main():
    app = QApplication(sys.argv)
    ex = Deen()
    ex.setWindowIcon(QIcon(ICON))
    LOGGER.addHandler(ex.log)
    return app.exec_()
