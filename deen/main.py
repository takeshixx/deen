import sys
import logging
import os.path

from PyQt5.QtWidgets import QApplication
from PyQt5.QtGui import QIcon

from deen.widgets.core import Deen

ICON = os.path.dirname(os.path.realpath(__file__)) + '/icon.png'
LOGGER = logging.getLogger()
logging.basicConfig(format='[%(lineno)s - %(funcName)s() ] %(message)s')


def main():
    app = QApplication(sys.argv)
    ex = Deen()
    ex.setWindowIcon(QIcon(ICON))
    LOGGER.addHandler(ex.log)
    return app.exec_()
