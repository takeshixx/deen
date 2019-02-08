# -*- coding: utf-8 -*-

# Form implementation generated from reading ui file 'fuzzy_search_widget.ui'
#
# Created by: PyQt5 UI code generator 5.11.3
#
# WARNING! All changes made in this file will be lost!

from PyQt5 import QtCore, QtGui, QtWidgets

class Ui_DeenFuzzySearchWidget(object):
    def setupUi(self, DeenFuzzySearchWidget):
        DeenFuzzySearchWidget.setObjectName("DeenFuzzySearchWidget")
        DeenFuzzySearchWidget.resize(400, 146)
        self.fuzzy_search_buttons = QtWidgets.QDialogButtonBox(DeenFuzzySearchWidget)
        self.fuzzy_search_buttons.setGeometry(QtCore.QRect(50, 90, 341, 32))
        self.fuzzy_search_buttons.setOrientation(QtCore.Qt.Horizontal)
        self.fuzzy_search_buttons.setStandardButtons(QtWidgets.QDialogButtonBox.Cancel|QtWidgets.QDialogButtonBox.Ok)
        self.fuzzy_search_buttons.setObjectName("fuzzy_search_buttons")
        self.fuzzy_search_field = QtWidgets.QLineEdit(DeenFuzzySearchWidget)
        self.fuzzy_search_field.setGeometry(QtCore.QRect(10, 30, 381, 32))
        self.fuzzy_search_field.setObjectName("fuzzy_search_field")

        self.retranslateUi(DeenFuzzySearchWidget)
        self.fuzzy_search_buttons.accepted.connect(DeenFuzzySearchWidget.accept)
        self.fuzzy_search_buttons.rejected.connect(DeenFuzzySearchWidget.reject)
        QtCore.QMetaObject.connectSlotsByName(DeenFuzzySearchWidget)

    def retranslateUi(self, DeenFuzzySearchWidget):
        _translate = QtCore.QCoreApplication.translate
        DeenFuzzySearchWidget.setWindowTitle(_translate("DeenFuzzySearchWidget", "Search Action"))

