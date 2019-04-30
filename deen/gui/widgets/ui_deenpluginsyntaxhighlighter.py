# -*- coding: utf-8 -*-

# Form implementation generated from reading ui file 'plugin-syntaxhighlighter.ui'
#
# Created by: PyQt5 UI code generator 5.10.1
#
# WARNING! All changes made in this file will be lost!

from PyQt5 import QtCore, QtGui, QtWidgets

class Ui_SyntaxHighlighterGui(object):
    def setupUi(self, SyntaxHighlighterGui):
        SyntaxHighlighterGui.setObjectName("SyntaxHighlighterGui")
        SyntaxHighlighterGui.resize(400, 218)
        self.buttonBox = QtWidgets.QDialogButtonBox(SyntaxHighlighterGui)
        self.buttonBox.setGeometry(QtCore.QRect(30, 170, 341, 32))
        self.buttonBox.setOrientation(QtCore.Qt.Horizontal)
        self.buttonBox.setStandardButtons(QtWidgets.QDialogButtonBox.Cancel|QtWidgets.QDialogButtonBox.Ok)
        self.buttonBox.setObjectName("buttonBox")
        self.gridLayoutWidget = QtWidgets.QWidget(SyntaxHighlighterGui)
        self.gridLayoutWidget.setGeometry(QtCore.QRect(20, 10, 361, 141))
        self.gridLayoutWidget.setObjectName("gridLayoutWidget")
        self.gridLayout = QtWidgets.QGridLayout(self.gridLayoutWidget)
        self.gridLayout.setContentsMargins(0, 0, 0, 0)
        self.gridLayout.setObjectName("gridLayout")
        self.lexer_combo = QtWidgets.QComboBox(self.gridLayoutWidget)
        self.lexer_combo.setObjectName("lexer_combo")
        self.gridLayout.addWidget(self.lexer_combo, 0, 1, 1, 1)
        self.formatter_combo = QtWidgets.QComboBox(self.gridLayoutWidget)
        self.formatter_combo.setObjectName("formatter_combo")
        self.gridLayout.addWidget(self.formatter_combo, 1, 1, 1, 1)
        self.label = QtWidgets.QLabel(self.gridLayoutWidget)
        self.label.setObjectName("label")
        self.gridLayout.addWidget(self.label, 0, 0, 1, 1)
        self.label_2 = QtWidgets.QLabel(self.gridLayoutWidget)
        self.label_2.setObjectName("label_2")
        self.gridLayout.addWidget(self.label_2, 1, 0, 1, 1)

        self.retranslateUi(SyntaxHighlighterGui)
        self.buttonBox.accepted.connect(SyntaxHighlighterGui.accept)
        self.buttonBox.rejected.connect(SyntaxHighlighterGui.reject)
        QtCore.QMetaObject.connectSlotsByName(SyntaxHighlighterGui)

    def retranslateUi(self, SyntaxHighlighterGui):
        _translate = QtCore.QCoreApplication.translate
        SyntaxHighlighterGui.setWindowTitle(_translate("SyntaxHighlighterGui", "Syntax Highlighter"))
        self.label.setText(_translate("SyntaxHighlighterGui", "Lexer"))
        self.label_2.setText(_translate("SyntaxHighlighterGui", "Formatter"))

