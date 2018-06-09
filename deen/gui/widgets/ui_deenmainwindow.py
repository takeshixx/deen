# -*- coding: utf-8 -*-

# Form implementation generated from reading ui file 'main-window.ui'
#
# Created by: PyQt5 UI code generator 5.10.1
#
# WARNING! All changes made in this file will be lost!

from PyQt5 import QtCore, QtGui, QtWidgets

class Ui_MainWindow(object):
    def setupUi(self, MainWindow):
        MainWindow.setObjectName("MainWindow")
        MainWindow.resize(800, 600)
        self.centralwidget = QtWidgets.QWidget(MainWindow)
        self.centralwidget.setObjectName("centralwidget")
        self.verticalLayout = QtWidgets.QVBoxLayout(self.centralwidget)
        self.verticalLayout.setObjectName("verticalLayout")
        self.DeenMainWindow = QtWidgets.QScrollArea(self.centralwidget)
        self.DeenMainWindow.setEnabled(True)
        self.DeenMainWindow.setWidgetResizable(True)
        self.DeenMainWindow.setObjectName("DeenMainWindow")
        self.scrollAreaWidgetContents = QtWidgets.QWidget()
        self.scrollAreaWidgetContents.setGeometry(QtCore.QRect(0, 0, 784, 513))
        self.scrollAreaWidgetContents.setObjectName("scrollAreaWidgetContents")
        self.verticalLayout_2 = QtWidgets.QVBoxLayout(self.scrollAreaWidgetContents)
        self.verticalLayout_2.setObjectName("verticalLayout_2")
        self.encoder_widget_layout = QtWidgets.QVBoxLayout()
        self.encoder_widget_layout.setObjectName("encoder_widget_layout")
        self.verticalLayout_2.addLayout(self.encoder_widget_layout)
        self.DeenMainWindow.setWidget(self.scrollAreaWidgetContents)
        self.verticalLayout.addWidget(self.DeenMainWindow)
        MainWindow.setCentralWidget(self.centralwidget)
        self.menubar = QtWidgets.QMenuBar(MainWindow)
        self.menubar.setGeometry(QtCore.QRect(0, 0, 800, 39))
        self.menubar.setObjectName("menubar")
        self.menuFile = QtWidgets.QMenu(self.menubar)
        self.menuFile.setObjectName("menuFile")
        self.menuHelp = QtWidgets.QMenu(self.menubar)
        self.menuHelp.setObjectName("menuHelp")
        MainWindow.setMenuBar(self.menubar)
        self.statusbar = QtWidgets.QStatusBar(MainWindow)
        self.statusbar.setObjectName("statusbar")
        MainWindow.setStatusBar(self.statusbar)
        self.actionLoad_from_file = QtWidgets.QAction(MainWindow)
        self.actionLoad_from_file.setShortcut("")
        self.actionLoad_from_file.setObjectName("actionLoad_from_file")
        self.actionQuit = QtWidgets.QAction(MainWindow)
        self.actionQuit.setObjectName("actionQuit")
        self.actionAbout = QtWidgets.QAction(MainWindow)
        self.actionAbout.setObjectName("actionAbout")
        self.actionStatus_console = QtWidgets.QAction(MainWindow)
        self.actionStatus_console.setObjectName("actionStatus_console")
        self.menuFile.addAction(self.actionLoad_from_file)
        self.menuFile.addAction(self.actionQuit)
        self.menuHelp.addAction(self.actionAbout)
        self.menuHelp.addAction(self.actionStatus_console)
        self.menubar.addAction(self.menuFile.menuAction())
        self.menubar.addAction(self.menuHelp.menuAction())

        self.retranslateUi(MainWindow)
        QtCore.QMetaObject.connectSlotsByName(MainWindow)

    def retranslateUi(self, MainWindow):
        _translate = QtCore.QCoreApplication.translate
        MainWindow.setWindowTitle(_translate("MainWindow", "MainWindow"))
        self.menuFile.setTitle(_translate("MainWindow", "Fi&le"))
        self.menuHelp.setTitle(_translate("MainWindow", "Help"))
        self.actionLoad_from_file.setText(_translate("MainWindow", "Load from file"))
        self.actionQuit.setText(_translate("MainWindow", "Quit"))
        self.actionQuit.setShortcut(_translate("MainWindow", "F4"))
        self.actionAbout.setText(_translate("MainWindow", "About"))
        self.actionStatus_console.setText(_translate("MainWindow", "Status console"))
        self.actionStatus_console.setShortcut(_translate("MainWindow", "Ctrl+P"))

