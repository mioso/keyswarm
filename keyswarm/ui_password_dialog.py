from PySide2.QtWidgets import (QMainWindow, QApplication, QFrame, QHBoxLayout, QTextEdit, QAction, QDialog,
                               QLineEdit, QPushButton, QVBoxLayout, QGroupBox, QGridLayout, QLabel)
from .ui_recipients import RecipientList
from .ui_filesystem_tree import PassUiFileSystemTree
from os import path
from pathlib import Path
from .pass_file_system import create_password_file, create_folder, get_config
from .gpg_handler import write_gpg_id_file, recursive_reencrypt
from .pass_file_format_parser import PassFile
from .generate_passwords import random_password

import logging


class PasswordDialog(QDialog):
    """
    An add password Dialog
    """
    def __init__(self, optional_fields=[]):
        # Setup Dialog Window
        QDialog.__init__(self)
        self.setMinimumHeight(360)
        self.setMinimumWidth(480)
        self.setWindowTitle('Create New Password')
        self.grid_layout = QGridLayout()
        self.setLayout(self.grid_layout)

        # Setup Labels, Inputs and Buttons
        name_label = QLabel('Name:')
        pass_label = QLabel('Password:')
        pass_confirm_label = QLabel('Confirm:')
        self.password_name_input = QLineEdit()
        self.grid_layout.addWidget(name_label, 0, 0)
        self.grid_layout.addWidget(self.password_name_input, 0, 1)
        self.password_input = QLineEdit()
        self.password_input.setEchoMode(QLineEdit.EchoMode.Password)
        self.pass_confirm_input = QLineEdit()
        self.pass_confirm_input.setEchoMode(QLineEdit.EchoMode.Password)
        view_password_button = QPushButton('&View')
        view_password_button.clicked.connect(self.toggle_password_visibility)
        self.layout().addWidget(view_password_button, 1, 2)
        generate_password_button = QPushButton('&Generate')
        generate_password_button.clicked.connect(self.generate_password)
        self.layout().addWidget(generate_password_button, 2, 2)
        self.grid_layout.addWidget(pass_label, 1, 0)
        self.grid_layout.addWidget(self.password_input, 1, 1)
        self.grid_layout.addWidget(pass_confirm_label, 2, 0)
        self.grid_layout.addWidget(self.pass_confirm_input, 2, 1)

        # Setup Optional fields
        self.optional_fields = list()
        for field in optional_fields:
            self.__add_optional_field__(field)
        comment_label = QLabel('comments')
        self.comment_field = QTextEdit()
        self.layout().addWidget(comment_label, self.layout().rowCount() + 1, 0)
        self.layout().addWidget(self.comment_field, self.layout().rowCount(), 1)

        # Setup Confirm Button
        self.confirm_button = QPushButton()
        self.confirm_button.setShortcut('Return')
        self.confirm_button.setText('&OK')
        self.grid_layout.addWidget(self.confirm_button, self.grid_layout.rowCount() + 1, 1)
        self.confirm_button.clicked.connect(self.confirm)

    def toggle_password_visibility(self):
        if self.password_input.echoMode() == QLineEdit.EchoMode.Password:
            self.password_input.setEchoMode(QLineEdit.EchoMode.Normal)
            self.pass_confirm_input.setEchoMode(QLineEdit.EchoMode.Normal)
        else:
            self.password_input.setEchoMode(QLineEdit.EchoMode.Password)
            self.pass_confirm_input.setEchoMode(QLineEdit.EchoMode.Password)

    def generate_password(self):
        logger = logging.getLogger(__name__)
        password = random_password()
        logger.debug('PassworfDialog.generate_password: password.__class__: %s', password.__class__)
        logger.debug('PasswordDialog.generate_password: len(password): %s', len(password))
        self.password_input.setText(password)
        self.pass_confirm_input.setText(password)

    def confirm(self):
        """
        confirms the add password dialog
        :return: None
        """
        logger = logging.getLogger(__name__)
        if self.password_input.text() != self.pass_confirm_input.text():
            logger.debug('PasswordDialog.confirm: password mismatch')
            return
        if self.password_name_input.text() == '':
            logger.debug('PasswordDialog.confirm: empty name')
            return
        logger.debug('PasswordDialog.confirm: accept')
        self.accept()

    def __add_optional_field__(self, name):
        """
        adds an optional field to the Dialog
        :param name:
        :return:
        """
        next_row = self.grid_layout.rowCount() + 1
        label = QLabel('{name}:'.format(name=name))
        input_field = QLineEdit()
        self.grid_layout.addWidget(label, next_row, 0)
        self.grid_layout.addWidget(input_field, next_row, 1)
        self.optional_fields.append((label, input_field))

    def to_pass_file(self):
        pass_file = PassFile()
        pass_file.password = self.password_input.text()
        for label_field, input_field in self.optional_fields:
            if input_field.text() is not None and input_field.text() != '':
                pass_file.attributes.append((label_field.text().replace(':', ''), input_field.text()))
        pass_file.comments = self.comment_field.toPlainText()
        return pass_file

    def from_pass_file(pass_file):
        dialog = PasswordDialog(pass_file.attributes)
        dialog.setWindowTitle('Edit Password')
        dialog.password_name_input.setText(pass_file.name)
        dialog.password_input.setText(pass_file.password)
        dialog.pass_confirm_input.setText(pass_file.password)
        dialog.comment_field.setText(pass_file.comments)
        return dialog
