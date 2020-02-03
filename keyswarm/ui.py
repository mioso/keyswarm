from PySide2.QtWidgets import (QMainWindow, QApplication, QFrame, QHBoxLayout, QTextEdit, QAction, QDialog,
                               QLineEdit, QPushButton, QVBoxLayout, QGroupBox, QGridLayout, QLabel)
from .ui_recipients import RecipientList
from .ui_filesystem_tree import PassUiFileSystemTree
from os import path
from pathlib import Path
from .pass_file_system import create_password_file, create_folder, get_config
from .gpg_handler import write_gpg_id_file, recursive_reencrypt
from .pass_file_format_parser import PassFile
from .ui_password_view import PasswordView
from .generate_passwords import random_password

import logging


class MainWindow(QMainWindow):
    """
    Multipass Main Window
    """
    def __init__(self):
        QMainWindow.__init__(self)
        self.config = get_config(path.join(Path.home(), '.password-store', '.cfg'))
        self.tree = PassUiFileSystemTree(path.join(Path.home(), '.password-store'))
        self.frame = QFrame()
        self.setCentralWidget(self.frame)
        self.horizontal_box_layout = QHBoxLayout(self.frame)
        self.horizontal_box_layout.addWidget(self.tree)
        self.password_browser_group = PasswordView()
        self.horizontal_box_layout.addWidget(self.password_browser_group)
        self.tree.itemSelectionChanged.connect(self.tree.on_item_selection_changed)
        self.user_list_group = QGroupBox('Authorized Keys')
        self.user_list_layout = QVBoxLayout()
        self.user_list_group.setLayout(self.user_list_layout)
        self.user_list = RecipientList()
        self.user_list_layout.addWidget(self.user_list)
        self.user_list_save_button = QPushButton('save')
        self.user_list_save_button.clicked.connect(self.reencrypt_files)
        self.user_list_layout.addWidget(self.user_list_save_button)
        self.horizontal_box_layout.addWidget(self.user_list_group)
        self.user_list_group.hide()
        self.tool_bar = self.addToolBar('tools')
        self.tool_bar.setMovable(False)
        exit_action = QAction('Exit', self)
        exit_action.setShortcut('Ctrl+q')
        exit_action.triggered.connect(self.close)
        self.tool_bar.addAction(exit_action)
        add_folder_action = QAction('Add &Folder', self)
        add_folder_action.setShortcut('Ctrl+f')
        add_folder_action.triggered.connect(self.add_folder)
        self.tool_bar.addAction(add_folder_action)
        add_pass_action = QAction('Add &Password', self)
        add_pass_action.setShortcut('Ctrl+p')
        add_pass_action.triggered.connect(self.add_password)
        self.tool_bar.addAction(add_pass_action)

    def add_folder(self):
        """
        Adds a sub folder to the current folder.
        :return: None
        """
        folder_dialog = FolderDialog()
        if folder_dialog.exec_():
            folder_path = self.tree.currentItem().file_system_path
            folder_name = folder_dialog.folder_name_input.text()
            create_folder(folder_path, folder_name)
            self.tree.refresh_tree()

    def add_password(self):
        """
        Displays an add password dialog.
        :return: None
        """
        optional_fields = list()
        if 'attributes' in self.config:
            optional_fields = list(self.config['attributes'])
        pass_dialog = PasswordDialog(optional_fields=optional_fields)
        if pass_dialog.exec_():
            current_item_parent = self.tree.currentItem().file_system_path
            current_item_name = self.tree.currentItem().name
            current_item_is_dir = self.tree.currentItem().isdir
            if current_item_is_dir:
                password_dir = path.join(current_item_parent, current_item_name)
            else:
                password_dir = current_item_parent
            password_file = PassFile()
            password_file.password = pass_dialog.password_input.text()
            for label_field, input_field in pass_dialog.optional_fields:
                if input_field.text() != '' and input_field.text() is not None:
                    password_file.attributes.append((label_field.text().replace(':', ''), input_field.text()))
            password_file.comments = pass_dialog.comment_field.toPlainText()
            create_password_file(path_to_folder=password_dir,
                                 name=pass_dialog.password_name_input.text(),
                                 password_file=password_file)
            self.tree.refresh_tree()

    def reencrypt_files(self):
        """
        :return: None
        """
        list_of_keys = self.user_list.get_checked_item_names()
        folder_path = path.join(self.tree.currentItem().file_system_path, self.tree.currentItem().name)
        gpg_id_path = path.join(folder_path, '.gpg-id')
        write_gpg_id_file(gpg_id_path, list_of_keys)
        recursive_reencrypt(folder_path, list_of_keys)


class FolderDialog(QDialog):
    """
    An add Folder Dialog.
    """
    def __init__(self):
        QDialog.__init__(self)
        self.setFixedHeight(120)
        self.setFixedWidth(300)
        self.setWindowTitle('Enter a folder name')
        self.grid_layout = QGridLayout()
        self.setLayout(self.grid_layout)
        self.folder_name_input = QLineEdit()
        input_label = QLabel('Folder Name:')
        self.grid_layout.addWidget(input_label, 0, 0)
        self.grid_layout.addWidget(self.folder_name_input, 0, 1)
        self.confirm_button = QPushButton()
        self.confirm_button.setShortcut('Return')
        self.confirm_button.setText('OK')
        self.grid_layout.addWidget(self.confirm_button, 1, 1)
        self.confirm_button.clicked.connect(self.accept)


class PasswordDialog(QDialog):
    """
    An add password Dialog
    """
    def __init__(self, optional_fields=[]):
        # Setup Dialog Window
        QDialog.__init__(self)
        self.setMinimumHeight(360)
        self.setMinimumWidth(480)
        self.setWindowTitle('Enter a Password')
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
        logger = logging.getLogger(__name__)
        logger.debug(self.password_input.echoMode())
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


def main():
    app = QApplication()
    window = MainWindow()
    window.setWindowTitle('multipass')
    window.resize(640, 480)
    window.show()
    app.exec_()


if __name__ == '__main__':
    main()
