"""
this module provides a password information widget to view and edit passwords
and their metadata and to copy the password to clipboard
"""

import logging

# pylint: disable=no-name-in-module
from PySide2.QtGui import QFontDatabase
from PySide2.QtWidgets import QGroupBox, QTextBrowser, QLabel, QLineEdit, QGridLayout, QPushButton
# pylint: enable=no-name-in-module

from .git_handler import GitError
from .pass_clipboard import copy
from .ui_password_dialog import PasswordDialog


logging.getLogger(__name__).setLevel(logging.INFO)
def enable_password_view_debug_logging():
    """ enable password view debug logging """
    logging.getLogger(__name__).setLevel(logging.INFO)

class PasswordView(QGroupBox):
    """
    A group box that displays a PassFile
    """
    def __init__(self, config, tree, pass_file_object=None):
        QGroupBox.__init__(self)
        self.setLayout(QGridLayout())
        welcome_message = QTextBrowser()
        welcome_message.setText('Leeloo Dallas - Multipass!')
        self.layout().addWidget(welcome_message, 0, 0)
        self.setTitle('Password Details')
        self.config = config
        self.tree = tree
        self.pass_file = None
        self.password_field = None
        if pass_file_object:
            self.load_pass_file(pass_file_object)

    def __repr__(self):
        return (f'PasswordView(config={repr(self.config)}, tree={repr(self.tree)}, '
                f'pass_file_object={repr(self.pass_file)})')

    def load_pass_file(self, pass_file_object):
        """
        populates the window with pass_file data
        :param pass_file_object: a PassFile
        :return: None
        """
        self.clear()
        if not pass_file_object:
            return
        self.pass_file = pass_file_object
        password_field_label = QLabel('password')
        self.password_field = QLineEdit()
        self.password_field.setFont(QFontDatabase.systemFont(QFontDatabase.FixedFont))
        self.password_field.setEchoMode(QLineEdit.EchoMode.Password)
        self.password_field.setReadOnly(True)
        copy_password_button = QPushButton('&Copy')
        copy_password_button.setShortcut('Ctrl+c')
        copy_password_button.clicked.connect(self.copy_password)
        edit_password_button = QPushButton('&Edit')
        edit_password_button.setShortcut('Ctrl+e')
        edit_password_button.clicked.connect(self.edit_password)
        view_password_button = QPushButton('&Toggle')
        view_password_button.setShortcut('Ctrl+t')
        view_password_button.clicked.connect(self.toggle_password_visibility)
        self.layout().addWidget(password_field_label, 0, 0)
        self.layout().addWidget(self.password_field, 0, 1)
        self.layout().addWidget(copy_password_button, 1, 2)
        self.layout().addWidget(edit_password_button, 0, 2)
        self.layout().addWidget(view_password_button, 1, 1)
        self.password_field.setText(self.pass_file.password)
        for key, value in self.pass_file.attributes:
            current_grid_view_row = self.layout().rowCount()
            additional_field_label = QLabel(key)
            additional_field = QLineEdit()
            self.layout().addWidget(additional_field_label, current_grid_view_row + 1, 0)
            self.layout().addWidget(additional_field, current_grid_view_row + 1, 1)
            additional_field.setText(value)
            additional_field.setReadOnly(True)
        comment_browser_label = QLabel('comments')
        comment_browser = QTextBrowser()
        self.layout().addWidget(comment_browser_label, self.layout().rowCount() + 1, 0)
        self.layout().addWidget(comment_browser, self.layout().rowCount(), 1)
        comment_browser.setPlainText(self.pass_file.comments)

    def edit_password(self):
        """
        Displays an edit password dialog.
        """
        logger = logging.getLogger(__name__)
        old_name = self.pass_file.name
        logger.debug('edit_password: old_name: "%s"', old_name)

        config_attributes = self.config['attributes'] if 'attributes' in self.config else None
        pass_dialog = PasswordDialog.from_pass_file(self.pass_file, config_attributes)
        if pass_dialog.exec_():
            current_item = self.tree.currentItem()
            if not current_item.isfile:
                logger.warning('edit_password: invalid program flow: '
                               'selection is not a regular file')
                return
            self.pass_file = pass_dialog.to_pass_file()
            logger.debug('edit_password: self.pass_file.name: "%s"', self.pass_file.name)
            try:
                self.tree.file_system.change_password_file(
                    path_to_old_folder=current_item.file_system_path, old_name=old_name,
                    path_to_new_folder=current_item.file_system_path, new_name=self.pass_file.name,
                    password_file=self.pass_file)
            except GitError as error:
                self.window().show_error(error.__repr__())
            except ValueError:
                self.window().show_missing_key_error()
                return
            new_name = self.pass_file.name
            self.clear()
            self.tree.refresh_tree()
            self.tree.select_item(current_item.file_system_path, new_name)

    def toggle_password_visibility(self):
        """
        toggle the visibility of the password field
        """
        if self.password_field.echoMode() == QLineEdit.EchoMode.Password:
            self.password_field.setEchoMode(QLineEdit.EchoMode.Normal)
        else:
            self.password_field.setEchoMode(QLineEdit.EchoMode.Password)

    def clear(self):
        """
        deletes all widgets from the PasswordView
        :return: None
        """
        self.pass_file = None
        self.password_field = None
        for i in reversed(range(self.layout().count())):
            self.layout().itemAt(i).widget().setParent(None)

    def copy_password(self):
        """
        copy password handler
        :return: None
        """
        copy(self.pass_file.password)
