from PySide2.QtGui import QFontDatabase
from PySide2.QtWidgets import (QMainWindow, QApplication, QCheckBox, QFrame, QHBoxLayout, QTextEdit, QAction,
                               QDialog, QLineEdit, QPushButton, QVBoxLayout, QGroupBox, QGridLayout, QLabel,
                               QSpacerItem, QSpinBox, QTabWidget, QComboBox)
from .ui_recipients import RecipientList
from .ui_filesystem_tree import PassUiFileSystemTree
from os import path
from pathlib import Path
from .pass_file_system import create_password_file, create_folder, get_config
from .gpg_handler import write_gpg_id_file, recursive_reencrypt
from .pass_file_format_parser import PassFile
from .generate_passwords import random_password
import string

import logging


class PasswordGenerationDialog(QDialog):
    """
    a password generation dialog
    """
    def __init__(self):
        fixed_font = QFontDatabase.systemFont(QFontDatabase.FixedFont)
        QDialog.__init__(self)
        self.setMinimumWidth(480)
        self.setWindowTitle('Generate Password')
        self.setLayout(QVBoxLayout())
        self.password_view = QFrame()
        self.password_view.setLayout(QGridLayout())
        self.layout().addWidget(self.password_view)
        self.tab_widget = QTabWidget()
        self.layout().addWidget(self.tab_widget)

        self.random_characters = QFrame()
        self.random_characters.setLayout(QHBoxLayout())

        self.password_view.preview_line = QLineEdit()
        self.password_view.preview_line.setFont(fixed_font)
        self.password_view.preview_line.setEchoMode(QLineEdit.EchoMode.Password)
        self.password_view.layout().addWidget(self.password_view.preview_line, 0, 0)

        self.password_view.button_view = QPushButton('&View')
        self.password_view.button_view.clicked.connect(self.toggle_view)
        self.password_view.layout().addWidget(self.password_view.button_view, 0, 1)

        self.random_characters.box_character_low = QCheckBox('a-z')
        self.random_characters.box_character_high = QCheckBox('A-Z')
        self.random_characters.box_digit = QCheckBox('0-9')
        self.random_characters.box_punctuation = QCheckBox('.;[')

        self.random_characters.box_character_low.setChecked(True)
        self.random_characters.box_character_high.setChecked(True)
        self.random_characters.box_digit.setChecked(True)
        self.random_characters.box_punctuation.setChecked(True)

        self.random_characters.layout().addWidget(self.random_characters.box_character_low)
        self.random_characters.layout().addWidget(self.random_characters.box_character_high)
        self.random_characters.layout().addWidget(self.random_characters.box_digit)
        self.random_characters.layout().addWidget(self.random_characters.box_punctuation)
        self.random_characters.layout().addStretch(2**16)

        self.random_characters.layout().addWidget(QLabel('Length:'))
        self.random_characters.length_selector = QSpinBox()
        # Since secrets uses the operating systems entropy pool generating too long passwords
        # will block the application. Additionally many providers impose a much lower limit
        # on the maximum lenght of passwords (which is not relevant for their database when
        # only storing salt+pepper+digest)
        self.random_characters.length_selector.setRange(16, 256)
        self.random_characters.length_selector.setValue(50)
        self.random_characters.length_selector.setFixedWidth(60)
        self.random_characters.layout().addWidget(self.random_characters.length_selector)

        self.random_characters.button_generate = QPushButton('&Generate')
        self.random_characters.button_generate.clicked.connect(self.generate_random_characters)
        self.random_characters.layout().addWidget(self.random_characters.button_generate)

        self.tab_widget.addTab(self.random_characters, 'Random Characters')

        self.random_words = QFrame()
        self.random_words.setLayout(QHBoxLayout())

        self.random_words.dictionary_selector = QComboBox()
        self.random_words.dictionary_selector.addItem('temporary_wordlist')
        self.random_words.layout().addWidget(self.random_words.dictionary_selector)

        self.random_words.layout().addStretch(2**16)
        self.random_words.layout().addWidget(QLabel('number of words:'))

        self.random_words.length_selector = QSpinBox()
        self.random_words.length_selector.setRange(5, 20)
        self.random_words.length_selector.setValue(6)
        self.random_words.length_selector.setFixedWidth(60)
        self.random_words.layout().addWidget(self.random_words.length_selector)

        self.random_words.button_generate = QPushButton('&Generate')
        self.random_words.button_generate.clicked.connect(self.generate_random_words)
        self.random_words.layout().addWidget(self.random_words.button_generate)

        self.tab_widget.addTab(self.random_words, 'Random Words')

        bottom_row = QFrame()
        bottom_row.setLayout(QHBoxLayout())
        self.layout().addWidget(bottom_row)

        bottom_row.layout().addStretch(2**16)

        self.button_accept = QPushButton('&Accept')
        self.button_accept.clicked.connect(self.confirm)
        bottom_row.layout().addWidget(self.button_accept)

    def generate_random_characters(self):
        logger = logging.getLogger(__name__)
        length = self.random_characters.length_selector.value()
        logger.debug('PasswordGenerationDialog: generate_random_characters: length: %r', length)
        alphabet = ''
        if self.random_characters.box_digit.isChecked():
            alphabet += string.digits
        if self.random_characters.box_character_low.isChecked():
            alphabet += string.ascii_lowercase
        if self.random_characters.box_character_high.isChecked():
            alphabet += string.ascii_uppercase
        if self.random_characters.box_punctuation.isChecked():
            alphabet += string.punctuation
        logger.debug('PasswordGenerationDialog: generate_random_characters: alphabet: %r', alphabet)
        password = random_password(size=length, alphabet=alphabet)
        self.password_view.preview_line.setText(password)

    def generate_random_words(self):
        logger = logging.getLogger(__name__)
        dictionary_name = self.random_words.dictionary_selector.currentText()
        logger.debug('PasswordGenerationDialog: generate_random_words: dictionary: %r', dictionary_name)
        with open(path.join('dict', dictionary_name), 'r') as dictionary_file:
            dictionary = dictionary_file.readlines()
        #logger.debug('PasswordGenerationDialog: generate_random_words: len(dictionary)', len(dictionary))
        count = self.random_words.length_selector.value()
        logger.debug('PasswordGenerationDialog: generate_random_words: count: %r', count)
        password = random_password(size=count, alphabet=dictionary).replace('\n', '')
        self.password_view.preview_line.setText(password)

    def toggle_view(self):
        logger = logging.getLogger(__name__)
        logger.debug('PasswordGenerationDialog: toggle_view')
        if self.password_view.preview_line.echoMode() == QLineEdit.EchoMode.Password:
            self.password_view.preview_line.setEchoMode(QLineEdit.EchoMode.Normal)
        else:
            self.password_view.preview_line.setEchoMode(QLineEdit.EchoMode.Password)

    def confirm(self):
        """
        confirms the add password dialog
        :return: None
        """
        logger = logging.getLogger(__name__)
        if self.password_view.preview_line.text() == '':
            logger.debug('PasswordGenerationDialog.accept: empty password')
            return
        logger.debug('PasswordGenerationDialog.accept: accept')
        self.accept()


class PasswordDialog(QDialog):
    """
    An add password Dialog
    """
    def __init__(self, optional_fields=[]):
        logger = logging.getLogger(__name__)
        logging.debug('PasswordDialog: optional_fields: %r', optional_fields)
        fixed_font = QFontDatabase.systemFont(QFontDatabase.FixedFont)
        # Setup Dialog Window
        QDialog.__init__(self)
        self.setMinimumHeight(360)
        self.setMinimumWidth(480)
        self.setWindowTitle('Create New Password')
        self.grid_layout = QGridLayout()
        self.setLayout(self.grid_layout)

        # Setup mandatory Labels and Inputs
        name_label = QLabel('Name:')
        self.grid_layout.addWidget(name_label, 0, 0)
        self.password_name_input = QLineEdit()
        self.grid_layout.addWidget(self.password_name_input, 0, 1)
        pass_label = QLabel('Password:')
        self.grid_layout.addWidget(pass_label, 1, 0)
        self.password_input = QLineEdit()
        self.password_input.setFont(fixed_font)
        self.password_input.setEchoMode(QLineEdit.EchoMode.Password)
        self.grid_layout.addWidget(self.password_input, 1, 1)
        pass_confirm_label = QLabel('Confirm:')
        self.grid_layout.addWidget(pass_confirm_label, 2, 0)
        self.pass_confirm_input = QLineEdit()
        self.pass_confirm_input.setFont(fixed_font)
        self.pass_confirm_input.setEchoMode(QLineEdit.EchoMode.Password)
        self.grid_layout.addWidget(self.pass_confirm_input, 2, 1)

        # Setup Optional Labels and Inputs
        self.optional_fields = list()
        for field, value in optional_fields:
            self.__add_optional_field__(field, value)
        comment_label = QLabel('comments')
        self.comment_field = QTextEdit()
        self.layout().addWidget(comment_label, self.layout().rowCount() + 1, 0)
        self.layout().addWidget(self.comment_field, self.layout().rowCount(), 1)

        # Setup Buttons
        generate_password_button = QPushButton('&Generate')
        generate_password_button.clicked.connect(self.generate_password)
        self.layout().addWidget(generate_password_button, 2, 2)
        view_password_button = QPushButton('&View')
        view_password_button.clicked.connect(self.toggle_password_visibility)
        self.layout().addWidget(view_password_button, 1, 2)
        self.confirm_button = QPushButton()
        self.confirm_button.setShortcut('Return')
        self.confirm_button.setText('&OK')
        self.grid_layout.addWidget(self.confirm_button, self.grid_layout.rowCount() + 1, 2)
        self.confirm_button.clicked.connect(self.confirm)

    def __repr__(self):
        return f'PasswordDialog(optional_fields={repr(self.optional_fields)}'

    def toggle_password_visibility(self):
        if self.password_input.echoMode() == QLineEdit.EchoMode.Password:
            self.password_input.setEchoMode(QLineEdit.EchoMode.Normal)
            self.pass_confirm_input.setEchoMode(QLineEdit.EchoMode.Normal)
        else:
            self.password_input.setEchoMode(QLineEdit.EchoMode.Password)
            self.pass_confirm_input.setEchoMode(QLineEdit.EchoMode.Password)

    def generate_password(self):
        generate_dialog = PasswordGenerationDialog()
        if not generate_dialog.exec_():
            return
        password = generate_dialog.password_view.preview_line.text()
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

    def __add_optional_field__(self, name, value=''):
        """
        adds an optional field to the Dialog
        :param name:
        :return:
        """
        next_row = self.grid_layout.rowCount() + 1
        label = QLabel('{name}:'.format(name=name))
        input_field = QLineEdit()
        input_field.setText(value)
        self.grid_layout.addWidget(label, next_row, 0)
        self.grid_layout.addWidget(input_field, next_row, 1)
        self.optional_fields.append((label, input_field))

    def to_pass_file(self):
        pass_file = PassFile()
        pass_file.name = self.password_name_input.text()
        pass_file.password = self.password_input.text()
        for label_field, input_field in self.optional_fields:
            if input_field.text() is not None and input_field.text() != '':
                pass_file.attributes.append((label_field.text().replace(':', ''), input_field.text()))
        pass_file.comments = self.comment_field.toPlainText()
        return pass_file

    @staticmethod
    def from_pass_file(pass_file):
        dialog = PasswordDialog(pass_file.attributes)
        dialog.setWindowTitle('Edit Password')
        dialog.password_name_input.setText(pass_file.name)
        dialog.password_input.setText(pass_file.password)
        dialog.pass_confirm_input.setText(pass_file.password)
        dialog.comment_field.setText(pass_file.comments)
        return dialog
