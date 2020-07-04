"""
a collection of ui helper functions
"""

import logging
from sys import exit as sys_exit

# pylint: disable=no-name-in-module
from PySide2.QtWidgets import (QDialog, QVBoxLayout, QComboBox, QLabel, QFrame, QHBoxLayout,
                               QPushButton, QTabWidget, QFormLayout, QLineEdit)


def clone_password_store_dialog():
    """
    Show a dialog to collect data required to clone the password store
    """
    logger = logging.getLogger(__name__)
    dialog = QDialog()
    dialog.setWindowTitle('Repository URL')
    dialog.setLayout(QVBoxLayout())
    tab_widget = QTabWidget()
    dialog.layout().addWidget(tab_widget)

    ssh_frame = QFrame()
    ssh_frame.setLayout(QFormLayout())
    ssh_url_edit = QLineEdit()
    ssh_frame.layout().addRow(dialog.tr('U&RL'), ssh_url_edit)
    tab_widget.addTab(ssh_frame, 'SSH')

    http_frame = QFrame()
    http_frame.setLayout(QFormLayout())
    http_url_edit = QLineEdit()
    http_username_edit = QLineEdit()
    http_password_edit = QLineEdit()
    http_frame.layout().addRow(dialog.tr('U&RL'), http_url_edit)
    http_frame.layout().addRow(dialog.tr('&Username'), http_username_edit)
    http_frame.layout().addRow(dialog.tr('&Password'), http_password_edit)
    tab_widget.addTab(http_frame, 'HTTP')

    button_frame = QFrame()
    button_frame.setLayout(QVBoxLayout())
    button_frame.layout().addStretch(2**16)
    dialog.layout().addWidget(button_frame)
    button_accept = QPushButton('&Accept')
    button_accept.clicked.connect(dialog.accept)
    button_frame.layout().addWidget(button_accept)

    if dialog.exec_():
        result = {
            'ssh': {
                'url': ssh_url_edit.text()
            },
            'http': {
                'url': http_url_edit.text(),
                'username': http_username_edit.text(),
                'password': http_password_edit.text()
            },
        }
        logger.debug('clone_password_store_dialog: result: %r', result)
        return result
    logger.debug('clone_password_store_dialog: aborted')
    return None


def selection_dialog(list_of_options, window_title, label_text=None):
    """
    Show a selection dialog with a list of options to select from and return the selected
    option or None if the dialog was canceled.
    :param list_of_options: [string] options to select from
    :param window_title: string title of the dialog window
    :param label_text: Maybe(string) text of an optional label above the selection
    :return: Maybe(string) one element of the list of options or None
    """
    logger = logging.getLogger(__name__)
    if not list_of_options:
        return None
    dialog = QDialog()
    dialog.setWindowTitle(window_title)
    dialog.setLayout(QVBoxLayout())
    if label_text:
        dialog.layout().addWidget(QLabel(label_text))
    selection = QComboBox()
    selection.addItems(list_of_options)
    dialog.layout().addWidget(selection)
    frame = QFrame()
    frame.setLayout(QHBoxLayout())
    frame.layout().addStretch(2**16)
    button_accept = QPushButton('&Accept')
    button_accept.clicked.connect(dialog.accept)
    frame.layout().addWidget(button_accept)
    dialog.layout().addWidget(frame)

    if dialog.exec_():
        logger.debug('get_user_key: currentText: %r', selection.currentText())
        return selection.currentText()
    logger.debug('get_user_key: aborted')
    return None


def a_b_dialog(option_a, option_b, window_title, label_a=None, label_b=None, label_text=None):
    # pylint: disable=too-many-arguments
    """
    Show an A B selection dialog to the user with an optional label text

    :param option_a: string the first option
    :param option_b: string the second option
    :param window_title: string title of the dialog window
    :param label_a: string optional text of the first button
    :param label_b: string optional text of the second button
    :param label_text: string optional text shown above the buttons
    :return: Maybe(string) the selected option or None if dialog window is closed
    """
    logger = logging.getLogger(__name__)
    logger.debug('a_b_dialog: (%r, %r, %r, %r, %r, %r)', option_a, option_b, window_title,
                 label_a, label_b, label_text)
    label_a = label_a or option_a
    label_b = label_b or option_b
    dialog = QDialog()
    dialog.setWindowTitle(window_title)
    dialog.setLayout(QVBoxLayout())
    if label_text:
        text_label = QLabel(label_text)
        text_label.setWordWrap(True)
        dialog.layout().addWidget(text_label)
    dialog.selection = None
    button_a = QPushButton(label_a)
    button_b = QPushButton(label_b)
    def function_a():
        dialog.selection = option_a
        dialog.accept()
    def function_b():
        dialog.selection = option_b
        dialog.accept()
    button_a.clicked.connect(function_a)
    button_b.clicked.connect(function_b)
    dialog.layout().addStretch(2*16)
    frame = QFrame()
    frame.setLayout(QHBoxLayout())
    frame.layout().addWidget(button_a)
    frame.layout().addStretch(2*16)
    frame.layout().addWidget(button_b)
    dialog.layout().addWidget(frame)
    if dialog.exec_():
        logger.debug('a_b_dialog: result: %r', dialog.selection)
        return dialog.selection
    logger.debug('a_b_dialog: aborted')
    return None


def a_b_dialog_or_exit(option_a, option_b, window_title, label_a=None, label_b=None,
                       label_text=None):
    """
    Show an A B selection dialog to the user with an optional label text.
    If the user closes the dialog window without choosing an option, another
    dialog is opened giving the choice to repeat the selection or to exit
    the application.

    :param option_a: string the first option
    :param option_b: string the second option
    :param window_title: string title of the dialog window
    :param label_a: string optional text of the first button
    :param label_b: string optional text of the second button
    :param label_text: string optional text shown above the buttons
    :return: string the selected option
    """
    # pylint: disable=too-many-arguments
    result = None
    while not result:
        result = a_b_dialog(
            option_a, option_b, window_title, label_a, label_b, label_text)
        if not result and not a_b_dialog(
                None, 'retry', 'No Selection', label_a='&Exit', label_b='&Retry'):
            sys_exit()
    return result


def confirm_error(error_widget):
    """
    Confirm an error message, removing the widget displaying it
    :param error_widget: QWidget outer most container of the error message
    """
    logger = logging.getLogger(__name__)
    logger.debug('confirm_error: %r', error_widget)
    error_widget.setParent(None)


def confirm_info(info_widget):
    """
    Confirm an error message, removing the widget displaying it
    :param error_widget: QWidget outer most container of the error message
    """
    logger = logging.getLogger(__name__)
    logger.debug('confirm_info: %r', info_widget)
    info_widget.setParent(None)


def apply_error_style_to_widget(widget):
    """
    apply a stylesheet to the given QWidget indicating something is wrong with it
    """
    widget.setStyleSheet((
        'QWidget {'
        '  color: white;'
        '  background-color: darkred;'
        '}'))

def clear_widget_style_sheet(widget):
    widget.setStyleSheet('')
