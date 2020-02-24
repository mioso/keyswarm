"""
This module provides the main application window and the main function.
"""

from functools import partial
from os import path
from pathlib import Path
import logging

# pylint: disable=no-name-in-module
from PySide2.QtWidgets import (QMainWindow, QApplication, QFrame, QHBoxLayout, QAction,
                               QDialog, QLineEdit, QPushButton, QVBoxLayout, QGroupBox,
                               QGridLayout, QLabel, QMenu, QSplitter, QStackedLayout,
                               QListWidget, QButtonGroup, QRadioButton)
from PySide2.QtGui import QIcon
from PySide2.QtCore import QPoint

from .ui_recipients import RecipientList
from .ui_filesystem_tree import PassUiFileSystemTree
from .pass_file_system import create_password_file, create_folder, get_config
from .gpg_handler import write_gpg_id_file, recursive_reencrypt
from .ui_password_view import PasswordView
from .ui_password_dialog import PasswordDialog
from .search import PasswordSearch


class MainWindow(QMainWindow):
    """
    Multipass Main Window
    """
    # pylint: disable=too-many-instance-attributes
    def __init__(self):
        QMainWindow.__init__(self)
        self.config = get_config(Path('~/.password-store/.cfg').expanduser())
        self.tree = PassUiFileSystemTree(str(Path('~/.password-store').expanduser()))
        self.__get_searcher(Path('~/.password-store-search-index.gpg').expanduser())

        exit_action = QAction('Exit', self)
        exit_action.setShortcut('Ctrl+q')
        exit_action.triggered.connect(self.close)
        self.menuBar().addAction(exit_action)

        add_folder_action = QAction('Add &Folder', self)
        add_folder_action.setShortcut('Ctrl+f')
        add_folder_action.triggered.connect(self.add_folder)
        self.menuBar().addAction(add_folder_action)

        add_pass_action = QAction('Add &Password', self)
        add_pass_action.setShortcut('Ctrl+p')
        add_pass_action.triggered.connect(self.add_password)
        self.menuBar().addAction(add_pass_action)

        self.main_frame = QFrame()
        self.main_frame.setLayout(QVBoxLayout())
        self.setCentralWidget(self.main_frame)

        self.content_frame = QSplitter()
        self.content_frame.addWidget(self.tree)
        self.main_frame.layout().addWidget(self.content_frame, stretch=2**16)

        self.right_content_frame = QFrame()
        self.right_content_frame.setStyleSheet('''QFrame: {margin: 0px;padding: 0px;}''')
        self.right_content_frame.setLayout(QStackedLayout())
        self.content_frame.addWidget(self.right_content_frame)

        self.password_browser_group = PasswordView(config=self.config, tree=self.tree)
        self.right_content_frame.layout().addWidget(self.password_browser_group)

        self.tree.itemSelectionChanged.connect(self.tree.on_item_selection_changed)

        self.user_list_group = QGroupBox('Authorized Keys')
        self.user_list_group.setLayout(QVBoxLayout())
        self.user_list = RecipientList()
        self.user_list_group.layout().addWidget(self.user_list)
        self.user_list_save_button = QPushButton('save')
        self.user_list_save_button.clicked.connect(self.reencrypt_files)
        self.user_list_group.layout().addWidget(self.user_list_save_button)
        self.right_content_frame.layout().addWidget(self.user_list_group)

        self.tool_bar = self.addToolBar('search')
        search_frame = QFrame()
        search_frame.setLayout(QVBoxLayout())
        self.tool_bar.setMovable(False)
        self.tool_bar.search_bar = QLineEdit()
        self.tool_bar.search_bar.setPlaceholderText('Search')
        self.tool_bar.search_bar.textEdited.connect(self.search)
        search_frame.layout().addWidget(self.tool_bar.search_bar)
        self.tool_bar.search_results = QListWidget()
        self.tool_bar.search_results.currentItemChanged.connect(self._select_search_result)
        search_frame.layout().addWidget(self.tool_bar.search_results)
        self.tool_bar.search_results.hide()
        self.tool_bar.addWidget(search_frame)

        self.tool_bar.search_options = QFrame()
        self.tool_bar.search_options.setLayout(QHBoxLayout())
        search_frame.layout().addWidget(self.tool_bar.search_options)
        self.tool_bar.search_options.button_group = QButtonGroup()
        self.tool_bar.search_options.radio_button_normal = QRadioButton('normal')
        self.tool_bar.search_options.radio_button_glob = QRadioButton('*auto-glob*')
        self.tool_bar.search_options.radio_button_glob_prefix = QRadioButton('*auto-glob')
        self.tool_bar.search_options.radio_button_glob_suffix = QRadioButton('auto-glob*')
        self.tool_bar.search_options.radio_button_fuzzy = QRadioButton('auto-fuzzy~')
        self.tool_bar.search_options.button_group.addButton(
            self.tool_bar.search_options.radio_button_normal)
        self.tool_bar.search_options.button_group.addButton(
            self.tool_bar.search_options.radio_button_glob)
        self.tool_bar.search_options.button_group.addButton(
            self.tool_bar.search_options.radio_button_glob_prefix)
        self.tool_bar.search_options.button_group.addButton(
            self.tool_bar.search_options.radio_button_glob_suffix)
        self.tool_bar.search_options.button_group.addButton(
            self.tool_bar.search_options.radio_button_fuzzy)
        self.tool_bar.search_options.layout().addWidget(
            self.tool_bar.search_options.radio_button_normal)
        self.tool_bar.search_options.layout().addWidget(
            self.tool_bar.search_options.radio_button_glob)
        self.tool_bar.search_options.layout().addWidget(
            self.tool_bar.search_options.radio_button_glob_prefix)
        self.tool_bar.search_options.layout().addWidget(
            self.tool_bar.search_options.radio_button_glob_suffix)
        self.tool_bar.search_options.layout().addWidget(
            self.tool_bar.search_options.radio_button_fuzzy)
        self.tool_bar.search_options.layout().addStretch(2**16)
        self.tool_bar.search_options.radio_button_glob_suffix.setChecked(True)
        self.tool_bar.search_options.button_group.buttonToggled.connect(self.search)

        #TODO: remove debug action
        test_error_action = QAction('DEBUG: showError', self)
        test_error_action.triggered.connect(self.__random_error)
        self.menuBar().addAction(test_error_action)
        test_reindex_action = QAction('DEBUG: reindex', self)
        test_reindex_action.triggered.connect(self.__create_new_index)
        self.menuBar().addAction(test_reindex_action)

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
            password_file = pass_dialog.to_pass_file()
            create_password_file(path_to_folder=password_dir,
                                 name=pass_dialog.password_name_input.text(),
                                 password_file=password_file)
            self.tree.refresh_tree()

    def reencrypt_files(self):
        """
        :return: None
        """
        list_of_keys = self.user_list.get_checked_item_names()
        folder_path = path.join(self.tree.currentItem().file_system_path,
                                self.tree.currentItem().name)
        gpg_id_path = path.join(folder_path, '.gpg-id')
        write_gpg_id_file(gpg_id_path, list_of_keys)
        recursive_reencrypt(folder_path, list_of_keys)

    def show_error(self, error_message):
        logger = logging.getLogger(__name__)
        logger.debug('show_error: %r', error_message)
        error_widget = QFrame()
        error_widget.setLayout(QHBoxLayout())
        error_widget.layout().addWidget(QLabel(error_message))
        error_widget.layout().addStretch(2**16)
        error_widget.setStyleSheet('''
QFrame {
    margin: 0px;
    padding: 0px;
    color: white;
    background-color: darkred;
    border-radius: 0.5em;
}

QPushButton {
    color: white;
    background-color: #00000000;
    border-style: none;
}
        ''')
        error_confirm_button = QPushButton()
        error_confirm_button.setIcon(QIcon.fromTheme('window-close'))
        error_confirm_button.clicked.connect(partial(self.confirm_error, error_widget))
        error_widget.layout().addWidget(error_confirm_button)
        self.main_frame.layout().insertWidget(0, error_widget)

    def confirm_error(self, error_widget):
        logger = logging.getLogger(__name__)
        logger.debug('confirm_error: %r', error_widget)
        error_widget.setParent(None)

    def search(self):
        logger = logging.getLogger(__name__)
        if not self.search:
            logger.debug('search: no searcher')
            return

        glob_prefix = (self.tool_bar.search_options.radio_button_glob.isChecked() or
                       self.tool_bar.search_options.radio_button_glob_prefix.isChecked())
        glob_suffix = (self.tool_bar.search_options.radio_button_glob.isChecked() or
                       self.tool_bar.search_options.radio_button_glob_suffix.isChecked())
        fuzzy = self.tool_bar.search_options.radio_button_fuzzy.isChecked()

        results = self.searcher.search(self.tool_bar.search_bar.text(),
                                       glob_prefix=glob_prefix,
                                       glob_suffix=glob_suffix,
                                       fuzzy=fuzzy)
        self.tool_bar.search_results.clear()
        self.tool_bar.search_results.dict = {}
        if len(results) > 0:
            for result in results:
                item_name = f'''{result['path']}/{result['name']}'''
                self.tool_bar.search_results.dict[item_name] = result
                self.tool_bar.search_results.addItem(item_name)
            self.tool_bar.search_results.show()
        else:
            self.tool_bar.search_results.hide()

    def clear_search(self):
        logger = logging.getLogger(__name__)
        logger.debug('clear_search')
        self.tool_bar.search_bar.setText('')
        self.tool_bar.search_results.clear()
        self.tool_bar.search_results.hide()
        self.tool_bar.search_results.dict = {}

    def __get_searcher(self, stored_index_path):
        try:
            self.searcher = PasswordSearch(stored_index_path=stored_index_path)
        except FileNotFoundError:
            self.searcher = PasswordSearch(file_system_tree=self.tree)

    def _select_search_result(self, current, previous):
        logger = logging.getLogger(__name__)
        logger.debug('_select_search_result: %r %r', current, previous)
        item_name = current.text()
        logger.debug('_select_search_result: %r', item_name)
        result = self.tool_bar.search_results.dict[item_name]
        self.tree.select_item(result['path'], result['name'])

    def __random_error(self):
        #TODO: remove this debug method
        from .generate_passwords import random_password
        logging.getLogger(__name__).debug('__random_error')
        self.show_error(random_password(64))

    def __create_new_index(self):
        # TODO: remove this debug method
        logging.getLogger(__name__).debug('__create_new_index')
        search = PasswordSearch(file_system_tree=self.tree)
        search.store_search_index(Path('~/.password-store-search-index').expanduser())

    def __load_index(self):
        # TODO: remove this debug method
        PasswordSearch(stored_index_path=Path('~/.password-store-search-index').expanduser())

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


def main():
    app = QApplication()
    window = MainWindow()
    window.setWindowTitle('Keyswarm')
    window.resize(640, 480)
    window.show()
    app.exec_()


if __name__ == '__main__':
    main()
