"""
This module provides the main application window and the main function.
"""

from functools import partial
import logging
from os import path
from pathlib import Path
from sys import exit as sys_exit

# pylint: disable=no-name-in-module
from PySide2.QtWidgets import (QMainWindow, QApplication, QFrame, QHBoxLayout, QAction,
                               QDialog, QLineEdit, QPushButton, QVBoxLayout, QGroupBox,
                               QGridLayout, QLabel, QSplitter, QStackedLayout, QListWidget,
                               QButtonGroup, QRadioButton, QComboBox, QFormLayout)
from PySide2.QtGui import QIcon

from .config import get_config
from .ui_recipients import RecipientList
from .ui_filesystem_tree import PassUiFileSystemTree
from .pass_file_system import (create_password_file, create_folder, initialize_password_store,
                               recursive_reencrypt)
from .gpg_handler import (write_gpg_id_file, generate_keypair, import_gpg_keys, list_available_keys)
from .ui_password_view import PasswordView
from .ui_password_dialog import PasswordDialog
from .search import PasswordSearch


class MainWindow(QMainWindow):
    """
    Multipass Main Window
    """
    # pylint: disable=too-many-instance-attributes
    def __init__(self):
        # pylint: disable=too-many-statements
        QMainWindow.__init__(self)
        password_store_root = Path('~/.password-store').expanduser()
        self.config = get_config(password_store_root)
        import_gpg_keys(password_store_root)
        try:
            self.tree = PassUiFileSystemTree(password_store_root)
        except FileNotFoundError:
            self.create_password_store(password_store_root)
        self.searcher = None

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

        self.right_content_frame.empty_frame = QFrame()
        self.right_content_frame.layout().addWidget(self.right_content_frame.empty_frame)
        self.right_content_frame.layout().setCurrentWidget(self.right_content_frame.empty_frame)

        self.create_new_search_index()

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
        self.tool_bar.search_options.hide()

    @staticmethod
    def critical_error_message(message, exit_value=1):
        """
        Show a modal dialog with an error message and an exit button.
        On closing the dialog in any way sys.exit will be called
        :param message: sting message displayed in the dialog
        :param exit_value: 3..125,166..254 non-reserved error code as return value of the process
        """
        logging.getLogger(__name__).critical(message)
        dialog = QDialog()
        dialog.setLayout(QVBoxLayout())
        dialog.layout().addWidget(QLabel(message))
        frame = QFrame()
        frame.setLayout(QHBoxLayout())
        frame.layout().addStretch(2**16)
        button = QPushButton('&Exit')
        button.clicked.connect(dialog.accept)
        frame.layout().addWidget(button)
        dialog.layout().addWidget(frame)
        dialog.exec_()
        sys_exit(exit_value)

    def create_password_store(self, password_store_root):
        """
        Create a new password store or show an error if unable to do so.
        Future version will ask the user if they want to clone a git repository instead.
        :param password_store_root: PathLike path of the root directory to create
        """
        # TODO: ask user if the want to clone a git repo as the password store
        logger = logging.getLogger(__name__)
        logger.debug('create_password_store: password_store_root: %r', password_store_root)
        try:
            user_key = self.get_user_key()
            if not user_key:
                self.critical_error_message("No private key selected.\nCan't continue.")
            initialize_password_store(password_store_root, user_key)
            self.tree = PassUiFileSystemTree(password_store_root)
        except PermissionError as error:
            logger.debug(error)
            self.critical_error_message('Unable to create password store at %r, permission denied'
                                        % (password_store_root,))
        except FileExistsError as error:
            logger.debug(error)
            self.critical_error_message('Unable to create password store at %r, there already is a'
                                        ' file or directory with that path' %
                                        (password_store_root,))
        except Exception as error: # pylint: disable=broad-except
            logger.warning(error)
            self.critical_error_message(error)

    def get_user_key(self):
        """
        Retrieve the identifier of the users private gpg key.
        Asks the user which key to select if gpg reports multiple private keys.
        """
        logger = logging.getLogger(__name__)
        list_of_private_keys = list_available_keys(get_secret_keys=True)
        logger.debug('get_user_key: list_of_private_keys: %r', list_of_private_keys)
        if len(list_of_private_keys) == 0:
            return self.generate_key_dialog()
        if len(list_of_private_keys) == 1:
            return list_of_private_keys[0]

        selection = self.selection_dialog(list_of_private_keys,
                                          "Which private key should be used?")
        return selection or self.generate_key_dialog()

    @staticmethod
    def generate_key_dialog():
        """
        Show a dialog to collect data required for gpg private key generation and generate
        said key returning the id of the generated key.
        :return: string id of the generated key
        """
        logger = logging.getLogger(__name__)
        dialog = QDialog()
        dialog.setWindowTitle('Create GPG Key')
        dialog.setLayout(QFormLayout())
        name_edit = QLineEdit()
        dialog.layout().addRow(dialog.tr('&Name'), name_edit)
        email_edit = QLineEdit()
        dialog.layout().addRow(dialog.tr('&Email'), email_edit)
        button_accept = QPushButton('&Accept')
        button_accept.clicked.connect(dialog.accept)
        bottom_row_layout = QHBoxLayout()
        bottom_row_layout.addStretch(2**16)
        bottom_row_layout.addWidget(button_accept)
        dialog.layout().addRow(bottom_row_layout)

        if dialog.exec_():
            key_id = f'{name_edit.text()} <{email_edit.text()}>'
            logger.debug('generate_key_dialog: key_id: %r', key_id)
            return generate_keypair(key_id)
        return None

    @staticmethod
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
        return None

    def add_folder(self):
        """
        Adds a sub folder to the current folder.
        :return: None
        """
        folder_dialog = QDialog()
        folder_dialog.setFixedHeight(120)
        folder_dialog.setFixedWidth(300)
        folder_dialog.setWindowTitle('Enter a folder name')
        grid_layout = QGridLayout()
        folder_dialog.setLayout(grid_layout)
        folder_name_input = QLineEdit()
        input_label = QLabel('Folder Name:')
        grid_layout.addWidget(input_label, 0, 0)
        grid_layout.addWidget(folder_name_input, 0, 1)
        confirm_button = QPushButton()
        confirm_button.setShortcut('Return')
        confirm_button.setText('OK')
        grid_layout.addWidget(confirm_button, 1, 1)
        confirm_button.clicked.connect(folder_dialog.accept)

        if folder_dialog.exec_():
            current_item = self.tree.currentItem()
            folder_path = current_item.file_system_path if current_item.isfile else str(
                Path(current_item.file_system_path, current_item.name))
            folder_name = folder_name_input.text()
            create_folder(folder_path, folder_name)
            self.tree.refresh_tree()
            self.tree.select_item(folder_path, folder_name)

    def add_password(self):
        """
        Displays an add password dialog.
        :return: None
        """
        optional_fields = []
        if 'attributes' in self.config:
            optional_fields = list(map(lambda a: (a[0], '', a[1]),
                                       dict(self.config['attributes']).items()))
            optional_fields.sort()
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
            try:
                create_password_file(path_to_folder=password_dir,
                                     name=pass_dialog.password_name_input.text(),
                                     password_file=password_file)

                self.tree.refresh_tree()
                self.tree.select_item(path_to_folder=password_dir,
                                      name=pass_dialog.password_name_input.text())
            except ValueError:
                self.show_missing_key_error()

    def reencrypt_files(self):
        """
        :return: None
        """
        logger = logging.getLogger(__name__)

        list_of_keys = self.user_list.get_checked_item_names()
        logger.debug('reencrypt_files: list_of_keys: %r', list_of_keys)
        if not list_of_keys:
            logger.debug('no recipients selected')
            self.show_error('no recipients selected')
            return

        folder_path = path.join(self.tree.currentItem().file_system_path,
                                self.tree.currentItem().name)
        logger.debug('reencrypt_files: folder_path: %r', folder_path)

        gpg_id_path = path.join(folder_path, '.gpg-id')
        logger.debug('reencrypt_files: gpg_id_path: %r', gpg_id_path)

        try:
            recursive_reencrypt(folder_path, list_of_keys)
            write_gpg_id_file(gpg_id_path, list_of_keys)
        except ValueError:
            self.show_missing_key_error()

    def show_missing_key_error(self):
        """
        show the error message for encrypting to an unavailable key
        """
        self.show_error(("At least one public key is not available. "
                         "Import public key or manually remove it."))

    def show_error(self, error_message):
        """
        display an error message to the user inside the main window
        :param error_message: string displayed to the user
        """
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

    @staticmethod
    def confirm_error(error_widget):
        """
        Confirm an error message, removing the widget displaying it
        :param error_widget: QWidget outer most container of the error message
        """
        logger = logging.getLogger(__name__)
        logger.debug('confirm_error: %r', error_widget)
        error_widget.setParent(None)

    def search(self):
        """
        search for the raw query written in the search bar and display possible results
        """
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
        if len(self.tool_bar.search_bar.text()) > 0:
            self.tool_bar.search_options.show()
        else:
            self.tool_bar.search_options.hide()

    def clear_search(self):
        """
        clears the search bar and hides the result widget
        """
        logger = logging.getLogger(__name__)
        logger.debug('clear_search')
        self.tool_bar.search_bar.setText('')
        self.tool_bar.search_results.clear()
        self.tool_bar.search_results.hide()
        self.tool_bar.search_results.dict = {}

    def _select_search_result(self, current, previous):
        logger = logging.getLogger(__name__)
        logger.debug('_select_search_result: %r %r', current, previous)
        item_name = current.text()
        logger.debug('_select_search_result: %r', item_name)
        result = self.tool_bar.search_results.dict[item_name]
        self.tree.select_item(result['path'], result['name'])

    def create_new_search_index(self):
        """
        create a new search index from the password tree
        """
        logging.getLogger(__name__).debug('create_new_search_index')
        self.searcher = PasswordSearch(file_system_tree=self.tree)


def main():
    """
    runs the application
    """
    app = QApplication()
    window = MainWindow()
    window.setWindowTitle('Keyswarm')
    window.resize(800, 600)
    window.show()
    app.exec_()


if __name__ == '__main__':
    main()
