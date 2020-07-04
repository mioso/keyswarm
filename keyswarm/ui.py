"""
This module provides the main application window and the main function.
"""

from configparser import DuplicateSectionError
from distutils.util import strtobool
from functools import partial
import logging
from os import path
from pathlib import Path
from sys import argv, exit as sys_exit

# pylint: disable=no-name-in-module
from PySide2.QtCore import QTimer
from PySide2.QtWidgets import (QMainWindow, QApplication, QFrame, QHBoxLayout, QAction,
                               QDialog, QLineEdit, QPushButton, QVBoxLayout, QGroupBox,
                               QGridLayout, QLabel, QSplitter, QStackedLayout, QListWidget,
                               QButtonGroup, QRadioButton, QFormLayout)
from PySide2.QtGui import QIcon
# pylint: enable=no-name-in-module

from .config import get_config, save_config, get_user_config
from .gpg_handler import (write_gpg_id_file, generate_keypair, import_gpg_keys, list_available_keys)
from .git_handler import GitError, git_soft_clean
from .name_filter import is_valid_file_name
from .pass_file_system import PassFileSystem
from .task_queue import TaskQueue, Task, TaskPriority
from .ui_filesystem_tree import PassUiFileSystemTree
from .ui_helper import (apply_error_style_to_widget, selection_dialog,
                        a_b_dialog_or_exit, confirm_error, confirm_info,
                        clone_password_store_dialog)
from .ui_password_view import PasswordView
from .ui_password_dialog import PasswordDialog
from .ui_recipients import RecipientList
from .search import PasswordSearch


class MainWindow(QMainWindow):
    """
    Multipass Main Window
    """
    # pylint: disable=too-many-instance-attributes
    def __init__(self, password_store_root):
        # pylint: disable=too-many-statements
        QMainWindow.__init__(self)

        logger = logging.getLogger()

        self.__task_queue = TaskQueue()
        self.unhandled_tasks = []
        self.__task_timer = QTimer(self)
        self.__task_timer.setInterval(50) # 0 avoids downtime but creates too much cpu load
        self.__task_timer.timeout.connect(self._task_queue_handler)
        self.__task_timer.start()

        self.main_frame = QFrame()
        self.main_frame.setLayout(QVBoxLayout())
        self.setCentralWidget(self.main_frame)

        self.password_store_root = password_store_root
        self.config = get_config(password_store_root)
        try:
            self.get_user_key()
            logger.info('trying to open password store')
            self.tree = PassUiFileSystemTree(password_store_root, self.config)
        except FileNotFoundError:
            logger.info('creating new password store')
            self.create_password_store(password_store_root)
        except GitError as error:
            self.show_error(error.__repr__())
            self.tree = PassUiFileSystemTree(password_store_root, self.config,
                                             no_git_override=True)
        import_gpg_keys(password_store_root)
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

        refresh_action = QAction('&Refresh', self)
        refresh_action.setShortcut('Ctrl+r')
        refresh_action.triggered.connect(self.refresh_password_store)
        self.menuBar().addAction(refresh_action)

        try:
            if strtobool(self.config.get('debug', 'enabled', fallback='false')):
                test_task_action = QAction('Test Task', self)
                test_task_action.triggered.connect(self.__create_test_task)
                self.menuBar().addAction(test_task_action)
        except ValueError:
            pass

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

    def _task_queue_handler(self):
        """
        Forwards the task queue, called by timer every run of the event loop
        """
        self.__task_queue.run()
        try:
            task = self.__task_queue.pop()
        except IndexError:
            return

        if task.failed:
            if task.error_handler:
                task.error_handler(task)
            else:
                self.unhandled_tasks.append(task)
        else:
            if task.callback:
                task.callback(task)
            else:
                self.unhandled_task.append(task)

    def queue_task(self, task):
        """
        add a task to the queue to be executed in order of priority
        """
        self.__task_queue.push(task)

    def __create_test_task(self):
        from random import choice # pylint: disable=import-outside-toplevel
        from time import sleep # pylint: disable=import-outside-toplevel
        def fib(n): # pylint: disable=invalid-name
            """ using inefficient implementation on purpose """
            if n <= 1:
                return n
            return fib(n-1) + fib(n-2)

        def callback_(task):
            self.show_error(str(task.result))

        test_task = Task(
            partial(choice([fib, sleep]), choice([23, 32, 42])),
            "Test Task",
            TaskPriority.CREATE_SEARCH_INDEX,
            callback=callback_
            )

        self.queue_task(test_task)

    def create_password_store(self, password_store_root):
        """
        Create a new password store or show an error if unable to do so.
        Future version will ask the user if they want to clone a git repository instead.
        :param password_store_root: PathLike path of the root directory to create
        """
        logger = logging.getLogger(__name__)
        logger.info('create_password_store: password_store_root: %r', password_store_root)

        git_or_plain = git_or_plain = a_b_dialog_or_exit(
            'git', 'plain', 'Git or Plain', '&Git', '&Plain',
            'There currently is no password store at %s.\n\n'
            'You can create a plain folder holding the password store or use git to create or clon'
            'e a repository to sync your passwords with a remote or just use a local repository fo'
            'r versioning' % (password_store_root,))

        if git_or_plain == 'git':
            clone_or_init = a_b_dialog_or_exit(
                'clone', 'init', 'Clone or Init', '&Clone', '&Init',
                'Initialize a local git repository with no remote '
                'or clone a repository from a remote?')

        try:
            if git_or_plain == 'git' and clone_or_init == 'clone':
                try:
                    repo_info = clone_password_store_dialog()
                    logger.debug('create_password_store: %r', repo_info)
                    file_system = PassFileSystem.clone_password_store(
                        password_store_root, repo_info, self.config)
                    self.tree = PassUiFileSystemTree(password_store_root, self.config, file_system)
                    return
                except GitError as error:
                    self.critical_error_message(str(error))
                except ValueError as error:
                    self.critical_error_message(str(error))
                except Exception as error: # pylint: disable=broad-except
                    self.critical_error_message(str(error))
            else:
                user_key = self.get_user_key()
                if not user_key:
                    self.critical_error_message("No private key selected.\nCan't continue.")
                file_system = PassFileSystem.initialize_password_store(
                    password_store_root=password_store_root, config=self.config,
                    use_git=git_or_plain == 'git')
                self.tree = PassUiFileSystemTree(password_store_root, self.config, file_system)
        except PermissionError as error:
            logger.critical(error)
            self.critical_error_message('Unable to create password store at %r, permission denied'
                                        % (password_store_root,))
        except FileExistsError as error:
            logger.critical(error)
            self.critical_error_message('Unable to create password store at %r, there already is a'
                                        ' file or directory with that path' %
                                        (password_store_root,))
        except Exception as error: # pylint: disable=broad-except
            logger.warning(error)
            self.critical_error_message(str(error))

    def get_user_key(self):
        """
        Retrieve the identifier of the users private gpg key.
        Asks the user which key to select if gpg reports multiple private keys.
        """
        logger = logging.getLogger(__name__)
        list_of_private_keys = list_available_keys(get_secret_keys=True)
        logger.debug('get_user_key: list_of_private_keys: %r', list_of_private_keys)

        try:
            user_key_id = self.config['gpg']['user_key_id']
            logger.debug('get_user_key: config_key: %r', user_key_id)
            if user_key_id in list_of_private_keys:
                return user_key_id
            logger.debug('get_user_key: config_key not in list_of_private_keys')
        except (KeyError, TypeError):
            logger.debug('get_user_key: key not in config')

        selection = selection_dialog(list_of_private_keys,
                                     "Which private key should be used?")
        try:
            user_key_id = selection or generate_key_dialog()
            logger.debug('get_user_key: user_key_id: %r', user_key_id)
        except ValueError as error:
            self.critical_error_message(f'Error while generating keypair:\n\n{str(error)}')
        if not user_key_id:
            self.critical_error_message('A GPG key needs to be selected or created.')
        try:
            self.config.add_section('gpg')
        except DuplicateSectionError:
            pass
        self.config['gpg']['user_key_id'] = user_key_id
        save_config(self.config)
        return user_key_id

    def search(self):
        """
        search for the raw query written in the search bar and display possible results
        """
        logger = logging.getLogger(__name__)
        if not self.search:
            logger.info('search: no searcher')
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
        logger.info('clear_search')
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
        logging.getLogger(__name__).info('create_new_search_index')
        self.searcher = PasswordSearch(file_system_tree=self.tree)

    def add_folder(self):
        """
        Adds a sub folder to the current folder.
        :return: None
        """
        logger = logging.getLogger(__name__)

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

        def folder_name_check():
            if is_valid_file_name(folder_name_input.text()):
                folder_dialog.accept()
            else:
                apply_error_style_to_widget(folder_name_input)

        confirm_button.clicked.connect(folder_name_check)

        if folder_dialog.exec_():
            logger.debug('add_folder: tree: %r', self.tree)
            current_item = self.tree.currentItem()
            logger.debug('add_folder: current_item: %r', current_item)
            folder_path = current_item.file_system_path if current_item.isfile else str(
                Path(current_item.file_system_path, current_item.name))
            folder_name = folder_name_input.text()
            self.tree.file_system.create_folder(folder_path, folder_name)
            self.tree.refresh_tree()
            self.tree.select_item(folder_path, folder_name)

    def add_password(self):
        """
        Displays an add password dialog.
        :return: None
        """
        logger = logging.getLogger(__name__)

        optional_fields = []
        if 'attributes' in self.config:
            optional_fields = list(map(lambda a: (a[0], '', a[1]),
                                       dict(self.config['attributes']).items()))
            optional_fields.sort()
        logger.debug('add_password: optional_fields: %r', optional_fields)

        pass_dialog = PasswordDialog(optional_fields=optional_fields)
        if pass_dialog.exec_():
            logger.debug('add_password: tree: %r', self.tree)
            current_item = self.tree.currentItem()
            logger.debug('add_password: current_item: %r', current_item)
            if current_item.isdir:
                password_dir = path.join(current_item.file_system_path, current_item.name)
            else:
                password_dir = current_item.file_system_path
            password_file = pass_dialog.to_pass_file()
            try:
                self.tree.file_system.create_password_file(
                    path_to_folder=password_dir,
                    name=pass_dialog.password_name_input.text(),
                    password_file=password_file)
            except GitError as error:
                logger.debug('add_password: %r', error)
                self.show_error(error.__repr__())
            except ValueError as error:
                logger.debug('add_password: %r', error)
                self.show_missing_key_error()
            finally:
                self.tree.refresh_tree()
                self.create_new_search_index()
                self.tree.select_item(path_to_folder=password_dir,
                                      name=pass_dialog.password_name_input.text())

    def refresh_password_store(self):
        """
        Refreshes the password store and reloads it.
        """
        self._refresh_password_store()

    def _refresh_password_store(self):
        logger = logging.getLogger(__name__)
        logger.info('refresh_password_store button triggered')
        def index_callback_(task):
            self.show_info('refreshed_search_index')
        def tree_callback_(task):
            self.show_info('refreshed tree')
        refresh_tree_task = Task(callable_=self.tree.refresh_tree,
                                 description='refresh tree',
                                 priority=TaskPriority.CREATE_FILE_TREE,
                                 callback=tree_callback_)
        logger.info('queuing refresh tree task')
        self.queue_task(refresh_tree_task)
        create_search_index_task = Task(callable_=self.create_new_search_index,
                                        description='refresch search index',
                                        priority=TaskPriority.CREATE_SEARCH_INDEX,
                                        callback=index_callback_)
        logger.info('queuing create search index task')
        self.queue_task(create_search_index_task)

    def reencrypt_files(self):
        """
        :return: None
        """
        logger = logging.getLogger(__name__)

        list_of_keys = self.user_list.get_checked_item_names()
        logger.debug('reencrypt_files: list_of_keys: %r', list_of_keys)
        if not list_of_keys:
            logger.info('reencrypt_files: no recipients selected')
            self.show_error('no recipients selected')
            return

        folder_path = path.join(self.tree.currentItem().file_system_path,
                                self.tree.currentItem().name)
        logger.info('reencrypt_files: folder_path: %r', folder_path)

        gpg_id_path = path.join(folder_path, '.gpg-id')
        logger.info('reencrypt_files: gpg_id_path: %r', gpg_id_path)

        try:
            write_gpg_id_file(gpg_id_path, list_of_keys)
            self.tree.file_system.recursive_reencrypt(folder_path, list_of_keys)
        except (ValueError, GitError) as error:
            logger.debug('reencrypt_files: %r', error)
            self.show_error(str(error))
            try:
                git_soft_clean(folder_path)
            except GitError as error:
                self.show_error(str(error))

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
        error_widget.setStyleSheet((
            'QFrame {'
            '    margin: 0px;'
            '    padding: 0px;'
            '    color: white;'
            '    background-color: darkred;'
            '    border-radius: 0.5em;'
            '}'
            ''
            'QPushButton {'
            '    color: white;'
            '    background-color: #00000000;'
            '    border-style: none;'
            '}'))
        error_confirm_button = QPushButton()
        error_confirm_button.setIcon(QIcon.fromTheme('window-close'))
        error_confirm_button.clicked.connect(partial(confirm_error, error_widget))
        error_widget.layout().addWidget(error_confirm_button)
        self.main_frame.layout().insertWidget(0, error_widget)

    def show_info(self, info_message):
        """
        display an error message to the user inside the main window
        :param error_message: string displayed to the user
        """
        logger = logging.getLogger(__name__)
        logger.debug('show_info: %r', info_message)
        info_widget = QFrame()
        info_widget.setLayout(QHBoxLayout())
        info_widget.layout().addWidget(QLabel(info_message))
        info_widget.layout().addStretch(2**16)
        info_widget.setStyleSheet((
            'QFrame {'
            '    margin: 0px;'
            '    padding: 0px;'
            '    color: white;'
            '    background-color: lightblue;'
            '    border-radius: 0.5em;'
            '}'
            ''
            'QPushButton {'
            '    color: white;'
            '    background-color: #00000000;'
            '    border-style: none;'
            '}'))
        info_confirm_button = QPushButton()
        info_confirm_button.setIcon(QIcon.fromTheme('window-close'))
        info_confirm_button.clicked.connect(partial(confirm_info, info_widget))
        info_widget.layout().addWidget(info_confirm_button)
        self.main_frame.layout().insertWidget(0, info_widget)


def generate_key_dialog():
    """
    Show a dialog to collect data required for gpg private key generation and generate
    said key returning the id of the generated key.
    :return: string id of the generated key
    :throws ValueError: on gpg error (also when the user aborts the passphrase dialog)
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
        logger.debug('generate_key_dialog: name: %r', name_edit.text())
        logger.debug('generate_key_dialog: email: %r', email_edit.text())
        return generate_keypair(name_edit.text(), email_edit.text())
    return None


def main():
    """
    runs the application
    """
    user_config = get_user_config()

    try:
        log_level = {
            'debug': logging.DEBUG,
            'info': logging.INFO,
            'warn': logging.WARN,
            'warning': logging.WARNING,
            'error': logging.ERROR,
            'fatal': logging.FATAL,
            'critical': logging.CRITICAL
        }[user_config['logging']['log_level']]

        try:
            file_name = user_config['logging']['file_name']
            try:
                file_mode = user_config['logging']['file_mode']
            except KeyError:
                file_mode = 'w'
        except KeyError:
            file_name = None
            file_mode = None

        logging.basicConfig(level=log_level, filename=file_name, filemode=file_mode)
    except KeyError:
        logging.basicConfig(level=logging.INFO)

    try:
        password_store_root = user_config['general']['password_store_root']
    except KeyError:
        password_store_root = Path('~/.password-store').expanduser()

    app = QApplication(argv)
    window = MainWindow(password_store_root)
    window.setWindowTitle('Keyswarm')
    window.resize(800, 600)
    window.show()
    sys_exit(app.exec_())


if __name__ == '__main__':
    main()
