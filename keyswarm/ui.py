"""
This module provides the main application window and the main function.
"""

# pylint: disable=too-many-instance-attributes

from configparser import DuplicateSectionError
from functools import partial
import logging
from logging.handlers import SocketHandler
from ipaddress import ip_address
from os import path
from pathlib import Path
from sys import argv, exit as sys_exit
import threading

# pylint: disable=no-name-in-module
from PySide2.QtCore import QTimer
from PySide2.QtWidgets import (QMainWindow, QApplication, QFrame, QHBoxLayout, QAction,
                               QDialog, QLineEdit, QPushButton, QVBoxLayout, QGroupBox,
                               QGridLayout, QLabel, QSplitter, QStackedWidget, QListWidget,
                               QButtonGroup, QRadioButton, QFormLayout)
from PySide2.QtGui import QIcon, QPalette, QColor, Qt
# pylint: enable=no-name-in-module

from .config import get_config, save_config, get_user_config
from ._debug import create_test_task
from .decoder import enable_decoder_debug_logging
from .gpg_handler import (write_gpg_id_file, generate_keypair, import_gpg_keys, list_available_keys,
                          enable_gpg_debug_logging)
from .git_handler import GitError, git_soft_clean, enable_git_debug_logging
from .name_filter import is_valid_file_name
from .pass_file_format_parser import enable_file_format_debug_logging
from .pass_file_system import PassFileSystem, enable_file_system_debug_logging
from .ui_filesystem_tree import PassUiFileSystemTree, enable_tree_view_debug_logging
from .ui_helper import (apply_error_style_to_widget, selection_dialog,
                        a_b_dialog_or_exit, confirm_error, clone_password_store_dialog)
from .ui_password_view import PasswordView, enable_password_view_debug_logging
from .ui_password_dialog import PasswordDialog, enable_password_dialog_debug_logging
from .ui_recipients import RecipientList, enable_recipient_view_debug_logging
from .search import PasswordSearch, enable_search_debug_logging
from .task_queue import TaskQueue, Task, TaskPriority, enable_task_queue_debug_logging
from .types import RightFrameContentType

from .fail_always import Fail


class MainWindow(QMainWindow):
    """
    Multipass Main Window
    """
    def __init__(self, password_store_root):
        # TODO every instance attribute initialization that requires more than two statements is to be moved to its own init function for decluttering
        QMainWindow.__init__(self)

        self.__readonly = False
        self.__config = None
        self.__task_queue = TaskQueue()
        self.__task_timer = None
        self._main_frame = None
        self._content_frame = None
        self._right_content_frame = None
        self._password_browser_group = None
        self._user_list_group = None
        self._tool_bar = None
        self._status_bar = self.statusBar()
        self._password_store_root = password_store_root
        self._tree = None
        self._tree_frame = None
        self._searcher = None
        self._content_frame = None
        self._right_content_frame = None
        self._password_browser_group = None
        self._user_list_group = None
        self.unhandled_tasks = []

        self._init_view()
        self._init_action_bar()
        self._init_search_frame()
        self._init_status_bar()
        self._init_task_timer()
        self._init_config()
        self._init_password_store()
        self._init_content_frame()
        self._init_debug()

    @property
    def readonly(self):
        """ wether editing is disabled """
        return self.__readonly

    @property
    def config(self):
        """ config currently being used """
        return self.__config

    def _init_config(self):
        self.__config = get_config(self._password_store_root)

    def _init_password_store(self):
        def task_():
            return

        def callback_(task):
            self._tree.connect_to_file_system(self._init_password_store_())
            import_gpg_keys(self._password_store_root)
            self.create_new_search_index()

        task = Task(
            task_,
            'starting',
            TaskPriority.INIT_PASSWORD_STORE,
            callback=callback_
            )

        self.queue_task(task)

    def _init_password_store_(self): # TODO FIXME
        logger = logging.getLogger(__name__)
        try:
            self.get_user_key()
            logger.info('trying to open password store')
            return PassFileSystem(
                self._password_store_root,
                self.__config,
                no_git_override=False)
        except FileNotFoundError:
            logger.info('creating new password store')
            return self.create_password_store(self._password_store_root)
        except GitError as error:
            self.show_error(error.__repr__())
            return PassFileSystem(
                self._password_store_root,
                self.__config,
                no_git_override=True)

    def _init_debug(self):
        if self.__config.getboolean('debug', 'task_queue', fallback=False):
            test_task_action = QAction('Test Task', self)
            test_task_action.triggered.connect(partial(create_test_task, self))
            self.menuBar().addAction(test_task_action)

    def _init_content_frame(self):
        self._content_frame = QSplitter()
        self._tree = PassUiFileSystemTree(
            self._password_store_root, self.__config, self.queue_task)
        self._content_frame.addWidget(self._tree)
        self._main_frame.layout().addWidget(self._content_frame, stretch=2**16)

        self._right_content_frame = QStackedWidget()
        self._right_content_frame.setStyleSheet('''QStackedWidget: {margin: 0px;padding: 0px;}''')
        self._content_frame.addWidget(self._right_content_frame)

        self._password_browser_group = PasswordView(config=self.__config, tree=self._tree)
        self._right_content_frame.layout().addWidget(self._password_browser_group)

        self._user_list_group = QGroupBox('Authorized Keys')
        self._user_list_group.setLayout(QVBoxLayout())
        self._user_list = RecipientList()
        self._user_list_group.layout().addWidget(self._user_list)
        self._user_list_save_button = QPushButton('save')
        self._user_list_save_button.clicked.connect(self.reencrypt_files)
        self._user_list_group.layout().addWidget(self._user_list_save_button)
        self._right_content_frame.layout().addWidget(self._user_list_group)

        self._right_content_frame.empty_frame = QFrame()
        self._right_content_frame.layout().addWidget(self._right_content_frame.empty_frame)
        self._right_content_frame.layout().setCurrentWidget(self._right_content_frame.empty_frame)

    def _init_task_timer(self):
        self.__task_timer = QTimer(self)
        self.__task_timer.setInterval(50) # 0 avoids downtime but creates too much cpu load
        self.__task_timer.timeout.connect(self._task_queue_handler)
        self.__task_timer.start()

    def _init_status_bar(self):
        self._status_bar.showMessage("Initializing...")

    def _init_view(self):
        self._main_frame = QFrame()
        self._main_frame.setLayout(QVBoxLayout())
        self.setCentralWidget(self._main_frame)

    def _init_action_bar(self):
        exit_action = QAction('E&xit', self)
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

    def _init_search_frame(self):
        self._tool_bar = self.addToolBar('search')
        search_frame = QFrame()
        search_frame.setLayout(QVBoxLayout())
        self._tool_bar.setMovable(False)
        self._tool_bar.search_bar = QLineEdit()
        self._tool_bar.search_bar.setPlaceholderText('Search')
        self._tool_bar.search_bar.textEdited.connect(self.search)
        search_frame.layout().addWidget(self._tool_bar.search_bar)
        self._tool_bar.search_results = QListWidget()
        self._tool_bar.search_results.currentItemChanged.connect(self._select_search_result)
        search_frame.layout().addWidget(self._tool_bar.search_results)
        self._tool_bar.search_results.hide()
        self._tool_bar.addWidget(search_frame)

        self._tool_bar.search_options = QFrame()
        self._tool_bar.search_options.setLayout(QHBoxLayout())
        search_frame.layout().addWidget(self._tool_bar.search_options)
        self._tool_bar.search_options.button_group = QButtonGroup()
        self._tool_bar.search_options.radio_button_normal = QRadioButton('normal')
        self._tool_bar.search_options.radio_button_glob = QRadioButton('*auto-glob*')
        self._tool_bar.search_options.radio_button_glob_prefix = QRadioButton('*auto-glob')
        self._tool_bar.search_options.radio_button_glob_suffix = QRadioButton('auto-glob*')
        self._tool_bar.search_options.radio_button_fuzzy = QRadioButton('auto-fuzzy~')
        self._tool_bar.search_options.button_group.addButton(
            self._tool_bar.search_options.radio_button_normal)
        self._tool_bar.search_options.button_group.addButton(
            self._tool_bar.search_options.radio_button_glob)
        self._tool_bar.search_options.button_group.addButton(
            self._tool_bar.search_options.radio_button_glob_prefix)
        self._tool_bar.search_options.button_group.addButton(
            self._tool_bar.search_options.radio_button_glob_suffix)
        self._tool_bar.search_options.button_group.addButton(
            self._tool_bar.search_options.radio_button_fuzzy)
        self._tool_bar.search_options.layout().addWidget(
            self._tool_bar.search_options.radio_button_normal)
        self._tool_bar.search_options.layout().addWidget(
            self._tool_bar.search_options.radio_button_glob)
        self._tool_bar.search_options.layout().addWidget(
            self._tool_bar.search_options.radio_button_glob_prefix)
        self._tool_bar.search_options.layout().addWidget(
            self._tool_bar.search_options.radio_button_glob_suffix)
        self._tool_bar.search_options.layout().addWidget(
            self._tool_bar.search_options.radio_button_fuzzy)
        self._tool_bar.search_options.layout().addStretch(2**16)
        self._tool_bar.search_options.radio_button_glob_suffix.setChecked(True)
        self._tool_bar.search_options.button_group.buttonToggled.connect(self.search)
        self._tool_bar.search_options.hide()

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

    def _handle_task_status(self, status):
        logger = logging.getLogger(__name__)
        if status.running or status.blocked or status.pending or status.finished:
            logger.debug('_handle_task_status: status: %r', status)

        if status.running:
            message = f'{status.running[0]}'
        elif status.blocked:
            message = f'blocked: {status.blocked[0]}'
        elif status.pending:
            message = f'pending: {status.pending[0]}'
        elif status.finished:
            message = f'finished: {status.finished[0]}'
        else:
            # this does happen one task handling cylcle later than is could
            message = 'ready'
            #self.setDisabled(False)

        self._status_bar.showMessage(message)

    def _task_queue_handler(self):
        """
        Forwards the task queue, called by timer every run of the event loop
        """
        logger = logging.getLogger(__name__)
        self.__task_queue.run()
        self._handle_task_status(self.__task_queue.get_status())

        try:
            task = self.__task_queue.pop()
        except IndexError:
            return

        logger.debug('_task_queue_handler: task: %r', task)
        if task.failed:
            if task.error_handler:
                task.error_handler(task)
            else:
                self.show_error(f"{task.description} failed:\n{task.exception}")
                self.unhandled_tasks.append(task)
        else:
            if task.callback:
                task.callback(task)
            else:
                self.unhandled_task.append(task)
                logger.debug('unhandled_tasks: %r', self.unhandled_tasks)

    def queue_task(self, task):
        """
        add a task to the queue to be executed in order of priority
        """
        logger = logging.getLogger(__name__)
        logger.debug('queue_task: (%r)', task)
        #TODO implement task abortion to keep ui enabled
        #self.setDisabled(True)
        self.__task_queue.push(task)

    def create_password_store(self, password_store_root):
        """
        Create a new password store or show an error if unable to do so.
        Future version will ask the user if they want to clone a git repository instead.
        :param password_store_root: PathLike path of the root directory to create
        """
        if threading.main_thread() != threading.current_thread():
            raise Fail('MainWindow.create_password_store')

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
                    return PassFileSystem.clone_password_store(
                        password_store_root, repo_info, self.__config)
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
                return PassFileSystem.initialize_password_store(
                    password_store_root=password_store_root, config=self.config,
                    use_git=git_or_plain == 'git')
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
        if threading.main_thread() != threading.current_thread():
            raise Fail('MainWindow.get_user_key')

        logger = logging.getLogger(__name__)
        list_of_private_keys = list_available_keys(get_secret_keys=True)
        logger.debug('get_user_key: list_of_private_keys: %r', list_of_private_keys)

        try:
            user_key_id = self.__config['gpg']['user_key_id']
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
        self.__config['gpg']['user_key_id'] = user_key_id
        save_config(self.__config)
        return user_key_id

    def search(self):
        """
        search for the raw query written in the search bar and display possible results
        """
        if threading.main_thread() != threading.current_thread():
            raise Fail('MainWindow.search')

        # TODO decide wether this should be considered blocking for the UI
        logger = logging.getLogger(__name__)
        if not self._searcher:
            logger.debug('search: no searcher')
            return

        glob_prefix = (self._tool_bar.search_options.radio_button_glob.isChecked() or
                       self._tool_bar.search_options.radio_button_glob_prefix.isChecked())
        glob_suffix = (self._tool_bar.search_options.radio_button_glob.isChecked() or
                       self._tool_bar.search_options.radio_button_glob_suffix.isChecked())
        fuzzy = self._tool_bar.search_options.radio_button_fuzzy.isChecked()

        results = self._searcher.search(self._tool_bar.search_bar.text(),
                                        glob_prefix=glob_prefix,
                                        glob_suffix=glob_suffix,
                                        fuzzy=fuzzy)
        self._tool_bar.search_results.clear()
        self._tool_bar.search_results.dict = {}
        if len(results) > 0:
            for result in results:
                item_name = f'''{result['path']}/{result['name']}'''
                self._tool_bar.search_results.dict[item_name] = result
                self._tool_bar.search_results.addItem(item_name)
            self._tool_bar.search_results.show()
        else:
            self._tool_bar.search_results.hide()
        if len(self._tool_bar.search_bar.text()) > 0:
            self._tool_bar.search_options.show()
        else:
            self._tool_bar.search_options.hide()

    def clear_search(self):
        """
        clears the search bar and hides the result widget
        """
        if threading.main_thread() != threading.current_thread():
            raise Fail('MainWindow.clear_search')

        logger = logging.getLogger(__name__)
        logger.info('clear_search')

        self._tool_bar.search_bar.setText('')
        self._tool_bar.search_results.clear()
        self._tool_bar.search_results.hide()
        self._tool_bar.search_results.dict = {}

    def _select_search_result(self, current, previous):
        logger = logging.getLogger(__name__)
        logger.debug('_select_search_result: %r %r', current, previous)
        item_name = current.text()
        logger.debug('_select_search_result: %r', item_name)
        result = self._tool_bar.search_results.dict[item_name]
        self._tree.select_item(result['path'], result['name'])

    def create_new_search_index(self):
        """
        create a new search index from the password tree
        """
        if threading.main_thread() != threading.current_thread():
            raise Fail('MainWindow.create_new_search_index')

        logger = logging.getLogger(__name__)
        logger.info('create_new_search_index')

        self.clear_search()

        if not self._tree:
            logger.debug('create_new_search_index: no tree loaded')
            return

        def callback(task):
            self._searcher = task.result
            # Redo current search with new searcher
            self.search()

        def error_handler(task):
            self.show_error(f'{task.description}: {str(task.exception)}') # TODO proper error message

        task = Task(
            partial(self._create_new_search_index, self._tree),
            'Creating Search Index',
            TaskPriority.CREATE_SEARCH_INDEX,
            callback=callback,
            error_handler=error_handler,
            abortable=False # TODO set to True once that behaviour has been defined
            )
        logger.debug('create_new_search_index: %r', task)
        self.queue_task(task)

    @staticmethod
    def _create_new_search_index(tree):
        logger = logging.getLogger(__name__)
        logger.debug('_create_new_search_index')
        if not tree:
            logger.warning('_create_new_search_tree: task created without data')
            raise ValueError('None is not a valid Data Model')
        return PasswordSearch(file_system_tree=tree)

    def add_folder(self):
        """
        Adds a sub folder to the current folder.
        :return: None
        """
        if threading.main_thread() != threading.current_thread():
            raise Fail('MainWindow.add_folder')

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
            logger.debug('add_folder: tree: %r', self._tree)
            current_item = self._tree.currentItem()
            logger.debug('add_folder: current_item: %r', current_item)
            folder_path = current_item.file_system_path if current_item.isfile else str(
                Path(current_item.file_system_path, current_item.name))
            folder_name = folder_name_input.text()
            self._tree.file_system.create_folder(folder_path, folder_name)
            self._tree.refresh_tree()
            self._tree.select_item(folder_path, folder_name)

    def add_password(self):
        """
        Displays an add password dialog.
        :return: None
        """
        if threading.main_thread() != threading.current_thread():
            raise Fail('MainWindow.add_password')

        logger = logging.getLogger(__name__)

        optional_fields = []
        if 'attributes' in self.__config:
            optional_fields = list(map(lambda a: (a[0], '', a[1]),
                                       dict(self.__config['attributes']).items()))
            optional_fields.sort()
        logger.debug('add_password: optional_fields: %r', optional_fields)

        pass_dialog = PasswordDialog(optional_fields=optional_fields)
        if pass_dialog.exec_():
            logger.debug('add_password: tree: %r', self._tree)
            current_item = self._tree.currentItem()
            logger.debug('add_password: current_item: %r', current_item)
            if current_item.isdir:
                password_dir = path.join(current_item.file_system_path, current_item.name)
            else:
                password_dir = current_item.file_system_path
            password_file = pass_dialog.to_pass_file()
            try:
                self._tree.file_system.create_password_file(
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
                self._tree.refresh_tree()
                self.create_new_search_index()
                self._tree.select_item(path_to_folder=password_dir,
                                       name=pass_dialog.password_name_input.text())

    def refresh_password_store(self):
        """
        Refreshes the password store and reloads it.
        """
        if threading.main_thread() != threading.current_thread():
            raise Fail('MainWindow.refresh_password_store')

        #TODO rework password tree to use QFileSystemModel to see if refresh_tree can be dropped
        logger = logging.getLogger(__name__)
        logger.info('refresh_password_store')
        self._tree.refresh_tree()
        self.create_new_search_index()

    def reencrypt_files(self):
        """
        :return: None
        """
        if threading.main_thread() != threading.current_thread():
            raise Fail('MainWindow.reencrypt_files')

        logger = logging.getLogger(__name__)

        list_of_keys = self._user_list.get_checked_item_names()
        logger.debug('reencrypt_files: list_of_keys: %r', list_of_keys)
        if not list_of_keys:
            logger.info('reencrypt_files: no recipients selected')
            self.show_error('no recipients selected')
            return

        folder_path = path.join(self._tree.currentItem().file_system_path,
                                self._tree.currentItem().name)
        logger.info('reencrypt_files: folder_path: %r', folder_path)

        gpg_id_path = path.join(folder_path, '.gpg-id')
        logger.info('reencrypt_files: gpg_id_path: %r', gpg_id_path)

        try:
            write_gpg_id_file(gpg_id_path, list_of_keys)
            self._tree.file_system.recursive_reencrypt(folder_path, list_of_keys)
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
        if threading.main_thread() != threading.current_thread():
            raise Fail('MainWindow.show_error')

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
        self._main_frame.layout().insertWidget(0, error_widget)

    def show_right_frame_content(self, content_type, value=None):
        """
        set the content type of the frame to the right of the tree

        :param content_type: RightFrameContentType type of the content to show
        :param value: return value of PassFileSystem.handle
        """
        if threading.main_thread() != threading.current_thread():
            raise Fail('MainWindow.show_right_frame_content')

        if content_type == RightFrameContentType.EMPTY:
            self._right_content_frame.layout().setCurrentWidget(
                self._right_content_frame.empty_frame)
        elif content_type == RightFrameContentType.PASSWORD_VIEW:
            self._right_content_frame.layout().setCurrentWidget(self._password_browser_group)
            self._password_browser_group.load_pass_file(value)
        elif content_type == RightFrameContentType.RECIPIENT_VIEW:
            self._right_content_frame.layout().setCurrentWidget(self._user_list_group)
            self._user_list.refresh_recipients(value)
        else:
            raise ValueError("Invalid content type.")


def generate_key_dialog():
    """
    Show a dialog to collect data required for gpg private key generation and generate
    said key returning the id of the generated key.
    :return: string id of the generated key
    :throws ValueError: on gpg error (also when the user aborts the passphrase dialog)
    """
    if threading.main_thread() != threading.current_thread():
        raise Fail('ui.generate_key_dialog')

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


def __setup_debugging(user_config):
    log_level = {
        'debug': logging.DEBUG,
        'info': logging.INFO,
        'warn': logging.WARN,
        'warning': logging.WARNING,
        'error': logging.ERROR,
        'fatal': logging.FATAL,
        'critical': logging.CRITICAL
    }.get(user_config.get('logging', 'log_level', fallback='info'), logging.INFO)

    config_flag_actions = [
        ('debug', 'git', enable_git_debug_logging),
        ('debug', 'gpg', enable_gpg_debug_logging),
        ('debug', 'search', enable_search_debug_logging),
        ('debug', 'file_format', enable_file_format_debug_logging),
        ('debug', 'file_system', enable_file_system_debug_logging),
        ('debug', 'tree_view', enable_tree_view_debug_logging),
        ('debug', 'recipient_view', enable_recipient_view_debug_logging),
        ('debug', 'password_view', enable_password_view_debug_logging),
        ('debug', 'password_dialog', enable_password_dialog_debug_logging),
        ('debug', 'task_queue', enable_task_queue_debug_logging),
        ('debug', 'decoder', enable_decoder_debug_logging),
        ]

    for section, key, action in config_flag_actions:
        try:
            if user_config.getboolean(section, key, fallback=False):
                action()
        except ValueError:
            pass

    file_name = user_config.get('logging', 'file_name', fallback=None)
    file_mode = user_config.get('logging', 'file_mode', fallback='w') if file_name else None
    log_handler = user_config.get('logging', 'log_handler', fallback=None)

    if log_handler:
        address, port = log_handler.split(' ')
        address = ip_address(address)
        log_handler = SocketHandler(str(address), port)

        logging.basicConfig(level=log_level, handlers=[log_handler])
    else:
        logging.basicConfig(level=log_level, filename=file_name, filemode=file_mode)


def apply_dark_mode(app):
    app.setStyle('Fusion')
    palette = QPalette()
    palette.setColor(QPalette.Window, QColor(53, 53, 53))
    palette.setColor(QPalette.WindowText, Qt.white)
    palette.setColor(QPalette.Disabled, QPalette.WindowText, QColor(127, 127, 127))
    palette.setColor(QPalette.Base, QColor(42, 42, 42))
    palette.setColor(QPalette.AlternateBase, QColor(66, 66, 66))
    palette.setColor(QPalette.ToolTipBase, Qt.white)
    palette.setColor(QPalette.ToolTipText, Qt.white)
    palette.setColor(QPalette.Text, Qt.white)
    palette.setColor(QPalette.Disabled, QPalette.Text, QColor(127, 127, 127))
    palette.setColor(QPalette.Dark, QColor(35, 35, 35))
    palette.setColor(QPalette.Shadow, QColor(20, 20, 20))
    palette.setColor(QPalette.Button, QColor(53, 53, 53))
    palette.setColor(QPalette.ButtonText, Qt.white)
    palette.setColor(QPalette.Disabled, QPalette.ButtonText, QColor(127, 127, 127))
    palette.setColor(QPalette.BrightText, Qt.red)
    palette.setColor(QPalette.Link, QColor(42, 130, 218))
    palette.setColor(QPalette.Highlight, QColor(42, 130, 218))
    palette.setColor(QPalette.Disabled, QPalette.Highlight, QColor(80, 80, 80))
    palette.setColor(QPalette.HighlightedText, Qt.white)
    palette.setColor(QPalette.Disabled, QPalette.HighlightedText, QColor(127, 127, 127))
    app.setPalette(palette)


def apply_app_settings(user_config, app):
    if user_config.get('ui', 'dark_mode', fallback=False):
        apply_dark_mode(app)


def main():
    """
    runs the application
    """
    user_config = get_user_config()

    __setup_debugging(user_config)

    try:
        password_store_root = user_config['general']['password_store_root']
    except KeyError:
        password_store_root = Path('~/.password-store').expanduser()

    app = QApplication(argv)
    apply_app_settings(user_config, app)
    window = MainWindow(password_store_root)
    window.setWindowTitle('Keyswarm')
    window.resize(800, 600)
    window.show()
    sys_exit(app.exec_())


if __name__ == '__main__':
    main()
