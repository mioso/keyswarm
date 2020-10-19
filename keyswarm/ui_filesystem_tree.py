"""
This module provides a pass file system tree as extension of a QTreeWidget.
No separation of ui and data so far.
"""

from functools import partial
import logging
from os import path, listdir
from pathlib import PurePath
import threading

# pylint: disable=no-name-in-module
from PySide2.QtWidgets import QAbstractItemView, QTreeWidget, QTreeWidgetItem
from PySide2.QtCore import Qt
# pylint: enable=no-name-in-module

from .git_handler import GitError
from .pass_file_format_parser import PassFile
from .task_queue import Task, TaskPriority
from .types import RightFrameContentType

from .fail_always import Fail


logging.getLogger(__name__).setLevel(logging.INFO)
def enable_tree_view_debug_logging():
    """ enable tree view debug logging """
    logging.getLogger(__name__).setLevel(logging.DEBUG)

class PassUIFileSystemItem(QTreeWidgetItem):
    """
    A Node in the Pass tree
    """

    def __init__(self, file_system_path, name):
        QTreeWidgetItem.__init__(self)

        if threading.main_thread() != threading.current_thread():
            Fail('PassUIFileSystemItem.__init__')

        self.file_system_path = file_system_path
        self.name = name
        self.isdir = path.isdir(path.join(file_system_path, name))
        self.isfile = path.isfile(path.join(file_system_path, name))
        if not name == '':
            self.setText(0, name)
        else:
            self.setText(0, file_system_path)
        if self.isdir:
            flags = self.flags()
            new_flags = flags | Qt.ItemIsDragEnabled
            new_flags |= Qt.ItemIsDropEnabled
            self.setFlags(new_flags)
        if self.isfile:
            flags = self.flags()
            new_flags = flags | Qt.ItemIsDragEnabled
            new_flags &= ~Qt.ItemIsDropEnabled
            self.setFlags(new_flags)

    def __repr__(self):
        return (f'PassUIFileSystemItem(file_system_path={repr(self.file_system_path)}, '
                f'name={repr(self.name)})')

    def __str__(self):
        return self.__repr__()

    def __eq__(self, other):
        try:
            return self.file_system_path == other.file_system_path and self.name == other.name
        except AttributeError:
            return NotImplemented

    def __ne__(self, other):
        return not self == other


class PassUiFileSystemTree(QTreeWidget):
    """
    A Pass UI Tree representing the pass Filesystem
    """
    def __init__(self, root, config, queue_functor):
        QTreeWidget.__init__(self)

        if threading.main_thread() != threading.current_thread():
            Fail('PassUiFileSystemTree.__init__')

        self.__root = str(root)
        self.__config = config
        self.__queue_functor = queue_functor
        self.__file_system = None
        self.__current_item = None
        self.setHeaderLabel('PasswordStore')
        self.setSelectionMode(QAbstractItemView.SingleSelection)
        self.setDragDropMode(QAbstractItemView.InternalMove)
        self.setDropIndicatorShown(True)
        self.setDragEnabled(True)
        self.refresh_tree()
        self.setStyleSheet('QTreeView {qproperty-animated: true;}')
        self.itemSelectionChanged.connect(self.on_item_selection_changed)

    def __repr__(self):
        return f'PassUiFileSystemTree(root={repr(self.__root)})'

    @property
    def file_system(self):
        return self.__file_system

    def connect_to_file_system(self, file_system):
        if threading.main_thread() != threading.current_thread():
            Fail('PassUiFileSystemTree.connect_to_file_system')

        self.__file_system = file_system
        self.refresh_tree()

    def refresh_tree(self):
        """
        recursively refreshes PassUIFileSystem Tree to match its Filessystem representation.
        :return: None
        """
        if threading.main_thread() != threading.current_thread():
            Fail('PassUiFileSystemTree.refresh_tree')

        logger = logging.getLogger(__name__)

        if not self.__file_system:
            logger.debug("refresh_tree: not file system")
            return

        def tmp_callback(task):
            logger.debug('tmp_callback: %r', task)
            self.__refresh_tree()

        task = Task(
            self.__file_system.refresh_password_store,
            "Refreshing Password Store",
            TaskPriority.GIT_PULL,
            callback=tmp_callback,
            error_handler=None,
            abortable=False # Don't abort git calls
            )

        logger.debug('refresh_tree: %r', task)
        self.__queue_functor(task)

    def __refresh_tree(self, node=None):
        logger = logging.getLogger(__name__)
        logger.debug('__refresh_tree: %r', node)
        root_node = False
        if not node:
            logger.info('__refresh_tree')
            root_node = True
            node = PassUIFileSystemItem(self.__root, '')
            self.invisibleRootItem().takeChildren()
            self.addTopLevelItem(node)
            node.setExpanded(True)
        file_system_path = path.join(node.file_system_path, node.name)
        for filesystem_item in listdir(file_system_path):
            if filesystem_item[0] != '.':
                child_node = PassUIFileSystemItem(file_system_path, filesystem_item)
                child_node.setText(0, filesystem_item.replace('.gpg', ''))
                node.addChild(child_node)
                if child_node.isdir:
                    self.__refresh_tree(child_node)
                    child_node.setExpanded(self.__config.get('ui', 'expand_tree', fallback=False))
        if root_node:
            self.sortItems(0, Qt.SortOrder(0))
            self.setCurrentItem(self.topLevelItem(0))

    def select_item(self, path_to_folder, name):
        """
        select a specific item in the tree
        :param path_to_folder: PathLike path to the folder containing the item
        :param name: string name of the item
        """
        if threading.main_thread() != threading.current_thread():
            Fail('PassUiFileSystemTree.select_item')

        logger = logging.getLogger(__name__)
        logger.debug('select_item: path_to_folder: %r', path_to_folder)
        logger.debug('select_item: name: %r', name)
        logger.debug('select_item: self: %r', self)
        node = self.topLevelItem(0)
        logger.debug('select_item: node: %r', node)
        logger.debug('select_item: root: %r', self.__root)
        if not node:
            return
        path_ = PurePath(path_to_folder.replace(self.__root, ''))
        parts = path_.parts
        logger.debug('select_item: path_: %r', path_)
        logger.debug('select_item: parts: %r', parts)
        if parts and parts[0] == path_.root:
            parts = parts[1:]
        logger.debug('select_item: cleaned(parts): %r', parts)

        node_found = False
        for part in parts:
            logger.debug('select_item: part: %r', part)
            for i in range(node.childCount()):
                child = node.child(i)
                logger.debug('select_item: node.child(%d): %r', i, child)
                if child.name == part:
                    logger.debug('select_item: found child, descending')
                    node_found = True
                    node = child
                    break

        if node_found or not parts:
            logger.debug('select_item: final node: %r', node)
            for i in range(node.childCount()):
                child = node.child(i)
                logger.debug('select_item: node.child(%d): %r', i, child)
                if (child.isfile and child.name == f'{name}.gpg') or (
                        child.isdir and child.name == name):
                    logger.debug('select_item: found entry, selecting')
                    self.setCurrentItem(child)
                    return

        logger.warning('select_item: tree does not match path: node not found')
        self.setCurrentItem(self.topLevelItem(0))

    def on_item_selection_changed(self):
        """
        handles ui item selection changed events
        :return: None
        """
        if threading.main_thread() != threading.current_thread():
            Fail('PassUiFileSystemTree.on_item_selection_changed')

        logger = logging.getLogger(__name__)
        item = self.currentItem()
        self.__current_item = item
        if not item:
            logger.debug('on_item_selection_changed: no item')
            return
        if not self.__file_system:
            logger.debug('on_item_selection_changed: no file system')
            return

        def callback_(task):
            if not task.result:
                #TODO avoid self.window()
                self.window().show_right_frame_content(RightFrameContentType.EMPTY)
                return

            if isinstance(task.result, PassFile):
                #TODO avoid self.window()
                self.window().show_right_frame_content(
                    RightFrameContentType.PASSWORD_VIEW,
                    value=task.result)
                return

            #TODO avoid self.window()
            self.window().show_right_frame_content(
                RightFrameContentType.RECIPIENT_VIEW,
                value=task.result)

        def error_handler(task):
            if isinstance(task.exception, ValueError):
                logger.debug(task.exception)
            elif isinstance(task.exception, TimeoutError):
                logger.debug('Selection Timeout')
            else:
                logger.warning(task.exception)
            #TODO avoid self.window()
            self.window().show_right_frame_content(RightFrameContentType.EMPTY)

        task = Task(
            partial(self._on_item_selection_changed, item),
            f'Retrieving information for {item.file_system_path}',
            TaskPriority.FILE_SYSTEM_HANDLE,
            callback=callback_,
            error_handler=error_handler)

        self.__queue_functor(task)

    def _on_item_selection_changed(self, item):
#        if item != self.__current_item:
#            raise TimeoutError
        return self.__file_system.handle(item.file_system_path, item.name)

    # pylint: disable=invalid-name
    def dropEvent(self, event):
        """
        Qt drop event handler
        """
        if threading.main_thread() != threading.current_thread():
            Fail('PassUiFileSystemTree.dropEvent')

        logger = logging.getLogger(__name__)
        logger.debug('PassUiFileSystemTree: dropEvent: event.pos(): %r', event.pos())
        logger.debug('PassUiFileSystemTree: dropEvent: event.source(): %r', event.source())
        logger.debug('PassUiFileSystemTree: dropEvent: event.proposedAction(): %r',
                     event.proposedAction())
        logger.debug('PassUiFileSystemTree: dropEvent: event.possibleActions(): %r',
                     int(event.possibleActions()))
        logger.debug('PassUiFileSystemTree: dropEvent: self.itemAt(event.pos()): %r',
                     self.itemAt(event.pos()))
        logger.debug('PassUiFileSystemTree: dropEvent: self.selectedItems(): %r',
                     self.selectedItems())

        if not self.__file_system:
            logger.debug('dropEvent: no file system')
            return

        try:
            dragged_item = self.selectedItems()[0]
            drop_target = self.itemAt(event.pos())
            name = dragged_item.name.replace('.gpg', '')
            source_folder = dragged_item.file_system_path
            target_folder = drop_target.file_system_path if drop_target.isfile else str(
                PurePath(drop_target.file_system_path, drop_target.name))

            logger.debug('PassUiFileSystemTree: dropEvent: dragged_item: %r', dragged_item)
            logger.debug('PassUiFileSystemTree: dropEvent: drop_target: %r', drop_target)
            logger.debug('PassUiFileSystemTree: dropEvent: name: %r', name)
            logger.debug('PassUiFileSystemTree: dropEvent: source_folder: %r', source_folder)
            logger.debug('PassUiFileSystemTree: dropEvent: target_folder: %r', target_folder)

            if dragged_item.isfile:
                self.__file_system.move_password_file(
                    path_to_old_folder=source_folder, old_name=name,
                    path_to_new_folder=target_folder, new_name=name)
            else:
                self.__file_system.move_password_folder(
                    path_to_old_parent_folder=source_folder, old_name=name,
                    path_to_new_parent_folder=target_folder, new_name=name)
        except GitError as error:
            self.window().show_error(error.__repr__())
        except IndexError as error:
            logger.warning('PassIoFileSystemTree: dropEvent: %r', error)
        except ValueError as error:
            logger.warning('PassIoFileSystemTree: dropEvent: %r', error)
        finally:
            self.refresh_tree()
            self.select_item(target_folder, name)
