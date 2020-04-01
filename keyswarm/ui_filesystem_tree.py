"""
This module provides a pass file system tree as extension of a QTreeWidget.
No separation of ui and data so far.
"""

import logging
from os import path, listdir
from pathlib import PurePath

# pylint: disable=no-name-in-module
from PySide2.QtWidgets import QAbstractItemView, QTreeWidget, QTreeWidgetItem, QMainWindow
from PySide2.QtCore import Qt
from .pass_file_system import PassFileSystem

class PassUIFileSystemItem(QTreeWidgetItem):
    """
    A Node in the Pass tree
    """

    def __init__(self, file_system_path, name):
        QTreeWidgetItem.__init__(self)
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


class PassUiFileSystemTree(QTreeWidget):
    """
    A Pass UI Tree representing the pass Filesystem
    """
    def __init__(self, root, config, file_system=None):
        QTreeWidget.__init__(self)
        self.root = str(root)
        self.config = config
        self.file_system = file_system or PassFileSystem(root, config=config)
        self.setHeaderLabel('PasswordStore')
        self.setSelectionMode(QAbstractItemView.SingleSelection)
        self.setDragDropMode(QAbstractItemView.InternalMove)
        self.setDropIndicatorShown(True)
        self.setDragEnabled(True)
        self.refresh_tree()

    def __repr__(self):
        return f'PassUiFileSystemTree(root={repr(self.root)})'

    def refresh_tree(self, node=None):
        """
        recursively refreshes PassUIFileSystem Tree to match its Filessystem representation.
        :param node: Node to start with
        :return: None
        """
        logger = logging.getLogger(__name__)
        logger.debug('refresh_tree: %r', self)
        logger.debug('refresh_tree: %r', self.window())
        root_node = False
        if not node:
            root_node = True
            node = PassUIFileSystemItem(self.root, '')
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
                    self.refresh_tree(child_node)
                    child_node.setExpanded(True)
        if root_node:
            self.sortItems(0, Qt.SortOrder(0))
            window = self.window()
            if isinstance(window, QMainWindow):
                window.clear_search()

    def select_item(self, path_to_folder, name):
        """
        select a specific item in the tree
        :param path_to_folder: PathLike path to the folder containing the item
        :param name: string name of the item
        """
        logger = logging.getLogger(__name__)
        logger.debug('select_item: path_to_folder: %r', path_to_folder)
        logger.debug('select_item: name: %r', name)
        logger.debug('select_item: self: %r', self)
        node = self.topLevelItem(0)
        logger.debug('select_item: node: %r', node)
        logger.debug('select_item: root: %r', self.root)
        path_ = PurePath(path_to_folder.replace(self.root, ''))
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
        logger = logging.getLogger(__name__)
        value = None
        try:
            value = self.file_system.handle(self.currentItem().file_system_path,
                                            self.currentItem().name)
            logger.debug('on_item_selection_changed: value: %r', value)
        except ValueError:
            self.window().right_content_frame.layout().setCurrentWidget(
                self.window().right_content_frame.empty_frame)
            return
        if value is None:
            self.window().right_content_frame.layout().setCurrentWidget(
                self.window().right_content_frame.empty_frame)
            return
        if self.currentItem().isfile:
            self.window().right_content_frame.layout().setCurrentWidget(
                self.window().password_browser_group)
            self.window().password_browser_group.load_pass_file(value)
        elif self.currentItem().isdir:
            self.window().right_content_frame.layout().setCurrentWidget(
                self.window().user_list_group)
            self.window().user_list.refresh_recipients(value)
        else:
            logger.warning('on_item_selection_changed: selection is neither file nor directory: %r',
                           self.currentItem())

    # pylint: disable=invalid-name
    def dropEvent(self, event):
        """
        Qt drop event handler
        """
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
                self.file_system.move_password_file(
                    path_to_old_folder=source_folder, old_name=name,
                    path_to_new_folder=target_folder, new_name=name)
            else:
                self.file_system.move_password_folder(
                    path_to_old_parent_folder=source_folder, old_name=name,
                    path_to_new_parent_folder=target_folder, new_name=name)

            self.refresh_tree()
            self.select_item(target_folder, name)
        except IndexError as error:
            logger.warning('PassIoFileSystemTree: dropEvent: %r', error)
        except ValueError as error:
            logger.warning('PassIoFileSystemTree: dropEvent: %r', error)
