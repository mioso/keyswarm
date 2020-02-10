from PySide2.QtWidgets import QTreeWidget, QTreeWidgetItem
from PySide2.QtCore import Qt
from os import path, listdir
from .pass_file_system import handle
from pathlib import PurePath
from re import match
import logging

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

    def __repr__(self):
        return f'PassUIFileSystemItem(file_system_path={repr(self.file_system_path)}, name={repr(self.name)})'

class PassUiFileSystemTree(QTreeWidget):
    """
    A Pass UI Tree representing the pass Filesystem
    """
    def __init__(self, root):
        QTreeWidget.__init__(self)
        self.root = root
        self.setHeaderLabel('PasswordStore')
        self.refresh_tree()

    def __repr__(self):
        return f'PassUiFileSystemTree(root={repr(self.root)})'

    def refresh_tree(self, node=None):
        """
        recursively refreshes PassUIFileSystem Tree to match its Filessystem representation.
        :param node: Node to start with
        :return: None
        """
        if not node:
            node = PassUIFileSystemItem(self.root, '')
            self.invisibleRootItem().takeChildren()
            self.addTopLevelItem(node)
            node.setExpanded(True)
        file_system_path = path.join(node.file_system_path, node.name)
        for filesystem_item in listdir(file_system_path):
            if filesystem_item != '.gpg-id' and filesystem_item != '.cfg':
                child_node = PassUIFileSystemItem(file_system_path, filesystem_item)
                child_node.setText(0, filesystem_item.replace('.gpg', ''))
                node.addChild(child_node)
                if child_node.isdir:
                    self.refresh_tree(child_node)
                    child_node.setExpanded(True)
        self.sortItems(0, Qt.SortOrder(0))

    def select_item(self, path_to_folder, name):
        logger = logging.getLogger(__name__)
        logger.debug('select_item: path_to_folder: %r', path_to_folder)
        logger.debug('select_item: name: %r', name)
        logger.debug('select_item: self: %r', self)
        node = self.topLevelItem(0)
        logger.debug('select_item: node: %r', node)
        path = PurePath(path_to_folder.replace(self.root, ''))
        parts = path.parts
        logger.debug('select_item: path: %r', path)
        logger.debug('select_item: parts: %r', parts)
        if parts[0] == path.root:
            parts = parts[1:]
        logger.debug('select_item: cleaned(parts): %r', parts)
        for part in parts:
            logger.debug('select_item: part: %r', part)
            old_node = node
            for i in range(node.childCount()):
                child = node.child(i)
                logger.debug('select_item: node.child(%d): %r', i, child)
                if child.name == part:
                    logger.debug('select_item: found child, descending')
                    node = child
                    break

        logger.debug('select_item: final node: %r', node)
        for i in range(node.childCount()):
            child = node.child(i)
            logger.debug('select_item: node.child(%d): %r', i, child)
            if child.name == f'{name}.gpg':
                logger.debug('select_item: found entry, selecting')
                self.setCurrentItem(child)
                break

    def on_item_selection_changed(self):
        """
        handles ui item selection changed events
        :return: None
        """
        value = handle(self.currentItem().file_system_path, self.currentItem().name)
        if not value:
            return
        if self.currentItem().isfile:
            self.window().user_list_group.hide()
            self.window().password_browser_group.show()
            self.parentWidget().parentWidget().password_browser_group.load_pass_file(value)
        elif self.currentItem().isdir:
            self.window().user_list_group.show()
            self.window().password_browser_group.hide()
            self.parentWidget().parentWidget().user_list.refresh_recipients(value)
