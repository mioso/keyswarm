from PySide2.QtWidgets import QTreeWidget, QTreeWidgetItem
from PySide2.QtCore import Qt
from os import path, listdir
from .pass_file_system import handle
from re import match


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


class PassUiFileSystemTree(QTreeWidget):
    """
    A Pass UI Tree representing the pass Filesystem
    """
    def __init__(self, root):
        QTreeWidget.__init__(self)
        self.root = root
        self.setHeaderLabel('PasswordStore')
        self.refresh_tree()

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

    def on_item_selection_changed(self):
        """
        handles ui item selection changed events
        :return: None
        """
        value = handle(self.currentItem().file_system_path, self.currentItem().name)
        if self.currentItem().isfile:
            self.window().user_list_group.hide()
            self.window().password_browser_group.show()
            self.parentWidget().parentWidget().password_browser_group.load_pass_file(value)
        elif self.currentItem().isdir:
            self.window().user_list_group.show()
            self.window().password_browser_group.hide()
            self.parentWidget().parentWidget().user_list.refresh_recipients(value)
