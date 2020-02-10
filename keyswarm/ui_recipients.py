from PySide2.QtWidgets import QListWidget, QListWidgetItem
from PySide2.QtCore import Qt
from .gpg_handler import list_available_keys


class Recipient(QListWidgetItem):
    def __init__(self, name, ischecked=False, enabled=True):
        QListWidgetItem.__init__(self)
        self.setText(name)
        self.setFlags(self.flags() | Qt.ItemIsUserCheckable)
        if ischecked:
            self.setCheckState(Qt.Checked)
        else:
            self.setCheckState(Qt.Unchecked)
        if not enabled:
            self.setFlags(Qt.ItemIsUserCheckable)

    def __repr__(self):
        return f'Recipient(name={repr(self.text())}, ischecked={repr(self.checkState())}, enabled={repr(self.flags(Qt.ItemIsUserCheckable))}'


class RecipientList(QListWidget):
    def __init__(self):
        QListWidget.__init__(self)

    def add_recipients(self, list_of_recipient_data):
        for recipient_data in list_of_recipient_data:
            name, checked, enabled = recipient_data
            self.addItem(Recipient(name, checked, enabled))

    def refresh_recipients(self, list_of_recipients):
        self.clear()
        keys_available = list_available_keys()
        for key in keys_available:
            if key in list_of_recipients:
                self.add_recipients([(key, True, True)])
            else:
                self.add_recipients([(key, False, True)])
        for key in list_of_recipients:
            if key not in keys_available:
                self.add_recipients([(key, True, False)])

    def get_checked_item_names(self):
        list_of_key_ids_to_return = []
        for i in range(0, self.count()):
            item = self.item(i)
            if item.checkState():
                list_of_key_ids_to_return.append(item.text())
        return list_of_key_ids_to_return
