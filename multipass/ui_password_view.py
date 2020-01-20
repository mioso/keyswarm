from PySide2.QtWidgets import QGroupBox, QTextBrowser, QLabel, QLineEdit, QGridLayout, QPushButton
from .pass_clipboard import copy


class PasswordView(QGroupBox):
    """
    A group box that displays a PassFile
    """
    def __init__(self, pass_file_object=None):
        QGroupBox.__init__(self)
        self.setLayout(QGridLayout())
        welcome_message = QTextBrowser()
        welcome_message.setText('Leeloo Dallas - Multipass!')
        self.layout().addWidget(welcome_message, 0, 0)
        self.setTitle('Password Details')
        self.pass_file = None
        if pass_file_object:
            self.load_pass_file(pass_file_object)

    def load_pass_file(self, pass_file_object):
        """
        populates the window with pass_file data
        :param pass_file_object: a PassFile
        :return: None
        """
        self.clear()
        self.pass_file = pass_file_object
        password_field_label = QLabel('password')
        password_field = QLineEdit()
        password_field.setEchoMode(QLineEdit.EchoMode(2))
        password_field.setDisabled(True)
        copy_password_button = QPushButton('copy')
        copy_password_button.clicked.connect(self.copy_password)
        self.layout().addWidget(password_field_label, 0, 0)
        self.layout().addWidget(password_field, 0, 1)
        self.layout().addWidget(copy_password_button, 0, 2)
        password_field.setText(self.pass_file.password)
        for key, value in self.pass_file.attributes:
            current_grid_view_row = self.layout().rowCount()
            additional_field_label = QLabel(key)
            additional_field = QLineEdit()
            self.layout().addWidget(additional_field_label, current_grid_view_row + 1, 0)
            self.layout().addWidget(additional_field, current_grid_view_row + 1, 1)
            additional_field.setText(value)
        comment_browser_label = QLabel('comments')
        comment_browser = QTextBrowser()
        self.layout().addWidget(comment_browser_label, self.layout().rowCount() + 1, 0)
        self.layout().addWidget(comment_browser, self.layout().rowCount(), 1)
        comment_browser.setPlainText(self.pass_file.comments)

    def clear(self):
        """
        deletes all widgets from the PasswordView
        :return: None
        """
        for i in reversed(range(self.layout().count())):
            self.layout().itemAt(i).widget().setParent(None)

    def copy_password(self):
        """
        copy password handler
        :return: None
        """
        copy(self.pass_file.password)
