"""
this module provides an interface to files in the format used by pass
"""

from re import search, compile as re_compile
from os import path
import logging

from .gpg_handler import decrypt


class PassFile():
    """
    A representation of a pass file.
    """
    def __init__(self, root_path=None, name=None):
        logger = logging.getLogger(__name__)
        logger.debug('PassFile.__init__: %r %r)', root_path, name)
        try:
            regex = re_compile(r'^(.*)\.gpg$')
            match = regex.match(name)
            self.name = match.group(1)
        except (IndexError, TypeError):
            self.name = name
        logger.debug('PassFile.__init__: self.name: %r', self.name)
        self.root_path = root_path
        gpg_file = path.join(root_path, name) if name and root_path else None
        self.file = gpg_file
        self.password = ''
        self.attributes = []
        self.comments = ''
        if gpg_file:
            lines = decrypt(gpg_file).split('\n')
            self.password = lines.pop(0)
            logger.debug('PassFile.__init__: lines: %r', lines)
            try:
                while search(r'^.*:.*$', lines[0]):
                    line = lines[0].split(':', maxsplit=1)
                    attribute_key = line[0]
                    attribute_value = line[1]
                    self.attributes.append((attribute_key, attribute_value))
                    lines.pop(0)
            except IndexError:
                pass
            logger.debug('PassFile.__init__: self.attributes: %r', self.attributes)
            self.comments = '\n'.join(lines)
            logger.debug('PassFile.__init__: self.comments: %r', self.comments)

    def __repr__(self):
        return f'PassFile(root_path={repr(self.root_path)}, name={repr(self.name)})'

    def get_cleartext(self):
        """
        :return: string - cleartext data of a Password file
        """
        output = None
        if self.password != '':
            output = '{password}\n'.format(password=self.password)
        if self.attributes:
            for key, value in self.attributes:
                attribute = '{key}:{value}'.format(key=key, value=value)
                output = '{output}{attribute}\n'.format(output=output, attribute=attribute)
        if self.comments != '':
            output = '{output}{comments}'.format(output=output, comments=self.comments)
        if output:
            return output
        raise ValueError

    def __str__(self):
        return self.get_cleartext()
