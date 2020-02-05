from re import search, compile
from os import path
from .gpg_handler import decrypt


class PassFile(object):
    """
    A representation of a pass file.
    """
    def __init__(self, root_path=None, name=None):
        try:
            r = compile('^(.*)\.gpg$')
            m = r.match(name)
            self.name = m.group(1)
        except:
            self.name = name
        gpg_file = path.join(root_path, name) if name and root_path else None
        self.file = gpg_file
        self.password = str()
        self.attributes = list()
        self.comments = str()
        if gpg_file:
            lines = decrypt(gpg_file).split('\n')
            self.password = lines.pop(0)
            while search(r'^.*:.*$', lines[0]):
                line = lines[0].split(':', maxsplit=1)
                attribute_key = line[0]
                attribute_value = line[1]
                self.attributes.append((attribute_key, attribute_value))
                lines.pop(0)
            self.comments = '\n'.join(lines)

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
        else:
            raise ValueError

    def __str__(self):
        return self.get_cleartext()
