from string import digits, ascii_letters, punctuation
from secrets import choice


def random_password(size=50, alphabet=ascii_letters + digits + punctuation):
    """
    generate a random password
    :param size: int - password length
    :param alphabet: list - of characters
    :return: string
    """
    return ''.join(choice(alphabet) for x in range(size))
