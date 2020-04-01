"""
Git branch names and filenames are not utf-8 and different systems may handle them differently.

Many systems use the C char type for names and do some filtering on them.
Git names restrict the usage of some ASCII characters in branch names.
Not all character are fine for filenames.

This module describes what an acceptable file/branch name is in the context of this application.

There are functions for checking names and for replacing invalid characters with underscores.
These functions are ment to check/modify user provided file names that were recieved via the
add/edit folder/password dialogs, not for the resulting actual filename.
"""

import logging

# after checking up on commonly used filesystems the length limit seems to be 255 bytes
# we need to reserve at least 4 bytes for the '.gpg' file extension
# arbitrarily reserving some more bytes just in case we limit the name to 240 bytes
NAME_BYTE_LIMIT = 240

FILENAME_CHARACTER_WHITELIST = set((
    ' !#$%^&()+,-.'
    '0123456789;='
    '@ABCDEFGHIJKLMNO'
    'PQRSTUVWXYZ[]^_'
    '`abcdefghijklmno'
    'pqrstuvwxyz{}~'
))

# only lowercase
FILENAME_PREFIX_BLACKLIST = set([
    '.'
])

# only lowercase
FILENAME_SUFFIX_BLACKLIST = set([
    '.gpg'
])

# only lowercase
FILENAME_NAME_BLACKLIST = set([
    #'.',
    #'..',
    '.git',
    '.available-keys'
    '.gpg-id'
])

FILENAME_SEQUENCE_BLACKLIST = set()


GIT_CHARACTER_WHITELIST = set((
    '!#$%&()+,-.'
    '0123456789;='
    '@ABCDEFGHIJKLMNO'
    'PQRSTUVWXYZ]_'
    '`abcdefghijklmno'
    'pqrstuvwxyz{}'
))

GIT_SEQUENCE_BLACKLIST = set([
    '..',
    '@{'
])

# only lowercase
GIT_PREFIX_BLACKLIST = set([
    '-',
    '.'
])

# only lowercase
GIT_SUFFIX_BLACKLIST = set([
    '.',
    '.lock'
])

# only lowercase
GIT_NAME_BLACKLIST = set([
    #'.',
    #'..',
])


def has_valid_length(name):
    """
    a valid name needs to have at least one character and be within the limits of the filesystem

    with utf-8 the length in bytes is not necessacily the amount of characters but since
    we limit names to certain whitelisted ascii characters it actually is but just in case
    we whitelist more characters in the future this implementation will encode the name as
    utf-8 and use len on the resulting bytes instead of using len directly

    :param name: string
    :return: boolean
    """
    return 0 < len(name.encode('utf-8')) <= NAME_BYTE_LIMIT


def is_valid_name(name, name_blacklist, character_whitelist,
                  prefix_blacklist, suffix_blacklist, sequence_blacklist):
# pylint: disable=too-many-arguments
# pylint: disable=too-many-return-statements
    """
    checks wether a given unicode name is valid ascii, is not on a blacklist,
    only contains characters on a whitelist, does not start with a blacklisted
    prefix, does not end with a blacklisted suffix and does not contain a
    blacklisted sequence

    :param name: string
    :param name_blacklist: set(string) set of blacklisted names
    :param character_whitelist: set(character) set of valid ascii characters
    :param prefix_blacklist: set(string) set of blacklisted prefixes
    :param suffix_blacklist: set(string) set of blacklisted suffixes
    :return: boolean
    """
    # because case insensitive filesystems
    lower_name = name.lower()

    try:
        if not has_valid_length(name) or not has_valid_length(lower_name):
            return False
        lower_name.encode('ascii')
    except UnicodeEncodeError:
        return False

    if lower_name in name_blacklist:
        return False

    invalid_characters = set(lower_name).difference(character_whitelist)
    if invalid_characters:
        return False

    for prefix in prefix_blacklist:
        if lower_name.startswith(prefix):
            return False

    for suffix in suffix_blacklist:
        if lower_name.endswith(suffix):
            return False

    for sequence in sequence_blacklist:
        try:
            lower_name.index(sequence)
            return False
        except ValueError:
            pass

    return True


def is_valid_file_name(name):
    """
    checks wether a given user provided unicode name is valid
    as a filename in the context of this application

    :param name: string
    :return: boolean
    """
    return is_valid_name(name, FILENAME_NAME_BLACKLIST, FILENAME_CHARACTER_WHITELIST,
                               FILENAME_PREFIX_BLACKLIST, FILENAME_SUFFIX_BLACKLIST,
                               FILENAME_SEQUENCE_BLACKLIST)


def is_valid_branch_name(name):
    """
    checks wether a given user provided unicode name is valid as part of a git branch name

    :param name: string
    :return: boolean
    """
    return is_valid_name(name, GIT_NAME_BLACKLIST, GIT_CHARACTER_WHITELIST,
                               GIT_PREFIX_BLACKLIST, GIT_SUFFIX_BLACKLIST,
                               GIT_SEQUENCE_BLACKLIST)


def make_valid_name(name, name_blacklist, character_whitelist, prefix_blacklist,
                          suffix_blacklist, sequence_blacklist, fill_character):
# pylint: disable=too-many-arguments
    """
    modify a unicode name to not be equal to any blacklist entry, only contain whitelisted
    charcacters, not start with a blacklisted prefix and not end with a blacklisted suffix

    the strategy is to:
    1 if the name is empty return the fill character
    2 replace all non-whitelisted characters with the fill character
    3 replace all blacklisted sequences with the fill character
    4 if the name is on the blacklist append the fill character
    4.1 trim and return
    5 if the name starts with a blacklisted prefix prepend the fill character
    5.1 trim and return
    6 if the name ends with a blacklisted suffix append the fill character
    6.1 trim and return
    7 trim and return the name

    this strategy requires that:
    - the fill character is a valid name
    - no blacklisted sequence contains the fill character
    - no name on the blacklist ends with the fill character
    - no prefix on the blacklist begins with the fill character
    - no suffix on the blacklist ends with the fill character

    :param name: string the user provided name
    :param name_blacklist: iterable containing lowercase utf-8 strings
    :param character_whitelist: iterable containing single utf-8 characters
    :param prefix_blacklist: iterable containing lowercase utf-8 strings
    :param suffix_blacklist: iterable containing lowercase utf-8 strings
    :param sequence_blacklist: iterable containing lowercase utf-8 strings
    :param fill_character: one single utf-8 character
    """
    logger = logging.getLogger(__name__)
    if not isinstance(fill_character, str) or len(fill_character) != 1:
        raise ValueError('fill_character must be exactly one utf-8 character')

    if not name:
        return fill_character
    
    fill_character_byte_length = TODO

    class WhitelistTranslationTable:
        """
        str.translate wants a blacklist style lookup table but we defined a whitelist so we need a
        wrapper for the whitelist, that returns the fill character for every character not in the
        whitelist.

        the __getitem__ function could either return the unicode character of the given ordinal or
        behave like a dictionary and throw a key error, this one acts like a dictionary
        """
        def __init__(self, whitelist):
            self.whitelist = set(map(ord, whitelist))
        def __repr__(self):
            return 'WhitelistTranslationTable(%r)' % (set(map(chr, self.whitelist)),)
        def __getitem__(self, key):
            if key in self.whitelist:
                raise KeyError
            return fill_character

    table = WhitelistTranslationTable(character_whitelist)
    name = name.translate(table)

    for sequence in sequence_blacklist:
        if sequence: #prevent '' in the blacklist to place fill_character between all characters
            name = name.replace(sequence, fill_character)

    lower_name = name.lower()
    if lower_name in name_blacklist:
        return trim_to_byte_length(name, NAME_BYTE_LIMIT - fill_character_byte_length) + fill_character

    for prefix in prefix_blacklist:
        if lower_name.startswith(prefix):
            return trim_to_byte_length(name, NAME_BYTE_LIMIT - fill_character_byte_length) + fill_character
    
    for suffix in suffix_blacklist:
        if lower_name.endswith(suffix):
            return trim_to_byte_length(name, NAME_BYTE_LIMIT - fill_character_byte_length) + fill_character


def make_valid_file_name(name):
    """
    modify a user provided unicode name to be a valid file name in the context of this application

    :param name: string
    :return: string
    """
    return make_valid_name(name, FILENAME_NAME_BLACKLIST, FILENAME_CHARACTER_WHITELIST,
                                 FILENAME_PREFIX_BLACKLIST, FILENAME_SUFFIX_BLACKLIST,
                                 FILENAME_SEQUENCE_BLACKLIST, '_')


def make_valid_branch_name(name):
    """
    modify a user provided unicode name to be a valid part of a git branch name

    :param name: string
    :return: string
    """
    return make_valid_name(name, GIT_NAME_BLACKLIST, GIT_CHARACTER_WHITELIST,
                                 GIT_PREFIX_BLACKLIST, GIT_SUFFIX_BLACKLIST,
                                 GIT_SEQUENCE_BLACKLIST, '_')
