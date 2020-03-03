"""
this module interacts with the gpg binary and provides file encryption and decryption
as well as utility function like key listing and reencryption of a file tree.
"""

from functools import lru_cache
import logging
from os import path, listdir
from pathlib import Path
from re import compile as re_compile, match as re_match, DOTALL
from subprocess import PIPE, Popen, STDOUT
from sys import exit as sys_exit

def try_decode(byteslike):
    logger = logging.getLogger(__name__)
    try:
        logger.debug('try_decode: utf-8')
        return byteslike.decode('utf-8')
    except UnicodeDecodeError as error:
        logger.debug('try_decode: error: %r', error)
    try:
        logger.debug('try_decode: latin1')
        return byteslike.decode('latin1')

    except Exception as error:
        logger.debug('try_decode: error: %r', error)
        logger.critical('try_decode: did not find an encoding')
        sys_exit(1)


@lru_cache(maxsize=1)
def get_binary():
    """
    check the gpg binaty for its version
    if the version is 1 try the gpg2 binary
    exits the application if neither binary is present
    or reports to be version 2

    :return: the binary which returned version 2
    """
    logger = logging.getLogger()
    regex = re_compile(r'gpg \(GnuPG\) ([1-2])\..*')

    gpg_subprocess = Popen(['gpg', '--version'], stdout=PIPE, stderr=None)
    stdout, _ = gpg_subprocess.communicate()
    logger.debug('get_binary: %r', stdout)
    version = try_decode(stdout).splitlines()[0]

    match = regex.match(version)
    if match:
        group = match.groups()[0]
        logger.debug('get_binary: gpg, version: %r', group)
        if group == "2":
            return 'gpg'
        if group == "1":
            gpg2_subprocess = Popen(['gpg2', '--version'], stdout=PIPE, stderr=None)
            stdout_2, _ = gpg2_subprocess.communicate()
            version_2 = stdout_2.decode('utf-8').splitlines()[0]

            m_2 = regex.match(version_2)
            if m_2:
                g_2 = m_2.groups()[0]
                logger.debug('get_binary: gpg2, version: %r', g_2)
                if g_2 == "2":
                    return 'gpg2'
    logger.critical('get_binary: unkown gpg version')
    sys_exit(1)


# noinspection DuplicatedCode
def list_packets(path_to_file):
    """
    lists all gpg public keys a respective file is encrypted to
    :param path_to_file: string - complete path to gog encrypted file
    :return: list of stings
    """
    logger = logging.getLogger(__name__)
    logger.debug('list_packets: path_to_file: %r', path_to_file)
    gpg_subprocess = Popen([get_binary(), '--with-colons', '--status-fd=2', '--batch-mode',
                            '--list-only', '--list-packets', path_to_file],
                           stdout=PIPE, stderr=PIPE)
    stdout, stderr = gpg_subprocess.communicate()
    if re_match(b".*can't open.*", stderr):
        raise FileNotFoundError('can\'t open file')
    if re_match(b".*read error: Is a directory.*", stderr):
        raise ValueError('file is a directory')
    if re_match(rb".*\[GNUPG:\] NODATA.*", stderr):
        raise ValueError('no valid openpgp data found')
    stdout = stdout.split(b'\n')
    regex = re_compile(b'.*(keyid [0-9A-Fa-f]{16}).*')
    list_of_packet_ids = []
    for line in stdout:
        logger.debug('list_packets: %r', line)
        if regex.match(line):
            list_of_packet_ids.append(try_decode(list(regex.search(line).groups())[0]))
    logger.debug('list_packets: list_of_packet_ids: %r', list_of_packet_ids)
    return list_of_packet_ids


def decrypt(path_to_file, gpg_home=None, additional_parameter=None, utf8=True):
    """
    Decripts a gpg encrypted file and returns the cleartext
    :param path_to_file: complete path to gpg encrypted file
    :param gpg_home: string the gpg home directory
    :param additional_parameter: do not use this parameter; for testing only
    :return: utf-8 encoded string
    """
    logger = logging.getLogger(__name__)
    logger.debug('decrypt: path_to_file: %r', path_to_file)
    logger.debug('decrypt: gpg_home: %r', gpg_home)
    logger.debug('decrypt: additional_parameter: %r', additional_parameter)
    additional_parameter = additional_parameter or []
    gpg_command = [get_binary(), '--with-colons', '--status-fd=2', '--quiet',
                   *additional_parameter, '--decrypt', path_to_file]
    if gpg_home:
        gpg_command = [get_binary(), '--with-colons', '--status-fd=2', '--quiet', '--homedir',
                       gpg_home, *additional_parameter, '--decrypt', path_to_file]
    logger.debug('decrypt: gpg_command: %r', gpg_command)
    gpg_subprocess = Popen(gpg_command, stdout=PIPE, stderr=PIPE)
    stdout, stderr = gpg_subprocess.communicate()
    logger.debug('decrypt: stdout: %r', stdout)
    logger.debug('decrypt: stderr: %r', stderr)
    if stdout:
        if utf8:
            return try_decode(stdout)
        return stdout

    if re_match(rb".*\[GNUPG:\] DECRYPTION_FAILED*", stderr, DOTALL):
        raise ValueError('no secret key')
    if re_match(rb".*\[GNUPG:\] NODATA.*", stderr, DOTALL):
        raise ValueError('file is a directory or empty')
    if re_match(rb".*\[GNUPG:\] FAILURE decrypt.*", stderr, DOTALL):
        raise FileNotFoundError
    if re_match(rb".*no valid OpenPGP data found.*", stderr, DOTALL):
        raise ValueError('no valid openpgp data found')
    raise ValueError('unkown gpg error: %r' % (stderr,))


def encrypt(clear_text, list_of_recipients, path_to_file=None, gpg_home=None):
    """
    Encrypts a cleartext  to one or more public keys
    :param clear_text:
    :param list_of_recipients:
    :param path_to_file: if provided cyphertext is directly written to the file provided
    :param gpg_home: string gpg home directory
    :return: bytes of cyphertext or None
    """
    logger = logging.getLogger(__name__)
    logger.debug('encrypt: len(clear_text): %r', len(clear_text))
    logger.debug('encrypt: list_of_recipients: %r', list_of_recipients)
    logger.debug('encrypt: path_to_file: %r', path_to_file)
    logger.debug('encrypt: gpg_home: %r', gpg_home)
    if not list_of_recipients:
        raise ValueError('no recipients')
    if path_to_file and not path.exists(path.dirname(path_to_file)):
        raise FileNotFoundError('specified file path does not exist')
    cli_recipients = []
    for recipient in list_of_recipients:
        cli_recipients.append('-r')
        cli_recipients.append(recipient)
    gpg_command = [get_binary(), '--with-colons', '--status-fd=2', '--quiet', '--encrypt',
                   '--auto-key-locate', 'local', '--trust-model', 'always', *cli_recipients]
    if gpg_home:
        gpg_command = [get_binary(), '--with-colons', '--status-fd=2', '--quiet', '--homedir',
                       gpg_home, '--encrypt', '--auto-key-locate', 'local', '--trust-model',
                       'always', *cli_recipients]
    logger.debug('encrypt: gpg_command: %r', gpg_command)
    gpg_subprocess = Popen(gpg_command, stdin=PIPE, stdout=PIPE, stderr=PIPE)
    stdout, stderr = gpg_subprocess.communicate(input=clear_text)
    logger.debug('encrypt: stdout: %r', stdout)
    logger.debug('encrypt: stderr: %r', stderr)
    if re_match(rb'.*No such file or directory.*', stderr, DOTALL):
        raise FileNotFoundError
    if re_match(rb'.*\[GNUPG:\] NO_RECP.*', stderr, DOTALL):
        logger.error('logic error: no recipients should have been caught already')
        raise ValueError('no recipients')
    if re_match(rb'.*\[GNUPG:\] INV_RECP.*', stderr, DOTALL):
        raise ValueError('no public key')
    if re_match(rb'.*\[GNUPG:\] FAILURE encrypt.*', stderr, DOTALL):
        raise ValueError('unknown gpg error')
    if path_to_file:
        with open(path_to_file, 'bw') as file:
            file.write(stdout)
        return None
    return stdout


def get_recipients_from_gpg_id(path_to_gpg_id_file):
    """
    lists all public keys that are specified in a respective .gpg-id file
    :param path_to_gpg_id_file: complete path to .gpg-id file
    :return: list of strings
    """
    logger = logging.getLogger(__name__)
    logger.debug('get_recipients_from_gpg_id: path_to_gpg_id_file: %r', path_to_gpg_id_file)
    list_of_recipients = []
    with open(path_to_gpg_id_file, 'r') as file:
        for line in file.readlines():
            list_of_recipients.append(line.replace('\n', ''))
    logger.debug('get_recipients_from_gpg_id: return: %r', list_of_recipients)
    return list_of_recipients


# noinspection DuplicatedCode
def list_available_keys(additional_parameter=None, get_secret_keys=False):
    """
    lists all to gpg binary available public keys
    :param additional_parameter: do not use this; for testing only
    :return: list of strings
    """
    logger = logging.getLogger(__name__)
    logger.debug('list_available_keys: additional_parameter: %r', additional_parameter)
    additional_parameter = additional_parameter or []
    command = '--list-keys' if not get_secret_keys else '--list-secret-keys'
    gpg_subprocess = Popen([get_binary(), '--with-colons', command, *additional_parameter],
                           stdout=PIPE,
                           stderr=PIPE)
    stdout, stderr = gpg_subprocess.communicate()
    logger.debug('list_available_keys: stdout: %r', stdout)
    logger.debug('list_available_keys: stderr: %r', stderr)
    stdout = stdout.splitlines()
    regex = re_compile(rb'^uid:.*')
    list_of_packet_ids = []
    for line in stdout:
        logger.debug('list_available_keys: line: %r', line)
        if regex.match(line):
            key_id = try_decode(line).split(':')[9]
            logger.debug('list_available_keys: match: %r', key_id)
            list_of_packet_ids.append(key_id)
    return list_of_packet_ids

def generate_keypair(key_id, key_length=4096, expiration_date=None, additional_parameter=None):
    """
    generates a gpg keypair
    """
    logger = logging.getLogger(__name__)
    logger.debug('generate_private_key: key_id: %r', key_id)
    logger.debug('generate_private_key: key_length: %r', key_length)
    logger.debug('generate_private_key: expiration_date: %r', expiration_date)
    additional_parameter = additional_parameter or []
    gpg_subprocess = Popen([get_binary(), '--with-colons', '--status-fd=2', '--quick-gen-key',
                            key_id, *additional_parameter], stdout=PIPE, stderr=PIPE)
    stdout, stderr = gpg_subprocess.communicate()
    logger.debug('generate_keypair: stdout: %r', stdout)
    logger.debug('generate_keypair: stderr: %r', stderr)

    if stdout:
        lines = try_decode(stdout).splitlines()
        regex = re_compile(r'^uid:.*')
        for line in lines:
            logger.debug('generate_keypair: line: %r', line)
            if regex.match(line):
                key_id = line.split(':')[9]
                logger.debug('generate_keypair: key_id: %r', key_id)
                return key_id
        raise ValueError('gpg returned no uid line')
    raise ValueError(stderr)

def import_gpg_keys(root_path):
    """
    try to read all keys inside the `.available-keys` directory
    directly at the root of the password store
    :param root_path: PathLike path to the password store, usually `~/.password-store`
    """
    logger = logging.getLogger(__name__)
    logger.debug('import_gpg_keys: root_path: %r', root_path)
    key_directory = Path(root_path, '.available-keys')
    logger.debug('import_gpg_keys: key_directory: %r', key_directory)
    if path.isdir(key_directory):
        logger.debug('import_gpg_keys: key directory exists')
        key_files = list(map(str, filter(lambda a: True, map(lambda a: Path(key_directory, a),
                                                             listdir(key_directory)))))
        logger.debug('%r', key_files)
        logger.debug('%r', *key_files)
        if key_files:
            gpg_subprocess = Popen([get_binary(), '--with-colons', '-status-fd=2', '--import',
                                    *key_files], stdout=PIPE, stderr=PIPE)
            stdout, stderr = gpg_subprocess.communicate()
            logger.debug('import_gpg_keys: stdout: %r', stdout)
            logger.debug('import_gpg_keys: stderr: %r', stderr)
        else:
            logger.debug('import_gpg_keys: no files in key directory')
    else:
        logger.debug('import_gpg_keys: key directory does not exist')


def write_gpg_id_file(path_to_file, list_of_gpg_ids):
    """
    creates a .gpg-id file with respective public key ids
    :param path_to_file: complete path to file
    :param list_of_gpg_ids: a list of strings
    :return: None
    """
    logger = logging.getLogger(__name__)
    logger.debug('write_gpg_id_file: path_to_file: %r', path_to_file)
    logger.debug('write_gpg_id_file: list_of_gpg_ids: %r', list_of_gpg_ids)
    with open(path_to_file, 'w') as file:
        for key_id in list_of_gpg_ids:
            file.write('{key}\n'.format(key=key_id))


def recursive_reencrypt(path_to_folder, list_of_keys, gpg_home=None, additional_parameter=None):
    """
    recursively reencrypts all files in a given path with the respective gpg public keys
    :param additional_parameter: gpg parameter - DO NOT USE THIS Except for testing purposes
    :param gpg_home: gpg_home directory to use
    :param path_to_folder: complete path to root folder
    :param list_of_keys: list of strings
    :return: None
    """
    logger = logging.getLogger(__name__)
    logger.debug('recursive_reencrypt: path_to_folder: %r', path_to_folder)
    logger.debug('recursive_reencrypt: list_of_keys: %r', list_of_keys)
    logger.debug('recursive_reencrypt: gpg_home: %r', gpg_home)
    logger.debug('recursive_reencrypt: additional_parameter: %r', additional_parameter)
    for file_ in listdir(path_to_folder):
        if Path(path_to_folder, file_).is_dir():
            logger.debug('recursive_reencrypt: folder: %r %r', path_to_folder, file_)
            if Path(path_to_folder, file_, '.gpg-id').exists():
                logger.debug('recursive_reencrypt: has .gpg-id file')
            else:
                logger.debug('recursive_reencrypt: does not have .gpg-id file')
                recursive_reencrypt(Path(path_to_folder, file_),
                                    list_of_keys,
                                    gpg_home,
                                    additional_parameter)
        else:
            logger.debug('recursive_reencrypt: file: %r %r', path_to_folder, file_)
            if file_[-4:] == '.gpg':
                logger.debug('recursive_reencrypt: gpg_file')
                file_path = Path(path_to_folder, file_)
                cleartext = decrypt(file_path, gpg_home=gpg_home,
                                    additional_parameter=additional_parameter)
                encrypt(clear_text=cleartext.encode(),
                        list_of_recipients=list_of_keys,
                        path_to_file=file_path,
                        gpg_home=gpg_home)
    logger.debug('recursive_reencrypt: done with %r', path_to_folder)
