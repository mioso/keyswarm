from os import path, walk
from subprocess import PIPE, Popen, STDOUT
from re import compile, match


# noinspection DuplicatedCode
def list_packages(path_to_file):
    """
    lists all gpg public keys a respective file is encrypted to
    :param path_to_file: string - complete path to gog encrypted file
    :return: list of stings
    """
    gpg_subprocess = Popen(['gpg', '--pinentry-mode', 'cancel', '--list-packets', path_to_file],
                           stdout=PIPE,
                           stderr=STDOUT)
    stdout, stderr = gpg_subprocess.communicate()
    if match(b".*can't open.*", stdout):
        raise FileNotFoundError
    if match(b".*read error: Is a directory.*", stdout):
        raise ValueError
    if match(b".*no valid OpenPGP data found.*", stdout):
        raise ValueError
    stdout = stdout.split(b'\n')
    r = compile(b'.*<(.*\@.*)>.*')
    list_of_packet_ids = []
    for line in stdout:
        if r.match(line):
            list_of_packet_ids.append(list(r.search(line).groups())[0].decode('utf-8'))
    return list_of_packet_ids


def decrypt(path_to_file, gpg_home=None, additional_parameter=None):
    """
    Decripts a gpg encrypted file and returns the cleartext
    :param path_to_file: complete path to gpg encrypted file
    :param gpg_home: string the gpg home directory
    :param additional_parameter: do not use this parameter; for testing only
    :return: utf-8 encoded string
    """
    if additional_parameter is None:
        additional_parameter = list()
    gpg_command = ['gpg', '--quiet', *additional_parameter, '--decrypt', path_to_file]
    if gpg_home:
        gpg_command = ['gpg', '--quiet', '--homedir', gpg_home, *additional_parameter, '--decrypt', path_to_file]
    gpg_subprocess = Popen(gpg_command, stdout=PIPE, stderr=STDOUT)
    stdout, stderr = gpg_subprocess.communicate()
    if match(b".*decryption failed: No secret key.*", stdout):
        raise ValueError
    if match(b".*can't open.*No such file or directory.*", stdout):
        raise FileNotFoundError
    if match(b".*read error: Is a directory.*", stdout):
        raise ValueError
    if match(b".*no valid OpenPGP data found.*", stdout):
        raise ValueError
    return stdout.decode('utf-8')


def encrypt(clear_text, list_of_recipients, path_to_file=None, gpg_home=None):
    """
    Encrypts a cleartext  to one or more public keys
    :param clear_text:
    :param list_of_recipients:
    :param path_to_file: if provided cyphertext is directly written to the file provided
    :param gpg_home: string gpg home directory
    :return: bytes of cyphertext or None
    """
    if not list_of_recipients:
        raise ValueError
    if path_to_file and not path.exists(path.dirname(path_to_file)):
        raise FileNotFoundError
    cli_recipients = []
    for recipient in list_of_recipients:
        cli_recipients.append('-r')
        cli_recipients.append(recipient)
    gpg_command = ['gpg', '--encrypt', *cli_recipients]
    if gpg_home:
        gpg_command = ['gpg', '--quiet', '--homedir', gpg_home, '--encrypt', *cli_recipients]
    gpg_subprocess = Popen(gpg_command, stdin=PIPE, stdout=PIPE, stderr=STDOUT)
    stdout, stderr = gpg_subprocess.communicate(input=clear_text)
    if match(b'.*No such file or directory.*', stdout):
        raise FileNotFoundError
    if match(b'.*No public key.*', stdout):
        raise ValueError
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
    list_of_recipients = []
    with open(path_to_gpg_id_file, 'r') as file:
        for line in file.readlines():
            list_of_recipients.append(line.replace('\n', ''))
    return list_of_recipients


# noinspection DuplicatedCode
def list_available_keys(additional_parameter=None):
    """
    lists all to gpg binary available public keys
    :param additional_parameter: do not use this; for testing only
    :return: list of strings
    """
    if additional_parameter is None:
        additional_parameter = list()
    gpg_subprocess = Popen(['gpg', '--list-keys', *additional_parameter],
                           stdout=PIPE,
                           stderr=STDOUT)
    stdout, stderr = gpg_subprocess.communicate()
    stdout = stdout.split(b'\n')
    r = compile(b'.*<(.*\@.*)>.*')
    list_of_packet_ids = []
    for line in stdout:
        if r.match(line):
            list_of_packet_ids.append(list(r.search(line).groups())[0].decode('utf-8'))
    return list_of_packet_ids


def write_gpg_id_file(path_to_file, list_of_gpg_ids):
    """
    creates a .gpg-id file with respective public key ids
    :param path_to_file: complete path to file
    :param list_of_gpg_ids: a list of strings
    :return: None
    """
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
    for root, dirs, files in walk(path_to_folder):
        if root == path_to_folder:
            for file in files:
                if file[-4:] == '.gpg':
                    file_path = path.join(root, file)
                    cleartext = decrypt(file_path, gpg_home=gpg_home, additional_parameter=additional_parameter)
                    encrypt(clear_text=cleartext.encode(),
                            list_of_recipients=list_of_keys,
                            path_to_file=file_path,
                            gpg_home=gpg_home)
        else:
            if not path.exists(path.join(root, '.gpg-id')):
                recursive_reencrypt(root, list_of_keys)
