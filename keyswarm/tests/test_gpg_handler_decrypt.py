from os import path
from base64 import b64decode
from tempfile import TemporaryDirectory
from keyswarm.gpg_handler import decrypt
from pytest import raises
from subprocess import run
from . import private_key, encrypted_file


def test_decrypt_key_unknown():
    with TemporaryDirectory() as tmpdirname:
        with open(file=path.join(tmpdirname, 'secret.gpg'), mode='bw') as gpg_file:
            gpg_file.write(b64decode(encrypted_file))
        with raises(ValueError):
            decrypt(path.join(tmpdirname, 'secret.gpg'))


def test_decrypt_file_not_found():
    with TemporaryDirectory() as tmpdirname:
        with raises(FileNotFoundError):
            decrypt(path_to_file=path.join(tmpdirname, 'file_that_doesnt_exist.gpg'))


def test_decrypt_file_is_dir():
    with TemporaryDirectory() as tmpdirname:
        with raises(ValueError):
            decrypt(path_to_file=tmpdirname)


def test_decrypt_file_not_gpg():
    with TemporaryDirectory() as tmpdirname:
        with open(file=path.join(tmpdirname, 'not.gpg'), mode='bw') as gpg_file:
            gpg_file.write(b'''test''')
        with raises(ValueError):
            decrypt(path.join(tmpdirname, 'not.gpg'))


def test_decrypt():
    with TemporaryDirectory() as tmpdirname:
        with open(file=path.join(tmpdirname, 'sec_key.asc'), mode='bw') as asc_file:
            asc_file.write(b64decode(private_key))
        run(['gpg',
             '--homedir', tmpdirname,
             '--batch',
             '--passphrase', 'test',
             '--import', path.join(tmpdirname, 'sec_key.asc')])
        with open(file=path.join(tmpdirname, 'encrypted.gpg'), mode='bw') as encrypted_gpg_file:
            encrypted_gpg_file.write(b64decode(encrypted_file))
        cleartext = decrypt(path_to_file=path.join(tmpdirname, 'encrypted.gpg'),
                            gpg_home=tmpdirname,
                            additional_parameter=['--pinentry-mode', 'loopback', '--passphrase', 'test'])
        assert cleartext == 'test'
