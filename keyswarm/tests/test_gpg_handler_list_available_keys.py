from base64 import b64decode
from os import path
from subprocess import run
from tempfile import TemporaryDirectory

from keyswarm.gpg_handler import list_available_keys

from . import private_key

def test_list_available_keys():
    with TemporaryDirectory() as tmpdirname:
        with open(file=path.join(tmpdirname, 'sec_key.asc'), mode='bw') as asc_file:
            asc_file.write(b64decode(private_key))
        run(['gpg',
             '--homedir', tmpdirname,
             '--batch',
             '--passphrase', 'test',
             '--import', path.join(tmpdirname, 'sec_key.asc')])
        assert list_available_keys(['--homedir', tmpdirname]) == ['tester <tester@test.com>']


def test_list_available_keys_no_key_available():
    with TemporaryDirectory() as tmpdirname:
        assert list_available_keys(['--homedir', tmpdirname]) == []
