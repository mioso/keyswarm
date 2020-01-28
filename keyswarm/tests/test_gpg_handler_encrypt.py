from tempfile import TemporaryDirectory
from base64 import b64decode
from os import path, system
from keyswarm.gpg_handler import encrypt, get_binary
from subprocess import PIPE, Popen, run
from pytest import raises
from . import private_key


def test_gpg_encrypt():
    with TemporaryDirectory() as tmpdirname:
        with open(file=path.join(tmpdirname, 'sec_key.asc'), mode='bw') as asc_file:
            asc_file.write(b64decode(private_key))
        run([get_binary(),
             '--homedir', tmpdirname,
             '--batch',
             '--passphrase', 'test',
             '--import', path.join(tmpdirname, 'sec_key.asc')])
        ownertrust_cmd = 'echo "80035649BDABA4EC6A02E7D36BF58E6E9B697F1C:6:" | %s --homedir "{}" --import-ownertrust' % (get_binary(),)
        system(ownertrust_cmd.format(tmpdirname))
        cyphertext = encrypt(clear_text=b'payload',
                             list_of_recipients=['tester@test.com'],
                             gpg_home=tmpdirname)
        gpg_decrypt_command = [get_binary(),
                               '--homedir', tmpdirname,
                               '--pinentry-mode', 'loopback',
                               '--passphrase', 'test',
                               '--quiet',
                               '--decrypt']
        gpg_subprocess = Popen(gpg_decrypt_command, stdin=PIPE, stdout=PIPE)
        gpg_subprocess.stdin.write(cyphertext)
        stdout, stderr = gpg_subprocess.communicate()
        assert stdout.decode('utf8') == 'payload'


def test_gpg_encrypt_homedir_not_found():
    with TemporaryDirectory() as tmpdirname:
        with raises(FileNotFoundError):
            output = encrypt(clear_text=b'payload',
                             list_of_recipients=['thiskey@isnot.relevenat-for-the.test'],
                             gpg_home=path.join(tmpdirname, 'this_path_does_not_exist'))


def test_gpg_encrypt_public_key_not_found():
    with TemporaryDirectory() as tmpdirname:
        with raises(ValueError):
             encrypt(clear_text=b'payload',
                     list_of_recipients=['thiskey@does_not.exist'],
                     gpg_home=tmpdirname)


def test_gpg_encrypt_output_dir_not_found():
    with TemporaryDirectory() as tmpdirname:
        with raises(FileNotFoundError):
            test = encrypt(clear_text=b'payload',
                           list_of_recipients=['thiskey@isnot.relevenat-for-the.test'],
                           path_to_file=path.join(tmpdirname, 'this_folder_doesnt_exist', 'file.gpg'))


def test_gpg_encrypt_no_recipients():
    with raises(ValueError):
        test = encrypt(clear_text=b'payload',
                       list_of_recipients=[])
