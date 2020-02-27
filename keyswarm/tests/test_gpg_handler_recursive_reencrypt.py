from tempfile import TemporaryDirectory
from os import path, system
from base64 import b64decode
from subprocess import run

from keyswarm.gpg_handler import recursive_reencrypt, list_packets, get_binary
from . import private_key, eddsa_private_key, encrypted_file

def test_gpg_handler_recursive_reencrypt_no_recursion():
    with TemporaryDirectory() as tmp_gpg_home:
        with open(file=path.join(tmp_gpg_home, 'sec_key.asc'), mode='bw') as asc_file:
            asc_file.write(b64decode(private_key))
        run([get_binary(),
             '--homedir', tmp_gpg_home,
             '--batch',
             '--passphrase', 'test',
             '--import', path.join(tmp_gpg_home, 'sec_key.asc')])
        with open(file=path.join(tmp_gpg_home, 'eddsa_sec_key.asc'), mode='bw') as asc_file:
            asc_file.write(b64decode(eddsa_private_key))
        run([get_binary(),
             '--homedir', tmp_gpg_home,
             '--batch',
             '--passphrase', 'test',
             '--import', path.join(tmp_gpg_home, 'eddsa_sec_key.asc')])
        owner_trust1_cmd = ('echo "80035649BDABA4EC6A02E7D36BF58E6E9B697F1C:6:" | '
                            '%s --homedir "{}" --import-ownertrust') % (get_binary(),)
        system(owner_trust1_cmd.format(tmp_gpg_home))
        owner_trust2_cmd = ('echo "A76F69733F4FBE97A4553B7C414129BA435C3226:6:" | '
                            '%s --homedir "{}" --import-ownertrust') % (get_binary(),)
        system(owner_trust2_cmd.format(tmp_gpg_home))
        with TemporaryDirectory() as tmp_password_store:
            with open(file=path.join(tmp_password_store, '.gpg-id'), mode='w') as dot_gpg_id_file:
                dot_gpg_id_file.write('tester2@test.com')
            with open(file=path.join(tmp_password_store, 'encrypted.gpg'),
                      mode='bw') as encrypted_gpg_file:
                encrypted_gpg_file.write(b64decode(encrypted_file))
            recursive_reencrypt(path_to_folder=tmp_password_store,
                                list_of_keys=['tester@test.com', 'tester2@test.com'],
                                gpg_home=tmp_gpg_home,
                                additional_parameter=['--pinentry-mode', 'loopback',
                                                      '--passphrase', 'test'])
            packages = list_packets(path_to_file=path.join(tmp_password_store, 'encrypted.gpg'))
            print(packages)
            assert ('keyid 304C48B44BD634E0' in packages and 'keyid BD0E6C2E8C5A523C'
                    in packages and len(packages) == 2)
