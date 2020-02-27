from base64 import b64decode
from inspect import getfile, currentframe
from os import path
from tempfile import TemporaryDirectory

from pytest import raises

from keyswarm.gpg_handler import list_packets


def test_gpg_list_packages_file_not_exists():
    with raises(FileNotFoundError):
        list_packets('')


def test_gpg_list_packages_file_is_dir():
    with raises(ValueError):
        list_packets(path.dirname(path.abspath(getfile(currentframe()))))


def test_gpg_list_packages_file_not_gpg():
    with raises(ValueError):
        list_packets(path.abspath(getfile(currentframe())))


def test_gpg_list_packages():
    with TemporaryDirectory() as tmpdir:
        with open(path.join(tmpdir, 'cyphertext.gpg'), mode='bw') as cyphertext_gpg_file:
            binary_cyphertext = b64decode(
                b'hQEMAzBMSLRL1jTgAQgAhPDZBYyUS6Jy3iQ6IDXhUJTGhXqt8rZFlG6Oz2bezx0OGzbTbDj6'
                b'ifporDM8/XVT5y/TUQNSYhBWoz0sq9EUT2+5bqdO0znNJvxLJxctHOZU5TJpsw1dI6FqvXeN'
                b'r+9NIlRrPWx9VLeZwIf1wUxqMoGnYj7euzaKZKPMMarW6M5P/n5SocXxWetUCtPThOitdLFg'
                b'6tRQGY+WBjvV0gH0+yLUoZfFw5bOi4r1EXRfz3zM0ot9S69t+Fn9Tu9QwlCcr1pEJn9JNgDr'
                b'bxu6dvtuCX4bEmxtzs41HWHGNkscEWvqz8+6EnpO8MNwUY8bmIEx5kGfB06i04IkAL311sCo'
                b'hdJDAc3G3HnpmH6o5Tyq6lhalj7Wkb0E92F875Uuhv+9nt8MwVstIWpDxWAVay1QddDOTsng'
                b'ULwTbFhBDdGMdrnUKE7hcQ==')
            cyphertext_gpg_file.write(binary_cyphertext)
        assert 'keyid 304C48B44BD634E0' in list_packets(path.join(tmpdir, 'cyphertext.gpg'))
