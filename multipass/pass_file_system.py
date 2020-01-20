from os import path, mkdir
from pathlib import Path
from .gpg_handler import encrypt, get_recipients_from_gpg_id
from .pass_file_format_parser import PassFile


def handle(root_path, name):
    """
    handles a change item selection change event from the UI
    :param root_path: string - path to a file, without its name
    :param name: string - name of the file
    :return: list of strings of gpg ids or cypher cleartext
    """
    if path.isfile(path.join(root_path, name)):
        return PassFile(gpg_file=path.join(root_path, name))
    if path.isdir(path.join(root_path, name)) and path.exists(path.join(path.join(root_path, name), '.gpg-id')):
        list_to_return = []
        with open(path.join(path.join(root_path, name), '.gpg-id')) as file:
            for line in file.readlines():
                list_to_return.append(line.replace('\n', ''))
        return list_to_return
    if path.isdir(path.join(root_path, name)):
        gpg_id_file_path = search_gpg_id_file(path.join(root_path, name))
        list_to_return = []
        with open(gpg_id_file_path) as file:
            for line in file.readlines():
                list_to_return.append(line.replace('\n', ''))
        return list_to_return


def create_password_file(path_to_folder, name, password_file):
    """
    creates a gpg encrypted .gpg file with respective name in the respective folder from PassFile Object
    :param path_to_folder:
    :param name:
    :param password_file:
    :return:
    """
    gpg_id_file = search_gpg_id_file(path_to_folder)
    if path.exists(gpg_id_file):
        return encrypt(clear_text=password_file.get_cleartext().encode(),
                       list_of_recipients=get_recipients_from_gpg_id(gpg_id_file),
                       path_to_file=path.join(path_to_folder, '{name}.gpg'.format(name=name)))
    else:
        return False


def create_folder(path_to_folder, name):
    """
    creates a new folder with respective name in respective path
    :param path_to_folder: string
    :param name: string
    :return: None
    """
    mkdir(path.join(path_to_folder, name))


def search_gpg_id_file(path_to_folder):
    """
    recursively find the folder containing the correct .gpg-id file
    :param path_to_folder: string - path to start
    :return: string
    """
    return_path = path.join(path_to_folder, '.gpg-id')
    parent_of_path_to_folder = Path(path_to_folder).parent
    if not path.exists(return_path):
        return search_gpg_id_file(str(parent_of_path_to_folder))
    return return_path


def get_config(cfg_file):
    """
    reads and parses config from file
    :param cfg_file: string - path to config file
    :return: ConfigParser Object
    """
    from configparser import ConfigParser
    config_parser = ConfigParser()
    config_parser.read(cfg_file, encoding='utf8')
    return config_parser
