from os import path, mkdir
from pathlib import Path
from .gpg_handler import encrypt, get_recipients_from_gpg_id
from .pass_file_format_parser import PassFile

import logging

def handle(root_path, name):
    """
    handles a change item selection change event from the UI
    :param root_path: string - path to a file, without its name
    :param name: string - name of the file
    :return: list of strings of gpg ids or cypher cleartext
    """
    logger = logging.getLogger(__name__)
    logger.debug('handle: root_path: "%s"', root_path)
    logger.debug('handle: name: "%s"', name)
    if path.isfile(path.join(root_path, name)):
        logger.debug('handle: path is file')
        return PassFile(gpg_file=path.join(root_path, name))
    if path.isdir(path.join(root_path, name)) and path.exists(path.join(path.join(root_path, name), '.gpg-id')):
        logger.debug('handle: path is directory with .gpg-id')
        list_to_return = []
        with open(path.join(path.join(root_path, name), '.gpg-id')) as file:
            for line in file.readlines():
                list_to_return.append(line.replace('\n', ''))
        logger.debug('handle: return: %s', list_to_return)
        return list_to_return
    if path.isdir(path.join(root_path, name)):
        logger.debug('handle: path is directory')
        gpg_id_file_path = search_gpg_id_file(path.join(root_path, name))
        logger.debug('handle: gpg_id_file_path: "%s"', gpg_id_file_path)
        list_to_return = []
        with open(gpg_id_file_path) as file:
            for line in file.readlines():
                list_to_return.append(line.replace('\n', ''))
        logger.debug('handle: return: %s', list_to_return)
        return list_to_return


def create_password_file(path_to_folder, name, password_file):
    """
    creates a gpg encrypted .gpg file with respective name in the respective folder from PassFile Object
    :param path_to_folder:
    :param name:
    :param password_file:
    :return:
    """
    logger = logging.getLogger(__name__)
    logger.debug('create_password_file: path_to_folder: "%s"', path_to_folder)
    logger.debug('create_password_file: name: "%s"', name)
    gpg_id_file = search_gpg_id_file(path_to_folder)
    logger.debug('create_password_file: gpg_id_file: "%s"', gpg_id_file)
    if path.exists(gpg_id_file):
        clear_text = password_file.get_cleartext().encode()
        logger.debug('create_password_file: len(clear_text): %d', len(clear_text))
        list_of_recipients = get_recipients_from_gpg_id(gpg_id_file)
        logger.debug('create_password_file: list_of_recipients: "%s"', list_of_recipients)
        path_to_file = path.join(path_to_folder, f'{name}.gpg')
        logger.debug('create_password_file: path_to_file: "%s"', path_to_file)
        return encrypt(clear_text=clear_text,
                       list_of_recipients=list_of_recipients,
                       path_to_file=path_to_file)
    else:
        return False


def create_folder(path_to_folder, name):
    """
    creates a new folder with respective name in respective path
    :param path_to_folder: string
    :param name: string
    :return: None
    """
    logger = logging.getLogger(__name__)
    logger.debug('create_folder: path_to_folder: "%s"', path_to_folder)
    logger.debug('create_folder: name: "%s"', name)
    mkdir(path.join(path_to_folder, name))


def search_gpg_id_file(path_to_folder):
    """
    recursively find the folder containing the correct .gpg-id file
    :param path_to_folder: string - path to start
    :return: string
    """
    logger = logging.getLogger(__name__)
    logger.debug('search_gpg_id_file: path_to_folder: "%s"', path_to_folder)
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
    logger = logging.getLogger(__name__)
    logger.debug('get_config: cfg_file: "%s"', cfg_file)
    from configparser import ConfigParser
    config_parser = ConfigParser()
    config_parser.read(cfg_file, encoding='utf8')
    return config_parser
