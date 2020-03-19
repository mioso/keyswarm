"""
This module profides interaction with the config files
of both the password store as well as the user
"""

from configparser import ConfigParser
import logging
from pathlib import Path

def _get_user_config_path():
    return Path('~/.keyswarm.ini').expanduser()

def _get_repository_config_name():
    return '.cfg'

def get_config(password_store_root, user_can_override=False):
    """
    reads and parses both the repository config file and the users config file if present
    and returns the combined config
    """
    logger = logging.getLogger(__name__)
    logger.debug('get_config: password_store_root: %r', password_store_root)
    logger.debug('get_config: user_can_override: %r', user_can_override)

    repository_config = Path(password_store_root, _get_repository_config_name())
    user_config = _get_user_config_path()

    strong_config = user_config if user_can_override else repository_config
    weak_config = repository_config if user_can_override else user_config
    logger.debug('get_config: strong_config: %r', strong_config)
    logger.debug('get_config: weak_config: %r', weak_config)

    config_parser = ConfigParser()
    config_parser.read([weak_config, strong_config], encoding='utf8')

    for section_name in config_parser:
        for option_name in config_parser[section_name]:
            logger.debug('get_config: config[%r][%r]: %r', section_name, option_name,
                         config_parser[section_name][option_name])

    return config_parser

def save_config(config_parser):
    """
    saves the user config in the appropriate file
    :param config_parser: ConfigParser
    """
    logger = logging.getLogger(__name__)
    logger.debug('save_config: (%r)', config_parser)
    for section in config_parser.sections():
        logger.debug('save_config: config[%r] = %r', section, dict(config_parser[section]))

    with open(Path('~/.keyswarm.ini').expanduser(), 'w') as config_file:
        config_parser.write(config_file)

def get_user_config():
    """
    reads and parses the users config file and returns the config parser
    """
    config_parser = ConfigParser()
    config_parser.read(_get_user_config_path())
    return config_parser
