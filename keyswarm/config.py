"""
This module profides interaction with the config files
of both the password store as well as the user
"""

from configparser import ConfigParser
import logging
from pathlib import Path

def get_config(password_store_root, user_can_override=False):
    """
    reads and parses both the repository config file and the users config file if present
    and returns the combined config
    """
    logger = logging.getLogger(__name__)
    logger.debug('get_config: password_store_root: %r', password_store_root)
    logger.debug('get_config: user_can_override: %r', user_can_override)

    repository_config = Path(password_store_root, '.cfg')
    user_config = Path('~/.keyswarm.ini').expanduser()

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
    #TODO
