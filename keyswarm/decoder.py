"""
This module tries to handle the encoding of external input.
"""

import logging
from sys import exit as sys_exit


logging.getLogger(__name__).setLevel(logging.INFO)
def enable_decoder_debug_logging():
    """ enable decoder debug logging """
    logging.getLogger(__name__).setLevel(logging.DEBUG)


def try_decode(byteslike):
    """
    Tries to decode the input or fails with a critical error

    :param byteslike: BytesLike encoded input
    """
    logger = logging.getLogger(__name__)
    try:
        logger.debug('try_decode: utf-8')
        return byteslike.decode('utf-8')
    except UnicodeDecodeError as error:
        logger.debug('try_decode: error: %r', error)
    try:
        logger.debug('try_decode: latin1')
        return byteslike.decode('latin1')

    except Exception as error: #TODO
        logger.debug('try_decode: error: %r', error)
        logger.critical('try_decode: did not find an encoding')
        sys_exit(1)
