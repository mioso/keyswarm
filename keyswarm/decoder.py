import logging
from sys import exit as sys_exit

def try_decode(byteslike):
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
