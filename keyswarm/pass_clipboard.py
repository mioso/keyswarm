"""
this module provides clipboard interaction with auto clear
"""

from multiprocessing import Process
from time import sleep

import clipboard


def copy(text, clear_after=40):
    """
    spawns subprocess to copy string to system clipboard, and clears clipboard after some time
    :param text: string - to copy to clipboard
    :param clear_after: int - seconds to clear clipboard after
    :return: None
    """
    Process(target=_copy_to_clipboard_, args=(text, clear_after)).start()


def _copy_to_clipboard_(text, seconds):
    """
    copy string to system clipboard, and clears clipboard after some time
    :param text: string - to copy to clipboard
    :param seconds: int - seconds to clear clipboard after
    :return: None
    """
    clipboard.copy(text)
    sleep(seconds)
    if clipboard.paste() == text:
        clipboard.copy('')
