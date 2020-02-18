"""
This module provides search capability for the password
store based on password names and comment fields.
"""

from os import PathLike
import logging

from whoosh.fields import Schema, ID, TEXT
from whoosh.filedb.filestore import RamStorage

from .pass_file_system import PassFile
from .pass_file_system import handle
from .ui_filesystem_tree import PassUiFileSystemTree


class InitializationError(Exception):
    """
    Raised when an function is called for the wrong initialization state of an object.
    """

class AlreadyInitializedError(InitializationError):
    """
    Raised when an initialization method is called on an already initialized object.
    This is a subclass of InitializationError.
    """

class NotInitializedError(InitializationError):
    """
    Raised when a method requiring prior initialization is called before the object
    has been initialized.
    This is a subclass of InitializationError.
    """

class PasswordSearch:
    """
    Provides metadata search over a PassUiFileSystemTree.
    """
    def __init__(self, file_system_tree=None, stored_index_path=None):
        """
        Can be initialized by givin a file system tree or a previously stored index.
        Providing neither will create the object but requires to initialize it by
        calling create_search_index or load_search_index manually.
        :param file_system_tree: PassUiFileSystemTree when provided create a new index
            from the file system tree
        :param stored_index_path: string or PathLike when provided and file_system_tree
            is not provided load a stored index from a file stored at the given path
        """
        logger = logging.getLogger(__name__)
        logger.debug('PasswordSearch.__init__: %r %r', file_system_tree, stored_index_path)
        self.__storage = None
        self.__index = None
        if file_system_tree:
            self.create_search_index(file_system_tree)
        elif stored_index_path:
            self.load_search_index(stored_index_path)

    @staticmethod
    def __create_schema():
        return Schema(name=ID(stored=True), path=ID(stored=True), comments=TEXT(stored=True))

    def is_initialized(self):
        """
        :return: bool does self have an index
        """
        return self.__index is not None

    def create_search_index(self, file_system_tree):
        """
        initialize self with index from generated from given PassUiFileSystemTree
        :param file_system_tree: PassUiFileSystemTree
        """
        logger = logging.getLogger(__name__)
        logger.debug('PasswordSearch.create_search_index: %r', file_system_tree)
        if self.is_initialized():
            raise AlreadyInitializedError
        if not isinstance(file_system_tree, PassUiFileSystemTree):
            raise ValueError('invalid input type')
        self.__storage = RamStorage()
        schema = PasswordSearch.__create_schema()
        self.__index = self.__storage.create_index(schema)

        writer = self.__index.writer()
        node = file_system_tree.topLevelItem(0)
        child_index = 0
        child_count = node.childCount()
        stack = []
        logger.debug('create_search_index: start of iteration')
        while True:
            logger.debug('create_search_index: %r %r (%r/%r)',
                         list(map(lambda a: (a[0].name, a[1], a[2]), stack)),
                         node.name,
                         child_index,
                         child_count)
            if child_index >= child_count:
                if len(stack) == 0:
                    logger.debug('create_search_index: end of iteration')
                    break
                logger.debug('create_search_index: end of directory')
                node, child_index, child_count = stack.pop()
                child_index += 1
            elif node.isdir:
                if child_index == 0:
                    logger.debug('create_search_index: processing directory')
                else:
                    logger.debug('create_search_index: continuing directory')
                stack.append((node, child_index, child_count))
                node = node.child(child_index)
                child_index = 0
                child_count = node.childCount()
                if node.isfile:
                    logger.debug('create_search_index: processing file %r', node.name)
                    pass_file = handle(node.file_system_path, node.name)
                    if not isinstance(pass_file, PassFile):
                        raise ValueError('file in tree is not a PassFile')
                    path = '/'.join(list(map(lambda a: a[0].name, stack)))
                    writer.add_document(name=pass_file.name,
                                        path=path,
                                        comments=pass_file.comments)
        writer.commit()
        with self.__index.searcher() as searcher:
            logger.debug('create_search_index: %r', list(searcher.all_stored_fields()))

    def load_search_index(self, stored_index_path):
        """
        initialize self with index from
        """
        logger = logging.getLogger(__name__)
        logger.debug('PasswordSearch.load_search_index: %r', stored_index_path)
        if self.is_initialized():
            raise AlreadyInitializedError
        if not isinstance(stored_index_path, (str, PathLike)):
            raise ValueError('invalid input type')
        #TODO
