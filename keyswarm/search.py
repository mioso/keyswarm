"""
This module provides search capability for the password
store based on password names and comment fields.
"""

import logging

from whoosh.fields import Schema, TEXT
from whoosh.filedb.filestore import RamStorage
from whoosh.qparser import MultifieldParser, FuzzyTermPlugin, PhrasePlugin
from whoosh.query.qcore import _NullQuery
from whoosh.query.terms import Term, FuzzyTerm, Prefix, Wildcard

from .pass_file_system import PassFile
from .ui_filesystem_tree import PassUiFileSystemTree


class PasswordSearch:
    """
    Provides metadata search over a PassUiFileSystemTree.
    """
    def __init__(self, file_system_tree):
        """
        Can be initialized by givin a file system tree or a previously stored index.
        Providing neither will create the object but requires to initialize it by
        calling create_search_index or load_search_index manually.
        :param file_system_tree: PassUiFileSystemTree when provided create a new index
            from the file system tree
        """
        logger = logging.getLogger(__name__)
        logger.debug('PasswordSearch.__init__: %r', file_system_tree)
        self.__tree = file_system_tree
        self.__storage = None
        self.__index = None
        self.__fields = ['name', 'path', 'comments']
        self.__create_search_index(file_system_tree)

    @staticmethod
    def __create_schema():
        return Schema(name=TEXT(stored=True), path=TEXT(stored=True), comments=TEXT(stored=True))

    def __create_search_index(self, file_system_tree):
        """
        initialize self with index from generated from given PassUiFileSystemTree
        :param file_system_tree: PassUiFileSystemTree
        """
        logger = logging.getLogger(__name__)
        logger.debug('PasswordSearch.create_search_index: %r', file_system_tree)
        if not isinstance(file_system_tree, PassUiFileSystemTree):
            raise ValueError('invalid input type')
        self.__storage = RamStorage()
        schema = PasswordSearch.__create_schema()
        self.__index = self.__storage.create_index(schema)

        attributes = set()
        documents = []
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
                    try:
                        pass_file = self.__tree.file_system.handle(node.file_system_path,
                                                                   node.name)
                        if not isinstance(pass_file, PassFile):
                            raise ValueError('file in tree is not a PassFile')
                        path = '/'.join(list(map(lambda a: a[0].name, stack)))
                        document = {
                            'name': pass_file.name,
                            'path': path,
                            'comments': pass_file.comments
                            }
                        logger.debug('__create_search_index: file_attributes: %r', pass_file.attributes)
                        for attribute in pass_file.attributes:
                            try:
                                key, value = attribute
                                logger.debug('__create_search_index: (key, value): (%r, %r)', key, value)
                                if key not in ['name', 'path', 'comments']:
                                    attributes.add(key)
                                    document[key] = value
                            except ValueError as error:
                                logger.debug('__create_search_index: unpack_error: %r', error)
                        documents.append(document)
                    except ValueError as error:
                        logger.debug('create_search_index: %r', error)
        logger.debug('__create_search_index: attributes: %r', attributes)
        self.__fields.extend(attributes)
        writer = self.__index.writer()
        for attribute in attributes:
            logger.debug('__create_search_index: adding field for attribute %r', attribute)
            writer.add_field(attribute, TEXT)
        for document in documents:
            logger.debug('__create_search_index: adding document %r', document)
            writer.add_document(**document)
        writer.commit()
        with self.__index.searcher() as searcher:
            logger.debug('create_search_index: %r', list(searcher.all_stored_fields()))

    @staticmethod
    def modify_query(query, glob_prefix, glob_suffix, fuzzy):
        """
        change all terms of a query according to flags
        :param query: whoosh.query
        :param glob_prefix: flag change term to Wildcard with `*` prepended
        :param glob_suffix: flag change term to Prefix or wildcard with `*` appended
        :param fuzzy: flag change term to FuzzyTerm with `~` appended
        """
        logger = logging.getLogger(__name__)
        logger.debug('modify_query: %r %r %r %r', query, glob_prefix, glob_suffix, fuzzy)
        if isinstance(query, Term):
            if glob_prefix:
                if glob_suffix:
                    logger.debug('modify_query: glob')
                    return Wildcard(query.fieldname, f'*{query.text}*')
                logger.debug('modify_query: prefix glob')
                return Wildcard(query.fieldname, f'*{query.text}')
            if glob_suffix:
                logger.debug('modify_query: suffix glob')
                return Prefix(query.fieldname, query.text)
            if fuzzy:
                logger.debug('modify_query: fuzzy')
                return FuzzyTerm(query.fieldname, query.text)
            logger.debug('modify_query: invalid flag permutation: %r',
                         (glob_prefix, glob_suffix, fuzzy))
            raise ValueError(f'invalid flag permutation: {(glob_prefix, glob_suffix, fuzzy)}')
        try:
            query.subqueries = list(map(lambda a: PasswordSearch.modify_query(
                a, glob_prefix, glob_suffix, fuzzy), query.subqueries))
            return query
        except AttributeError:
            logger.debug('modify_query: no subqueries')
            return query

    def search(self, raw_query, glob_prefix=False, glob_suffix=True, fuzzy=False):
        """
        perform a search on the internal index

        :param raw_query: string the search query as entered by the user
        :param glob_prefix: Boolean wether to prefix every term with `*`
        :param glob_suffix: Boolean wether to suffix every term with `*`
        :param fuzzy: Boolean wether to suffix every term with `~`
        :param return: [dict]
        """
        logger = logging.getLogger(__name__)
        logger.debug('search: raw_query: %r %r %r %r', raw_query, glob_prefix, glob_suffix, fuzzy)
        if (glob_prefix or glob_suffix) and fuzzy:
            logger.warning('search: auto-glob and auto-fuzzy are mutually exclusive')
            raise ValueError('auto-glob and auto-fuzzy are mutually exclusive')

        with self.__index.searcher() as searcher:
            # pylint: disable=no-member
            logger.debug('search: %r', list(searcher.all_stored_fields()))
            parser = MultifieldParser(self.__fields, self.__index.schema)
            parser.add_plugin(FuzzyTermPlugin())
            parser.add_plugin(PhrasePlugin())
            query = parser.parse(raw_query)
            logger.debug('search: query: %r', query)

            if not isinstance(query, _NullQuery) and (glob_prefix or glob_suffix or fuzzy):
                query = PasswordSearch.modify_query(query, glob_prefix, glob_suffix, fuzzy)
                logger.debug('search: modified_query: %r', query)

            results = searcher.search(query, limit=None)
            logger.debug('search: results: %r', results)
            logger.debug('search: results: %r', list(results))
            return list(map(dict, results))
