"""
provides an interface to the pass file system
"""

# pylint: disable=too-many-arguments

# reusing variable names causes confusion
# pylint: disable=too-many-locals

import logging
from os import listdir, mkdir, rmdir, remove, walk
from pathlib import Path
from re import compile as re_compile
from shutil import move
from datetime import datetime as dt

from .gpg_handler import (decrypt, encrypt, get_recipients_from_gpg_id, write_gpg_id_file,
                          import_gpg_keys)
from .git_handler import (git_init, git_add, git_commit, git_clone, git_pull, git_commit_cycle,
                          repository_config_has_user_data, repository_config_set_user_data,
                          path_belongs_to_repository, repository_has_remote)
from .name_filter import make_valid_branch_name
from .pass_file_format_parser import PassFile


logging.getLogger(__name__).setLevel(logging.INFO)
def enable_file_system_debug_logging():
    """ enable file system debug logging """
    logging.getLogger(__name__).setLevel(logging.DEBUG)

class PassFileSystem():
    """
    Interface to the pass file system with the given root path
    """
    def __init__(self, password_store_root, config=None, git_credentials=None,
                 no_git_override=False):
        logger = logging.getLogger(__name__)
        logger.debug('PassFileSystem.__init__: (%r, %r, %r)', password_store_root, config,
                     'git_credentials' if git_credentials else None)

        self.password_store_root = password_store_root
        self.config = config or {}

        try:
            if not git_credentials:
                git_credentials = self.handle(password_store_root, '.git-credentials.gpg')

            if isinstance(git_credentials, PassFile):
                attributes = dict(git_credentials.attributes)
                self.git_credentials = {
                    'url': attributes['url'],
                    'username': attributes['username'],
                    'password': git_credentials.password
                }
            else:
                raise ValueError
        except (FileNotFoundError, ValueError, KeyError):
            self.git_credentials = {'url': None, 'username': None, 'password': None}

        if (not no_git_override and
                path_belongs_to_repository(password_store_root) and
                repository_has_remote(password_store_root)):
            logger.info('PassFileSystem.__init__:git_pull')
            git_pull(repository_path=password_store_root,
                     http_url=self.git_credentials['url'],
                     http_username=self.git_credentials['username'],
                     http_password=self.git_credentials['password'])

        logger.debug('PassFileSystem.__init__: %r', self)

    def __repr__(self):
        return 'PassFileSystem(%r, %r, %r)' % (
            self.password_store_root, self.config,
            'git_credentials' if self.git_credentials['password'] else None)

    def handle(self, root_path, name):
        """
        handles a change item selection change event from the UI
        :param root_path: PathLike - path to the folder containing the file
        :param name: string - name of the file
        :return: list of strings of gpg ids or cypher cleartext
        """
        logger = logging.getLogger(__name__)
        logger.debug('handle: root_path: %r', root_path)
        logger.debug('handle: name: %r', name)

        # Raises ValueError if root_path is not a subpath of self.password_store_root
        Path(root_path).relative_to(Path(self.password_store_root))

        if not Path(root_path, name).exists():
            raise FileNotFoundError
        if Path(root_path, name).is_file():
            logger.debug('handle: path is file')
            return PassFile(root_path=root_path, name=name)
        if Path(root_path, name).is_dir() and Path(root_path, name, '.gpg-id').exists():
            logger.debug('handle: path is directory with .gpg-id')
            list_to_return = []
            with open(Path(root_path, name, '.gpg-id')) as file_:
                for line in file_.readlines():
                    list_to_return.append(line.replace('\n', ''))
            logger.debug('handle: return: %r', list_to_return)
            return list_to_return
        logger.debug('handle: path is directory')
        gpg_id_file_path = self.search_gpg_id_file(Path(root_path, name))
        logger.debug('handle: gpg_id_file_path: %r', gpg_id_file_path)
        list_to_return = []
        with open(gpg_id_file_path) as file_:
            for line in file_.readlines():
                list_to_return.append(line.replace('\n', ''))
        logger.debug('handle: return: %r', list_to_return)
        return list_to_return

    def create_password_file(self, path_to_folder, name, password_file, skip_git=False):
        """
        creates a gpg encrypted .gpg file with respective name
        in the respective folder from PassFile Object
        :param path_to_folder:
        :param name:
        :param password_file:
        :return:
        """
        logger = logging.getLogger(__name__)
        logger.debug('create_password_file: path_to_folder: %r', path_to_folder)
        logger.debug('create_password_file: name: %r', name)

        # Raises ValueError if path_to_folder is not a subpath of self.password_store_root
        relative_path = str(Path(path_to_folder).relative_to(Path(self.password_store_root)))
        logger.debug('create_password_file: relative_path: %r', relative_path)

        gpg_id_file = self.search_gpg_id_file(path_to_folder)
        logger.debug('create_password_file: gpg_id_file: %r', gpg_id_file)
        if Path(gpg_id_file).exists():
            clear_text = password_file.get_cleartext().encode()
            logger.debug('create_password_file: len(clear_text): %r', len(clear_text))
            list_of_recipients = get_recipients_from_gpg_id(gpg_id_file)
            logger.debug('create_password_file: list_of_recipients: %r', list_of_recipients)
            file_name = f'{name}.gpg'
            path_to_file = str(Path(path_to_folder, file_name))
            logger.debug('create_password_file: path_to_file: %r', path_to_file)
            result = encrypt(clear_text=clear_text,
                             list_of_recipients=list_of_recipients,
                             path_to_file=path_to_file)

            if not skip_git:
                timestamp = dt.utcnow().isoformat().replace(':', '-').split('.')[0]
                branch_folder_part, folder_part, _ = self._format_relative_paths(relative_path, '.')
                git_commit_cycle(
                    repository_path=self.password_store_root,
                    file_paths=[Path(relative_path, file_name)],
                    branch_name=(f'create_password/{timestamp}/{branch_folder_part}'
                                 f'{make_valid_branch_name(name)}'),
                    commit_message=f'Create password for `{folder_part}{name}` using keyswarm.',
                    http_url=self.git_credentials['url'],
                    http_username=self.git_credentials['username'],
                    http_password=self.git_credentials['password'],
                    network_timeout=self.config.get('network', 'timeout', fallback=60))

            return result
        return False

    def delete_password_file(self, path_to_folder, name, skip_git=False):
        """
        deletes a .gpg file with the respective name in the respective folder
        :param path_to_folder: string
        :param name: string
        """
        logger = logging.getLogger(__name__)
        logger.debug('delete_password_file: path_to_folder: %r', path_to_folder)
        logger.debug('delete_password_file: name: %r', name)

        # Raises ValueError if path_to_folder is not a subpath of self.password_store_root
        relative_path = str(Path(path_to_folder).relative_to(Path(self.password_store_root)))

        file_name = f'{name}.gpg'
        absolute_file_path = Path(path_to_folder, file_name)
        relative_file_path = Path(relative_path, file_name)
        try:
            remove(absolute_file_path)

            if not skip_git:
                timestamp = dt.utcnow().isoformat().replace(':', '-').split('.')[0]
                folder_part, branch_folder_part, _ = self._format_relative_paths(relative_path, '.')
                git_commit_cycle(
                    repository_path=self.password_store_root, file_paths=[relative_file_path],
                    branch_name=(f'delete_password/{timestamp}/{branch_folder_part}'
                                 f'{make_valid_branch_name(name)}'),
                    commit_message=(f'Delete password for `{folder_part}{name}` using keyswarm.'),
                    http_url=self.git_credentials['url'],
                    http_username=self.git_credentials['username'],
                    http_password=self.git_credentials['password'],
                    network_timeout=self.config.get('network', 'timeout', fallback=60))

        except IsADirectoryError:
            logger.warning('delete_password_file: tried to remove directory: %r',
                           absolute_file_path)
        except FileNotFoundError:
            logger.warning('delete_password_file: tried to remove non-existent file: %r',
                           absolute_file_path)
        except PermissionError:
            logger.warning('delete_password_file: insufficient permission to remove file: %r',
                           absolute_file_path)

    def move_password_file(self, path_to_old_folder, old_name, path_to_new_folder, new_name,
                           skip_git=False):
        """
        convinience function around change_password_file that retrieves the password_file
        before calling change_password_file
        :param path_to_old_folder: PathLike
        :param old_name: string
        :param path_to_new_folder: PathLike
        :param new_name: string
        """
        logger = logging.getLogger(__name__)
        logger.debug('move_password_file: path_to_old_folder: %r', path_to_old_folder)
        logger.debug('move_password_file: old_name: %r', old_name)
        logger.debug('move_password_file: path_to_new_folder: %r', path_to_new_folder)
        logger.debug('move_password_file: new_name: %r', new_name)

        # Raises ValueError if path_to_old_folder is not a subpath of self.password_store_root
        relative_old_path = Path(path_to_old_folder).relative_to(Path(self.password_store_root))
        # Raises ValueError if path_to_new_folder is not a subpath of self.password_store_root
        relative_new_path = Path(path_to_new_folder).relative_to(Path(self.password_store_root))

        pass_file = self.handle(path_to_old_folder, f'{old_name}.gpg')
        logger.debug('move_password_file: pass_file: %r', pass_file)
        if pass_file and pass_file.__class__ == PassFile:
            self.change_password_file(
                path_to_old_folder=path_to_old_folder, old_name=old_name,
                path_to_new_folder=path_to_new_folder, new_name=new_name,
                password_file=pass_file, skip_git=True)

            if not skip_git:
                timestamp = dt.utcnow().isoformat().replace(':', '-').split('.')[0]
                branch_folder_part, old_folder_part, new_folder_part = self._format_relative_paths(
                    relative_old_path, relative_new_path)
                git_commit_cycle(
                    repository_path=self.password_store_root,
                    file_paths=[Path(relative_old_path, f'{old_name}.gpg'),
                                Path(relative_new_path, f'{new_name}.gpg')],
                    branch_name=(f'move_password/{timestamp}/{branch_folder_part}'
                                 f'{make_valid_branch_name(old_name)}'),
                    commit_message=(f'Move password from `{old_folder_part}{old_name}` to `'
                                    f'{new_folder_part}{new_name}` using keyswarm.'),
                    http_url=self.git_credentials['url'],
                    http_username=self.git_credentials['username'],
                    http_password=self.git_credentials['password'],
                    network_timeout=self.config.get('network', 'timeout', fallback=60))


    def change_password_file(self, path_to_old_folder, old_name, path_to_new_folder,
                             new_name, password_file, skip_git=False):
        """
        write the given password file to the new location under the new name
        if the new name or path differs from the old the old file will be deleted
        :param path_to_old_folder: PathLike
        :param old_name: string
        :param path_to_new_folder: PathLike
        :param new_name: string
        :param password_file: PassFile
        """
        logger = logging.getLogger(__name__)
        logger.debug('change_password_file: path_to_old_folder: %r', path_to_old_folder)
        logger.debug('change_password_file: old_name: %r', old_name)
        logger.debug('change_password_file: path_to_new_folder: %r', path_to_new_folder)
        logger.debug('change_password_file: new_name: %r', new_name)

        # Raises ValueError if path_to_old_folder is not a subpath of self.password_store_root
        relative_old_path = Path(path_to_old_folder).relative_to(Path(self.password_store_root))
        # Raises ValueError if path_to_new_folder is not a subpath of self.password_store_root
        relative_new_path = Path(path_to_new_folder).relative_to(Path(self.password_store_root))

        if path_to_old_folder == path_to_new_folder and old_name == new_name:
            self.create_password_file(
                path_to_folder=path_to_old_folder,
                name=old_name,
                password_file=password_file,
                skip_git=True)

            file_path = (Path(relative_old_path, f'{old_name}.gpg'))

            if not skip_git:
                timestamp = dt.utcnow().isoformat().replace(':', '-').split('.')[0]
                branch_folder_part, old_folder_part, new_folder_part = self._format_relative_paths(
                    relative_old_path, relative_new_path)
                git_commit_cycle(
                    repository_path=self.password_store_root,
                    file_paths=[file_path],
                    branch_name=(f'change_password/{timestamp}/{branch_folder_part}'
                                 f'{make_valid_branch_name(old_name)}'),
                    commit_message=(f'Change password for `{old_folder_part}{old_name}` '
                                    f'using keyswarm.'),
                    http_url=self.git_credentials['url'],
                    http_username=self.git_credentials['username'],
                    http_password=self.git_credentials['password'],
                    network_timeout=self.config.get('network', 'timeout', fallback=60))
        else:
            if Path(path_to_new_folder, new_name).exists():
                logger.debug('change_password_file: new file already exists')
                raise ValueError('duplicate password name')

            self.create_password_file(path_to_folder=path_to_new_folder, name=new_name,
                                      password_file=password_file, skip_git=True)
            self.delete_password_file(path_to_folder=path_to_old_folder, name=old_name,
                                      skip_git=True)

            if not skip_git:
                timestamp = dt.utcnow().isoformat().replace(':', '-').split('.')[0]
                branch_folder_part, old_folder_part, new_folder_part = self._format_relative_paths(
                    relative_old_path, relative_new_path)
                git_commit_cycle(
                    repository_path=self.password_store_root,
                    file_paths=[Path(relative_old_path, f'{old_name}.gpg'),
                                Path(relative_new_path, f'{new_name}.gpg')],
                    branch_name=(f'change_move_password/{timestamp}/{branch_folder_part}'
                                 f'{make_valid_branch_name(old_name)}'),
                    commit_message=(f'Change/Move password from `{old_folder_part}{old_name}` t'
                                    f'o `{new_folder_part}{new_name}` using keyswarm.'),
                    http_url=self.git_credentials['url'],
                    http_username=self.git_credentials['username'],
                    http_password=self.git_credentials['password'],
                    network_timeout=self.config.get('network', 'timeout', fallback=60))

    def create_folder(self, path_to_folder, name):
        """
        creates a new folder with respective name in respective path
        :param path_to_folder: string
        :param name: string
        :return: None
        """
        logger = logging.getLogger(__name__)
        logger.debug('create_folder: path_to_folder: %r', path_to_folder)
        logger.debug('create_folder: name: %r', name)

        # Raises ValueError if path_to_folder is not a subpath of self.password_store_root
        Path(path_to_folder).relative_to(Path(self.password_store_root))

        mkdir(Path(path_to_folder, name))

    def move_password_folder(self, path_to_old_parent_folder, old_name, path_to_new_parent_folder,
                             new_name, skip_git=False):
        """
        moves a folder including its content into another folder
        :param path_to_old_paren_folder: string
        :param old_name: string
        :path_to_new_parent_folder: string
        :new_name: string
        """
        logger = logging.getLogger(__name__)
        logger.debug('move_password_folder: path_to_old_parent_folder: %r',
                     path_to_old_parent_folder)
        logger.debug('move_password_folder: old_name: %r', old_name)
        logger.debug('move_password_folder: path_to_new_parent_folder: %r',
                     path_to_new_parent_folder)
        logger.debug('move_password_folder: new_name: %r', new_name)

        #Raises ValueError if path_to_old_parent_folder is not a subpath of self.password_store_root
        relative_old_path = Path(path_to_old_parent_folder).relative_to(Path(
            self.password_store_root))
        #Raises ValueError if path_to_new_parent_folder is not a subpath of self.password_store_root
        relative_new_path = Path(path_to_new_parent_folder).relative_to(Path(
            self.password_store_root))

        if not Path(path_to_old_parent_folder, old_name).exists():
            raise FileNotFoundError('source folder does not exists')
        if not Path(path_to_new_parent_folder).exists():
            raise FileNotFoundError('target parent folder does not exist')
        if Path(path_to_new_parent_folder, new_name).exists():
            raise FileExistsError('target folder already exists')
        if Path(path_to_old_parent_folder, old_name, '.gpg-id').exists():
            logger.debug('move_password: .gpg-id found, moving folder without reencryption')
            move(Path(path_to_old_parent_folder, old_name),
                 Path(path_to_new_parent_folder, new_name))
        else:
            self.create_folder(path_to_new_parent_folder, new_name)
            for root, folders, files in walk(Path(path_to_old_parent_folder, old_name)):
                logger.debug('move_password_folder: root: %r folders: %r files: %r',
                             root, folders, files)
                for file_ in files:
                    logger.debug('move_password_folder: file: %r', file_)
                    self.move_password_file(
                        path_to_old_folder=Path(path_to_old_parent_folder, old_name),
                        old_name=file_.replace('.gpg', ''),
                        path_to_new_folder=Path(path_to_new_parent_folder, new_name),
                        new_name=file_.replace('.gpg', ''),
                        skip_git=True)
                for folder in folders:
                    logger.debug('move_password_folder: folder: %r', folder)
                    self.move_password_folder(
                        path_to_old_parent_folder=Path(path_to_old_parent_folder, old_name),
                        old_name=folder,
                        path_to_new_parent_folder=Path(path_to_new_parent_folder, new_name),
                        new_name=folder,
                        skip_git=True)
                break
            rmdir(Path(path_to_old_parent_folder, old_name))

        if not skip_git:
            timestamp = dt.utcnow().isoformat().replace(':', '-').split('.')[0]

            branch_folder_part, old_folder_part, new_folder_part = self._format_relative_paths(
                relative_old_path, relative_new_path)

            git_commit_cycle(
                repository_path=self.password_store_root,
                file_paths=[Path(relative_old_path, old_name),
                            Path(relative_new_path, new_name)],
                branch_name=(f'move_folder/{timestamp}/{branch_folder_part}'
                             f'{make_valid_branch_name(old_name)}'),
                commit_message=(f'Move folder from `{old_folder_part}{old_name}` to `'
                                f'{new_folder_part}{new_name}` using keyswarm.'),
                http_url=self.git_credentials['url'],
                http_username=self.git_credentials['username'],
                http_password=self.git_credentials['password'],
                network_timeout=self.config.get('network', 'timeout', fallback=60))

    def search_gpg_id_file(self, path_to_folder):
        """
        recursively find the folder containing the correct .gpg-id file
        :param path_to_folder: PathLike - path to start
        :return: string
        """
        logger = logging.getLogger(__name__)
        logger.debug('search_gpg_id_file: path_to_folder: %r', path_to_folder)

        # Raises ValueError if path_to_folder is not a subpath of self.password_store_root
        Path(path_to_folder).relative_to(Path(self.password_store_root))

        return_path = Path(path_to_folder, '.gpg-id')
        parent_of_path_to_folder = Path(path_to_folder).parent
        if not Path(return_path).exists():
            return self.search_gpg_id_file(parent_of_path_to_folder)
        return str(return_path)

    def recursive_reencrypt(self, path_to_folder, list_of_keys, gpg_home=None,
                            additional_parameter=None, skip_git=False):
        """
        recursively reencrypts all files in a given path with the respective gpg public keys
        :param additional_parameter: gpg parameter - DO NOT USE THIS Except for testing purposes
        :param gpg_home: gpg_home directory to use
        :param path_to_folder: complete path to root folder
        :param list_of_keys: list of strings
        :return: None
        """
        logger = logging.getLogger(__name__)
        logger.debug('recursive_reencrypt: path_to_folder: %r', path_to_folder)
        logger.debug('recursive_reencrypt: list_of_keys: %r', list_of_keys)
        logger.debug('recursive_reencrypt: gpg_home: %r', gpg_home)
        logger.debug('recursive_reencrypt: additional_parameter: %r', additional_parameter)

        # Raises ValueError if path_to_folder is not a subpath of self.password_store_root
        relative_path = Path(path_to_folder).relative_to(Path(self.password_store_root))

        for file_ in listdir(path_to_folder):
            if Path(path_to_folder, file_).is_dir():
                logger.debug('recursive_reencrypt: folder: %r %r', path_to_folder, file_)
                if Path(path_to_folder, file_, '.gpg-id').exists():
                    logger.debug('recursive_reencrypt: has .gpg-id file')
                else:
                    logger.debug('recursive_reencrypt: does not have .gpg-id file')
                    self.recursive_reencrypt(
                        path_to_folder=Path(path_to_folder, file_),
                        list_of_keys=list_of_keys,
                        gpg_home=gpg_home,
                        additional_parameter=additional_parameter,
                        skip_git=True)
            else:
                logger.debug('recursive_reencrypt: file: %r %r', path_to_folder, file_)
                if file_[-4:] == '.gpg':
                    logger.debug('recursive_reencrypt: gpg_file')
                    file_path = Path(path_to_folder, file_)
                    cleartext = decrypt(file_path, gpg_home=gpg_home,
                                        additional_parameter=additional_parameter)
                    encrypt(clear_text=cleartext.encode(),
                            list_of_recipients=list_of_keys,
                            path_to_file=file_path,
                            gpg_home=gpg_home)

        logger.debug('recursive_reencrypt: done with %r', path_to_folder)

        if not skip_git:
            timestamp = dt.utcnow().isoformat().replace(':', '-').split('.')[0]
            git_commit_cycle(
                repository_path=self.password_store_root,
                file_paths=['.gpg-id', relative_path],
                branch_name=(f'reencrypt/{timestamp}/'
                             f'{make_valid_branch_name(str(relative_path))}'),
                commit_message=(f'Reencrypt passwords in {relative_path} for changed recipients us'
                                f'ing keyswarm.'),
                http_url=self.git_credentials['url'],
                http_username=self.git_credentials['username'],
                http_password=self.git_credentials['password'],
                network_timeout=self.config.get('network', 'timeout', fallback=60))


    def refresh_password_store(self):
        """ pulls from git remote and imports new gpg keys from repository """
        logger = logging.getLogger(__name__)
        logger.info('refresh_password_store:git_pull')
        git_pull(
            repository_path=self.password_store_root,
            http_url=self.git_credentials['url'],
            http_username=self.git_credentials['username'],
            http_password=self.git_credentials['password'],
            timeout=self.config.get('network', 'timeout', fallback=60))
        logger.info('refresh_password_store:import_gpg_keys')
        import_gpg_keys(self.password_store_root)


    @staticmethod
    def initialize_password_store(password_store_root, config, use_git=False):
        """
        set up an empty password store for self use
        :param password_store_root: PathLike root path of the password store directory
        :param own_key_id: string id of the users gpg secret key
        """
        logger = logging.getLogger(__name__)
        logger.info('initialize_password_store')
        logger.debug('initialize_password_store: (%r, %r, %r)',
                     password_store_root, config, git_init)

        own_key_id = config['gpg']['user_key_id']
        mkdir(password_store_root)
        write_gpg_id_file(Path(password_store_root, '.gpg-id'), [own_key_id])
        if use_git:
            git_init(password_store_root)
            git_add(password_store_root, ['.gpg-id'])
            git_commit(password_store_root, f'initialized empty password store for "{own_key_id}"')

        return PassFileSystem(password_store_root, config)

    @staticmethod
    def clone_password_store(password_store_root, repo_info, config):
        """
        clone a repository as the password store
        :param password_store_root: PathLike root path of the password store directory
        :param repo_info: dict(dict(string)) connection information for the remote repository
        """
        logger = logging.getLogger(__name__)
        logger.info('clone_password_store')
        logger.debug('clone_password_store: (%r, %r)', password_store_root, repo_info)

        own_key_id = config['gpg']['user_key_id']
        if len(repo_info['ssh']['url']) > 0:
            git_clone(repository_path=password_store_root, url=repo_info['ssh']['url'])
            file_system = PassFileSystem(password_store_root, config)
        else:
            git_clone(repository_path=password_store_root,
                      url=repo_info['http']['url'],
                      http_username=repo_info['http']['username'],
                      http_password=repo_info['http']['password'],
                      timeout=config.get('network', 'timeout', fallback=60))
            git_auth = PassFile()
            git_auth.password = repo_info['http']['password']
            git_auth.attributes.append(('username', repo_info['http']['username']))
            git_auth.attributes.append(('url', repo_info['http']['url']))
            git_auth.root_path = password_store_root
            git_auth.name = '.git_credentials'

            clear_text = git_auth.get_cleartext().encode()
            logger.debug('clone_password_store: len(clear_text): %r', len(clear_text))
            path_to_file = Path(password_store_root, '.git-credentials.gpg')
            logger.debug('clone_password_store: path_to_file: %r', path_to_file)
            encrypt(clear_text=clear_text,
                    list_of_recipients=[own_key_id],
                    path_to_file=path_to_file)
            file_system = PassFileSystem(password_store_root, config, git_auth)

        if not repository_config_has_user_data(password_store_root):
            regex = re_compile('^([^<]+) <([^>]+)>$')
            match = regex.match(own_key_id)
            user_name, user_email = match.groups()
            repository_config_set_user_data(password_store_root, user_name, user_email)

        return file_system

    @staticmethod
    def _format_relative_paths(relative_old_path, relative_new_path):
        old_folder_part = str(relative_old_path)
        if old_folder_part == '.':
            old_folder_part = ''
            branch_folder_part = ''
        else:
            old_folder_part = f'{relative_old_path}/'
            branch_folder_part = f'{make_valid_branch_name(str(relative_old_path))}/'

        new_folder_part = str(relative_new_path)
        if new_folder_part == '.':
            new_folder_part = ''
        else:
            new_folder_part = f'{relative_new_path}/'

        return branch_folder_part, old_folder_part, new_folder_part
