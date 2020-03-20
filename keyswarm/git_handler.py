"""
this module interacts with the git binary and provides
pulling, branching, staging, committing and pushing
"""

from functools import lru_cache
import logging
from subprocess import call, PIPE, Popen

class GitError(Exception):
    """
    base class for representing unspecified errors thrown by the git executable
    """

class NotARepositoryError(GitError):
    """
    class for representing a git command being called on a non-git path
    """

class GitInitError(GitError):
    """
    class for representing errors during git init
    """

class GitPullError(GitError):
    """
    class for representing errors during git pull
    """

class GitPushError(GitError):
    """
    class for representing errors during git push
    """

class GitCommitError(GitError):
    """
    class for representing errors during git commit
    """

class GitAddError(GitError):
    """
    class for representing errors during git add
    """

class GitCheckoutError(GitError):
    """
    class for representing errors during git checkout
    """

class GitBranchError(GitError):
    """
    class for representing errors during git branch
    """

class GitCloneError(GitError):
    """
    class for representing errors during git clone
    """


def get_binary():
    """
    returns the name of the git binary
    """
    return 'git'


def git_config_credential_helper():
    """
    sets `credential.helper` to `cache` in the global git config
    """
    logger = logging.getLogger(__name__)
    logger.debug('`git config credential.helper cache`')
    return_code = call([get_binary(), 'config', '--global', 'credential.helper', 'cache'])
    logger.debug('return_code: %r', return_code)


def _split_url(url):
    logger = logging.getLogger(__name__)
    logger.debug('_split_url: (%r)', url)
    splits = url.split('://')
    logger.debug('_split_url: %r', splits)

    if len(splits) != 2:
        logger.debug('_split_url: not split in 2')
        raise ValueError("url format not accepted")

    schema = splits[0]
    host = splits[1].split('/')[0]

    return schema, host


def cache_credentials(url, username, password):
    """
    writes the credentials for the host extraced from the given url to the git credential cache

    :param url: string url of the remote host or the repository on the remote host
        must contain schema, must contain host, must not contain userinfo
        general url shape: `scheme:[//[userinfo@]host[:port]]path[?query][#fragment]`
        accepted url shape: `scheme://host[:port][/[path][?query][#fragment]]`
    :param username: string username
    :param password: string password
    """
    logger = logging.getLogger(__name__)
    logger.debug('cache_credentials: (%r, %r, %r)', url, username, password)
    protocol, host = _split_url(url)

    input_ = f'protocol={protocol}\nhost={host}\nusername={username}\npassword={password}\n\n'
    logger.debug('cache_credentials: %r', input_)
    git_config_credential_helper()
    git_process = Popen([get_binary(), 'credential-cache', 'store'],
                        stdin=PIPE, stdout=PIPE, stderr=PIPE)
    stdout, stderr = git_process.communicate(input_.encode('utf-8'), timeout=2)
    logger.debug('cache_credentials: stdout: %r', stdout)
    logger.debug('cache_credentials: stderr: %r', stderr)


def get_repository_root(directory_path):
    """
    returns the root path of a repository as determined by `git rev-parse --show-toplevel`
    """
    logger = logging.getLogger(__name__)
    logger.debug('get_repository_root: (%r)', directory_path)

    git_process = Popen([get_binary(), 'rev-parse', '--show-toplevel'],
                        cwd=directory_path, stdout=PIPE, stderr=PIPE)
    git_process.wait(timeout=2)
    logger.debug('get_repository_root: returncode: %r', git_process.returncode)
    logger.debug('get_repository_root: stdout: %r',
                 git_process.stdout.read() if git_process.stdout else None)
    logger.debug('get_repository_root: stderr: %r',
                 git_process.stderr.read() if git_process.stderr else None)

    if git_process.returncode == 0:
        return git_process.stdout.read()
    raise NotARepositoryError


@lru_cache(maxsize=1024)
def path_belongs_to_repository(directory_path):
    """
    returns wether the given directory path is part of a git repository

    the check is performed by changing to the directory path, calling `git status`
    and checking the return code

    :param directory_path: PathLike path of the directory
    :return: Boolean
    """
    logger = logging.getLogger(__name__)
    logger.debug('path_belongs_to_repository: (%r)', directory_path)

    try:
        get_repository_root(directory_path)
        return True
    except NotARepositoryError:
        return False


@lru_cache(maxsize=1024)
def repository_has_remote(repository_path):
    """
    returns wether the repository has a remote
    """
    logger = logging.getLogger(__name__)
    logger.debug('repository_has_remote: (%r)', repository_path)

    git_process = Popen([get_binary(), 'remote', 'show'], cwd=repository_path,
                        stdout=PIPE, stderr=PIPE)
    stdout, stderr = git_process.communicate(timeout=2)
    logger.debug('repository_has_remote: returncode: %r', git_process.returncode)
    logger.debug('repository_has_remote: stdout: %r', stdout)
    logger.debug('repository_has_remote: stderr: %r', stderr)
    if git_process.returncode != 0:
        raise NotARepositoryError
    return stdout and len(stdout) > 0


def git_init(directory_path):
    """
    performs `git init` on the given directory
    """
    logger = logging.getLogger(__name__)
    logger.debug('git_init: (%r)', directory_path)
    git_process = Popen([get_binary(), 'init'], cwd=directory_path, stdout=PIPE, stderr=PIPE)
    git_process.wait()
    logger.debug('git_init: returncode: %r', git_process.returncode)
    logger.debug('git_init: stdout: %r', git_process.stdout.read() if git_process.stdout else None)
    logger.debug('git_init: stderr: %r', git_process.stderr.read() if git_process.stderr else None)
    if git_process.returncode != 0:
        raise GitInitError


def git_clone(repository_path, url, http_username=None, http_password=None, timeout=60):
    """
    performs `git clone`
    """
    logger = logging.getLogger(__name__)
    logger.debug('git_clone: (%r, %r, %r, %r)', repository_path, url, http_username, http_password)

    if http_username and http_password:
        cache_credentials(url, http_username, http_password)

    git_process = Popen([get_binary(), 'clone', '--recurse-submodules', url, '--',
                         repository_path], stdout=PIPE, stderr=PIPE)
    git_process.wait(timeout=timeout)
    logger.debug('git_clone: returncode: %r', git_process.returncode)
    logger.debug('git_clone: stdout: %r', git_process.stdout.read() if git_process.stdout else None)
    logger.debug('git_clone: stderr: %r', git_process.stderr.read() if git_process.stderr else None)
    if git_process.returncode != 0:
        raise GitCloneError


def git_pull(repository_path, branch_name=None, http_url=None, http_username=None,
             http_password=None, timeout=60):
    """
    performs `git pull` on the given repository
    pulls a branch if given

    :param repository_path: PathLike path of the repository
    :param branch_name: string if present the branch pull the branch with this name
    """
    logger = logging.getLogger(__name__)
    logger.debug('git_pull: (%r, %r)', repository_path, branch_name)

    if not path_belongs_to_repository(repository_path):
        return
    if http_url and http_username and http_password:
        cache_credentials(http_url, http_username, http_password)

    if branch_name:
        git_process = Popen([get_binary(), 'pull', 'origin', branch_name, '--'],
                            cwd=repository_path, stdout=PIPE, stderr=PIPE)
    else:
        git_process = Popen([get_binary(), 'pull', '--recurse-submodules'], cwd=repository_path,
                            stdout=PIPE, stderr=PIPE)
    git_process.wait(timeout=timeout)
    logger.debug('git_pull: returncode: %r', git_process.returncode)
    logger.debug('git_pull: stdout: %r', git_process.stdout.read() if git_process.stdout else None)
    logger.debug('git_pull: stderr: %r', git_process.stderr.read() if git_process.stderr else None)
    if git_process.returncode != 0:
        raise GitPullError


def git_branch(repository_path, branch_name):
    """
    performs `git branch` on the given repository

    :param repository_path: PathLike path of the repository
    :param branch_name: string name of the new branch
    """
    logger = logging.getLogger(__name__)
    logger.debug('git_branch: (%r, %r)', repository_path, branch_name)

    if not path_belongs_to_repository(repository_path):
        return

    git_process = Popen([get_binary(), 'branch', branch_name, '--'], cwd=repository_path,
                        stdout=PIPE, stderr=PIPE)
    git_process.wait()
    logger.debug('git_branch: returncode: %r', git_process.returncode)
    logger.debug('git_branch: stdout: %r', git_process.stdout.read() if git_process.stdout
                 else None)
    logger.debug('git_branch: stderr: %r', git_process.stderr.read() if git_process.stderr
                 else None)
    if git_process.returncode != 0:
        raise GitBranchError


def git_checkout_branch(repository_path, branch_name):
    """
    performs `git checkout <branch> --` on the given repository

    :param repository_path: PathLike path of the repository
    :param branch_name: string name of the branch
    """
    logger = logging.getLogger(__name__)
    logger.debug('git_checkout_branch: (%r, %r)', repository_path, branch_name)

    if not path_belongs_to_repository(repository_path):
        return

    git_process = Popen([get_binary(), 'checkout', branch_name, '--'], cwd=repository_path,
                        stdout=PIPE, stderr=PIPE)
    if git_process.wait() != 0:
        raise GitCheckoutError


def git_add(repository_path, file_paths):
    """
    performs `git add -- <file>` on the given repository

    :param repository_path: PathLike path of the repository
    :param file_paths: [PathLike] paths of the files to add
    """
    logger = logging.getLogger(__name__)
    logger.debug('git_add: (%r, %r)', repository_path, file_paths)

    if not path_belongs_to_repository(repository_path):
        return

    git_process = Popen([get_binary(), 'add', '--', *file_paths], cwd=repository_path,
                        stdout=PIPE, stderr=PIPE)
    git_process.wait()
    logger.debug('git_add: returncode: %r', git_process.returncode)
    logger.debug('git_add: stdout: %r', git_process.stdout.read() if git_process.stdout else None)
    logger.debug('git_add: stderr: %r', git_process.stderr.read() if git_process.stderr else None)

    if git_process.returncode != 0:
        raise GitAddError


def git_commit(repository_path, commit_message):
    """
    performs `git commit` on the given repository

    :param repository_path: PathLike path of the repository
    :param commit_message: string the message for the commit
    """
    logger = logging.getLogger(__name__)
    logger.debug('git_commit: (%r, %r)', repository_path, commit_message)

    if not path_belongs_to_repository(repository_path):
        return

    git_process = Popen([get_binary(), 'commit', '-m', commit_message], cwd=repository_path,
                        stdout=PIPE, stderr=PIPE)
    git_process.wait()
    logger.debug('git_commit: returncode: %r', git_process.returncode)
    logger.debug('git_commit: stdout: %r', git_process.stdout.read() if git_process.stdout else
                 None)
    logger.debug('git_commit: stderr: %r', git_process.stderr.read() if git_process.stderr else
                 None)
    if git_process.returncode != 0:
        raise GitCommitError


def git_push(repository_path, http_url=None, http_username=None, http_password=None, timeout=60):
    """
    performs `git push` on the given repository

    :param repository_path: PathLike path of the repository
    """
    logger = logging.getLogger(__name__)
    logger.debug('git_push: (%r)', repository_path)

    if not path_belongs_to_repository(repository_path):
        return
    if http_url and http_username and http_password:
        cache_credentials(http_url, http_username, http_password)

    git_process = Popen([get_binary(), 'push'], cwd=repository_path, stdout=PIPE, stderr=PIPE)
    git_process.wait(timeout=timeout)
    logger.debug('git_push: returncode: %r', git_process.returncode)
    logger.debug('git_push: stdout: %r', git_process.stdout.read() if git_process.stdout else None)
    logger.debug('git_push: stderr: %r', git_process.stderr.read() if git_process.stderr else None)
    if git_process.returncode != 0:
        raise GitPushError


def git_push_set_origin(repository_path, branch_name, http_url=None, http_username=None,
                        http_password=None, timeout=60):
    """
    performs `git push --set-origin origin <branch>` on the given repository
    seperate function from git_push for explicities sake

    :param repository_path: PathLike path of the repository
    :param branch_name: string name ot the branch
    """
    logger = logging.getLogger(__name__)
    logger.debug('git_push_set_origin: (%r, %r)', repository_path, branch_name)

    if not path_belongs_to_repository(repository_path):
        return
    if http_url and http_username and http_password:
        cache_credentials(http_url, http_username, http_password)

    git_process = Popen([get_binary(), 'push', '--set-upstream', 'origin', branch_name],
                        cwd=repository_path, stdout=PIPE, stderr=PIPE)
    git_process.wait(timeout=timeout)
    logger.debug('git_push_set_origin: returncode: %r', git_process.returncode)
    logger.debug('git_push_set_origin: stdout: %r', git_process.stdout.read() if git_process.stdout
                 else None)
    logger.debug('git_push_set_origin: stderr: %r', git_process.stderr.read() if git_process.stderr
                 else None)
    if git_process.returncode != 0:
        raise GitPushError


def git_commit_cycle(repository_path, file_paths, branch_name, commit_message, http_url=None,
                     http_username=None, http_password=None, network_timeout=60):
    """
    performs a series of git commands to add a changed password file to the git repository

    :param repository_path: PathLike path of the repository
    :param file_paths: [PathLike] paths of the changed files
    :param branch_name: string name of the new branch the file is committed to before merge
    :param commit_message: string message to add to the commit
    """
    logger = logging.getLogger(__name__)
    logger.debug('git_commit_cycle: (%r, %r, %r, %r, %r, %r, %r, %r)', repository_path,
                 file_paths, branch_name, commit_message, http_url, http_username,
                 len(http_password) if http_password else None, network_timeout)

    if not path_belongs_to_repository(repository_path):
        return
    has_remote = repository_has_remote(repository_path)
    logger.debug('git_commit_cycle: has_remote: %r', has_remote)

    if has_remote:
        git_pull(repository_path, http_url=http_url, http_username=http_username,
                 http_password=http_password, timeout=network_timeout)
        git_branch(repository_path, branch_name)
        git_checkout_branch(repository_path, branch_name=branch_name)

    git_add(repository_path, file_paths)
    git_commit(repository_path, commit_message)

    if has_remote:
        git_push_set_origin(repository_path, branch_name, http_url=http_url,
                            http_username=http_username, http_password=http_password,
                            timeout=network_timeout)
        git_checkout_branch(repository_path, 'master')
        git_pull(repository_path, http_url=http_url, http_username=http_username,
                 http_password=http_password, timeout=network_timeout)
        git_pull(repository_path, branch_name, http_url=http_url, http_username=http_username,
                 http_password=http_password, timeout=network_timeout)
        git_push(repository_path, http_url=http_url, http_username=http_username,
                 http_password=http_password, timeout=network_timeout)
