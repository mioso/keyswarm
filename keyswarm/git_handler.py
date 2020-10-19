"""
this module interacts with the git binary and provides
pulling, branching, staging, committing and pushing
"""

# pylint: disable=too-many-arguments

from functools import lru_cache
import logging
from subprocess import call, PIPE, Popen

from .decoder import try_decode


logging.getLogger(__name__).setLevel(logging.INFO)
def enable_git_debug_logging():
    """ enable git debug logging """
    logging.getLogger(__name__).setLevel(logging.DEBUG)

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


    logger.debug('_split_url: (%r)', url)
    splits = url.split('://')
    logger.debug('_split_url: %r', splits)

    if len(splits) != 2:
        logger.debug('_split_url: not split in 2')
        raise ValueError("url format not accepted")

    schema = splits[0]
    host = splits[1].split('/')[0]

    return schema, host


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
    raise NotARepositoryError(directory_path)


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
    except (NotARepositoryError, NotADirectoryError):
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
        raise NotARepositoryError(repository_path)
    return stdout and len(stdout) > 0


def repository_config_has_user_data(repository_path):
    """
    returns wether the repository config has a username and email needed to create a commit
    """
    logger = logging.getLogger(__name__)
    logger.debug('repository_config_has_user_data: (%r)', repository_path)

    for property_ in ['user.name', 'user.email']:
        git_cmd = [get_binary(), 'config', property_]
        logger.debug('repository_config_has_user_data: git_cmd: %r', git_cmd)
        git_process = Popen(git_cmd, cwd=repository_path, stdout=PIPE, stderr=PIPE)
        stdout, stderr = git_process.communicate(timeout=2)
        return_code = git_process.returncode
        logger.debug('repository_config_has_user_data: return_code: %r', return_code)
        logger.debug('repository_config_has_user_data: stdout: %r', stdout)
        logger.debug('repository_config_has_user_data: stderr: %r', stderr)
        if return_code != 0:
            return False

    return True


def repository_config_set_user_data(repository_path, user_name, user_email):
    """
    sets user.name and user.email for the git repository

    :param repository_path: PathLike path of the repository
    :param user_name: str users name handed to git config
    :param user_email: str users email handed to git config
    """
    logger = logging.getLogger(__name__)
    logger.debug('repository_config_set_user_data: (%r, %r, %r)',
                 repository_path, user_name, user_email)

    result = True
    for key, value in [('user.name', user_name), ('user.email', user_email)]:
        git_cmd = [get_binary(), 'config', key, value]
        logger.debug('repository_config_set_user_data: git_cmd: %r', git_cmd)
        git_process = Popen(git_cmd, cwd=repository_path, stdout=PIPE, stderr=PIPE)
        stdout, stderr = git_process.communicate()
        return_code = git_process.returncode
        logger.debug('repository_config_set_user_data: return_code: %r', return_code)
        logger.debug('repository_config_set_user_data: stdout: %r', stdout)
        logger.debug('repository_config_set_user_data: stderr: %r', stderr)
        result = result and (return_code == 0)

    return result


def git_init(directory_path):
    """
    performs `git init` on the given directory
    """
    logger = logging.getLogger(__name__)
    logger.debug('git_init: (%r)', directory_path)
    git_process = Popen([get_binary(), 'init'], cwd=directory_path, stdout=PIPE, stderr=PIPE)
    stdout, stderr = git_process.communicate()
    logger.debug('git_init: returncode: %r', git_process.returncode)
    logger.debug('git_init: stdout: %r', stdout)
    logger.debug('git_init: stderr: %r', stderr)
    if git_process.returncode != 0:
        raise GitInitError(try_decode(stderr))


def git_clone(repository_path, url, http_username=None, http_password=None, timeout=60):
    """
    performs `git clone`
    """
    logger = logging.getLogger(__name__)
    logger.debug('git_clone: (%r, %r, %r, %r)', repository_path, url, http_username, http_password)

    if http_username and http_password:
        cache_credentials(url, http_username, http_password)

    git_cmd = [get_binary(), 'clone', '--recurse-submodules', url, '--', repository_path]
    logger.debug('git_clone: git_cmd: %r', git_cmd)
    git_process = Popen(git_cmd, stdout=PIPE, stderr=PIPE)
    stdout, stderr = git_process.communicate(timeout=timeout)
    logger.debug('git_clone: returncode: %r', git_process.returncode)
    logger.debug('git_clone: stdout: %r', stdout)
    logger.debug('git_clone: stderr: %r', stderr)
    if git_process.returncode != 0:
        raise GitCloneError(try_decode(stderr))


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
        git_cmd = [get_binary(), 'pull', 'origin', branch_name, '--']
    else:
        git_cmd = [get_binary(), 'pull', '--recurse-submodules']
    logger.debug('git_pull: git_cmd: %r', git_cmd)
    git_process = Popen(git_cmd, cwd=repository_path, stdout=PIPE, stderr=PIPE)
    stdout, stderr = git_process.communicate(timeout=timeout)
    logger.debug('git_pull: returncode: %r', git_process.returncode)
    logger.debug('git_pull: stdout: %r', stdout)
    logger.debug('git_pull: stderr: %r', stderr)
    if git_process.returncode != 0:
        raise GitPullError(try_decode(stderr))


def git_branch(repository_path, branch_name):
    """
    performs `git branch` on the given repository

    :param repository_path: PathLike path of the repository
    :param branch_name: string name of the new branch
    """
    logger = logging.getLogger(__name__)
    logger.debug('git_branch: (%r, %r)', repository_path, branch_name)

    if not path_belongs_to_repository(repository_path):
        logger.debug('git_branch: path is not a repository')
        return

    git_cmd = [get_binary(), 'branch', branch_name, '--']
    logger.debug('git_branch: git_cmd: %r', git_cmd)
    git_process = Popen(git_cmd, cwd=repository_path, stdout=PIPE, stderr=PIPE)
    stdout, stderr = git_process.communicate()
    logger.debug('git_branch: returncode: %r', git_process.returncode)
    logger.debug('git_branch: stdout: %r', stdout)
    logger.debug('git_branch: stderr: %r', stderr)
    if git_process.returncode != 0:
        raise GitBranchError(try_decode(stderr))


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

    git_cmd = [get_binary(), 'checkout', branch_name, '--']
    logger.debug('git_checkout_branch: git_cmd: %r', git_cmd)
    git_process = Popen(git_cmd, cwd=repository_path, stdout=PIPE, stderr=PIPE)
    stdout, stderr = git_process.communicate()
    logger.debug('git_branch: returncode: %r', git_process.returncode)
    logger.debug('git_branch: stdout: %r', stdout)
    logger.debug('git_branch: stderr: %r', stderr)
    if git_process.returncode != 0:
        raise GitCheckoutError(try_decode(stderr))


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

    git_cmd = [get_binary(), 'add', '--', *map(str, file_paths)]
    logger.debug('git_add: git_cmd: %r', git_cmd)
    git_process = Popen(git_cmd, cwd=repository_path, stdout=PIPE, stderr=PIPE)
    stdout, stderr = git_process.communicate()
    logger.debug('git_add: returncode: %r', git_process.returncode)
    logger.debug('git_add: stdout: %r', stdout)
    logger.debug('git_add: stderr: %r', stderr)

    if git_process.returncode != 0:
        raise GitAddError(try_decode(stderr))


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

    git_cmd = [get_binary(), 'commit', '-m', commit_message]
    logger.debug('git_commit: git_cmd: %r', git_cmd)
    git_process = Popen(git_cmd, cwd=repository_path, stdout=PIPE, stderr=PIPE)
    stdout, stderr = git_process.communicate()
    logger.debug('git_commit: returncode: %r', git_process.returncode)
    logger.debug('git_commit: stdout: %r', stdout)
    logger.debug('git_commit: stderr: %r', stderr)
    if git_process.returncode != 0:
        raise GitCommitError(try_decode(stderr))


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
    stdout, stderr = git_process.communicate(timeout=timeout)
    logger.debug('git_push: returncode: %r', git_process.returncode)
    logger.debug('git_push: stdout: %r', stdout)
    logger.debug('git_push: stderr: %r', stderr)
    if git_process.returncode != 0:
        raise GitPushError(try_decode(stderr))


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

    git_cmd = [get_binary(), 'push', '--set-upstream', 'origin', branch_name]
    logger.debug('git_push_set_origin: git_cmd: %r', git_cmd)
    git_process = Popen(git_cmd, cwd=repository_path, stdout=PIPE, stderr=PIPE)
    stdout, stderr = git_process.communicate(timeout=timeout)
    logger.debug('git_push_set_origin: returncode: %r', git_process.returncode)
    logger.debug('git_push_set_origin: stdout: %r', stdout)
    logger.debug('git_push_set_origin: stderr: %r', stderr)
    if git_process.returncode != 0:
        raise GitPushError(try_decode(stderr))


def git_soft_clean(repository_path):
    """
    uses git clean to remove changes and returns to master branch
    leaving prior branch as is for manual inspection

    :param repository_path: PathLike path of the repository
    """
    logger = logging.getLogger(__name__)
    logger.debug('git_soft_clean: (%r)', repository_path)

    git_cmd_list = [
        [get_binary(), 'clean', '-fdx'],
        [get_binary(), 'reset', '--hard', 'HEAD'],
        [get_binary(), 'checkout', 'master']]

    _git_cmd_chain(repository_path, git_cmd_list)


def git_clean(repository_path, delete_branch):
    """
    uses git clean to remove changes, returns to master branch and deletes the specified branch

    :param repository_path: PathLike path of the repository
    :param delete_branch: string name of the branch to delete
    """
    logger = logging.getLogger(__name__)
    logger.debug('git_clean: (%r, %r)', repository_path, delete_branch)

    git_cmd_list = [
        [get_binary(), 'clean', '-fdx'],
        [get_binary(), 'reset', '--hard', 'HEAD'],
        [get_binary(), 'checkout', 'master'],
        [get_binary(), 'branch', '--delete', delete_branch]]

    _git_cmd_chain(repository_path, git_cmd_list)

def _git_cmd_chain(repository_path, git_cmd_list):
    logger = logging.getLogger(__name__)
    logger.debug('_git_cmd_chain: (%r, %r)', repository_path, git_cmd_list)

    if not path_belongs_to_repository(repository_path):
        return

    for git_cmd in git_cmd_list:
        logger.debug('_git_cmd_chain: git_cmd: %r', git_cmd)
        git_process = Popen(git_cmd, cwd=repository_path, stdout=PIPE, stderr=PIPE)
        stdout, stderr = git_process.communicate()
        logger.debug('_git_cmd_chain: returncode: %r', git_process.returncode)
        logger.debug('_git_cmd_chain: stdout: %r', stdout)
        logger.debug('_git_cmd_chain: stderr: %r', stderr)
        if git_process.returncode != 0:
            raise GitError(f'Failed to return to clean state:\n\n{try_decode(stderr)}')


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
    logger.info('git_commit_cycle: start')
    logger.debug('git_commit_cycle: (%r, %r, %r, %r, %r, %r, %r, %r)', repository_path,
                 file_paths, branch_name, commit_message, http_url, http_username,
                 len(http_password) if http_password else None, network_timeout)

    if not path_belongs_to_repository(repository_path):
        logger.info('git_commit_cycle: not a repository, done here')
        return
    has_remote = repository_has_remote(repository_path)
    logger.info('git_commit_cycle: has_remote: %r', has_remote)

    if has_remote:
        logger.info('git_commit_cycle: pull')
        git_pull(repository_path, http_url=http_url, http_username=http_username,
                 http_password=http_password, timeout=network_timeout)
        logger.info('git_commit_cycle: branch')
        git_branch(repository_path, branch_name)
        logger.info('git_commit_cycle: switch branch')
        git_checkout_branch(repository_path, branch_name=branch_name)

    logger.info('git_commit_cycle: add')
    git_add(repository_path, file_paths)
    logger.info('git_commit_cycle: commit')
    git_commit(repository_path, commit_message)

    if has_remote:
        logger.info('git_commit_cycle: push')
        git_push_set_origin(repository_path, branch_name, http_url=http_url,
                            http_username=http_username, http_password=http_password,
                            timeout=network_timeout)
        logger.info('git_commit_cycle: checkout master')
        git_checkout_branch(repository_path, 'master')
        logger.info('git_commit_cycle: pull')
        git_pull(repository_path, http_url=http_url, http_username=http_username,
                 http_password=http_password, timeout=network_timeout)
        logger.info('git_commit_cycle: merge')
        git_pull(repository_path, branch_name, http_url=http_url, http_username=http_username,
                 http_password=http_password, timeout=network_timeout)
        logger.info('git_commit_cycle: push')
        git_push(repository_path, http_url=http_url, http_username=http_username,
                 http_password=http_password, timeout=network_timeout)
    logger.info('git_commit_cycle: done')
