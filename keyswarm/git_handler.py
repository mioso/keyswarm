"""
this module interacts with the git binary and provides
pulling, branching, staging, committing and pushing
"""

import logging
from subprocess import call, PIPE, Popen

class GitError(Exception):
    """
    base class for representing unspecified errors thrown by the git executable
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


def get_binary():
    """
    returns the name of the git binary
    """
    return 'git'

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
    result = call([get_binary(), 'status'], cwd=directory_path) == 0
    logger.debug('path_belongs_to_repository: result: %r', result)
    return result

def git_pull(repository_path, branch_name=None):
    """
    performs `git pull` on the given repository
    pulls a branch if given

    :param repository_path: PathLike path of the repository
    :param branch_name: string if present the branch pull the branch with this name
    """
    logger = logging.getLogger(__name__)
    logger.debug('git_pull: (%r, %r)', repository_path, branch_name)
    if branch_name:
        git_process = Popen([get_binary(), 'pull', branch_name, '--'], stdout=PIPE, stderr=PIPE)
    else:
        git_process = Popen([get_binary(), 'pull'])
    git_process.wait()
    logger.debug('git_pull: returncode: %r', git_process.returncode)
    logger.debug('git_pull: stdout: %r', git_process.stdout)
    logger.debug('git_pull: stderr: %r', git_process.stderr)
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
    git_process = Popen([get_binary(), 'branch', branch_name, '--'])
    git_process.wait()
    logger.debug('git_branch: returncode: %r', git_process.returncode)
    logger.debug('git_branch: stdout: %r', git_process.stdout)
    logger.debug('git_branch: stderr: %r', git_process.stderr)
    if git_process.returncode != 0:
        raise GitBranchError

def git_checkout_branch(repository_path, branch_name):
    """
    performs `git checkout <branch> --` on the given repository

    :param repository_path: PathLike path of the repository
    :param branch_name: string name of the branch
    """
    git_process = Popen([get_binary(), 'checkout', branch_name, '--'])
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
    git_process = Popen([get_binary(), 'add', '--', *file_paths])
    git_process.wait()
    logger.debug('git_add: returncode: %r', git_process.returncode)
    logger.debug('git_add: stdout: %r', git_process.stdout)
    logger.debug('git_add: stderr: %r', git_process.stderr)

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
    git_process = Popen([get_binary(), 'commit', commit_message], cwd=repository_path)
    git_process.wait()
    logger.debug('git_commit: returncode: %r', git_process.returncode)
    logger.debug('git_commit: stdout: %r', git_process.stdout)
    logger.debug('git_commit: stderr: %r', git_process.stderr)
    if git_process.returncode != 0:
        raise GitCommitError

def git_push(repository_path):
    """
    performs `git push` on the given repository

    :param repository_path: PathLike path of the repository
    """
    logger = logging.getLogger(__name__)
    logger.debug('git_push: (%r)', repository_path)
    git_process = Popen([get_binary(), 'push'], cwd=repository_path)
    logger.debug('git_push: returncode: %r', git_process.returncode)
    logger.debug('git_push: stdout: %r', git_process.stdout)
    logger.debug('git_push: stderr: %r', git_process.stderr)
    if git_process.returncode != 0:
        raise GitPushError

def git_push_set_origin(repository_path, branch_name):
    """
    performs `git push --set-origin origin <branch>` on the given repository
    seperate function from git_push for explicities sake

    :param repository_path: PathLike path of the repository
    :param branch_name: string name ot the branch
    """
    logger = logging.getLogger(__name__)
    logger.debug('git_push_set_origin: (%r, %r)', repository_path, branch_name)
    git_process = Popen([get_binary(), '--set-upstream', 'origin', branch_name],
                        cwd=repository_path)
    logger.debug('git_push_set_origin: returncode: %r', git_process.returncode)
    logger.debug('git_push_set_origin: stdout: %r', git_process.stdout)
    logger.debug('git_push_set_origin: stderr: %r', git_process.stderr)
    if git_process.returncode != 0:
        raise GitPushError

def git_commit_cycle(repository_path, file_paths, branch_name, commit_message):
    """
    performs a series of git commands to add a changed password file to the git repository

    :param repository_path: PathLike path of the repository
    :param file_paths: [PathLike] paths of the changed files
    :param branch_name: string name of the new branch the file is committed to before merge
    :param commit_message: string message to add to the commit
    """
    logger = logging.getLogger(__name__)
    logger.debug('git_commit_cycle: (%r, %r, %r, %r)', repository_path,
                 file_paths, branch_name, commit_message)
    git_pull(repository_path)
    git_branch(repository_path, branch_name)
    git_checkout_branch(repository_path, branch_name=branch_name)
    git_add(repository_path, file_paths)
    git_commit(repository_path, commit_message)
    git_push_set_origin(repository_path, branch_name)
    git_checkout_branch(repository_path, 'master')
    git_pull(repository_path)
    git_pull(repository_path, branch_name)
    git_push(repository_path)
