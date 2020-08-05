"""
This Module Provides the TaskQueue, Task and TaskPriority Classes

Task is similar to concurrent.futures.Future, but Future is not supposed to be used directly.
Each TaskQueue uses a concurrent.futures.ThreadPoolExecutor.
TaskPriority is used by TaskQueue so store both pending and finished Task Objects in a heapq.
"""

# pylint: disable=too-many-instance-attributes

from collections import namedtuple
from concurrent.futures import ThreadPoolExecutor
from enum import IntEnum
from heapq import heappop, heappush
import logging
import weakref


logging.getLogger(__name__).setLevel(logging.INFO)
def enable_task_queue_debug_logging():
    """ enable task queue debug logging """
    logging.getLogger(__name__).setLevel(logging.DEBUG)

class TaskPriority(IntEnum):
    """
    Describes the priority of tasks given to a TaskQueue

    Task objects are sorted by their TaskPriority in ascending order
    """
    CONFIG_LOAD = -10000
    INIT_PASSWORD_STORE = -9000
    GIT_CLONE = -1000
    GIT_CYCLE = 0
    GIT_PULL = 1
    FILE_SYSTEM_HANDLE = 90
    REENCRYPT_TREE = 100
    CREATE_FILE_TREE = 900
    CREATE_SEARCH_INDEX = 1000

class Task():
    """
    Create a Task object

    :param callable_: callable with no parameters/all required parameters baked in
    (See `funtools.partial`)
    :param description: str user-friendly description displayable while the task is in progress
    :param priority: TaskPriority priority of the task in relation to other tasks
    :param callback: callable custom handler expecting the task as parameter
    :param error_handler: callable error handler expecting the task as parameter
    :param context: addidional context for result/error handler, not passed to callable_
    :param abortable: Boolean states whether the task is safe to abort, defaults to False
    """
    def __init__(self, callable_, description, priority, **kwargs):
        self.priority = priority
        self.callable = callable_
        self.description = description
        self.callback = kwargs.get('callback', None)
        self.error_handler = kwargs.get('error_handler', None)
        self.context = kwargs.get('context', {})
        self.abortable = kwargs.get('abortable', False)
        self.started = False
        self.finished = False
        self.failed = False
        self.result = None
        self.exception = None

    def __repr__(self):
        return (
            'Task(callable_=%r, description=%r, priority=%r, callback=%r, error_handler=%r,context'
            '=%r, abortable=%r, started=%r, finished=%r, failed=%r, result=%r, exception=%r)'
            ) % (
                self.callable, self.description, self.priority, self.callback, self.error_handler,
                self.context, self.abortable, self.started, self.finished, self.failed,
                self.result, self.exception
            )

    def execute_(self):
        """
        actually run the task (blocking) catching any exception, storing it in the task object
        marks the task as started before calling the callable
        marks the task as failed if catchin an exception
        marks the task as finished before returning
        """
        self.started = True
        try:
            self.result = self.callable()
        except Exception as exception: # pylint: disable=broad-except
            self.failed = True
            self.exception = exception
        finally:
            self.finished = True

    @property
    def is_running(self):
        """
        returns wether the task is started and not finished
        """
        return self.started and not self.finished

    def __lt__(self, other):
        return self.priority < other

    def __le__(self, other):
        return self.priority <= other

    def __gt__(self, other):
        return self.priority > other

    def __ge__(self, other):
        return self.priority >= other

class TaskQueue():
    """
    A queue for tasks with a coupled ThreadPoolExecutor to process the queue
    tasks can be blocked by other tasks using block lists (not yet implemented)
    tasks can be removed from the queue by queing other tasks using kill lists
    intended to be used from the single threaded event loop of the UI
    not threadsafe

    :param block_list: {TaskPriority, [TaskPriority]} a task of the priority used as key is blocked
        by tasks of the priority in the list used as value
    :param kill_list: {TaskPriority, [TaskPriority]} a task of the priority used as keys will remove
        tasks of the priority in the list used as value from the queue
    :param max_workers: int used for ThreadPoolExecutor, default 1
    """

    __status_tuple = namedtuple('TaskQueueStatus', ['finished', 'running', 'pending', 'blocked'])

    def __init__(self, block_lists=None, kill_lists=None, max_workers=1):
        self.__pending_tasks = []
        self.__finished_tasks = []
        self.__blocked_tasks = []
        self.__running_tasks = []
        self.__block_lists = block_lists or {}
        self.__kill_lists = kill_lists or {}
        self.__max_workers = max_workers
        self.__executor = ThreadPoolExecutor(max_workers=max_workers)
        self._finalizer = weakref.finalize(self, self.__executor.shutdown, False)

    def __repr__(self):
        return 'TaskQueue(pending=%r, running=%r, done=%r, blocked=%r)' % (
            self.__pending_tasks,
            self.__running_tasks,
            self.__finished_tasks,
            self.__blocked_tasks)

    def run(self):
        """
        perform one management cycle of the task queue
        intended to be called once per run of the event loop
        """
        logger = logging.getLogger(__name__)
        for finished_task in filter(lambda a: a[1].done(), self.__running_tasks):
            logger.debug('TaskQueue.run: %r finished', finished_task[0])
            self.__running_tasks.remove(finished_task)
            heappush(self.__finished_tasks, finished_task[0])

        if len(self.__running_tasks) < self.__max_workers:
            try:
                task = heappop(self.__pending_tasks)
            except IndexError:
                return

            self.__running_tasks.append((task, self.__executor.submit(task.execute_)))
            logger.debug('TaskQueue.run: %r started', task)

    def pop(self):
        """
        Return the most important finished task or throw IndexError if there are none.
        """
        return heappop(self.__finished_tasks)

    def push(self, task):
        """
        queue a new task removing all tasks on the kill list from the queue

        :param task: Task the task
        """
        self.kill_all(self.get_kill_list(task.priority))
        heappush(self.__pending_tasks, task)

    def kill_all(self, task_priorities):
        """
        remove all tasks of the given priorities from the queue

        :param task_priorities: [TaskPriority] priorities of tasks to remove
        """
        old_queue, self.__pending_tasks = self.__pending_tasks, []
        for task in filter(lambda a: a.priority not in task_priorities, old_queue):
            heappush(self.__pending_tasks, task)

    def set_block_list(self, task_priority, block_list):
        """
        sets the block list for a given task priority

        :param task_priority: TaskPriority the task priority being blocked
        :param block_list: [TaskPriority] the task priorities blocking
        """
        self.__block_lists[task_priority] = block_list

    def set_kill_list(self, task_priority, kill_list):
        """
        sets the kill list for a given task priority

        :param task_priority: TaskPriority the task prioritiy causing the removal
        :param kill_list: [TaskPriorities] the task priorities being removed
        """
        self.__kill_lists[task_priority] = kill_list

    def get_block_list(self, task_priority):
        """
        returns the current block list for a given task priority

        :param task_priority: TaskPriority the task priority beging blocked
        :return: [TaskPriority] the task priorities blocking
        """
        return self.__block_lists.get(task_priority, [])

    def get_kill_list(self, task_priority):
        """
        returns the current kill list for a given task priority

        :param task_priority: TaskPriority the task causing the removal
        :return: [TaskPriority] the task priorities being removed
        """
        return self.__kill_lists.get(task_priority, [])

    @staticmethod
    def _get_task_descriptions(tasks):
        return list(map(lambda a: a.description, tasks))

    def get_finished_task_descriptions(self):
        """ Returns the descriptions of the unhandled finished tasks """
        return TaskQueue._get_task_descriptions(self.__finished_tasks)

    def get_running_task_descriptions(self):
        """ Returns the descriptions of the currently running tasks """
        return TaskQueue._get_task_descriptions(map(lambda a: a[0], self.__running_tasks))

    def get_pending_task_descriptions(self):
        """ Returns the descriptions of the tasks waiting to be run """
        return TaskQueue._get_task_descriptions(self.__pending_tasks)

    def get_blocked_task_descriptions(self):
        """ Returns the description of the tasks that currently cannot run """
        return TaskQueue._get_task_descriptions(self.__blocked_tasks)

    def get_status(self):
        """
        Returns a named tuple with the descriptions for
        `finished`, `running`, `pending` and `blocked` tasks
        """
        return TaskQueue.__status_tuple(
            finished=self.get_finished_task_descriptions(),
            running=self.get_running_task_descriptions(),
            pending=self.get_pending_task_descriptions(),
            blocked=self.get_blocked_task_descriptions()
            )
