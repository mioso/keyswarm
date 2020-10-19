"""
Bundle of functions used for debugging
"""

from functools import partial
from random import choice
from time import sleep

from .task_queue import Task, TaskPriority

def create_test_task(main_window):
    """
    add an action to the main window that creates a test task
    the task runs for a random amount of time
    the task either sleeps or does a cpu intense calculation at random
    the task uses a random priority
    shows an error message once the task is done
    if the task slept, the message is None
    if the task calculated the message is the result of the calculation
    """
    def fib(n): # pylint: disable=invalid-name
        """ using inefficient implementation on purpose """
        if n <= 1:
            return n
        return fib(n-1) + fib(n-2)

    def callback_(task):
        main_window.show_error(str(task.result))

    test_task = Task(
        partial(choice([fib, sleep]), choice([23, 32, 42])),
        f'Test Task: {choice(range(2**32))}',
        choice(list(TaskPriority)),
        callback=callback_
        )

    main_window.queue_task(test_task)
