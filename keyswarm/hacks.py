"""
some hacks for user acceptance quickfixes
"""

class Hack(Exception):
    """
    Some Hacks will throw an exception only used for that hack. This is the base class for them.
    """

class NoGitOverrideHack(Hack):
    """
    ReadOnly mode on git fail needs to happen fast and can't wait for rewrite that will fix it.

    Any function that is not allowed in ReadOnly mode will throw this until the rewrite.
    """
