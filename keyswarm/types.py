"""
This module provides custom types
"""

from enum import Enum

class RightFrameContentType(Enum):
    """
    This Enum defines values to describe the content type shown on the right side of the tree view.
    """
    EMPTY = 0
    PASSWORD_VIEW = 1
    RECIPIENT_VIEW = 2
