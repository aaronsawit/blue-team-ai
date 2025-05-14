# blue_team_ai/exceptions/unsupported_format.py

"""
Module defining custom exceptions for Blue Team AI tools.
"""

class UnsupportedFormat(Exception):
    """
    Exception raised when input log data is not in a supported syslog format.

    Attributes:
        message -- explanation of the error
    """

    def __init__(self, message="Input is not in a supported syslog format"):
        super().__init__(message)
