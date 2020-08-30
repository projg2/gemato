# gemato: Utility functions
# vim:fileencoding=utf-8
# (c) 2017-2020 Michał Górny
# Licensed under the terms of 2-clause BSD license


class MultiprocessingPoolWrapper:
    """
    A portability wrapper for multiprocessing.Pool that supports
    context manager API (and any future hacks we might need).

    Note: the multiprocessing behavior has been temporarily removed
    due to unresolved deadlocks. It will be restored once the cause
    of the issues is found and fixed or worked around.
    """

    __slots__ = []

    def __init__(self, processes):
        pass

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_value, exc_cb):
        pass

    def map(self, func, it, chunksize=None):
        return map(func, it)

    def imap_unordered(self, *args, **kwargs):
        """
        Use imap_unordered() if available and safe to use. Fall back
        to regular map() otherwise.
        """
        return self.map(*args, **kwargs)


def path_starts_with(path, prefix):
    """
    Returns True if the specified @path starts with the @prefix,
    performing component-wide comparison. Otherwise returns False.
    """
    return prefix == "" or (path + "/").startswith(prefix.rstrip("/") + "/")


def path_inside_dir(path, directory):
    """
    Returns True if the specified @path is inside @directory,
    performing component-wide comparison. Otherwise returns False.
    """
    return ((directory == "" and path != "")
            or path.rstrip("/").startswith(directory.rstrip("/") + "/"))


def throw_exception(e):
    """
    Raise the given exception. Needed for onerror= argument
    to os.walk(). Useful for other callbacks.
    """
    raise e
