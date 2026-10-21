"""Error types shared by the core decryptors.

Kept apart from ``core.logic`` so ``core.happ`` / ``core.incy`` can raise it
without importing the whole parsing pipeline (which imports them lazily).
"""


class DecryptError(RuntimeError):
    """A ``happ://`` / ``incy://`` link could not be decoded.

    Subclasses ``RuntimeError`` because callers historically caught that; the
    narrow type lets per-link handlers distinguish decode failures from bugs.
    """
