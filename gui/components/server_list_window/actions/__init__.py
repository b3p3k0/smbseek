"""
Server List Actions package.

Combines batch operations and filter/template handling mixins for the
ServerListWindow without altering behavior.
"""

from .batch import ServerListWindowBatchMixin
from .templates import ServerListWindowTemplateMixin


class ServerListWindowActionsMixin(ServerListWindowBatchMixin, ServerListWindowTemplateMixin):
    """Aggregate mixin used by ServerListWindow."""
    pass


__all__ = ["ServerListWindowActionsMixin", "ServerListWindowBatchMixin", "ServerListWindowTemplateMixin"]
