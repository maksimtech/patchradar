"""What a watchlist name may be, for every way of adding one."""
import re

# Single source of truth for what a watchlist name may be. The import endpoint
# used to enforce none of this, so anything the path endpoint rejected could be
# smuggled in through it and then rendered by the CLI. `patchradar add` did not
# either, until it was moved here out of the API module so the CLI can use it
# without importing the web application.
# A literal space rather than \s: \s also matches newlines and tabs, so the
# original pattern admitted multi-line names, which break the CLI table layout
# and open the door to log injection. Only a space is ever meant ("windows 10").
SOFTWARE_NAME_PATTERN = r"^[\w \-\.]+$"
SOFTWARE_NAME_MAX_LENGTH = 100
_SOFTWARE_NAME_RE = re.compile(SOFTWARE_NAME_PATTERN)


def normalise_software_name(value) -> str | None:
    """Canonical watchlist name, or None when the value is not acceptable.

    Accepts only strings: an import payload is arbitrary JSON, and calling
    .strip() on an int used to surface as HTTP 500. Over-long names are
    rejected rather than truncated — silently watching a different name than
    the caller asked for is worse than refusing.
    """
    if not isinstance(value, str):
        return None
    name = value.strip().lower()
    if not name or len(name) > SOFTWARE_NAME_MAX_LENGTH:
        return None
    if not _SOFTWARE_NAME_RE.match(name):
        return None
    return name
