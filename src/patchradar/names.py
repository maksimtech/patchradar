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


def keyword_pattern(keyword: str) -> re.Pattern[str]:
    """`keyword` as a word of a lower-cased text — a product name, a title, a note.

    One rule for every source. The Debian collector learned it first, when a
    substring match gave "git" the CVEs of python-digitalocean and "ssh" those of
    libssh; KEV and MSRC kept matching substrings, and on 2026-10-09 the same
    keyword took from KEV the exploited CVEs of GitLab, Gitea and a GitHub Action
    (eight of nine matches) and from MSRC 109 entries of one month, not one of
    them Git's — "GitHub", "legitimate", "digital", "10-digit".

    The keyword has to start the text or follow a separator, and may be followed
    by anything but a letter — so "python" still finds python3.13, "log4j" finds
    Log4j2 and "7-zip" finds 7-Zip, where the digits are a version and not
    another word. Escaped, because "7-zip" and "c++" are names here.
    """
    return re.compile(rf"(?<![a-z0-9]){re.escape(keyword.lower())}(?![a-z])")
