"""Failure reporting shared by the collectors.

Collectors used to swallow every failure and return [], which is exactly what
a clean scan returns — so a rate limit or an outage read as "no CVEs found".
They now raise CollectorError instead; an empty list only ever means the source
answered and had nothing to report.
"""
import httpx

RATE_LIMITED = "rate_limited"
FORBIDDEN = "forbidden"
SERVER_ERROR = "server_error"
HTTP_ERROR = "http_error"
NETWORK = "network"
BAD_PAYLOAD = "bad_payload"


class CollectorError(Exception):
    """A source could not be queried (completely or in part).

    `partial` carries any records gathered before the failure, so callers can
    keep them rather than discard a mostly successful fetch.
    """

    def __init__(self, source: str, reason: str, *, status: int | None = None,
                 partial: list[dict] | None = None, detail: str = ""):
        self.source = source
        self.reason = reason
        self.status = status
        self.partial = partial or []
        self.detail = detail
        where = f" (HTTP {status})" if status is not None else ""
        extra = f": {detail}" if detail else ""
        super().__init__(f"{source} {reason}{where}{extra}")


def reason_for_status(status: int) -> str:
    if status == 429:
        return RATE_LIMITED
    if status == 403:
        # NVD answers keyless clients over quota with 403, not 429.
        return FORBIDDEN
    if status >= 500:
        return SERVER_ERROR
    return HTTP_ERROR


def from_http_error(source: str, exc: Exception, partial: list[dict] | None = None) -> CollectorError:
    """Translate an httpx exception into a CollectorError."""
    if isinstance(exc, httpx.HTTPStatusError):
        status = exc.response.status_code
        return CollectorError(source, reason_for_status(status), status=status, partial=partial)
    return CollectorError(source, NETWORK, partial=partial, detail=type(exc).__name__)
