"""HTTP helpers shared by send and scan.

Redirects are not followed: urllib would resend the Authorization header to whatever host
the redirect names. A 3xx is returned to the caller as an HTTPError instead.
"""
import ssl
import urllib.request


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def opener(url, ca_file=None):
    handlers = [_NoRedirect()]
    if url.startswith("https"):
        handlers.append(urllib.request.HTTPSHandler(context=ssl.create_default_context(cafile=ca_file or None)))
    return urllib.request.build_opener(*handlers)


def read_capped(resp, limit):
    """Read at most `limit` bytes. Returns (data, truncated)."""
    data = resp.read(limit + 1)
    return data[:limit], len(data) > limit
