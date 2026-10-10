"""Trusted GitHub egress adapter. No proxy environment, URL override or redirects."""

from __future__ import annotations

import http.client
import ssl
from typing import Any

from .core import Route
from .errors import SecretsError
from .wire import dumps, loads

HOST = 'api.github.com'
API_VERSION = '2026-03-10'
MAX_RESPONSE = 2 * 1024 * 1024


class GitHubProvider:
    def execute(self, route: Route, credential: str) -> Any:
        # Defense in depth; routing authority originates in core.effect_route.
        if (route.method not in {'GET', 'POST', 'PATCH'}
                or not route.path.startswith('/repos/')
                or any(c in route.path for c in ('\r', '\n', '#', '\\', '%', ':'))
                or route.media not in {'json', 'diff'}):
            raise SecretsError('denied')
        body = dumps(route.body) if route.body is not None else None
        conn = http.client.HTTPSConnection(HOST, timeout=15,
                                           context=ssl.create_default_context())
        dispatched_write = False
        try:
            headers = {
                'Authorization': 'Bearer ' + credential,
                'Accept': ('application/vnd.github.diff' if route.media == 'diff'
                           else 'application/vnd.github+json'),
                'X-GitHub-Api-Version': API_VERSION,
                'User-Agent': 'aivm-secrets/0.1',
                'Accept-Encoding': 'identity',
            }
            if body is not None:
                headers['Content-Type'] = 'application/json'
            dispatched_write = route.method != 'GET'
            conn.request(route.method, route.path, body=body, headers=headers)
            response = conn.getresponse()
            # Deliberately do not follow even same-origin redirects. A moved
            # repository requires a host policy review, not automatic expansion.
            if not 200 <= response.status < 300:
                raise SecretsError('upstream_error')
            if response.getheader('Content-Encoding', 'identity') != 'identity':
                raise SecretsError('upstream_response')
            data = response.read(MAX_RESPONSE + 1)
            if len(data) > MAX_RESPONSE:
                raise SecretsError('upstream_response')
            if route.media == 'diff':
                return data.decode('utf-8')
            return loads(data, limit=MAX_RESPONSE)
        except SecretsError:
            if dispatched_write:
                raise SecretsError('outcome_unknown') from None
            raise
        except Exception:
            code = 'outcome_unknown' if dispatched_write else 'upstream_error'
            raise SecretsError(code) from None
        finally:
            conn.close()
