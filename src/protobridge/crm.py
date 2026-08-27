"""Twenty CRM exposed as governed MCP tools.

Twenty (https://twenty.com) is an open-source CRM whose REST API lives at
``{base}/rest/...`` behind ``Authorization: Bearer <key>``. Two properties of
that API shape this adapter:

1. **There is no static API reference.** Each workspace generates its own
   schema — add a custom object and it immediately gets REST endpoints beside
   the built-in ones. An adapter that hardcodes a schema is therefore wrong by
   construction, so every field read here is defensive.
2. **Records are mostly PII.** A person carries emails, phones, a city and a
   job title. That is exactly what ProtoBridge's egress rules were built to
   catch, so the CRM tools declare themselves ``restricted`` and let the audit
   layer decide who may see what.

The default backend is a deterministic fake with no network access, which keeps
ProtoBridge's promise that a fresh clone runs with zero API keys. Point it at a
real workspace by setting ``TWENTY_BASE_URL`` and ``TWENTY_API_KEY``.
"""

from __future__ import annotations

import json
import os
import sys
from datetime import UTC, datetime
from typing import Any, Protocol, runtime_checkable
from urllib.parse import quote
from urllib.request import Request, urlopen

from protobridge.envelope import Classification
from protobridge.protocols.jsonrpc import INVALID_PARAMS, Dispatcher, JsonRpcError

PROTOCOL_VERSION = "2025-06-18"
SUPPORTED_PROTOCOL_VERSIONS = ("2025-06-18", "2025-03-26", "2024-11-05")
SERVER_NAME = "protobridge-twenty-crm"
SERVER_VERSION = "0.1.0"

CLASSIFICATION_META_KEY = "protobridge/classification"
BACKEND_META_KEY = "protobridge/backend"

CRM_PII_FIELDS = frozenset(
    {
        "primaryEmail",
        "additionalEmails",
        "primaryPhoneNumber",
        "additionalPhones",
        "whatsapp",
        "linkedinLink",
        "city",
    }
)
"""Twenty person fields the audit layer treats as personally identifiable.

Merged into the shared ``mcp.PII_FIELDS`` at import time so the existing
redaction rules govern CRM responses without any rule changing.
"""


def _now_iso() -> str:
    return datetime.now(UTC).isoformat()


# --------------------------------------------------------------------------
# Backends
# --------------------------------------------------------------------------


@runtime_checkable
class TwentyBackend(Protocol):
    """What the CRM tools need from a Twenty workspace."""

    name: str

    def list_people(self, query: str = "", limit: int = 10) -> list[dict[str, Any]]: ...

    def get_person(self, person_id: str) -> dict[str, Any] | None: ...

    def list_companies(self, query: str = "", limit: int = 10) -> list[dict[str, Any]]: ...

    def list_opportunities(self, limit: int = 10) -> list[dict[str, Any]]: ...

    def create_note(self, title: str, body: str) -> dict[str, Any]: ...


class FakeTwentyBackend:
    """Offline, deterministic, shaped like a real Twenty workspace.

    Field layout mirrors Twenty's composite fields (``name.firstName``,
    ``emails.primaryEmail``) so code written against the fake keeps working
    against the real REST API. All records are synthetic.
    """

    name = "fake"

    def __init__(self) -> None:
        self._people: list[dict[str, Any]] = [
            {
                "id": "20202020-0000-4000-8000-0000000ap001",
                "name": {"firstName": "Nadia", "lastName": "Rahman"},
                "emails": {"primaryEmail": "nadia.rahman@example.test"},
                "phones": {"primaryPhoneNumber": "+92-300-0000001"},
                "city": "Karachi",
                "jobTitle": "Head of Procurement",
                "companyId": "20202020-0000-4000-8000-0000000co001",
                "createdAt": "2026-01-14T09:00:00+00:00",
            },
            {
                "id": "20202020-0000-4000-8000-0000000ap002",
                "name": {"firstName": "Tomas", "lastName": "Novak"},
                "emails": {"primaryEmail": "tomas.novak@example.test"},
                "phones": {"primaryPhoneNumber": "+420-000-0000002"},
                "city": "Prague",
                "jobTitle": "Logistics Director",
                "companyId": "20202020-0000-4000-8000-0000000co002",
                "createdAt": "2026-02-02T11:30:00+00:00",
            },
            {
                "id": "20202020-0000-4000-8000-0000000ap003",
                "name": {"firstName": "Amara", "lastName": "Okafor"},
                "emails": {"primaryEmail": "amara.okafor@example.test"},
                "phones": {"primaryPhoneNumber": "+234-800-0000003"},
                "city": "Lagos",
                "jobTitle": "CFO",
                "companyId": "20202020-0000-4000-8000-0000000co001",
                "createdAt": "2026-03-19T15:45:00+00:00",
            },
        ]
        self._companies: list[dict[str, Any]] = [
            {
                "id": "20202020-0000-4000-8000-0000000co001",
                "name": "Acme Logistics",
                "domainName": {"primaryLinkUrl": "https://acme.example.test"},
                "employees": 480,
                "addressCity": "Karachi",
            },
            {
                "id": "20202020-0000-4000-8000-0000000co002",
                "name": "Globex Freight",
                "domainName": {"primaryLinkUrl": "https://globex.example.test"},
                "employees": 1250,
                "addressCity": "Prague",
            },
        ]
        self._opportunities: list[dict[str, Any]] = [
            {
                "id": "20202020-0000-4000-8000-0000000op001",
                "name": "Acme - annual freight contract",
                "amount": {"amountMicros": 240000000000, "currencyCode": "USD"},
                "stage": "PROPOSAL",
                "closeDate": "2026-09-30T00:00:00+00:00",
                "companyId": "20202020-0000-4000-8000-0000000co001",
            },
            {
                "id": "20202020-0000-4000-8000-0000000op002",
                "name": "Globex - warehouse expansion",
                "amount": {"amountMicros": 875000000000, "currencyCode": "USD"},
                "stage": "NEGOTIATION",
                "closeDate": "2026-11-15T00:00:00+00:00",
                "companyId": "20202020-0000-4000-8000-0000000co002",
            },
        ]
        self._notes: list[dict[str, Any]] = []

    @staticmethod
    def _matches(record: dict[str, Any], query: str) -> bool:
        if not query:
            return True
        return query.lower() in json.dumps(record, ensure_ascii=False).lower()

    def list_people(self, query: str = "", limit: int = 10) -> list[dict[str, Any]]:
        hits = [p for p in self._people if self._matches(p, query)]
        return [dict(p) for p in hits[:limit]]

    def get_person(self, person_id: str) -> dict[str, Any] | None:
        for person in self._people:
            if person["id"] == person_id:
                return dict(person)
        return None

    def list_companies(self, query: str = "", limit: int = 10) -> list[dict[str, Any]]:
        hits = [c for c in self._companies if self._matches(c, query)]
        return [dict(c) for c in hits[:limit]]

    def list_opportunities(self, limit: int = 10) -> list[dict[str, Any]]:
        return [dict(o) for o in self._opportunities[:limit]]

    def create_note(self, title: str, body: str) -> dict[str, Any]:
        note = {
            "id": f"20202020-0000-4000-8000-{len(self._notes):012d}",
            "title": title,
            "bodyV2": {"markdown": body},
            "createdAt": _now_iso(),
        }
        self._notes.append(note)
        return dict(note)


class TwentyRestBackend:
    """Talks to a real Twenty workspace over its REST API.

    Twenty's schema is workspace-specific, so this backend returns whatever the
    workspace returns and does not reshape it into an assumed contract.
    """

    name = "twenty-rest"

    def __init__(self, base_url: str, api_key: str, *, timeout: float = 15.0) -> None:
        self.base_url = base_url.rstrip("/")
        self._api_key = api_key
        self.timeout = timeout

    def _call(
        self,
        path: str,
        *,
        params: dict[str, str] | None = None,
        method: str = "GET",
        body: dict[str, Any] | None = None,
    ) -> Any:
        url = f"{self.base_url}/rest/{path.lstrip('/')}"
        if params:
            query = "&".join(f"{k}={quote(str(v))}" for k, v in params.items() if v != "")
            if query:
                url = f"{url}?{query}"
        data = json.dumps(body).encode("utf-8") if body is not None else None
        request = Request(  # noqa: S310 - operator-configured workspace URL
            url,
            data=data,
            method=method,
            headers={
                "Authorization": f"Bearer {self._api_key}",
                "Content-Type": "application/json",
                "Accept": "application/json",
            },
        )
        try:
            with urlopen(request, timeout=self.timeout) as response:  # noqa: S310
                return json.loads(response.read().decode("utf-8"))
        except Exception as exc:  # noqa: BLE001 - surfaced as an RPC error, never a crash
            raise JsonRpcError(INVALID_PARAMS, f"Twenty request failed: {exc}") from exc

    @staticmethod
    def _unwrap(payload: Any, object_name: str) -> list[dict[str, Any]]:
        """Twenty nests results under ``data.<objectName>``; tolerate variation."""
        if isinstance(payload, dict):
            data = payload.get("data", payload)
            if isinstance(data, dict):
                found = data.get(object_name)
                if isinstance(found, list):
                    return found
                if isinstance(found, dict):
                    return [found]
            if isinstance(data, list):
                return data
        return []

    def list_people(self, query: str = "", limit: int = 10) -> list[dict[str, Any]]:
        params: dict[str, str] = {"limit": str(limit)}
        if query:
            # Twenty filter syntax: field[operator]:value
            params["filter"] = f"name.firstName[ilike]:%{query}%"
        return self._unwrap(self._call("people", params=params), "people")

    def get_person(self, person_id: str) -> dict[str, Any] | None:
        found = self._unwrap(self._call(f"people/{person_id}"), "person")
        return found[0] if found else None

    def list_companies(self, query: str = "", limit: int = 10) -> list[dict[str, Any]]:
        params: dict[str, str] = {"limit": str(limit)}
        if query:
            params["filter"] = f"name[ilike]:%{query}%"
        return self._unwrap(self._call("companies", params=params), "companies")

    def list_opportunities(self, limit: int = 10) -> list[dict[str, Any]]:
        return self._unwrap(
            self._call("opportunities", params={"limit": str(limit)}), "opportunities"
        )

    def create_note(self, title: str, body: str) -> dict[str, Any]:
        payload = self._call(
            "notes", method="POST", body={"title": title, "bodyV2": {"markdown": body}}
        )
        found = self._unwrap(payload, "note")
        return found[0] if found else {"title": title}


def get_backend() -> TwentyBackend:
    """Resolve a backend from the environment.

    Falls back to the offline fake unless both a workspace URL and an API key
    are present, so the zero-key promise holds by default.
    """
    base_url = os.getenv("TWENTY_BASE_URL", "").strip()
    api_key = os.getenv("TWENTY_API_KEY", "").strip()
    if base_url and api_key:
        return TwentyRestBackend(base_url, api_key)
    return FakeTwentyBackend()


# --------------------------------------------------------------------------
# Tool catalogue
# --------------------------------------------------------------------------

TOOL_SPECS: list[dict[str, Any]] = [
    {
        "name": "crm.person_search",
        "title": "Search CRM people",
        "description": "Find people in the CRM by name. Returns records containing PII.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "query": {"type": "string", "description": "Name fragment to search for."},
                "limit": {"type": "integer", "description": "Maximum results.", "default": 5},
            },
            "required": ["query"],
        },
    },
    {
        "name": "crm.person_get",
        "title": "Fetch one CRM person",
        "description": "Fetch a single person record by id. Returns PII.",
        "inputSchema": {
            "type": "object",
            "properties": {"person_id": {"type": "string", "description": "Twenty record id."}},
            "required": ["person_id"],
        },
    },
    {
        "name": "crm.company_search",
        "title": "Search CRM companies",
        "description": "Find companies in the CRM by name. Firmographic data, not personal.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "query": {"type": "string", "description": "Company name fragment."},
                "limit": {"type": "integer", "description": "Maximum results.", "default": 5},
            },
            "required": ["query"],
        },
    },
    {
        "name": "crm.opportunity_list",
        "title": "List CRM opportunities",
        "description": "List open deals with amounts and stages. Commercially sensitive.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "limit": {"type": "integer", "description": "Maximum results.", "default": 5}
            },
        },
    },
    {
        "name": "crm.note_create",
        "title": "Create a CRM note",
        "description": "Write a note into the CRM. This mutates customer records.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "title": {"type": "string", "description": "Note title."},
                "body": {"type": "string", "description": "Note body, markdown."},
            },
            "required": ["title", "body"],
        },
    },
]

TOOL_CLASSIFICATION: dict[str, Classification] = {
    "crm.person_search": Classification.RESTRICTED,
    "crm.person_get": Classification.RESTRICTED,
    "crm.company_search": Classification.INTERNAL,
    "crm.opportunity_list": Classification.CONFIDENTIAL,
    "crm.note_create": Classification.INTERNAL,
}

WRITE_TOOLS = frozenset({"crm.note_create"})
"""Tools that mutate the CRM.

Every ProtoBridge tool before this one was read-only, so "allowlisted" meant
"may read". A write against a live customer record needs its own check — see
rule ``GOV-003`` in ``rules.py``.
"""


def _require(args: dict[str, Any], key: str) -> Any:
    if key not in args:
        raise JsonRpcError(INVALID_PARAMS, f"missing required argument: {key!r}")
    return args[key]


# --------------------------------------------------------------------------
# MCP server
# --------------------------------------------------------------------------


def build_server(backend: TwentyBackend | None = None) -> Dispatcher:
    """Build an MCP dispatcher exposing the CRM as tools."""
    crm = backend if backend is not None else get_backend()
    rpc = Dispatcher()

    def _tool_person_search(args: dict[str, Any]) -> dict[str, Any]:
        query = str(_require(args, "query"))
        limit = int(args.get("limit", 5))
        return {"query": query, "people": crm.list_people(query, limit)}

    def _tool_person_get(args: dict[str, Any]) -> dict[str, Any]:
        person_id = str(_require(args, "person_id"))
        record = crm.get_person(person_id)
        if record is None:
            raise JsonRpcError(INVALID_PARAMS, f"unknown person: {person_id}")
        return {"person": record}

    def _tool_company_search(args: dict[str, Any]) -> dict[str, Any]:
        query = str(_require(args, "query"))
        limit = int(args.get("limit", 5))
        return {"query": query, "companies": crm.list_companies(query, limit)}

    def _tool_opportunity_list(args: dict[str, Any]) -> dict[str, Any]:
        limit = int(args.get("limit", 5))
        deals = crm.list_opportunities(limit)
        total = sum(
            float(d.get("amount", {}).get("amountMicros", 0)) / 1_000_000
            for d in deals
            if isinstance(d.get("amount"), dict)
        )
        return {"opportunities": deals, "pipeline_value": round(total, 2)}

    def _tool_note_create(args: dict[str, Any]) -> dict[str, Any]:
        title = str(_require(args, "title"))
        body = str(_require(args, "body"))
        return {"note": crm.create_note(title, body)}

    impls = {
        "crm.person_search": _tool_person_search,
        "crm.person_get": _tool_person_get,
        "crm.company_search": _tool_company_search,
        "crm.opportunity_list": _tool_opportunity_list,
        "crm.note_create": _tool_note_create,
    }

    @rpc.method("initialize")
    def _initialize(params: dict[str, Any]) -> dict[str, Any]:
        requested = params.get("protocolVersion", PROTOCOL_VERSION)
        if requested not in SUPPORTED_PROTOCOL_VERSIONS:
            raise JsonRpcError(
                INVALID_PARAMS,
                f"unsupported protocol version: {requested}",
                {"supported": list(SUPPORTED_PROTOCOL_VERSIONS)},
            )
        return {
            "protocolVersion": requested,
            "capabilities": {"tools": {"listChanged": False}},
            "serverInfo": {
                "name": SERVER_NAME,
                "version": SERVER_VERSION,
                "backend": crm.name,
            },
        }

    @rpc.method("notifications/initialized")
    def _initialized(_params: dict[str, Any]) -> None:
        return None

    @rpc.method("ping")
    def _ping(_params: dict[str, Any]) -> dict[str, Any]:
        return {}

    @rpc.method("tools/list")
    def _tools_list(_params: dict[str, Any]) -> dict[str, Any]:
        return {"tools": [dict(spec) for spec in TOOL_SPECS]}

    @rpc.method("tools/call")
    def _tools_call(params: dict[str, Any]) -> dict[str, Any]:
        name = params.get("name")
        impl = impls.get(name) if isinstance(name, str) else None
        if impl is None:
            raise JsonRpcError(INVALID_PARAMS, f"unknown tool: {name!r}")
        structured = impl(params.get("arguments") or {})
        classification = TOOL_CLASSIFICATION.get(name, Classification.CONFIDENTIAL)
        return {
            "content": [{"type": "text", "text": json.dumps(structured, ensure_ascii=False)}],
            "structuredContent": structured,
            "isError": False,
            "_meta": {
                CLASSIFICATION_META_KEY: str(classification),
                BACKEND_META_KEY: crm.name,
            },
        }

    return rpc


def serve_stdio(stdin: Any = None, stdout: Any = None, rpc: Dispatcher | None = None) -> None:
    """Run the CRM MCP server over newline-delimited JSON on stdio."""
    stdin = stdin or sys.stdin
    stdout = stdout or sys.stdout
    rpc = rpc or build_server()

    for raw in stdin:
        line = raw.strip()
        if not line:
            continue
        response = rpc.dispatch_raw(line)
        if response is None:
            continue
        stdout.write(json.dumps(response, ensure_ascii=False) + "\n")
        stdout.flush()


class InProcessTransport:
    """In-process transport for the CRM server, mirroring ``mcp.InProcessTransport``."""

    def __init__(self, backend: TwentyBackend | None = None) -> None:
        self._rpc = build_server(backend)

    def send(self, message: dict[str, Any]) -> dict[str, Any] | None:
        return self._rpc.dispatch_raw(json.dumps(message))

    def close(self) -> None:
        return None


if __name__ == "__main__":  # pragma: no cover - exercised via StdioTransport
    serve_stdio()
