# MCP Server Security Best Practices (Developer Guide)

> A practical, opinionated guide to help you **design, build, and
> operate secure MCP servers** and integrations.

> This consolidates and de-duplicates your draft content and expands it
> with concrete guidance, patterns, and code examples you can drop into
> production. It is written for **developers** (not pentesters) building
> MCP servers or integrating them into agent platforms.

------------------------------------------------------------------------

## 0) TL;DR --- Executive Checklist

-   **Threat model first:** Identify trust boundaries (client ⇄ server,
    server ⇄ OS/filesystem, server ⇄ network, server ⇄ external tools).
-   **Secure by default:** Bind locally, least-privilege
    tools/resources, deny egress by default, validate all inputs.
-   **AuthN/Z:** Require tokens for networked servers; implement
    **per-tool** authorization (allowlist by scope) and short-lived
    tokens.
-   **Transport:** Use HTTPS/mTLS for remote, strict CORS/Origin checks,
    timeouts, rate limits, backpressure.
-   **Input & schema validation:** Enforce JSON Schema on every method
    param. Canonicalize paths; sandbox FS access.
-   **Tool safety:** No implicit shell. Quotas (CPU/mem/fd), timeouts,
    output schema enforcement, redaction.
-   **Prompt & tool poisoning:** Keep descriptions minimal, detect
    "override/exfiltrate" patterns, require human confirmation for
    high-risk actions.
-   **Secrets:** Never log secrets; load from vaults; rotate keys;
    redact outputs.
-   **Monitoring:** Structured logs (redacted), audit every tool call
    (who/what/when), metrics & alerts.
-   **Supply chain:** Pin deps, SBOM, scan images, sign releases.
-   **Testing:** Unit + fuzz + integration security tests; secret
    scanning in CI; pre-prod security review.
-   **IR plan:** Kill-switch for risky tools, token revocation,
    forensics, comms.

------------------------------------------------------------------------

## 1) Primer: What MCP Is (and Why It's Risky)

MCP is a client--server protocol that lets AI runtimes call **tools**,
pull **resources**, and use **prompts** exposed by a server over
JSON-RPC, transported through STDIO or streamable HTTP (e.g., SSE). This
unlocks powerful integrations---but also exposes your filesystem,
networks, and data flows to model-driven decisions. Careless
implementations can lead to **data exfiltration, RCE, and privilege
abuse**.

**Core primitives the server exposes:** - **Tools:** Executable actions
(file ops, API calls, DB queries). - **Resources:** Read-only context
(files, records, config). - **Prompts:** Reusable templates for LLM
interactions.

------------------------------------------------------------------------

## 2) Threat Model (Developer Edition)

**Actors:** End-user, MCP client/host, your MCP server, OS/filesystem,
external APIs.

**Assets:** Secrets, local data, system integrity, protected
prompts/policies, audit logs.

**Top risks to design against:** - **Prompt & Tool poisoning**
(malicious descriptions/outputs steer the model). - **Path traversal &
arbitrary file access** (weak resource/tool guards). - **Command/code
injection** (shelling out with user data). - **Secrets leakage** (logs,
error traces, model context). - **Unauthenticated/over-privileged
access** (public listeners, no scopes). - **Memory poisoning** (poisoned
caches/vector stores alter decisions). - **DoS** (unbounded
inputs/outputs, long-running tools). - **Supply chain** (dependency or
third-party server compromise).

------------------------------------------------------------------------

## 3) Protocol Hygiene: Initialization & Capabilities

-   Implement a strict **initialize → initialized** handshake; reject
    malformed JSON-RPC.
-   Populate `serverInfo` minimally (name/version) and avoid leaking
    build paths.
-   Advertise only the capabilities you truly support (`tools`,
    `resources`, `prompts`), and set flags like
    `listChanged`/`subscribe` **conservatively** (false unless you
    implemented dynamic updates). Over-advertising increases your attack
    surface.

------------------------------------------------------------------------

## 4) Authentication & Authorization

### 4.1 Authentication

-   **Local / stdio-only:** Prefer **no network listener**; if you
    expose HTTP, bind to `127.0.0.1`, and require a local capability
    token.
-   **Remote:** Require **TLS** and **tokens** (PAT, OAuth/JWT, or
    mTLS). Validate `iss`, `aud`, `exp`, `nbf`, `iat`, and `jti` (replay
    cache). Short lifetimes; rotate keys.

### 4.2 Authorization

-   **Deny by default.** Map **scopes → tools/resources**; enforce
    **per-tool** and **per-resource** allowlists.
-   Partition risky abilities (write/delete/exec/network POST) from
    read-only ones. Require additional scopes or explicit user
    confirmation for high-risk actions.

**Example: simple per-tool policy check (Python/FastMCP):**

``` python
from typing import Callable
from mcp.server.fastmcp import FastMCP

mcp = FastMCP("secure-server")
ALLOWED = {
  # subject/client_id -> set of tool names
  "clientA": {"file/read", "http/get"},
  "clientB": {"db/query"},
}

def require_tool_scope(tool_name: str) -> Callable:
    def decorator(fn):
        async def guarded(*args, **kwargs):
            ctx = kwargs.get("context")
            client = getattr(ctx, "client_id", "anonymous")
            if tool_name not in ALLOWED.get(client, set()):
                raise PermissionError(f"tool '{tool_name}' not allowed for client '{client}'")
            return await fn(*args, **kwargs) if callable(getattr(fn, "__await__", None)) else fn(*args, **kwargs)
        return guarded
    return decorator

@mcp.tool(name="file/read")
@require_tool_scope("file/read")
def file_read(path: str) -> str:
    ...
```

------------------------------------------------------------------------

## 5) Transport Security (HTTP/SSE)

-   **HTTPS only** for remote access; enable mTLS in enterprise
    contexts.
-   **Origin & CORS:** Default **deny**. If you must allow browser
    clients, explicitly allow known origins and require CSRF tokens for
    state-changing RPCs.
-   **SSE hygiene:** Timeouts, heartbeat, and **rate limits** per
    session/IP. Don't stream internal logs or verbose errors over SSE.
-   **Backpressure:** Concurrency limits; cancel long-running tool calls
    cleanly.

------------------------------------------------------------------------

## 6) Input & Schema Validation

-   Define **JSON Schemas** for every tool's params; reject unknown
    fields and wrong types.
-   Bound **sizes** (request/response bytes), **depth** (nesting),
    **counts** (batch size), and **time** (per call/tool and per
    session).
-   Normalize and **canonicalize paths**; resolve symlinks; **stay
    inside an allowlisted root**.

**Secure path helper:**

``` python
from pathlib import Path
SANDBOX = Path("/srv/mcp/sandbox").resolve()

def safe_path(user_path: str) -> Path:
    p = (SANDBOX / user_path).resolve()
    if SANDBOX != p and SANDBOX not in p.parents:
        raise PermissionError("path escapes sandbox")
    if p.is_symlink():
        raise PermissionError("symlinks not allowed")
    return p
```

------------------------------------------------------------------------

## 7) Filesystem & System Interaction

-   **Separate capabilities:** read vs write vs delete vs exec. Make
    write/exec **opt-in** and audited.
-   Avoid returning absolute paths; minimize error detail to clients;
    log detailed errors server-side (redacted).
-   For subprocess tools: **no implicit shell**, pass an argv list, and
    enforce **ulimits** (CPU/mem/fd), **timeouts**, and **uid/gid
    drops**.

**Subprocess with limits (POSIX):**

``` python
import os, resource, subprocess

def _limits():
    resource.setrlimit(resource.RLIMIT_CPU, (2, 2))
    resource.setrlimit(resource.RLIMIT_AS, (256*1024*1024,)*2)
    os.setuid(2000); os.setgid(2000)

def run_cmd(argv: list[str], timeout=5):
    p = subprocess.Popen(argv, stdout=subprocess.PIPE, stderr=subprocess.PIPE, preexec_fn=_limits)
    out, err = p.communicate(timeout=timeout)
    return p.returncode, out.decode("utf-8","replace"), err.decode("utf-8","replace")
```

------------------------------------------------------------------------

## 8) Network Egress Control

-   **Default-deny** outbound network. Define a per-tool egress policy
    (domain + method + path prefix).
-   Strip/scrub headers on outbound requests; never reflect client
    `Authorization` headers to third-party services.

------------------------------------------------------------------------

## 9) Prompt & Tool Poisoning Defense

-   Keep tool descriptions **minimal** and **unambiguous**. Don't
    include hidden instructions that could be misinterpreted by the
    model.
-   **Runtime heuristics**: Detect and block outputs containing
    override/exfiltration patterns ("ignore previous", "upload secrets",
    etc.).
-   **Schema-first outputs**: Tools must return data conforming to
    declared schemas; reject extra unsolicited content (URLs, commands).
-   **User confirmation**: Gate high-risk actions
    (write/delete/exec/network POST) behind explicit confirmation with a
    **preview** of effects.

------------------------------------------------------------------------

## 10) Secrets Management & Redaction

-   Load secrets from the environment or a **secrets manager** (Vault,
    cloud KMS), not from code or config files.
-   **Never** log secrets or send them to the client/model context.
-   Redact with opinionated regexes (JWT, "sk-...", "Bearer ...", cloud
    keys) while preserving a few trailing chars for troubleshooting.
-   Provide **hot reload/rotation** without restart.

**Redaction helper:**

``` python
import re
PATTERNS = [
  re.compile(r"(?i)Bearer\s+[A-Za-z0-9\._\-]+"),
  re.compile(r"sk-[A-Za-z0-9]{20,}"),
  re.compile(r"AKIA[0-9A-Z]{16}"),
]
def redact(text: str) -> str:
    masked = text
    for pat in PATTERNS:
        masked = pat.sub(lambda m: m.group(0)[:3] + "***REDACTED***", masked)
    return masked
```

------------------------------------------------------------------------

## 11) Error Handling, Logging, and Auditing

-   **Client errors:** minimal and generic. Include a correlation ID.
-   **Server logs:** structured (JSON), correlate
    session/tool/method/duration/result; redact secrets.
-   **Audit log:** who/what/when/inputs (sanitized)/result/exits;
    immutable storage if feasible.
-   **Metrics & alerts:** error rates, denials, timeouts, suspected
    poisoning events.

------------------------------------------------------------------------

## 12) Supply Chain Security

-   Pin dependencies; use lockfiles; generate **SBOM**; run SCA (e.g.,
    `pip-audit`).
-   Container images: minimal base, non-root, image scans.
-   Verify signatures of third-party MCP servers/tools; sign your
    releases.

------------------------------------------------------------------------

## 13) Deployment Hardening

-   **Containers/VMs:** run as non-root with restrictive `umask`;
    AppArmor/seccomp profiles when possible.
-   **Network:** bind to localhost by default; expose publicly only via
    gateway/WAF with auth and rate limiting.
-   **Config:** schema-validate config; ignore unknown keys; secure
    defaults.

------------------------------------------------------------------------

## 14) Testing & CI/CD

-   **Unit tests** for: auth gates, path canonicalization, schema
    validation, redaction, permission checks.
-   **Fuzz** JSON-RPC inputs and path arguments (`..`, `%2e%2e`,
    symlinks).
-   **Integration**: simulate poisoning attempts, blocked egress,
    timeouts.
-   CI: secret scanners (gitleaks/detect-secrets), SAST (bandit/CodeQL),
    dependency & container scans.
-   Pre-prod **security review** and go/no-go.

------------------------------------------------------------------------

## 15) Incident Response Essentials

-   **Kill switch** to disable high-risk tools globally.
-   Token/key **revocation** and rotation procedure.
-   Preserve audit logs/temp dirs; forensics checklist.
-   Clear user/admin communications templates.

------------------------------------------------------------------------

## 16) "Known Security Gaps" (and how to close them)

-   **Tool Poisoning:** Keep descriptions minimal; enforce output
    schemas; confirmation for risky actions; provenance tagging.
-   **Prompt Injection:** Structured templates; strict delimiters; strip
    override phrases; contextual warnings to the model; confirm
    high-risk intent.
-   **Memory Poisoning:** Validate/trust-rank sources before write; sign
    entries; periodic audits; isolate per-tenant memory;
    human-in-the-loop for critical updates.
-   **Tool Interference:** Isolate tool side-effects; per-tool quotas;
    serialize access to shared state; detect unexpected cross-tool
    changes.
-   **No Auth by Default:** Require tokens for network listeners; scopes
    per tool; default-deny policy.

------------------------------------------------------------------------

## 17) Optional Advanced Hardening

-   **Signed tool manifests & registries:** Treat tool
    metadata/manifests as signed artifacts; verify signatures at load.
    Maintain an internal registry of **trusted servers/tools** (e.g.,
    "Agent Name Service"-style pattern) and pin by identity (key
    fingerprint). Deny unknowns by policy.
-   **Policy-as-code:** Store allowlists/scopes, egress policies, and
    size/time limits as versioned code reviewed in CI.

**Sample policy file (YAML):**

``` yaml
tools:
  file/read:
    scope: read
    sandbox_root: /srv/mcp/sandbox
    max_bytes: 1048576
  http/fetch:
    scope: net_read
    egress_allow:
      - method: GET
        host: api.example.com
        path_prefix: /v1/
auth:
  required: true
  accepted_audiences: ["mcp-host-123"]
limits:
  max_concurrent_calls: 8
  per_session_qps: 2
```

------------------------------------------------------------------------

## 18) Example: Secure `read_file` Tool

``` python
from mcp.server.fastmcp import FastMCP, Context
from pathlib import Path

mcp = FastMCP("secure-fs")

SANDBOX = Path("/srv/mcp/sandbox").resolve()
MAX_BYTES = 1_048_576  # 1 MiB

def _safe(path: str) -> Path:
    p = (SANDBOX / path.lstrip("/")).resolve()
    if p == SANDBOX or SANDBOX not in p.parents:  # stay inside sandbox
        raise PermissionError("path escapes sandbox")
    if p.is_dir():
        raise PermissionError("directories not readable")
    return p

@mcp.tool(name="file/read", description="Read a file under the sandbox root.")
def file_read(path: str, max_bytes: int = MAX_BYTES) -> dict:
    p = _safe(path)
    size = p.stat().st_size
    if size > max_bytes:
        return {"truncated": True, "bytes": 0, "path": str(p.relative_to(SANDBOX))}
    with p.open("rb") as f:
        data = f.read(max_bytes)
    return {
        "truncated": len(data) < size,
        "bytes": len(data),
        "path": str(p.relative_to(SANDBOX)),
        "content": data.decode("utf-8", "replace")
    }
```

------------------------------------------------------------------------

## 19) Appendix: Developer Checklists

**Server Defaults** - \[ \] Local binding only by default; TLS if
remote. - \[ \] Capabilities advertise only what's implemented. - \[ \]
Policy file loaded; unknown keys rejected.

**AuthN/Z** - \[ \] Token validation (iss/aud/exp/nbf/iat/jti). - \[ \]
Per-tool allowlist; deny by default. - \[ \] Short-lived tokens;
rotation tested.

**Inputs/Outputs** - \[ \] JSON Schema validation for all tools. - \[ \]
Size/time/concurrency limits enforced. - \[ \] Output schemas and
redaction in place.

**FS/Process** - \[ \] Sandbox root; no symlinks; canonicalization. - \[
\] No implicit shell; ulimits & timeouts. - \[ \] Non-root user;
restrictive `umask`.

**Network** - \[ \] Default-deny egress; allowlist by tool. - \[ \]
CORS/Origin restricted; CSRF where applicable. - \[ \] SSE heartbeat,
timeouts, and rate limiting.

**Ops** - \[ \] Structured, redacted logs; audit trail. - \[ \] Metrics
& alerts on denials/timeouts/poisoning. - \[ \] IR playbooks;
kill-switch for risky tools.

------------------------------------------------------------------------

## 20) Notes on Redundancy Removal

-   Combined overlapping sections in your draft on **auth**,
    **transport**, and **tool exposure** into unified, actionable
    controls; removed duplicate lists and folded "Known Gaps" into
    mitigations with concrete patterns.
