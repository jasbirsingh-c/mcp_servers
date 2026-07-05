import os
from typing import Optional
import httpx
from mcp.server.fastmcp import FastMCP

mcp = FastMCP("kibana")

KIBANA_URL = os.environ.get("KIBANA_URL", "http://localhost:5601").rstrip("/")
KIBANA_USERNAME = os.environ.get("KIBANA_USERNAME", "")
KIBANA_PASSWORD = os.environ.get("KIBANA_PASSWORD", "")
ES_INDEX = os.environ.get("ES_INDEX", "filebeat-*")
KIBANA_VERIFY_SSL = os.environ.get("KIBANA_VERIFY_SSL", "true").lower() != "false"

_AUTH = httpx.BasicAuth(KIBANA_USERNAME, KIBANA_PASSWORD) if KIBANA_USERNAME else None
_HEADERS = {"kbn-xsrf": "true", "Content-Type": "application/json"}


def _client() -> httpx.AsyncClient:
    return httpx.AsyncClient(auth=_AUTH, headers=_HEADERS, verify=KIBANA_VERIFY_SSL, timeout=30.0)


async def _es(client: httpx.AsyncClient, method: str, path: str, body: dict | None = None) -> dict:
    """Route an Elasticsearch request through Kibana's console proxy.

    Kibana's proxy always expects an outer POST; the ES method goes in ?method=.
    """
    resp = await client.post(
        f"{KIBANA_URL}/api/console/proxy",
        params={"path": path, "method": method},
        json=body,
    )
    resp.raise_for_status()
    return resp.json()


def _fmt_hit(hit: dict) -> str:
    src = hit.get("_source", {})
    ts = src.get("@timestamp", src.get("timestamp", "?"))
    level = src.get("log", {}).get("level", src.get("level", src.get("level_name", "?")))
    channel = src.get("log", {}).get("logger", src.get("channel", src.get("service", {}).get("name", "?")))
    message = src.get("message", "?")
    txn = src.get("transaction_uid", src.get("labels", {}).get("transaction_uid", ""))
    txn_str = f" [txn:{txn}]" if txn else ""
    return f"[{ts}] {channel}.{level}: {message}{txn_str}"


def _err(e: Exception, url: str) -> str:
    if isinstance(e, httpx.ConnectError):
        return f"ERROR: Could not connect to Kibana at {url}. Check KIBANA_URL."
    if isinstance(e, httpx.HTTPStatusError):
        return f"ERROR: Kibana returned {e.response.status_code}: {e.response.text[:500]}"
    return f"ERROR: {e}"


@mcp.tool()
async def search_logs(
    query: str,
    index: Optional[str] = None,
    start_time: Optional[str] = None,
    end_time: Optional[str] = None,
    level: Optional[str] = None,
    service: Optional[str] = None,
    size: int = 50,
) -> str:
    """Search logs using a Lucene query string.

    Args:
        query: Lucene query string, e.g. 'payment failed' or 'route:order-create'
        index: Elasticsearch index pattern (overrides ES_INDEX env var)
        start_time: Start of time range, ISO timestamp or relative like 'now-1h'
        end_time: End of time range, ISO timestamp or 'now'
        level: Filter by log level: DEBUG, INFO, WARNING, ERROR
        service: Filter by service/channel name (logger tag)
        size: Max number of results to return (default 50)
    """
    idx = index or ES_INDEX
    must = [{"query_string": {"query": query, "analyze_wildcard": True}}]

    time_range: dict = {}
    if start_time:
        time_range["gte"] = start_time
    if end_time:
        time_range["lte"] = end_time
    if not start_time and not end_time:
        time_range["gte"] = "now-1h"
        time_range["lte"] = "now"
    must.append({"range": {"@timestamp": time_range}})

    if level:
        must.append({
            "bool": {"should": [
                {"match": {"log.level": level.upper()}},
                {"match": {"level_name": level.upper()}},
                {"match": {"level": level.upper()}},
            ], "minimum_should_match": 1}
        })

    if service:
        must.append({
            "bool": {"should": [
                {"match": {"service.name": service}},
                {"match": {"channel": service}},
                {"match": {"log.logger": service}},
            ], "minimum_should_match": 1}
        })

    body = {
        "query": {"bool": {"must": must}},
        "sort": [{"@timestamp": "asc"}],
        "size": size,
    }

    try:
        async with _client() as client:
            data = await _es(client, "POST", f"/{idx}/_search", body)
    except Exception as e:
        return _err(e, KIBANA_URL)

    hits = data.get("hits", {}).get("hits", [])
    total = data.get("hits", {}).get("total", {})
    total_val = total.get("value", len(hits)) if isinstance(total, dict) else total

    if not hits:
        return f"No logs found for query '{query}' in index '{idx}'."

    lines = [f"Found {total_val} log(s) (showing {len(hits)}):\n"]
    lines.extend(_fmt_hit(h) for h in hits)
    return "\n".join(lines)


@mcp.tool()
async def get_by_transaction_uid(
    transaction_uid: str,
    index: Optional[str] = None,
    start_time: Optional[str] = None,
    end_time: Optional[str] = None,
) -> str:
    """Fetch all log lines for a single HTTP request using its transaction_uid.

    The PHP app (LoggerMiddleware) assigns a unique transaction_uid to every
    request so all related log lines can be correlated. Use this to trace
    exactly what happened during a specific request.

    Args:
        transaction_uid: The transaction_uid value from a log line
        index: Elasticsearch index pattern (overrides ES_INDEX env var)
        start_time: Narrow the time window for faster search, e.g. 'now-6h'
        end_time: End of time window (default 'now')
    """
    idx = index or ES_INDEX
    must: list = [
        {"bool": {"should": [
            {"term": {"transaction_uid": transaction_uid}},
            {"term": {"labels.transaction_uid": transaction_uid}},
            {"match_phrase": {"message": transaction_uid}},
        ], "minimum_should_match": 1}}
    ]

    time_range: dict = {}
    if start_time:
        time_range["gte"] = start_time
    if end_time:
        time_range["lte"] = end_time
    if time_range:
        must.append({"range": {"@timestamp": time_range}})

    body = {
        "query": {"bool": {"must": must}},
        "sort": [{"@timestamp": "asc"}],
        "size": 200,
    }

    try:
        async with _client() as client:
            data = await _es(client, "POST", f"/{idx}/_search", body)
    except Exception as e:
        return _err(e, KIBANA_URL)

    hits = data.get("hits", {}).get("hits", [])

    if not hits:
        return f"No logs found for transaction_uid '{transaction_uid}' in index '{idx}'."

    lines = [f"Request trace for transaction_uid '{transaction_uid}' — {len(hits)} log line(s):\n"]
    lines.extend(_fmt_hit(h) for h in hits)
    return "\n".join(lines)


@mcp.tool()
async def get_recent_errors(
    index: Optional[str] = None,
    service: Optional[str] = None,
    minutes: int = 60,
    size: int = 20,
) -> str:
    """Fetch recent ERROR and WARNING log lines.

    Args:
        index: Elasticsearch index pattern (overrides ES_INDEX env var)
        service: Filter by service/channel name (logger tag), e.g. 'PaymentController'
        minutes: How far back to look in minutes (default 60)
        size: Max number of results to return (default 20)
    """
    idx = index or ES_INDEX
    must: list = [
        {"range": {"@timestamp": {"gte": f"now-{minutes}m", "lte": "now"}}},
        {"bool": {"should": [
            {"terms": {"log.level": ["ERROR", "WARNING", "CRITICAL", "ALERT", "EMERGENCY"]}},
            {"terms": {"level_name": ["ERROR", "WARNING", "CRITICAL"]}},
            {"terms": {"level": ["ERROR", "WARNING", "CRITICAL"]}},
        ], "minimum_should_match": 1}},
    ]

    if service:
        must.append({
            "bool": {"should": [
                {"match": {"service.name": service}},
                {"match": {"channel": service}},
                {"match": {"log.logger": service}},
            ], "minimum_should_match": 1}
        })

    body = {
        "query": {"bool": {"must": must}},
        "sort": [{"@timestamp": "desc"}],
        "size": size,
    }

    try:
        async with _client() as client:
            data = await _es(client, "POST", f"/{idx}/_search", body)
    except Exception as e:
        return _err(e, KIBANA_URL)

    hits = data.get("hits", {}).get("hits", [])

    if not hits:
        return f"No errors/warnings in the last {minutes} minute(s) in index '{idx}'."

    lines = [f"Recent errors/warnings (last {minutes}m) — {len(hits)} result(s):\n"]
    lines.extend(_fmt_hit(h) for h in hits)
    return "\n".join(lines)


@mcp.tool()
async def list_indices(pattern: str = "*") -> str:
    """List Elasticsearch indices via Kibana, matching a pattern.

    Use this to discover the correct index name or pattern for your logs
    (e.g. 'filebeat-*', 'logs-*', 'admin-*').

    Args:
        pattern: Index name pattern to filter (default '*' = all indices)
    """
    try:
        async with _client() as client:
            data = await _es(client, "GET", f"/_cat/indices/{pattern}?h=index,docs.count,store.size&s=index&format=json")
    except Exception as e:
        return _err(e, KIBANA_URL)

    if not data:
        return f"No indices found matching pattern '{pattern}'."

    lines = [f"{'index':<45} {'docs':>10}  {'size':>10}", "-" * 70]
    for row in data:
        lines.append(f"{row.get('index',''):<45} {row.get('docs.count',''):>10}  {row.get('store.size',''):>10}")
    return "\n".join(lines)


@mcp.tool()
async def list_data_views() -> str:
    """List all Kibana data views (index patterns) configured in this Kibana instance."""
    try:
        async with _client() as client:
            resp = await client.get(f"{KIBANA_URL}/api/data_views")
            resp.raise_for_status()
            data = resp.json()
    except Exception as e:
        return _err(e, KIBANA_URL)

    views = data.get("data_view", [])
    if not views:
        return "No data views found."

    lines = [f"{'title':<60}  id", "-" * 80]
    for dv in views:
        lines.append(f"{dv.get('title',''):<60}  {dv.get('id','')}")
    return "\n".join(lines)


if __name__ == "__main__":
    mcp.run()
