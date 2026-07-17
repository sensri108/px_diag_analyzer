"""
px_jira.py — Link findings to the CNBU Portworx (PWX) Jira project.

Read-only connector for the Cloud Native Business Unit Portworx Engineering
Jira space. For each Finding it builds a JQL query from the finding's
`jira_keywords` (sourced from the pattern definitions / troubleshooting docs)
and, when run live, searches the PWX project for related existing issues and
attaches their keys + deep links to the Finding.

Behaviour:
    * Dry-run (default): compute the JQL and a browsable deep link for each
      finding. No network calls, no credentials required. This is what runs
      during a normal `--jira` invocation.
    * Live (`--jira-live`): call the Jira Cloud REST API to resolve matching
      issues. Requires JIRA_EMAIL + JIRA_API_TOKEN in the environment.

Configuration (environment variables):
    JIRA_BASE_URL   default https://purestorage-cnbu-sandbox.atlassian.net
    JIRA_PROJECT    default PWX  (Portworx Engineering — CNBU)
    JIRA_EMAIL      Atlassian account email (live mode only)
    JIRA_API_TOKEN  Atlassian API token     (live mode only)

The connector never creates, edits, or transitions issues — it only searches.
"""
from __future__ import annotations

import logging
import os
from urllib.parse import quote

log = logging.getLogger(__name__)

DEFAULT_BASE_URL = "https://purestorage-cnbu-sandbox.atlassian.net"
DEFAULT_PROJECT = "PWX"  # Portworx Engineering (CNBU)

# How many keywords to fold into a single JQL query, and how many issues to
# request per finding when searching live.
_MAX_KEYWORDS = 4
_MAX_RESULTS = 5


class JiraConfig:
    """Resolves Jira connection settings from the environment."""

    def __init__(self, project: str | None = None):
        self.base_url = os.environ.get("JIRA_BASE_URL", DEFAULT_BASE_URL).rstrip("/")
        self.project = project or os.environ.get("JIRA_PROJECT", DEFAULT_PROJECT)
        self.email = os.environ.get("JIRA_EMAIL", "")
        self.token = os.environ.get("JIRA_API_TOKEN", "")

    @property
    def has_credentials(self) -> bool:
        return bool(self.email and self.token)


def _keywords_for(finding) -> list[str]:
    """Pick the JQL search terms for a finding, most specific first."""
    kws: list[str] = list(getattr(finding, "jira_keywords", []) or [])
    if not kws:
        # Fall back to the smart-signal name (underscores → spaces) then the id.
        if finding.smart_signal:
            kws.append(finding.smart_signal.replace("_", " "))
        kws.append(finding.id)
    # De-duplicate preserving order, cap the count.
    seen: set[str] = set()
    ordered = []
    for k in kws:
        k = str(k).strip()
        if k and k.lower() not in seen:
            seen.add(k.lower())
            ordered.append(k)
    return ordered[:_MAX_KEYWORDS]


def build_jql(finding, project: str) -> str:
    """Build a text-search JQL scoped to the PWX project for one finding."""
    terms = _keywords_for(finding)
    # Escape embedded quotes for JQL string literals.
    clauses = [f'text ~ "{t.replace(chr(34), "")}"' for t in terms]
    text_filter = " OR ".join(clauses) if clauses else 'text ~ "portworx"'
    return f'project = {project} AND ({text_filter}) ORDER BY updated DESC'


def search_deep_link(base_url: str, jql: str) -> str:
    """Return a browser URL that opens the JQL in Jira's issue search."""
    return f"{base_url}/issues/?jql={quote(jql)}"


def browse_url(base_url: str, key: str) -> str:
    return f"{base_url}/browse/{key}"


def _search_live(config: JiraConfig, jql: str) -> list[dict]:
    """Call the Jira Cloud REST API and return normalized issue dicts."""
    import requests

    resp = requests.get(
        f"{config.base_url}/rest/api/3/search",
        params={"jql": jql, "maxResults": _MAX_RESULTS, "fields": "summary,status"},
        auth=(config.email, config.token),
        headers={"Accept": "application/json"},
        timeout=20,
    )
    resp.raise_for_status()
    issues = []
    for issue in resp.json().get("issues", []):
        fields = issue.get("fields", {})
        status = (fields.get("status") or {}).get("name", "")
        issues.append({
            "key": issue.get("key", ""),
            "summary": fields.get("summary", ""),
            "status": status,
            "url": browse_url(config.base_url, issue.get("key", "")),
        })
    return issues


def enrich_findings(
    findings: list,
    live: bool = False,
    project: str | None = None,
) -> None:
    """
    Attach PWX Jira linkage to each finding in place.

    Always sets: jira_project, jira_query, jira_search_url.
    In live mode (with credentials) also sets: jira_tickets = [{key, summary, ...}].
    """
    config = JiraConfig(project=project)

    if live and not config.has_credentials:
        log.warning(
            "Jira live mode requested but JIRA_EMAIL / JIRA_API_TOKEN are not set — "
            "falling back to dry-run (deep links only)."
        )
        live = False

    mode = "live" if live else "dry-run"
    log.info(f"Jira enrichment ({mode}) against project {config.project} @ {config.base_url}")

    n_linked = 0
    for f in findings:
        jql = build_jql(f, config.project)
        f.jira_project = config.project
        f.jira_query = jql
        f.jira_search_url = search_deep_link(config.base_url, jql)

        if not live:
            continue

        try:
            tickets = _search_live(config, jql)
            f.jira_tickets = tickets
            n_linked += len(tickets)
        except Exception as e:  # network / auth / API errors must not abort analysis
            log.warning(f"Jira search failed for {f.id}: {e}")

    if live:
        log.info(f"Jira enrichment complete: {n_linked} related PWX issue(s) linked.")
