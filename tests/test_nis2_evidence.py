"""What docs/nis2-compliance.md tells a customer has to stay true of this code.

The document answers the seven questions a customer subject to NIS2 (directive
2022/2555, in Italy d.lgs. 138/2024) can ask a software supplier, and a customer
reads it as evidence. Every statement in it that the repository can prove is
checked here, so that the document goes red when the code moves away from it
instead of quietly turning false: the hosts the tool contacts and what each one
receives, the address the web interface listens on and which of its endpoints a
key protects, where the watchlist is stored, what the inventory collector reads,
the user the image runs as, the files each release carries, the scanners it names,
and the words a supplier cannot honestly use.

What the repository cannot prove is not claimed as proven. The required status
checks live in GitHub's settings, so the document gives the date they were read
on; there is no penetration test, so the document says there is none.

The same pattern is in mailradar and exeradar. PatchRadar differs where it
matters: it has a web interface, it keeps a watchlist on disk, its releases are
cut by scripts/release.py with bare CalVer tags (no "v"), and its image tag is
that bare version.
"""

from __future__ import annotations

import ast
import inspect
import re
import tomllib
from pathlib import Path

import pytest
import yaml
from fastapi.routing import APIRoute
from httpx import ASGITransport, AsyncClient

import patchradar.api.main as api_main
from patchradar import cli, law_cache, law_checker
from patchradar.db import database

ROOT = Path(__file__).resolve().parents[1]
PACKAGE = ROOT / "src" / "patchradar"
DOC = ROOT / "docs" / "nis2-compliance.md"
SECURITY = ROOT / "SECURITY.md"
README = ROOT / "README.md"
DOCKERFILE = ROOT / "Dockerfile"
COMPOSE = ROOT / "docker-compose.yml"
PYPROJECT = ROOT / "pyproject.toml"
WORKFLOWS = ROOT / ".github" / "workflows"
EVIDENCE = WORKFLOWS / "sbom.yml"
DOCKER = WORKFLOWS / "docker.yml"
COLLECTOR_SCRIPT = PACKAGE / "data" / "inventory.ps1"
IMAGE = "maksimtech/patchradar"

# mutmut runs the suite from a copy in which every source file holds, beside each
# function, all of its mutated variants and a trampoline that picks one. A test
# that reads the source as text reads that, not this repository: a variant whose
# dict key "url" became "XXurlXX" would make a link look like a host. The tests
# below that read source text skip there, as tests/test_collector_wiring.py does;
# the ordinary run is the one that holds the claims.
IN_MUTMUT_COPY = "mutants" in ROOT.parts
reads_source = pytest.mark.skipif(IN_MUTMUT_COPY, reason="mutmut's copy holds every mutant beside the source")

# A module that imports one of these can reach the network; one that does not
# cannot, whatever URLs its comments or constants mention (debian_status.py
# prints bugs.debian.org links and never fetches them).
NETWORK_IMPORT = re.compile(
    r"^\s*(?:import|from)\s+(?:httpx|aiohttp|requests|urllib\.request|http\.client|socket|smtplib)\b",
    re.M,
)
URL_HOST = re.compile(r"https?://([A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)+)")
# The contact URL the law fetcher puts in its User-Agent. It names this
# repository; nothing is sent to it.
USER_AGENT_LINK = re.compile(r"\(\+https://github\.com/maksimtech/")


def _docstring_nodes(tree: ast.AST) -> set[int]:
    found: set[int] = set()
    for node in ast.walk(tree):
        if isinstance(node, (ast.Module, ast.ClassDef, ast.FunctionDef, ast.AsyncFunctionDef)):
            first = node.body[0] if node.body else None
            if (
                isinstance(first, ast.Expr)
                and isinstance(first.value, ast.Constant)
                and isinstance(first.value.value, str)
            ):
                found.add(id(first.value))
    return found


def _link_nodes(tree: ast.AST) -> set[int]:
    """String constants that are the `url` of a CVE record.

    The collectors store, with every CVE, a link to the page that describes it
    (nvd.nist.gov/vuln/detail/…, msrc.microsoft.com/update-guide/…): it is shown
    to the user and never fetched by PatchRadar.
    """
    found: set[int] = set()
    for node in ast.walk(tree):
        if not isinstance(node, ast.Dict):
            continue
        for key, value in zip(node.keys, node.values, strict=True):
            if isinstance(key, ast.Constant) and key.value == "url":
                found.update(id(inner) for inner in ast.walk(value) if isinstance(inner, ast.Constant))
    return found


def _hosts(skip_links: bool) -> dict[str, set[str]]:
    found: dict[str, set[str]] = {}
    for path in sorted(PACKAGE.rglob("*.py")):
        source = path.read_text(encoding="utf-8")
        if not NETWORK_IMPORT.search(source):
            continue
        tree = ast.parse(source)
        skip = _docstring_nodes(tree)
        links = _link_nodes(tree)
        for node in ast.walk(tree):
            if not (isinstance(node, ast.Constant) and isinstance(node.value, str)):
                continue
            if id(node) in skip or USER_AGENT_LINK.search(node.value):
                continue
            if (id(node) in links) == skip_links:
                continue
            for host in URL_HOST.findall(node.value):
                found.setdefault(host.lower().rstrip("."), set()).add(path.name)
    return found


def hosts_in_code() -> dict[str, set[str]]:
    """Fixed hosts named in string constants of the modules that can reach the network."""
    return _hosts(skip_links=True)


def link_hosts() -> set[str]:
    """Hosts of the links stored with each CVE, which PatchRadar does not contact."""
    return set(_hosts(skip_links=False)) - set(hosts_in_code())


def section(text: str, name: str) -> str:
    """The text between `<!-- name:start -->` and `<!-- name:end -->`."""
    match = re.search(rf"<!-- {name}:start -->(.*?)<!-- {name}:end -->", text, re.S)
    assert match, f"docs/nis2-compliance.md has no {name} section between its markers"
    return match.group(1)


def table_rows(block: str) -> dict[str, list[str]]:
    """{backticked first cell: the other cells} for every row of a markdown table."""
    rows: dict[str, list[str]] = {}
    for line in block.splitlines():
        if not line.lstrip().startswith("|"):
            continue
        cells = [c.strip() for c in line.strip().strip("|").split("|")]
        if cells and cells[0].startswith("`"):
            rows[cells[0].strip("`")] = cells[1:]
    return rows


def table_first_column(block: str) -> set[str]:
    return set(table_rows(block))


def prose(text: str) -> str:
    return " ".join(text.split())


@pytest.fixture(scope="module")
def doc() -> str:
    return DOC.read_text(encoding="utf-8")


# --- Question 3: what leaves the machine ------------------------------------


@reads_source
def test_every_host_the_code_contacts_is_declared_and_no_other(doc):
    declared = table_first_column(section(doc, "hosts"))
    in_code = set(hosts_in_code())
    assert declared == in_code, (
        f"declared but not in the code: {sorted(declared - in_code)}; "
        f"in the code but not declared: {sorted(in_code - declared)}"
    )


@reads_source
def test_the_host_rule_looks_at_something():
    """A rule that found no host would pass for the wrong reason."""
    assert len(hosts_in_code()) >= 6


@reads_source
def test_the_host_rule_skips_what_is_only_cited():
    """The law fetcher names github.com/maksimtech/patchradar in its User-Agent,
    and every CVE record carries a link to the page that describes it: neither is
    a host the tool talks to."""
    hosts = hosts_in_code()
    for cited in ("github.com", "nvd.nist.gov", "msrc.microsoft.com"):
        assert cited not in hosts


@reads_source
def test_the_links_the_records_carry_are_declared_as_not_contacted(doc):
    links = link_hosts()
    assert {"nvd.nist.gov", "msrc.microsoft.com"} <= links
    for host in links:
        assert f"`{host}`" in doc, f"the records link to {host} and the document does not say so"
    assert "non li apre" in prose(doc)


def _get_calls(module: str) -> list[ast.Call]:
    tree = ast.parse((PACKAGE / module).read_text(encoding="utf-8"))
    return [
        node for node in ast.walk(tree)
        if isinstance(node, ast.Call)
        and isinstance(node.func, ast.Attribute)
        and node.func.attr == "get"
        and isinstance(node.func.value, ast.Name)
        and node.func.value.id == "client"
    ]


@reads_source
def test_the_catalogues_are_downloaded_whole_and_are_told_nothing():
    """The document says CISA and the Debian tracker receive nothing about the
    watchlist: each is one GET of a fixed URL, filtered on this machine."""
    for module in ("collectors/kev.py", "collectors/debian.py"):
        calls = _get_calls(module)
        assert calls, f"{module} makes no request"
        for call in calls:
            assert len(call.args) == 1 and isinstance(call.args[0], ast.Name), module
            assert not call.keywords, f"{module} sends parameters"


@reads_source
def test_msrc_is_asked_for_a_month_and_nothing_else():
    calls = _get_calls("collectors/msrc.py")
    assert len(calls) == 1 and not calls[0].keywords
    names = {n.id for n in ast.walk(calls[0].args[0]) if isinstance(n, ast.Name)}
    assert names == {"MSRC_API", "month"}


@reads_source
def test_nvd_receives_the_watched_name_and_first_the_cve_ids(doc):
    nvd = (PACKAGE / "collectors" / "nvd.py").read_text(encoding="utf-8")
    assert '"keywordSearch": keyword' in nvd
    assert 'headers = {"apiKey": key} if key else {}' in nvd
    epss = (PACKAGE / "epss.py").read_text(encoding="utf-8")
    assert 'params = {"cve": ",".join(chunk)' in epss
    assert "NVD_API_KEY" in doc


@reads_source
def test_only_the_law_fetcher_names_the_repository_in_its_user_agent(doc):
    """mailradar can say every request names the repository; here only the law
    fetcher sets a User-Agent, and the collectors send httpx's own."""
    assert "User-Agent" in (PACKAGE / "law_fetcher.py").read_text(encoding="utf-8")
    for path in [*(PACKAGE / "collectors").glob("*.py"), PACKAGE / "epss.py"]:
        assert "User-Agent" not in path.read_text(encoding="utf-8"), path.name
    assert "python-httpx" in doc


def test_normattiva_is_not_reached_by_the_citations_patchradar_makes(doc):
    """The law fetcher is shared by the Radar tools and can ask Normattiva for an
    Italian act; PatchRadar's own mapping cites only acts EUR-Lex publishes."""
    cited = {act for refs in law_checker.FINDING_ARTICLES.values() for act, _ in refs}
    cited |= set(law_checker.ALSO_FETCH)
    assert cited and all(act.source == "EUR-Lex" for act in cited)
    assert "GDPR e NIS2" in doc


@reads_source
def test_the_law_check_runs_from_the_command_line_scan_only():
    api = (PACKAGE / "api" / "main.py").read_text(encoding="utf-8")
    assert "law_checker" not in api
    assert "_print_law_check(_law_check(cves))" in inspect.getsource(cli.scan)


@reads_source
def test_the_web_scan_asks_debian_and_the_command_line_scan_does_not():
    assert "debian_fetch(sw)" in inspect.getsource(api_main._scan_one)
    assert "for fetch in (fetch_cves, msrc_fetch, kev_fetch, vuldb_fetch):" in inspect.getsource(cli._scan_target)


@reads_source
def test_the_database_declared_is_the_one_written(doc):
    """The watchlist lives in a SQLite file under the home directory, at a path
    no setting moves: PATCHRADAR_HOME moves the law cache and not this."""
    written = database.DEFAULT_DB_PATH.relative_to(Path.home()).as_posix()
    assert f"~/{written}" in doc
    assert "environ" not in (PACKAGE / "db" / "database.py").read_text(encoding="utf-8")
    assert "non sposta il database" in prose(doc)


def test_the_cache_declared_is_the_one_written(doc, monkeypatch, tmp_path):
    monkeypatch.delenv("PATCHRADAR_HOME", raising=False)
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.setenv("USERPROFILE", str(tmp_path))
    written = law_cache.default_cache_path().relative_to(tmp_path).as_posix()
    assert f"~/{written}" in doc
    assert "PATCHRADAR_HOME" in doc


def test_the_volume_the_document_names_is_the_image_one(doc):
    volume = re.search(r'^VOLUME \["([^"]+)"\]', DOCKERFILE.read_text(encoding="utf-8"), re.M)
    assert volume
    assert f"`{volume.group(1)}`" in doc


SENDING = re.compile(
    r"Invoke-WebRequest|Invoke-RestMethod|WebClient|HttpClient|Net\.Sockets|Send-MailMessage"
    r"|Start-BitsTransfer|\bcurl\b|\bwget\b|\biwr\b|\birm\b",
    re.I,
)


@reads_source
def test_the_inventory_collector_sends_nothing_and_the_reader_too(doc):
    script = COLLECTOR_SCRIPT.read_text(encoding="utf-8")
    assert not SENDING.search(script), SENDING.search(script)
    assert script.count("WriteAllText") == 1
    assert not NETWORK_IMPORT.search((PACKAGE / "inventory.py").read_text(encoding="utf-8"))
    assert "Get-AuthenticodeSignature" in script
    assert "`Get-AuthenticodeSignature`" in doc


def test_every_section_of_the_inventory_is_declared(doc):
    """What a customer runs elevated on a machine has to be listed in full."""
    script = COLLECTOR_SCRIPT.read_text(encoding="utf-8")
    collected = set(re.findall(r"^ {4}(\w+)\s*=\s*@?\(?Safe '", script, re.M))
    assert len(collected) >= 10
    declared = table_first_column(section(doc, "inventory"))
    assert declared == collected, (
        f"declared but not collected: {sorted(declared - collected)}; "
        f"collected but not declared: {sorted(collected - declared)}"
    )


# --- Question 2: who can reach the web interface ------------------------------


def _option_default(command, name: str):
    return inspect.signature(command).parameters[name].default.default


@reads_source
def test_serve_listens_on_loopback_unless_told_otherwise(doc):
    assert _option_default(cli.serve, "host") == "127.0.0.1"
    assert _option_default(cli.serve, "port") == 8000
    assert "`--host`" in doc and "`127.0.0.1`" in doc


@reads_source
def test_serve_speaks_plain_http(doc):
    source = inspect.getsource(cli.serve)
    assert "uvicorn.run(" in source and "ssl" not in source
    assert "HTTP in chiaro" in prose(doc)


def test_the_image_listens_on_every_interface_and_the_document_says_so(doc):
    dockerfile = DOCKERFILE.read_text(encoding="utf-8")
    cmd = re.findall(r"^CMD\s+(.+)$", dockerfile, re.M)[-1]
    assert '"--host", "0.0.0.0"' in cmd
    assert re.search(r"^EXPOSE 8000$", dockerfile, re.M)
    assert '"127.0.0.1:8000:8000"' in COMPOSE.read_text(encoding="utf-8")
    assert "`0.0.0.0`" in doc
    assert "`127.0.0.1:8000:8000`" in doc


def routes_and_keys() -> dict[str, str]:
    """{"METHOD /path": "sì" or "no"}: whether the route asks for the key."""
    found = {}
    for route in api_main.app.routes:
        # The /static mount has no methods; the document names it in prose.
        if not getattr(route, "methods", None):
            continue
        methods = sorted(set(route.methods) - {"HEAD"})
        protected = isinstance(route, APIRoute) and any(
            dep.call is api_main.require_api_key for dep in route.dependant.dependencies
        )
        for method in methods:
            found[f"{method} {route.path}"] = "sì" if protected else "no"
    return found


def test_every_endpoint_and_whether_it_asks_for_the_key_is_declared(doc):
    rows = table_rows(section(doc, "endpoints"))
    declared = {name: cells[0] for name, cells in rows.items()}
    actual = routes_and_keys()
    assert declared == actual


async def test_reads_need_no_key_even_when_one_is_set(doc, monkeypatch):
    """Measured on 2026-10-11 against `patchradar serve` with the key set: the
    watchlist came back to a request without it. The document has to say so."""
    monkeypatch.setenv(api_main.API_KEY_ENV, "a-key-for-this-test")
    await database.init_db()
    async with AsyncClient(transport=ASGITransport(app=api_main.app), base_url="http://test") as client:
        assert (await client.post("/api/watchlist/nginx")).status_code == 401
        assert (await client.get("/api/watchlist")).status_code == 200
        assert (await client.get("/api/cves")).status_code == 200
    assert "anche quando la chiave è impostata" in prose(doc)


def test_the_image_runs_as_the_user_the_document_names(doc):
    dockerfile = DOCKERFILE.read_text(encoding="utf-8")
    user = re.findall(r"^USER\s+(\S+)", dockerfile, re.M)[-1]
    uid = re.search(rf"useradd\b[^\n]*-u\s+(\d+)[^\n]*\b{re.escape(user)}\b", dockerfile)
    assert user not in {"root", "0"}
    assert uid, f"the Dockerfile does not create {user} with an explicit UID"
    assert f"UID {uid.group(1)}" in doc
    assert f"`{user}`" in doc


# --- Questions 1 and 6: what every release carries ---------------------------


@pytest.fixture(scope="module")
def evidence() -> dict:
    return yaml.safe_load(EVIDENCE.read_text(encoding="utf-8"))


def test_the_evidence_follows_the_image_of_a_release(evidence):
    """The image SBOM and its scan describe the image of the release, so the job
    runs when docker.yml has pushed it. docker.yml runs on `release: published`,
    which scripts/release.py causes with `gh release create`: the release the
    files are attached to exists before the job starts."""
    triggers = evidence.get(True, evidence.get("on"))
    docker = yaml.safe_load(DOCKER.read_text(encoding="utf-8"))
    assert docker.get(True, docker.get("on"))["release"]["types"] == ["published"]
    assert triggers["workflow_run"]["workflows"] == [docker["name"]]
    assert triggers["workflow_run"]["types"] == ["completed"]
    assert "tag" in triggers["workflow_dispatch"]["inputs"]
    job = next(iter(evidence["jobs"].values()))
    assert "conclusion == 'success'" in job["if"]
    assert "github.event.workflow_run.event == 'release'" in job["if"]
    assert '"gh", "release", "create", version' in (ROOT / "scripts" / "release.py").read_text(encoding="utf-8")


JOB_ENV_CONTEXTS = {"github", "inputs", "matrix", "needs", "secrets", "strategy", "vars"}


def test_the_job_env_uses_only_contexts_github_allows_there(evidence):
    """`runner` is not available in a job's `env`, and GitHub refuses the whole
    file when it finds it: on 2026-10-11 mailradar's first dispatch of this
    workflow answered HTTP 422, "Unrecognized named-value: 'runner'", after the
    tests and every check had passed."""
    for job in evidence["jobs"].values():
        for name, value in (job.get("env") or {}).items():
            for expression in re.findall(r"\$\{\{(.*?)\}\}", str(value)):
                used = set(re.findall(r"(?<![\w.])([a-z_]+)\.", expression))
                assert used <= JOB_ENV_CONTEXTS, f"env {name} uses {sorted(used - JOB_ENV_CONTEXTS)}"


def _tag_pattern() -> re.Pattern[str]:
    match = re.search(r"grep -Eq '([^']+)'", EVIDENCE.read_text(encoding="utf-8"))
    assert match, "sbom.yml does not check the tag"
    return re.compile(match.group(1))


def test_the_tag_check_accepts_the_tags_this_project_cuts():
    """Every tag here is bare CalVer (2026.46, 2026.9.6): mailradar's check,
    which wants a leading v, would refuse every release of this repository."""
    version = tomllib.loads(PYPROJECT.read_text(encoding="utf-8"))["project"]["version"]
    pattern = _tag_pattern()
    for tag in (version, "2026.46", "2026.9.6", "2026.40.1"):
        assert pattern.fullmatch(tag), tag
    for tag in (f"v{version}", "latest", "2026.46; rm -rf /", ""):
        assert not pattern.fullmatch(tag), tag


def test_the_image_tag_named_is_the_one_docker_yml_pushes(doc):
    """docker.yml strips a leading v and tags the image with the bare version,
    which is also the git tag here: maksimtech/patchradar:2026.46. Docker Hub
    listed no v-prefixed tag on 2026-10-11."""
    docker = DOCKER.read_text(encoding="utf-8")
    assert 'echo "VERSION=${RAW#v}"' in docker
    assert f"{IMAGE}:${{{{ steps.version.outputs.VERSION }}}}" in docker
    for name, text in (("the document", doc), ("SECURITY.md", SECURITY.read_text(encoding="utf-8"))):
        assert re.search(rf"{re.escape(IMAGE)}:(?:\d{{4}}\.|<versione>|<version>)", text), (
            f"{name} does not name the image by its version tag"
        )
        assert f"{IMAGE}:v" not in text, f"{name} names a v tag docker.yml never pushes"
    workflow = EVIDENCE.read_text(encoding="utf-8")
    assert '"registry:${IMAGE}:${TAG}"' in workflow
    assert "image-ref: ${{ env.IMAGE }}:${{ env.TAG }}" in workflow


def test_the_evidence_note_gives_the_digest_and_not_the_tag_twice():
    """Syft puts the tag in metadata.component.version, and mailradar's first
    EVIDENCE note read "digest v2026.44". The digest a customer pins comes from
    Docker Hub, which gives the index digest and one per platform."""
    # Only the step that writes the note: the source SBOM step does write the
    # version into its own metadata.component, which is a different thing.
    describe = _evidence_step("Describe the evidence")
    assert '["metadata"]["component"]' not in describe
    assert "https://hub.docker.com/v2/repositories/${IMAGE}/tags/${TAG}" in describe


def test_the_source_sbom_names_the_package_it_describes():
    """Without --pyproject, cyclonedx-py lists the environment and names no main
    component: the SBOM did not say which product it was the SBOM of."""
    workflow = EVIDENCE.read_text(encoding="utf-8")
    assert "--pyproject pyproject.toml" in workflow
    assert "--mc-type application" in workflow


def test_the_evidence_job_pins_its_actions():
    for line in EVIDENCE.read_text(encoding="utf-8").splitlines():
        if "uses:" in line:
            ref = line.split("uses:", 1)[1].split("#")[0].strip()
            assert re.search(r"@[0-9a-f]{40}$", ref), f"not pinned to a commit: {line.strip()}"


def test_the_release_carries_the_files_the_document_promises(doc):
    promised = table_first_column(section(doc, "assets"))
    workflow = EVIDENCE.read_text(encoding="utf-8")
    assert len(promised) == 5, "the document promises five release files"
    for name in promised:
        stem = name.split("<")[0].rstrip("-")
        assert stem in workflow, f"{name} is promised but sbom.yml never writes {stem}"
    assert "gh release upload" in workflow


def test_the_scan_is_not_presented_as_a_penetration_test(doc):
    """Question 6 asks for a penetration test. There has been none, and a scan of
    known CVEs is not one: the release note that travels with the files says so."""
    assert "non è un penetration test" in prose(doc)
    assert "not a penetration test" in EVIDENCE.read_text(encoding="utf-8")


def test_the_workflow_set_accounts_for_the_evidence_workflow():
    workflow_set = (ROOT / "tests" / "test_workflow_set.py").read_text(encoding="utf-8")
    assert '"sbom":' in workflow_set


# --- Questions 4 and 5: policy and pipeline ----------------------------------

SCANNERS = {
    "CodeQL": "codeql",
    "Bandit": "bandit",
    "Trivy": "trivy",
    "Snyk": "snyk",
    "Docker Scout": "docker-scout",
    "SonarCloud": "sonarcloud",
    "Security Posture": "security-posture",
    "mutmut": "mutation",
    "CodSpeed": "codspeed",
}


def test_every_scanner_named_has_its_workflow_and_none_is_left_out(doc):
    named = table_first_column(section(doc, "scanners"))
    assert named <= set(SCANNERS), f"unknown scanner names: {sorted(named - set(SCANNERS))}"
    for name in named:
        assert (WORKFLOWS / f"{SCANNERS[name]}.yml").is_file(), f"{name} has no workflow"
    present = {n for n, w in SCANNERS.items() if (WORKFLOWS / f"{w}.yml").is_file()}
    assert present <= named, f"workflows the document does not name: {sorted(present - named)}"


def test_the_image_is_not_said_to_be_rebuilt_between_releases(doc):
    """mailradar rebuilds `latest` every week; here docker.yml runs on a release
    or by hand, so Debian's patches reach the image with the next release."""
    docker = yaml.safe_load(DOCKER.read_text(encoding="utf-8"))
    assert "schedule" not in docker.get(True, docker.get("on"))
    security = prose(SECURITY.read_text(encoding="utf-8"))
    assert "not rebuilt between releases" in security
    assert "settiman" not in section(doc, "rollback")


def test_security_md_answers_the_fourth_question():
    text = SECURITY.read_text(encoding="utf-8")
    for heading in (
        "## Reporting a vulnerability",
        "## How vulnerabilities are found",
        "## Response times",
        "## Customer notification",
        "## Rollback",
    ):
        assert heading in text, f"SECURITY.md has no {heading!r}"
    assert "single maintainer" in text
    assert "Massimo Moretti" in text


def test_security_md_does_not_count_the_feeds_patchradar_reads_as_its_own_monitoring():
    """NVD, CISA KEV, FIRST EPSS and the Debian tracker are hosts the tool
    contacts for its users, not sources that watch this project's code."""
    found = section_of(SECURITY.read_text(encoding="utf-8"), "## How vulnerabilities are found")
    for feed in ("NVD", "KEV", "EPSS", "OSV", "security-tracker"):
        assert feed not in found, f"SECURITY.md lists {feed} as a source of its own monitoring"


def section_of(markdown: str, heading: str) -> str:
    start = markdown.index(heading)
    following = markdown.find("\n## ", start + len(heading))
    return markdown[start:following if following != -1 else None]


def test_the_document_and_security_md_give_the_same_contact(doc):
    contact = re.search(r"[\w.+-]+@maksimtech\.com", SECURITY.read_text(encoding="utf-8"))
    assert contact and contact.group(0) == "security@maksimtech.com"
    assert contact.group(0) in doc


def test_no_personal_address_is_published(doc):
    for path, text in ((DOC, doc), (SECURITY, SECURITY.read_text(encoding="utf-8"))):
        addresses = set(re.findall(r"[\w.+-]+@[\w-]+(?:\.[\w-]+)+", text))
        assert addresses <= {"security@maksimtech.com"}, f"{path.name}: {sorted(addresses)}"


def test_the_document_does_not_claim_a_second_review(doc):
    """The repository has one maintainer and its ruleset has no pull request rule.
    Question 5 asks for a second reviewer; the honest answer is that there is none."""
    text = prose(doc)
    assert "manutentore unico" in text
    assert "nessuna revisione obbligatoria da parte di una seconda persona" in text


FORBIDDEN = [
    re.compile(r"NIS2[- ](?:ready|compliant|certified)", re.I),
    re.compile(r"certificat\w* NIS2", re.I),
    re.compile(r"nessun dato (?:è )?inviato a terzi", re.I),
    re.compile(r"no data (?:is )?sent to third parties", re.I),
    re.compile(r"ogni PR richiede", re.I),
]


@pytest.mark.parametrize("path", [DOC, SECURITY, README], ids=lambda p: p.name)
def test_no_claim_this_repository_cannot_back(path):
    text = path.read_text(encoding="utf-8")
    for pattern in FORBIDDEN:
        found = pattern.search(text)
        assert not found, f"{path.name} says {found.group(0)!r}"


# --- Question 1: the licence gate the document cites --------------------------


def test_the_licence_gate_matches_the_names_packages_actually_declare():
    """Without --partial-match, pip-licenses fails only on a licence string equal
    to "GPL", and no package declares that. Measured on 2026-10-11 with chardet
    5.2.0 (LGPLv2+) installed: `--fail-on="GPL;AGPL;LGPL"` exited 0, the same
    with --partial-match exited 1. PatchRadar's own runtime dependencies, in a
    fresh environment, exit 0 with the flag."""
    licences = (WORKFLOWS / "licenses.yml").read_text(encoding="utf-8")
    gate = next(line for line in licences.splitlines() if "--fail-on" in line)
    assert "--partial-match" in gate


# --- The lockfile the document points to ------------------------------------


def test_the_lockfile_exists_and_quality_keeps_it_in_step():
    """PatchRadar had no uv.lock until 2026-10-11. A lockfile shown to a customer
    as the list of dependencies has to be the current one, so the check that
    keeps it current came with it."""
    assert (ROOT / "uv.lock").is_file()
    quality = (WORKFLOWS / "quality.yml").read_text(encoding="utf-8")
    assert re.search(r"uv lock --check", quality)


# --- The weekly mutation run reads these files too ----------------------------


def test_mutmut_copies_the_files_the_suite_reads():
    """mutmut runs the suite from a copy holding only what it is told to copy; a
    file the suite reads that is not there stops the run before a mutant is
    tried. On 2026-10-10 the scheduled run stopped that way on README.md and
    LICENSE, which tests/test_declared_files.py reads because the Dockerfile
    copies them; this module adds docs/ and SECURITY.md."""
    also_copy = set(tomllib.loads(PYPROJECT.read_text(encoding="utf-8"))["tool"]["mutmut"]["also_copy"])
    needed_files = ("docs", "SECURITY.md", "README.md", "LICENSE", "scripts", "Dockerfile", ".github",
                    "docker-compose.yml")
    for needed in needed_files:
        assert needed in also_copy, f"{needed} is read by the suite but mutmut does not copy it"


# --- What the evidence says about itself --------------------------------------


def _evidence_step(name: str) -> str:
    workflow = yaml.safe_load(EVIDENCE.read_text(encoding="utf-8"))
    job = next(iter(workflow["jobs"].values()))
    return next(s["run"] for s in job["steps"] if s.get("name") == name)


def test_the_source_sbom_says_which_version_it_describes():
    """The version is dynamic in pyproject.toml, so cyclonedx-py names the main
    component and leaves its version out: the sbom-source files attached on
    2026-10-11 named the package and no version. The workflow writes the version
    of the package it installed, and refuses a tag that disagrees with it."""
    import tomllib

    dist = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))["project"]["name"]
    sbom = _evidence_step("SBOM of the Python environment")
    assert f'm.version("{dist}")' in sbom
    assert '!= "$VERSION"' in sbom
    assert '["version"] =' in sbom


def test_the_source_sbom_leaves_out_what_the_image_removes():
    """The Dockerfile uninstalls pip, and the sbom-source attached on 2026-10-11
    still listed it: the venv's own copy, which the image does not ship. The
    environment described drops what the image drops, before it is described."""
    dockerfile = DOCKERFILE.read_text(encoding="utf-8")
    removed = [p for p in ("pip", "setuptools", "wheel") if re.search(rf"pip uninstall[^\n]*\b{p}\b", dockerfile)]
    assert "pip" in removed
    sbom = _evidence_step("SBOM of the Python environment")
    install = sbom.index("/tmp/product/bin/pip install")
    uninstall = sbom.index("/tmp/product/bin/python -m pip uninstall --yes --quiet")
    describe = sbom.index("cyclonedx-py environment")
    assert install < uninstall < describe
    line = sbom[uninstall : sbom.index("\n", uninstall)].split()
    assert all(p in line for p in removed), f"the image removes {removed}"


def test_an_empty_repository_scan_is_not_presented_as_a_clean_one(doc):
    """A trivy-fs report with no Results means Trivy found no file it could read
    at that tag, such as a lockfile. Whoever opens it reads "no vulnerabilities",
    so the note and the document say what it is."""
    describe = _evidence_step("Describe the evidence")
    assert "found no file it could analyse" in describe
    assert "non indica l'assenza di vulnerabilità" in " ".join(doc.split())


def test_vuldb_is_declared_as_contacted_only_with_its_key(doc):
    """Without VULDB_API_KEY the collector refuses before any request, so the
    document says VulDB is reached only when the key is set."""
    source = (PACKAGE / "collectors" / "vuldb.py").read_text(encoding="utf-8")
    refuse = source.index('raise CollectorError(SOURCE, "no_api_key"')
    request = source.index("await client.post(")
    assert refuse < request
    assert "solo se `VULDB_API_KEY` è impostata" in prose(doc)


def test_the_branch_rules_are_described_without_an_exception(doc):
    """On 2026-10-12 the ruleset on main lost the owner's bypass and requires a pull
    request for every change, the version bump included (release.sh opens one). The
    document says so with the date it was read, and keeps the earlier state as past."""
    text = prose(doc)
    assert "lette dalle impostazioni del repository il 2026-10-12" in text
    assert "Non prevedono eccezioni, nemmeno per l'account del manutentore" in text
    for stale in ("è configurato per poter scavalcare", "può scavalcare queste regole",
                  "può scavalcare le regole", "vanno direttamente su `main`",
                  "Non c'è una regola che imponga la pull request"):
        assert stale not in text, stale
