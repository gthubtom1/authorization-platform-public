from __future__ import annotations

from html.parser import HTMLParser
from pathlib import Path
import re


ROOT = Path(__file__).resolve().parents[1]
PREVIEW_ROOT = ROOT / "docs" / "ui-preview"
STATIC_FILES = ("entry.html", "manage-login.html", "downstream-login.html", "downstream-register.html")

EXPECTED_PANELS = {
    "manage.html": (
        "overview",
        "analytics",
        "software",
        "downstreams",
        "credits",
        "licenses",
        "risk",
        "client",
        "releases",
        "audit",
        "backup",
    ),
    "downstream.html": ("workspace", "licenses", "devices", "ledger", "software", "support", "activity"),
}
EXPECTED_PRIMARY_NAV = {
    "manage.html": ("overview", "software", "downstreams", "credits", "licenses", "risk", "client", "audit", "backup"),
    "downstream.html": ("workspace", "licenses", "devices", "ledger", "support", "activity"),
}

VOID_TAGS = {"area", "base", "br", "col", "embed", "hr", "img", "input", "link", "meta", "param", "source", "track", "wbr"}

FORBIDDEN_STATIC_FIXTURES = (
    "LIC-",
    "INV-",
    "QUOTA-",
    "Alpha Desktop",
    "Beta Studio",
    "Gamma Tools",
    "渠道 A",
    "渠道 B",
    "渠道北区",
    "support@example",
    "portal.example",
    "shop.example",
    "new-software",
    "profile-new-",
    "data-static-code-key",
    "data-fixture",
    "data-demo",
    "AutoPilot",
    "XXXX-XXXX-XXXX-XXXX-XXXX",
)

SCAN_SUFFIXES = {".html", ".js", ".css"}

BUSINESS_ROW_ATTRIBUTES = (
    "data-public-id",
    "data-generated",
    "data-static-code-key",
    "data-downstream-row",
    "data-device-row",
    "data-release-id",
    "data-catalog-software-id",
)
LIVE_PREVIEW_NAMES = {
    "manage.html",
    "manage-login.html",
    "downstream.html",
    "downstream-login.html",
    "downstream-register.html",
    "preview.js",
}

EMPTY_METRIC_PATTERN = re.compile(
    r"<[^>]*data-(?:overview-metric|revenue-metric|analytics-metric|downstream-metric)=[^>]*>\s*([^<]*)",
    re.IGNORECASE,
)



class StrictStructureParser(HTMLParser):
    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.stack: list[tuple[str, dict[str, str | None], int]] = []
        self.errors: list[str] = []
        self.nav_screens: list[str] = []
        self.primary_nav_screens: list[str] = []
        self.panels: list[str] = []
        self.initial_panels: list[str] = []

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        attributes = dict(attrs)
        if tag == "a" and attributes.get("data-screen"):
            self.nav_screens.append(str(attributes["data-screen"]))
            if "nav-secondary" not in (attributes.get("class") or "").split():
                self.primary_nav_screens.append(str(attributes["data-screen"]))
        if attributes.get("data-screen-panel"):
            screen = str(attributes["data-screen-panel"])
            self.panels.append(screen)
            if "is-visible" in (attributes.get("class") or "").split():
                self.initial_panels.append(screen)
            if not any(
                ancestor_tag == "main" and "app-main" in (ancestor_attrs.get("class") or "").split()
                for ancestor_tag, ancestor_attrs, _ in self.stack
            ):
                self.errors.append(f"line {self.getpos()[0]}: panel {screen!r} is outside .app-main")
        if tag not in VOID_TAGS:
            self.stack.append((tag, attributes, self.getpos()[0]))

    def handle_startendtag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        self.handle_starttag(tag, attrs)

    def handle_endtag(self, tag: str) -> None:
        line = self.getpos()[0]
        if not self.stack:
            self.errors.append(f"line {line}: stray </{tag}>")
            return
        open_tag, _, open_line = self.stack[-1]
        if open_tag != tag:
            self.errors.append(f"line {line}: stray </{tag}> while <{open_tag}> from line {open_line} is open")
            return
        self.stack.pop()

    def finish(self) -> None:
        for tag, _, line in reversed(self.stack):
            self.errors.append(f"line {line}: unclosed <{tag}>")


def parse(source: str) -> StrictStructureParser:
    parser = StrictStructureParser()
    parser.feed(source)
    parser.close()
    parser.finish()
    return parser


def self_check() -> None:
    valid = parse('<main class="app-main"><section data-screen-panel="ok"></section></main>')
    if valid.errors or valid.panels != ["ok"]:
        raise AssertionError("UI preview checker rejected its valid control")
    void_elements = parse('<main class="app-main"><input /><br /><section data-screen-panel="ok"></section></main>')
    if void_elements.errors or void_elements.panels != ["ok"]:
        raise AssertionError("UI preview checker rejected standard void elements")
    invalid = parse('<main class="app-main"><section data-screen-panel="bad"></div></section></main>')
    if len(invalid.errors) != 1 or "stray </div>" not in invalid.errors[0]:
        raise AssertionError("UI preview checker did not reject its malformed control")
    navigation = parse(
        '<nav><a data-screen="primary"></a><a class="nav-secondary" data-screen="context"></a></nav>'
    )
    if navigation.nav_screens != ["primary", "context"] or navigation.primary_nav_screens != ["primary"]:
        raise AssertionError("UI preview checker did not distinguish primary and contextual navigation")
    dirty = scan_preview_source("<table><tbody><tr><td>Unlisted Product</td></tr></tbody></table>", "fixture.html")
    if not any("business table body" in error for error in dirty):
        raise AssertionError("UI preview checker did not reject an unlisted business row")
    loaded = scan_preview_source('<section data-server-data-loaded="true"></section>', "docs/ui-preview/manage.html")
    if not any("already loaded" in error for error in loaded):
        raise AssertionError("UI preview checker did not reject a frozen serverDataLoaded claim")
    entry = scan_preview_source('<a href="entry.html">hidden</a>', "docs/ui-preview/manage.html")
    if not any("entry.html" in error for error in entry):
        raise AssertionError("UI preview checker did not reject a live-page entry.html link")
    counts = scan_preview_source('<button type="button" data-count="12">运行中</button>', "docs/ui-preview/manage.html")
    if not any("static counts" in error for error in counts):
        raise AssertionError("UI preview checker did not reject a frozen chip count")
    missing_pages = collection_loader_errors("async function loadCatalog() { await apiRequest('/manage/catalog/'); }")
    if not any("fetchAllCollectionPages" in error for error in missing_pages):
        raise AssertionError("UI preview checker did not reject a catalog loader that skips pagination")
    hollow_card = collection_loader_errors(
        "\n".join(
            [
                "async function fetchAllCollectionPages(){}",
                "options.pageSize || 100",
                "options.maxPages || 20",
                "async function loadCatalog() { await fetchAllCollectionPages('/manage/catalog/'); }",
                "async function loadDownstreams() { await fetchAllCollectionPages('/manage/downstreams/'); }",
                "extraQuery: { status }",
                "async function loadPublishedReleases(softwareId) { return []; }",
                "async function applyReleaseContext(softwareId) { return softwareId; }",
                "function fillReleaseSignatureStatus(item) {}",
                "async function loadReleasesForSoftware(softwareId, page = releasePage) { await apiRequest('/manage/releases/'); }",
                "function catalogSoftwareForRelease(softwareId) { return null; }",
                "function currentReclaimFilters(panel) { return { status: 'unused' }; }",
                "function currentFilteredReclaimRows(panel) { return []; }",
            ]
        )
    )
    if not any("loadPublishedReleases" in error for error in hollow_card):
        raise AssertionError("UI preview checker did not reject a current-release card that skips published queries")
    if not any("software=all" in error for error in hollow_card):
        raise AssertionError("UI preview checker did not reject a current-release card that accepts software=all")
    if not any("stale software=all" in error for error in hollow_card):
        raise AssertionError("UI preview checker did not reject a release list loader without a generation token")
    if not any("recordScope" in error for error in hollow_card):
        raise AssertionError("UI preview checker did not reject reclaim filters that drop recordScope")
    failure_as_empty = collection_loader_errors(
        "\n".join(
            [
                'async function applyReleaseContext(softwareId) {',
                '  if (softwareId === "all") { currentTarget.textContent = "请选择软件"; return; }',
                "  let current = null;",
                "  try { current = highestPublishedRelease(await loadPublishedReleases(softwareId)); }",
                "  catch (_requestError) { current = null; }",
                '  statusTarget.textContent = current ? "分发中" : "暂无发布";',
                "}",
                "function fillReleaseSignatureStatus(item) {}",
                "async function loadPublishedReleases(softwareId) { if (!payload.pagination?.has_next) return []; }",
            ]
        )
    )
    if not any("paint published-query failure" in error for error in failure_as_empty):
        raise AssertionError("UI preview checker did not reject a current-release card that paints published failure as empty")
    stale_support = collection_loader_errors(
        "\n".join(
            [
                "async function loadDownstreamSupport(softwareId) {",
                "  const payload = await apiRequest(`/downstream/support/${softwareId}/`);",
                '  document.querySelector("[data-support-purchase]").value = support.purchase_url;',
                "}",
                'document.querySelector("[data-support-save]").addEventListener("click", async () => {',
                "  const softwareId = select?.value || \"\";",
                "  await apiRequest(`/downstream/support/${softwareId}/`, { method: \"POST\" });",
                "});",
            ]
        )
    )
    if not any("generation token" in error for error in stale_support):
        raise AssertionError("UI preview checker did not reject a support loader without a generation token")
    if not any("stale software responses" in error for error in stale_support):
        raise AssertionError("UI preview checker did not reject a support loader that applies stale software")
    if not any("loaded software" in error for error in stale_support):
        raise AssertionError("UI preview checker did not reject a support save that posts the live select")
    unused_used_time = collection_loader_errors(
        "\n".join(
            [
                "function renderInvitationRows(items, { serverSearch = false } = {}) {",
                '  appendTextCell(row, item.consumed_at ? formatApiDate(item.consumed_at) : "永久有效", "mono");',
                "}",
                "  const catalogSoftwareStatusCopy = {}",
            ]
        )
    )
    if not any("invitation unused used-time" in error for error in unused_used_time):
        raise AssertionError("UI preview checker did not reject invitation used-time falling back to 永久有效")


def check_file(path: Path, expected_panels: tuple[str, ...], expected_primary_nav: tuple[str, ...]) -> list[str]:
    parser = parse(path.read_text(encoding="utf-8"))
    errors = [f"{path.relative_to(ROOT)}:{message}" for message in parser.errors]
    if tuple(parser.nav_screens) != expected_panels:
        errors.append(f"{path.relative_to(ROOT)}: route links {parser.nav_screens!r} != {list(expected_panels)!r}")
    if tuple(parser.primary_nav_screens) != expected_primary_nav:
        errors.append(
            f"{path.relative_to(ROOT)}: primary navigation {parser.primary_nav_screens!r} != {list(expected_primary_nav)!r}"
        )
    if tuple(parser.panels) != expected_panels:
        errors.append(f"{path.relative_to(ROOT)}: panels {parser.panels!r} != {list(expected_panels)!r}")
    if parser.initial_panels != [expected_panels[0]]:
        errors.append(
            f"{path.relative_to(ROOT)}: initial visible panels {parser.initial_panels!r} != {[expected_panels[0]]!r}"
        )
    return errors


def scan_preview_source(source: str, label: str) -> list[str]:
    errors: list[str] = []
    lines = source.splitlines()
    html_source = label.lower().endswith(".html")
    for line_number, line in enumerate(lines, start=1):
        for marker in FORBIDDEN_STATIC_FIXTURES:
            if marker in line:
                errors.append(f"{label}:{line_number}: static fixture marker {marker!r}")
        if re.search(r"\b(?:LIC|INV|QUOTA)-", line):
            errors.append(f"{label}:{line_number}: credential prefix in frozen source")
        if html_source and any(attribute in line for attribute in BUSINESS_ROW_ATTRIBUTES):
            errors.append(f"{label}:{line_number}: business row attribute in frozen source")
        if Path(label).name in LIVE_PREVIEW_NAMES and "entry.html" in line:
            errors.append(f"{label}:{line_number}: live page must not mention hidden entry.html")
    if html_source and re.search(r"<tbody\b(?:(?!</?tbody\b).)*?<tr\b", source, re.IGNORECASE | re.DOTALL):
        errors.append(f"{label}: business table body contains a static row")
    if html_source and re.search(r'class=["\'][^"\']*\b(?:package-row|batch-row)[^"\']*["\']', source, re.IGNORECASE):
        errors.append(f"{label}: business card/list class contains a static item")
    if html_source and "data-server-data-loaded" in source:
        errors.append(f"{label}: frozen HTML must not claim server data already loaded")
    if html_source and re.search(r"\bdata-count=", source, re.IGNORECASE):
        errors.append(f"{label}: frozen HTML must not embed static counts")
    if html_source:
        for match in EMPTY_METRIC_PATTERN.finditer(source):
            if match.group(1).strip() not in {"", "—"}:
                errors.append(f"{label}: metric has a static value")
    return errors


def collection_loader_errors(source: str, label: str = "docs/ui-preview/preview.js") -> list[str]:
    errors: list[str] = []
    if "async function fetchAllCollectionPages" not in source:
        errors.append(f"{label}: missing fetchAllCollectionPages")
    if "options.pageSize || 100" not in source:
        errors.append(f"{label}: collection loader must default page_size to 100")
    if "options.maxPages || 20" not in source:
        errors.append(f"{label}: collection loader must cap pagination at 20 pages")
    if not re.search(r"async function loadCatalog\(\)[\s\S]*?fetchAllCollectionPages\(", source):
        errors.append(f"{label}: loadCatalog must drain fetchAllCollectionPages")
    if not re.search(r"async function loadDownstreams\(\)[\s\S]*?fetchAllCollectionPages\(", source):
        errors.append(f"{label}: loadDownstreams must drain fetchAllCollectionPages")
    if "extraQuery: { status }" not in source:
        errors.append(f"{label}: downstream collection must send extraQuery.status")
    if "function fillCreditAdjustDialog" in source:
        match = re.search(r"function fillCreditAdjustDialog\(\) \{([\s\S]*?)\n  function ", source)
        body = match.group(1) if match else ""
        if "downstreamProfiles" in body:
            errors.append(f"{label}: credit adjust dropdown must not reuse downstream table cache")
        if "quotaAccountsCache" not in body:
            errors.append(f"{label}: credit adjust dropdown must read quotaAccountsCache")
        if "item.downstream_public_id" not in body:
            errors.append(f"{label}: credit adjust dropdown must submit downstream_public_id")
    if "function applyReleaseContext" in source or "async function applyReleaseContext" in source:
        match = re.search(
            r"async function applyReleaseContext\(softwareId\) \{([\s\S]*?)\n\s*function fillReleaseSignatureStatus",
            source,
        )
        body = match.group(1) if match else ""
        if not match:
            errors.append(f"{label}: current-release card must be applyReleaseContext(softwareId)")
        if "softwareId === \"all\"" not in body or "请选择软件" not in body:
            errors.append(f"{label}: current-release card must refuse software=all instead of using the current page")
        if re.search(r"catch[\s\S]{0,240}current\s*=\s*null[\s\S]{0,480}暂无发布", body):
            errors.append(f"{label}: current-release card must not paint published-query failure as 暂无发布")
        if "await loadPublishedReleases(softwareId)" not in body:
            errors.append(f"{label}: current-release card must call loadPublishedReleases")
        if "releaseContextRequestGeneration" not in body:
            errors.append(f"{label}: current-release card must ignore stale software responses")
        if "releaseContext?.value" not in body:
            errors.append(f"{label}: current-release card must ignore stale software responses")
        if "paintReleaseUpdateCopy" not in body and "[data-update-copy]" not in body:
            errors.append(f"{label}: current-release card must paint [data-update-copy]")
        published = re.search(
            r"async function loadPublishedReleases\(softwareId\) \{([\s\S]*?)\n  async function applyReleaseContext",
            source,
        )
        published_body = published.group(1) if published else ""
        if "page_size" not in published_body:
            errors.append(f"{label}: published-release loader must request page_size")
        if "has_next" not in published_body:
            errors.append(f"{label}: published-release loader must drain pagination")
    if "async function loadReleasesForSoftware" in source:
        listed = re.search(
            r"async function loadReleasesForSoftware\([\s\S]*?\) \{([\s\S]*?)\n  function catalogSoftwareForRelease",
            source,
        )
        listed_body = listed.group(1) if listed else ""
        if "++releaseListRequestGeneration" not in listed_body:
            errors.append(f"{label}: release list loader must increment releaseListRequestGeneration")
        if "generation !== releaseListRequestGeneration" not in listed_body:
            errors.append(f"{label}: release list loader must ignore stale software=all responses")
    if "function currentReclaimFilters" in source:
        reclaim = re.search(
            r"function currentReclaimFilters\(panel\) \{([\s\S]*?)\n  function currentFilteredReclaimRows",
            source,
        )
        reclaim_body = reclaim.group(1) if reclaim else ""
        if 'recordScope: "scope"' not in reclaim_body:
            errors.append(f"{label}: reclaim filters must send recordScope as scope")
    if "async function loadDownstreamSupport" in source:
        support = re.search(
            r"async function loadDownstreamSupport\(softwareId\) \{([\s\S]*?)\n  window.__previewLoadDownstreamSupport",
            source,
        )
        support_body = support.group(1) if support else ""
        if not support:
            errors.append(f"{label}: downstream support loader must be loadDownstreamSupport(softwareId)")
        if "supportLoadGeneration" not in support_body:
            errors.append(f"{label}: downstream support loader must increment a generation token")
        if "generation !== supportLoadGeneration" not in support_body:
            errors.append(f"{label}: downstream support loader must ignore stale software responses")
        if "supportLoadedSoftwareId" not in source:
            errors.append(f"{label}: downstream support save must post the loaded software, not the live select")
    invite_start = source.find("function renderInvitationRows")
    if invite_start >= 0:
        invite_body_start = source.find("{", source.find(") {", invite_start))
        invite_next = source.find("\n  const catalogSoftwareStatusCopy", invite_start)
        invite_body = source[invite_body_start:invite_next] if invite_next > invite_body_start else source[invite_start:invite_start + 2500]
        if re.search(
            r"appendTextCell\(\s*row,\s*item\.consumed_at\s*\?[^;\n]*(?:永久有效|item\.expires_at)",
            invite_body,
        ):
            errors.append(f"{label}: invitation unused used-time must not fall back to 永久有效 or expires_at")
    return errors


def check_no_static_fixtures(root: Path) -> list[str]:
    errors: list[str] = []
    for path in sorted(root.rglob("*")):
        if not path.is_file() or path.suffix.lower() not in SCAN_SUFFIXES:
            continue
        source = path.read_text(encoding="utf-8")
        errors.extend(scan_preview_source(source, path.relative_to(ROOT).as_posix()))
        if path.suffix.lower() == ".html" and path.name not in {
            "entry.html",
            "manage.html",
            "manage-login.html",
            "downstream.html",
            "downstream-login.html",
            "downstream-register.html",
            "404.html",
        }:
            errors.append(f"{path.relative_to(ROOT).as_posix()}: extra frozen html is not in the preview whitelist")
        if re.search(r"auto_login|bridge_", path.name, re.I):
            errors.append(f"{path.relative_to(ROOT).as_posix()}: capture/bridge preview pages are forbidden")
        if path.name == "manage.html":
            if re.search(r'id=["\']inviteNote["\']', source):
                errors.append(f"{path.relative_to(ROOT).as_posix()}: invitation issue form must not show a fake note field")
            if re.search(r'id=["\']quotaCardNote["\']', source):
                errors.append(f"{path.relative_to(ROOT).as_posix()}: quota issue form must not show a fake note field")
        if path.name == "preview.js":
            errors.extend(collection_loader_errors(source, path.relative_to(ROOT).as_posix()))
    return errors



def main() -> int:
    self_check()
    errors: list[str] = []
    errors.extend(check_no_static_fixtures(PREVIEW_ROOT))
    for name in STATIC_FILES:
        parser = parse((PREVIEW_ROOT / name).read_text(encoding="utf-8"))
        errors.extend(f"{PREVIEW_ROOT.joinpath(name).relative_to(ROOT)}:{message}" for message in parser.errors)
    for name, panels in EXPECTED_PANELS.items():
        errors.extend(check_file(PREVIEW_ROOT / name, panels, EXPECTED_PRIMARY_NAV[name]))
    if errors:
        print(f"UI preview structure failed with {len(errors)} error(s):")
        for error in errors:
            print(f"- {error}")
        return 1
    panel_total = sum(len(screens) for screens in EXPECTED_PANELS.values())
    primary_total = sum(len(screens) for screens in EXPECTED_PRIMARY_NAV.values())
    print(
        f"UI preview structure passed: {primary_total} primary navigation entries and "
        f"{panel_total} route screens are balanced inside .app-main"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
