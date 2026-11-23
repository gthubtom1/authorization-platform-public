(async () => {
const base = config.base.replace(/\/$/, "");
const fixture = config.fixture;

function assert(condition, message) {
  if (!condition) throw new Error(message);
}

function acceptancePassword() {
  const seed = `${fixture.downstream_a_public_id}${fixture.downstream_b_public_id}`.replace(/-/g, "");
  return `Browser-fixture-${seed.slice(0, 48)}-123`;
}

async function open(path) {
  const response = await page.goto(`${base}${path}`, { waitUntil: "domcontentloaded" });
  assert(response, `page navigation produced no HTTP response: ${path} final=${page.url()}`);
  const status = response.status();
  assert(status === 200, `page failed: ${path} status=${status} final=${page.url()}`);
  assert(!page.url().includes(":8143"), `forbidden 8143 entry reached: ${page.url()}`);
  return response;
}

async function login(username, destination) {
  const path = destination === "manage.html" ? "/manage-login.html" : "/downstream-login.html";
  await open(path);
  await page.locator('input[name="username"]').fill(username);
  await page.locator('input[name="password"]').fill(acceptancePassword());
  await Promise.all([
    page.waitForURL((url) => url.pathname.endsWith(`/${destination}`)),
    page.locator('button[type="submit"]').click(),
  ]);
  const session = await page.evaluate(async () => {
    const response = await fetch("/api/v1/session/", { credentials: "same-origin" });
    return { status: response.status, payload: await response.json() };
  });
  assert(session.status === 200 && session.payload.authenticated, `login session was not retained: ${JSON.stringify(session)}`);
  const expectedRole = destination === "manage.html" ? "platform_admin" : "downstream";
  assert(session.payload.role === expectedRole, `login role mismatch for ${destination}: ${JSON.stringify(session)}`);
}

async function logout() {
  const button = page.locator('.header-actions .text-button').filter({ hasText: "退出" });
  if (await button.count()) {
    await button.click();
    await page.waitForURL((url) => url.pathname.endsWith("-login.html"));
  }
}

async function waitForToast(fragment) {
  const toast = page.locator(".toast");
  await toast.waitFor({ state: "visible", timeout: 15000 });
  await page.waitForFunction(
    (value) => document.querySelector(".toast")?.textContent.includes(value),
    fragment,
    { timeout: 15000 },
  );
  return toast.innerText();
}

function parseMetricNumber(text) {
  return Number(String(text || "").trim().replace(/,/g, ""));
}

async function fetchJson(path, options = {}) {
  return page.evaluate(async ({ path, options }) => {
    const response = await fetch(path, { credentials: "same-origin", ...options });
    let payload = {};
    try {
      payload = await response.json();
    } catch {
      payload = {};
    }
    return { status: response.status, payload };
  }, { path, options });
}

async function csrfToken() {
  return page.evaluate(() => {
    const raw = document.cookie.split(";").map((part) => part.trim()).find((part) => part.startsWith("csrftoken="));
    return raw ? decodeURIComponent(raw.slice("csrftoken=".length)) : "";
  });
}

async function releaseItems() {
  const result = await fetchJson(`/api/v1/manage/releases/?software_id=${encodeURIComponent(fixture.software_id)}`);
  assert(result.status === 200, `release list failed: ${JSON.stringify(result)}`);
  return result.payload.items || [];
}

async function closeReleaseDialog() {
  const dialog = page.locator("#releaseDialog");
  if (await dialog.isVisible()) {
    const close = dialog.locator("button[value='cancel']:visible").last();
    if (await close.count()) await close.click();
    await dialog.waitFor({ state: "hidden", timeout: 15000 });
  }
}

async function uploadAndPublish(packagePath, expectedVersion, label) {
  const releaseScreen = page.locator('[data-screen-panel="releases"]');
  await releaseScreen.locator('[data-dialog="releaseDialog"]').first().click();
  const dialog = page.locator("#releaseDialog");
  await dialog.waitFor({ state: "visible" });
  await page.locator("#releaseSoftware").selectOption(fixture.software_id);
  await page.locator("#releaseChannel").selectOption("stable");
  await page.locator("#releasePackage").setInputFiles(packagePath);
  const next = dialog.locator("[data-release-next]");
  await page.waitForFunction(() => !document.querySelector("[data-release-next]")?.disabled, null, { timeout: 15000 });
  await next.click();
  await dialog.locator('[data-release-stage="verify"]').waitFor({ state: "visible", timeout: 15000 });
  assert((await dialog.locator("[data-release-target]").innerText()).includes("stable"), `${label} verify stage missing channel`);
  await dialog.locator("#releaseNotes").fill(`${label} 真实 8123 发布验收`);
  await dialog.locator("[data-release-confirm]").click();
  await dialog.locator('[data-release-stage="result"]').waitFor({ state: "visible", timeout: 15000 });
  assert((await dialog.locator("[data-release-result-version]").innerText()).includes(expectedVersion), `${label} publish result missing version`);
  await closeReleaseDialog();
  const items = await releaseItems();
  const item = items.find((candidate) => candidate.version === expectedVersion);
  assert(item && item.status === "published", `${label} did not persist published release: ${JSON.stringify(items)}`);
  assert(item.package_available === true, `${label} package is not available after publish`);
  return item;
}

async function releaseFlow() {
  await open("/manage.html#releases");
  const releaseSoftware = page.locator("#releaseSoftware");
  await page.waitForFunction(
    (softwareId) => [...document.querySelectorAll("#releaseSoftware option")].some((option) => option.value === softwareId),
    fixture.software_id,
    { timeout: 15000 },
  );
  assert((await releaseSoftware.locator(`option[value="${fixture.software_id}"]`).count()) === 1, "release software options were not loaded from the real catalog");

  const dialog = page.locator("#releaseDialog");
  await page.locator('[data-screen-panel="releases"] [data-dialog="releaseDialog"]').first().click();
  await dialog.waitFor({ state: "visible" });
  await page.locator("#releaseSoftware").selectOption(fixture.software_id);
  await page.locator("#releaseChannel").selectOption("stable");
  await page.locator("#releasePackage").setInputFiles(config.bad_package);
  await page.waitForFunction(() => !document.querySelector("[data-release-next]")?.disabled, null, { timeout: 15000 });
  await dialog.locator("[data-release-next]").click();
  await page.waitForFunction(() => Boolean(document.querySelector("[data-release-error]")?.textContent.trim()), null, { timeout: 15000 });
  assert((await dialog.locator("[data-release-error]").innerText()).includes("Manifest"), "invalid release package did not show a manifest error");
  await closeReleaseDialog();

  const first = await uploadAndPublish(config.package_one, "1.0.0", "首个版本");
  const second = await uploadAndPublish(config.package_two, "1.1.0", "回退版本");
  await page.waitForFunction(
    () => document.querySelector('[data-screen-panel="releases"] .table-panel[data-server-paginated]')?.dataset.serverDataLoaded === "true",
    null,
    { timeout: 15000 },
  );
  const latestRow = page.locator(`[data-release-table] tr[data-release-id="${second.release_id}"]`);
  await latestRow.waitFor({ state: "visible", timeout: 15000 });
  await latestRow.locator("[data-dialog='withdrawReleaseDialog']").click();
  const withdrawDialog = page.locator("#withdrawReleaseDialog");
  await withdrawDialog.waitFor({ state: "visible" });
  await withdrawDialog.locator("textarea[name='reason']").fill("真实 8123 回退验收");
  await withdrawDialog.locator("[data-withdraw-confirm]").click();
  await withdrawDialog.waitFor({ state: "hidden", timeout: 15000 });
  await page.waitForFunction(
    (releaseId) => {
      const row = document.querySelector(`[data-release-table] tr[data-release-id="${releaseId}"]`);
      return Boolean(row) && !row.hidden && (row.textContent || "").includes("已撤回");
    },
    second.release_id,
    { timeout: 15000 },
  );
  const afterWithdraw = (await releaseItems()).find((candidate) => candidate.release_id === second.release_id);
  assert(afterWithdraw?.status === "withdrawn", `release withdrawal did not persist: ${JSON.stringify(afterWithdraw)}`);
  const registry = await fetchJson(`/api/v1/public/software/${fixture.software_id}/profiles/stable/releases/?client_id=${encodeURIComponent(fixture.client_id)}&target=windows&arch=x64&channel=stable&version=1.1.0`);
  assert(registry.status === 200 && registry.payload.release?.version === first.version, `public registry did not fall back after withdrawal: ${JSON.stringify(registry)}`);
  assert(registry.payload.has_update === false, `registry incorrectly reported an update after fallback: ${JSON.stringify(registry.payload)}`);
  const download = await page.evaluate(async (path) => {
    const response = await fetch(path, { credentials: "same-origin" });
    return { status: response.status, contentType: response.headers.get("content-type"), size: Number(response.headers.get("content-length") || 0) };
  }, registry.payload.release.download_url);
  // Local default may allow anonymous 200. That is not production download-auth
  // proof; Django tests.test_releases cover protected cards and cross-software 403.
  assert(
    download.status === 200 || download.status === 403,
    `public release download neither succeeded locally nor required a license key: ${JSON.stringify(download)}`,
  );
  if (download.status === 200) {
    assert(download.contentType === "application/zip", `unprotected local download was not a zip: ${JSON.stringify(download)}`);
  }
  return { first, second };
}

async function analyticsAdminFlow() {
  await open("/manage.html#analytics");
  const screen = page.locator('[data-screen-panel="analytics"]');
  const software = screen.locator('[name="analytics_software"]');
  const downstream = screen.locator('[name="analytics_downstream"]');
  const windowSelect = screen.locator('[name="analytics_window"]');
  await software.selectOption("all");
  await downstream.selectOption("all");
  await windowSelect.selectOption("7d");
  await screen.locator("[data-analytics-apply]").click();
  await page.waitForFunction(() => !document.querySelector('[data-screen-panel="analytics"]')?.hasAttribute("aria-busy"), null, { timeout: 15000 });
  await screen.locator("[data-analytics-content]").waitFor({ state: "visible", timeout: 15000 });
  const all = await fetchJson(`/api/v1/manage/analytics/summary/?software_id=all&downstream_id=all&window=7d`);
  assert(all.status === 200 && all.payload.has_data, `admin analytics all-scope failed: ${JSON.stringify(all)}`);
  assert(all.payload.timezone === "Asia/Shanghai", `analytics timezone is not Beijing: ${JSON.stringify(all.payload)}`);
  assert(
    parseMetricNumber(await screen.locator('[data-analytics-metric="active"]').innerText()) === Number(all.payload.active_authorizations),
    "analytics active metric is not from API",
  );
  const softwareOption = await software.locator(`option[value="${fixture.software_id}"]`).count();
  const downstreamOption = await downstream.locator(`option[value="${fixture.downstream_a_public_id}"]`).count();
  assert(softwareOption === 1 && downstreamOption === 1, "analytics filters were not replaced by real server options");
  await software.selectOption(fixture.software_id);
  await downstream.selectOption(fixture.downstream_a_public_id);
  await screen.locator("[data-analytics-apply]").click();
  await page.waitForFunction(
    ({ softwareId, downstreamId }) => document.querySelector('[data-screen-panel="analytics"] [data-analytics-scope]')?.textContent.includes(softwareId) || document.querySelector('[data-screen-panel="analytics"] [data-analytics-scope]')?.textContent.includes("Browser Acceptance Software"),
    { softwareId: fixture.software_id, downstreamId: fixture.downstream_a_public_id },
    { timeout: 15000 },
  );
  const scoped = await fetchJson(`/api/v1/manage/analytics/summary/?software_id=${encodeURIComponent(fixture.software_id)}&downstream_id=${encodeURIComponent(fixture.downstream_a_public_id)}&window=7d`);
  assert(scoped.status === 200 && scoped.payload.has_data, `admin analytics scoped query failed: ${JSON.stringify(scoped)}`);
  const overviewCredits = await page.locator('[data-overview-metric="credits"]').innerText();
  await windowSelect.selectOption("empty");
  await screen.locator("[data-analytics-apply]").click();
  await page.waitForFunction(() => !document.querySelector('[data-screen-panel="analytics"]')?.hasAttribute("aria-busy"), null, { timeout: 15000 });
  await screen.locator("[data-analytics-empty]").waitFor({ state: "visible", timeout: 15000 });
  assert(await screen.locator("[data-analytics-content]").isVisible(), "empty analytics window hid snapshot content");
  const emptySummary = await fetchJson(
    `/api/v1/manage/analytics/summary/?software_id=${encodeURIComponent(fixture.software_id)}&downstream_id=${encodeURIComponent(fixture.downstream_a_public_id)}&window=empty`,
  );
  assert(emptySummary.status === 200 && emptySummary.payload.has_data === false, `admin analytics empty window failed: ${JSON.stringify(emptySummary)}`);
  assert(
    parseMetricNumber(await screen.locator('[data-analytics-metric="active"]').innerText()) === Number(emptySummary.payload.active_authorizations),
    "empty analytics window hid or left stale active authorizations",
  );
  assert(await screen.locator('[data-export-query="analytics"]').isVisible(), "empty analytics window hid calendar export");
  assert(
    (await page.locator('[data-overview-metric="credits"]').innerText()) === overviewCredits,
    "empty analytics window rewrote overview quota consumption",
  );
}

async function downstreamAnalyticsFlow() {
  await logout();
  await login(fixture.downstream_a_username, "downstream.html");
  await open("/downstream.html#workspace");
  const workspace = page.locator('[data-screen-panel="workspace"]');
  const metrics = await fetchJson("/api/v1/downstream/analytics/summary/?software_id=all&window=7d");
  assert(metrics.status === 200 && metrics.payload.has_data, `downstream analytics failed: ${JSON.stringify(metrics)}`);
  await page.waitForFunction(
    (expected) => {
      const text = document.querySelector('[data-downstream-metric="active"]')?.textContent.trim().replace(/,/g, "");
      return Number(text) === expected;
    },
    metrics.payload.downstream.active,
    { timeout: 15000 },
  );
  assert(metrics.payload.downstream && metrics.payload.downstream.active === parseMetricNumber(await workspace.locator('[data-downstream-metric="active"]').innerText()), "downstream metric is not from server scope");
  const forged = await fetchJson("/api/v1/downstream/analytics/summary/?software_id=not-owned&window=7d");
  assert(forged.status === 403 && forged.payload.error?.code === "SOFTWARE_NOT_ALLOWED", `downstream analytics scope was forgeable: ${JSON.stringify(forged)}`);
  const disclosure = workspace.locator("[data-downstream-metrics-disclosure]");
  if (!(await disclosure.getAttribute("open"))) await disclosure.locator("summary").click();
  await workspace.locator('[name="downstream_metrics_window"]').selectOption("empty");
  await workspace.locator("[data-downstream-metrics-apply]").click();
  await workspace.locator("[data-downstream-metrics-empty]").waitFor({ state: "visible", timeout: 15000 });
  assert(await workspace.locator(".downstream-signals").isVisible(), "downstream empty window hid snapshot metrics");
  const emptyMetrics = await fetchJson("/api/v1/downstream/analytics/summary/?software_id=all&window=empty");
  assert(emptyMetrics.status === 200 && emptyMetrics.payload.has_data === false, `downstream empty window failed: ${JSON.stringify(emptyMetrics)}`);
  assert(
    parseMetricNumber(await workspace.locator('[data-downstream-metric="balance"]').innerText()) === Number(emptyMetrics.payload.downstream.balance),
    "downstream empty window hid or left stale balance",
  );
}

async function storageCleanupFlow(releases) {
  await logout();
  await login(fixture.admin_username, "manage.html");
  await open("/manage.html#backup");
  const panel = page.locator('[data-screen-panel="backup"] .panel').filter({ hasText: "存储清理" }).first();
  const scan = panel.locator("button").nth(0);
  const execute = panel.locator("button").nth(1);
  await scan.click();
  const scanToast = await waitForToast("已扫描");
  assert(scanToast.includes("2 个"), `storage scan did not expose the expected release/temp candidates: ${scanToast}`);
  const before = await fetchJson("/api/v1/manage/storage/cleanup/");
  assert(before.status === 200 && before.payload.candidate_count === 2, `storage scan API mismatch: ${JSON.stringify(before)}`);
  await execute.click();
  await page.locator("[data-storage-cleanup-confirm]").click();
  const executeToast = await waitForToast("已清理");
  assert(executeToast.includes("2 个"), `storage cleanup UI did not report both candidates: ${executeToast}`);
  const after = await fetchJson("/api/v1/manage/storage/cleanup/");
  assert(after.status === 200 && after.payload.candidate_count === 0, `storage cleanup left candidates: ${JSON.stringify(after)}`);
  const csrf = await csrfToken();
  const first = await fetchJson("/api/v1/manage/storage/cleanup/", {
    method: "POST",
    headers: { "Content-Type": "application/json", "X-CSRFToken": csrf, "Idempotency-Key": "platform-8123-cleanup-replay" },
    body: "{}",
  });
  const replay = await fetchJson("/api/v1/manage/storage/cleanup/", {
    method: "POST",
    headers: { "Content-Type": "application/json", "X-CSRFToken": csrf, "Idempotency-Key": "platform-8123-cleanup-replay" },
    body: "{}",
  });
  assert(first.status === 200 && replay.status === 200 && replay.payload.repeated === true, `storage cleanup idempotency failed: ${JSON.stringify({ first, replay })}`);
  const withdrawn = (await releaseItems()).find((item) => item.release_id === releases.second.release_id);
  assert(withdrawn?.status === "withdrawn" && withdrawn.package_available === false, `cleanup did not clear withdrawn package metadata: ${JSON.stringify(withdrawn)}`);
  await logout();
  await login(fixture.downstream_a_username, "downstream.html");
  const denied = await fetchJson("/api/v1/manage/storage/cleanup/");
  assert(denied.status === 403 && denied.payload.error?.code === "FORBIDDEN", `downstream could access storage cleanup: ${JSON.stringify(denied)}`);
}

await login(fixture.admin_username, "manage.html");
const releases = await releaseFlow();
await analyticsAdminFlow();
await downstreamAnalyticsFlow();
await storageCleanupFlow(releases);
return "F-018/F-019/F-020 frozen 8123 acceptance passed";
})();
