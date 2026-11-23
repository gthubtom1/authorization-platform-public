const fixture = config.fixture;
const base = config.base.replace(/\/$/, "");
const flow = config.flow;

if (config.viewport) {
  await page.setViewportSize(config.viewport);
}

function fixturePassword() {
  const seed = `${fixture.downstream_a_public_id}${fixture.downstream_b_public_id}`.replace(/-/g, "");
  return `Browser-fixture-${seed.slice(0, 48)}-123`;
}

const acceptancePassword = fixturePassword();

function assert(condition, message) {
  if (!condition) {
    throw new Error(message);
  }
}

async function bodyText() {
  return page.locator("body").innerText();
}

async function open(url) {
  const response = await page.goto(url, { waitUntil: "domcontentloaded" });
  assert(response && response.status() < 500, `unexpected page status for ${url}`);
  return response;
}

async function login(username, password, role) {
  const loginPath = role === "admin" ? "/manage/login/" : "/downstream/login/";
  await open(`${base}${loginPath}`);
  await page.locator('input[name="username"]').fill(username);
  await page.locator('input[name="password"]').fill(password);
  await Promise.all([
    page.waitForURL(/\/manage\/|\/downstream\//),
    page.locator('button[type="submit"]').click(),
  ]);
}

async function adminFlow() {
  await login(config.admin_username, acceptancePassword, "admin");
  await open(`${base}/manage/authorizations/`);
  let text = await bodyText();
  assert(text.includes("授权风险控制"), "admin risk page did not render");

  // The legacy HTML write routes are intentionally retired (410). Exercise
  // the current CSRF-protected, idempotent management API instead.
  const cookies = await page.context().cookies();
  const csrf = cookies.find(cookie => cookie.name === "csrftoken");
  assert(csrf && csrf.value, "admin CSRF cookie was not issued");
  const apiHeaders = {
    "Content-Type": "application/json",
    "X-CSRFToken": csrf.value,
  };

  await open(`${base}/manage/authorizations/`);
  const listing = await page.context().request.get(`${base}/api/v1/manage/authorizations/?q=${fixture.authorization_id}`);
  assert(listing.status() === 200, `authorization API returned ${listing.status()}`);
  const listingPayload = await listing.json();
  const device = listingPayload.items[0].devices[0];
  const authorizationId = listingPayload.items[0].authorization_id;
  assert(device && device.device_action_ref, "device action reference was not returned");
  const blockResponse = await page.context().request.post(
    `${base}/api/v1/manage/authorizations/${authorizationId}/devices/${device.device_action_ref}/block/`,
    { headers: { ...apiHeaders, "Idempotency-Key": `browser-block-${fixture.device_id}` }, data: { reason: "browser device block acceptance" } },
  );
  assert(blockResponse.status() === 200, `block API returned ${blockResponse.status()}`);
  await open(`${base}/manage/authorizations/`);
  text = await bodyText();
  assert(text.includes("blocked"), "blocked device state was not rendered");

  await open(`${base}/manage/authorizations/`);
  const unblockResponse = await page.context().request.post(
    `${base}/api/v1/manage/authorizations/${authorizationId}/devices/${device.device_action_ref}/unblock/`,
    { headers: { ...apiHeaders, "Idempotency-Key": `browser-unblock-${fixture.device_id}` }, data: { reason: "browser device unblock acceptance" } },
  );
  assert(unblockResponse.status() === 200, `unblock API returned ${unblockResponse.status()}`);
  await open(`${base}/manage/authorizations/`);
  text = await bodyText();
  assert(text.includes("normal"), "unblocked device state was not rendered");
  assert(text.includes("历史绑定"), "device history summary disappeared after unblock");
  if (config.risk_screenshot) {
    await page.screenshot({ path: config.risk_screenshot, fullPage: true });
  }

  const revokeResponse = await page.context().request.post(
    `${base}/api/v1/manage/authorizations/${fixture.authorization_id}/revoke/`,
    { headers: { ...apiHeaders, "Idempotency-Key": `browser-revoke-${fixture.authorization_id}` }, data: { reason: "browser revoke acceptance" } },
  );
  assert(revokeResponse.status() === 200, `revoke API returned ${revokeResponse.status()}`);
  await open(`${base}/manage/authorizations/`);
  text = await bodyText();
  assert(text.includes("revoked"), "revoked authorization state was not rendered");

  await open(`${base}/manage/audit/?action=browser.acceptance&page=2`);
  text = await bodyText();
  assert(text.includes("第 2 / 21 页"), "audit pagination did not expose the expected second page");
  assert(await page.locator("table.data-table tbody tr").count() === 50, "audit page did not contain 50 rows");

  const exportResponse = await page.context().request.get(`${base}/manage/audit/export/?action=browser.acceptance`);
  assert(exportResponse.status() === 200, "audit export did not return 200");
  assert((exportResponse.headers()["cache-control"] || "").includes("no-store"), "audit export is missing no-store");
  const csv = await exportResponse.text();
  const lines = csv.replace(/^\uFEFF/, "").split(/\r?\n/).filter(Boolean);
  assert(lines.length === 1001, `audit export returned ${lines.length - 1} rows instead of 1000`);
  assert(csv.includes("'=browser-formula"), "audit export did not neutralize a formula-like value");
  assert(!csv.includes("browser-secret"), "audit export leaked sensitive metadata");
  if (config.audit_screenshot) {
    await page.screenshot({ path: config.audit_screenshot, fullPage: true });
  }
}

async function downstreamFlow(username, expectedId, hiddenId, label) {
  await login(username, acceptancePassword, "downstream");
  await open(`${base}/downstream/audit/?action=browser.scope`);
  let text = await bodyText();
  assert(text.includes(expectedId), `${label} audit page did not show its own scoped event`);
  assert(!text.includes(hiddenId), `${label} audit page showed another downstream event`);
  if (config.scope_screenshot) {
    await page.screenshot({ path: config.scope_screenshot, fullPage: true });
  }

  await open(`${base}/downstream/audit/?action=browser.scope&object_public_id=${hiddenId}`);
  text = await bodyText();
  assert(text.includes("当前范围没有符合条件的审计记录"), `${label} forged object filter returned a record`);

  const forbidden = await open(`${base}/manage/authorizations/`);
  assert(forbidden.status() === 403, `${label} could access the admin risk page`);
  text = await bodyText();
  assert(text.includes("当前账号没有访问权限"), `${label} did not receive the designed permission page`);
  if (config.forbidden_screenshot) {
    await page.screenshot({ path: config.forbidden_screenshot, fullPage: true });
  }
}

if (!base || !fixture.authorization_id || !fixture.device_id || !fixture.downstream_a_public_id || !fixture.downstream_b_public_id) {
  throw new Error("browser acceptance environment is incomplete");
}

if (flow === "admin") {
  await adminFlow();
} else if (flow === "downstream-a") {
  await downstreamFlow(
    config.downstream_a_username,
    fixture.downstream_a_public_id,
    fixture.downstream_b_public_id,
    "downstream A",
  );
} else if (flow === "downstream-b") {
  await downstreamFlow(
    config.downstream_b_username,
    fixture.downstream_b_public_id,
    fixture.downstream_a_public_id,
    "downstream B",
  );
} else {
  throw new Error(`unknown browser acceptance flow: ${flow}`);
}
return `browser acceptance passed: ${flow}`;
