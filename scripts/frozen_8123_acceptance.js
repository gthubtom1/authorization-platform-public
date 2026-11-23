const base = config.base.replace(/\/$/, "");
const fixture = config.fixture;
const newSoftwareId = "b22-browser-catalog";
const newSoftwareName = "B2.2 Browser Catalog";

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
}

async function waitForCatalogRow(softwareId) {
  const row = page.locator(`tr[data-catalog-software-id="${softwareId}"]`);
  await row.waitFor({ state: "visible", timeout: 15000 });
  return row;
}

async function adminFlow() {
  await login(fixture.admin_username, "manage.html");
  await open("/manage.html#software");
  await waitForCatalogRow(fixture.software_id);

  await page.locator('[data-dialog="softwareDialog"][data-software-mode="create"]').first().click();
  await page.locator("#softwareName").fill(newSoftwareName);
  await page.locator("#softwareCode").fill(newSoftwareId);
  await page.locator("#softwarePlatform").selectOption("windows");
  await page.locator("#softwareDialog [data-software-advanced] summary").click();
  await page.locator("#softwareProfile").fill("stable");
  await page.locator("#softwarePolicy").selectOption("generic-online-v1");
  await page.locator("#softwareMaxDevices").fill("1");
  await page.locator("#softwareVerifyInterval").fill("15");
  await page.locator("#softwareOfflineGrace").fill("0");
  await page.locator("#softwarePlanName").fill("一分钟测试卡");
  await page.locator("#softwarePlanDuration").fill("1");
  await page.locator("#softwarePlanDurationUnit").selectOption("minute");
  await page.locator("#softwarePlanCost").fill("7");
  await page.locator("#softwareDialog [data-software-save]").click();
  const softwareResult = page.locator('#softwareDialog [data-software-stage="result"]');
  await softwareResult.waitFor({ state: "visible" });
  assert((await softwareResult.innerText()).includes(newSoftwareName), "software create result missing");
  await softwareResult.locator('button[value="cancel"]').click();
  await waitForCatalogRow(newSoftwareId);

  const originalPolicyRow = await waitForCatalogRow(fixture.software_id);
  await originalPolicyRow.locator('[data-dialog="policyDialog"]').first().click();
  const policyDialog = page.locator("#policyDialog");
  await policyDialog.waitFor({ state: "visible" });
  await policyDialog.locator("#policyMaxDevices").fill("3");
  await policyDialog.locator("#policyVerifyInterval").fill("45");
  await policyDialog.locator("#policyOfflineGrace").fill("2");
  await policyDialog.locator("#policyAllowSwitch").check();
  await policyDialog.locator("#policySwitchLimit").fill("2");
  await policyDialog.getByRole("button", { name: "保存授权参数" }).click();
  await policyDialog.waitFor({ state: "hidden", timeout: 15000 });
  await open("/manage.html#software");
  const refreshedPolicyRow = await waitForCatalogRow(fixture.software_id);
  const policyCatalog = await page.evaluate(async () => {
    const response = await fetch("/api/v1/manage/catalog/", { credentials: "same-origin" });
    return { status: response.status, payload: await response.json() };
  });
  const policyProfile = policyCatalog.payload.items.find((item) => item.software_id === fixture.software_id).profiles[0];
  const activePolicy = policyProfile.policies.find((item) => item.status === "active");
  const archivedPolicy = policyProfile.policies.find((item) => item.status === "archived");
  assert(policyCatalog.status === 200 && activePolicy?.max_devices === 3 && activePolicy?.verify_interval_seconds === 45 * 60 && activePolicy?.offline_grace_seconds === 2 * 3600 && activePolicy?.allow_device_switch === true && activePolicy?.device_switch_limit === 2, `policy revision did not persist: ${JSON.stringify(policyProfile.policies)}`);
  assert(archivedPolicy?.max_devices === 2, `policy revision overwrote the historical policy: ${JSON.stringify(policyProfile.policies)}`);
  assert((await refreshedPolicyRow.innerText()).includes("3 台设备"), "policy revision did not refresh the software registry summary");

  const originalPlanRow = await waitForCatalogRow(fixture.software_id);
  await originalPlanRow.locator('[data-dialog="planManagerDialog"]').first().click();
  const planManager = page.locator("#planManagerDialog");
  await planManager.waitFor({ state: "visible" });
  await planManager.getByRole("button", { name: "修改" }).first().click();
  const planDialog = page.locator("#planDialog");
  await planDialog.waitFor({ state: "visible" });
  assert(await planManager.isVisible(), "opening the plan editor closed the plan manager");
  await page.locator("#planDuration").press("Enter");
  assert(await planDialog.isVisible(), "Enter in plan duration closed the plan dialog");
  assert(await planManager.isVisible(), "Enter in the plan editor closed the plan manager");
  await page.locator("#planQuotaCost").fill("11");
  await page.locator('#planDialog [data-plan-save]').click();
  const planResult = page.locator('#planDialog [data-plan-stage="result"]');
  try {
    await planResult.waitFor({ state: "visible", timeout: 15000 });
  } catch {
    throw new Error(`plan revision failed: ${await page.locator("#planDialog [data-plan-error]").innerText()}`);
  }
  assert((await planResult.innerText()).includes("11"), "plan revision result missing updated cost");
  await planResult.locator('button[value="cancel"]').click();
  assert(await planManager.isVisible(), "closing the plan editor dismissed the plan manager");

  await open("/manage.html#downstreams");
  const downstreamB = page.locator(`tr[data-public-id="${fixture.downstream_b_public_id}"]`);
  await downstreamB.waitFor({ state: "visible", timeout: 15000 });
  await downstreamB.locator("[data-catalog-scope]").click();
  const scopeDialog = page.locator("#catalogScopeDialog");
  await scopeDialog.waitFor({ state: "visible" });
  const newScope = scopeDialog.locator(`input[data-scope-software="${newSoftwareId}"]`);
  await newScope.check();
  await scopeDialog.locator("[data-catalog-scope-save]").click();
  try {
    await scopeDialog.waitFor({ state: "hidden", timeout: 10000 });
  } catch {
    const error = await scopeDialog.locator("[data-catalog-scope-error]").innerText();
    throw new Error(`scope save did not complete: ${error || "unknown API error"}`);
  }
  await downstreamB.waitFor({ state: "visible" });
  await page.waitForFunction(
    ({ publicId, softwareName }) => {
      const row = [...document.querySelectorAll("tr[data-public-id]")].find(
        (item) => item.dataset.publicId === publicId,
      );
      return Boolean(row && row.innerText.includes(softwareName));
    },
    { publicId: fixture.downstream_b_public_id, softwareName: newSoftwareName },
    { timeout: 15000 },
  );
  const refreshedScopeText = await downstreamB.innerText();
  const refreshedCatalog = await page.evaluate(async () => {
    const response = await fetch("/api/v1/manage/catalog/", { credentials: "same-origin" });
    return { status: response.status, payload: await response.json() };
  });
  assert(
    refreshedScopeText.includes(newSoftwareName),
    `scope result did not refresh from API: row=${JSON.stringify(refreshedScopeText)} catalog=${JSON.stringify(refreshedCatalog)}`,
  );

  await page.screenshot({ path: `${config.artifact_dir}/admin-b22.png`, fullPage: true });
  await page.locator('.header-actions .text-button').filter({ hasText: "退出" }).click();
  await page.waitForURL((url) => url.pathname.endsWith("/manage-login.html"));
}

async function downstreamFlow(username, expectedName, hiddenName, label) {
  await login(username, "downstream.html");
  await open("/downstream.html#software");
  const catalog = page.locator("[data-plan-catalog]");
  await catalog.locator('article[data-plan-source="api"]').first().waitFor({ state: "visible", timeout: 15000 });
  const visibleText = await catalog.innerText();
  assert(visibleText.includes(expectedName), `${label} did not receive its own catalog`);
  assert(!visibleText.includes(hiddenName), `${label} received another downstream's catalog`);

  const apiResult = await page.evaluate(async () => {
    const response = await fetch("/api/v1/downstream/catalog/", { credentials: "same-origin" });
    return { status: response.status, payload: await response.json() };
  });
  assert(apiResult.status === 200, `${label} catalog API did not return 200`);
  assert(Array.isArray(apiResult.payload.items), `${label} catalog API did not return items`);

  await page.reload({ waitUntil: "domcontentloaded" });
  await catalog.locator('article[data-plan-source="api"]').first().waitFor({ state: "visible", timeout: 15000 });
  const refreshedText = await catalog.innerText();
  assert(refreshedText.includes(expectedName), `${label} catalog disappeared after refresh`);
  assert(!refreshedText.includes(hiddenName), `${label} catalog isolation disappeared after refresh`);
  await page.screenshot({ path: `${config.artifact_dir}/${label}-b22.png`, fullPage: true });
}

async function b4Flow() {
  await login(fixture.downstream_a_username, "downstream.html");
  await open("/downstream.html#licenses");
  await page.waitForFunction(
    () => document.querySelector("[data-downstream-recent-cards]")?.dataset.liveDataLoaded === "true",
    null,
    { timeout: 15000 },
  );
  const recentCardsText = await page.locator("[data-downstream-recent-cards]").innerText();
  assert(
    !["LIC-••••-7H2K", "LIC-••••-4M9Q", "LIC-••••-8A3N"].some((marker) => recentCardsText.includes(marker)),
    `B4 downstream dashboard retained static recent cards: ${recentCardsText}`,
  );
  assert(
    await page.locator('[data-downstream-recent-cards] .batch-row').count() === 0 ||
      await page.locator('[data-downstream-recent-cards]').innerText().then((text) => !text.includes("当前还没有授权卡密。")),
    "B4 downstream dashboard recent-card state is inconsistent",
  );
  assert(
    await page.locator('[data-record-view-scope="downstream-licenses"] [data-record-view="batches"], [data-record-view-scope="downstream-licenses"] [data-record-panel="batches"]').count() === 0,
    "B4 downstream still exposes a batch view",
  );
  const issueDialog = page.locator("#issueDialog");
  await page.locator('[data-screen-panel="licenses"] [data-dialog="issueDialog"]').click();
  await issueDialog.waitFor({ state: "visible" });
  await page.locator("#issueSoftware").selectOption(fixture.software_id);
  await page.locator("#issueQuantity").fill("12");
  const issueSubmit = page.locator("#issueSubmit");
  await issueSubmit.waitFor({ state: "visible", timeout: 15000 });
  await page.waitForFunction(() => !document.querySelector("#issueSubmit")?.disabled);
  await issueSubmit.click();
  await issueDialog.locator('[data-issue-result]').waitFor({ state: "visible", timeout: 15000 });
  const deliveredCodes = await issueDialog.locator("[data-issue-codes] code").allTextContents();
  const deliveredCodeSet = await issueDialog.evaluate((dialog) => JSON.parse(dialog.dataset.generatedCodes || "[]"));
  assert(deliveredCodes.length === 3 && deliveredCodes.every((code) => code.startsWith("LC-")) && deliveredCodeSet.length === 12 && deliveredCodeSet.every((code) => code.startsWith("LC-")), `B4 issue delivery invalid: ${JSON.stringify({ visible: deliveredCodes, delivered: deliveredCodeSet.length })}`);
  await issueDialog.locator("[data-issue-view-batch]").click();

  const downstreamRows = page.locator('[data-record-view-scope="downstream-licenses"] [data-record-panel="items"] tbody tr[data-public-id]');
  await page.waitForFunction(() => [...document.querySelectorAll('[data-record-view-scope="downstream-licenses"] [data-record-panel="items"] tbody tr[data-public-id]')].some((row) => !row.hidden), null, { timeout: 15000 });
  const pageOneIssuedIds = await downstreamRows.evaluateAll((rows) => rows
    .filter((row) => !row.hidden && row.querySelector("[data-reclaim-select]"))
    .map((row) => row.dataset.publicId));
  assert(pageOneIssuedIds.length > 0 && pageOneIssuedIds.every(Boolean), "B4 downstream list did not show issued cards on page one");
  const pageOneRows = await downstreamRows.evaluateAll((rows) => rows.filter((row) => !row.hidden).map((row) => ({
    id: row.dataset.publicId,
    batch: row.dataset.recordBatch || "",
    full: row.dataset.fullCode || "",
    checkbox: Boolean(row.querySelector("[data-reclaim-select]")),
  })));
  assert(pageOneRows.every((row) => !row.batch && !row.full), `B4 downstream list exposed batch/plaintext: ${JSON.stringify(pageOneRows)}`);

  const deviceFilter = page.locator('[data-record-view-scope="downstream-licenses"] [data-credential-filter="codeDeviceState"]');
  const filterResponse = page.waitForResponse((response) => response.request().method() === "GET" && response.url().includes("/api/v1/downstream/licenses/cards/") && response.url().includes("device_state=unbound"), { timeout: 15000 });
  await deviceFilter.selectOption("未绑定");
  await filterResponse;
  const licensePagination = page.locator('[data-record-view-scope="downstream-licenses"] [data-license-server-pagination]');
  await licensePagination.waitFor({ state: "visible", timeout: 15000 });
  const cardPaginationLayout = await page.locator('[data-record-view-scope="downstream-licenses"] [data-record-panel="items"]').evaluate((panel) => {
    const table = panel.querySelector("table").getBoundingClientRect();
    const controls = panel.querySelector("[data-license-server-pagination]").getBoundingClientRect();
    const panelRect = panel.getBoundingClientRect();
    return { controlsBelowTable: controls.top >= table.bottom - 1, controlsRightAligned: controls.right >= panelRect.right - 24 };
  });
  assert(cardPaginationLayout.controlsBelowTable && cardPaginationLayout.controlsRightAligned, `B4 card pagination is not bottom-right: ${JSON.stringify(cardPaginationLayout)}`);
  const filteredPageOneIds = await downstreamRows.evaluateAll((rows) => rows.filter((row) => !row.hidden && row.querySelector("[data-reclaim-select]")).map((row) => row.dataset.publicId));
  assert(filteredPageOneIds.length === 10, `B4 server-side device filter did not fill page one: ${JSON.stringify(filteredPageOneIds)}`);
  assert((await licensePagination.locator("[data-license-server-page]").innerText()) === "第 1 页", "B4 filtered card pagination did not reset to page one");
  const nextPageResponse = page.waitForResponse((response) => response.request().method() === "GET" && response.url().includes("/api/v1/downstream/licenses/cards/") && response.url().includes("device_state=unbound") && response.url().includes("page=2"), { timeout: 15000 });
  await licensePagination.locator("[data-license-server-next]").click();
  await nextPageResponse;
  await page.waitForFunction(() => document.querySelector('[data-record-view-scope="downstream-licenses"] [data-license-server-page]')?.textContent === "第 2 页", null, { timeout: 15000 });
  const filteredPageTwoIds = await downstreamRows.evaluateAll((rows) => rows.filter((row) => !row.hidden && row.querySelector("[data-reclaim-select]")).map((row) => row.dataset.publicId));
  assert(filteredPageTwoIds.length === 2 && new Set([...filteredPageOneIds, ...filteredPageTwoIds]).size === 12, `B4 filtered card page two is incomplete: ${JSON.stringify({ filteredPageOneIds, filteredPageTwoIds })}`);
  const previousPageResponse = page.waitForResponse((response) => response.request().method() === "GET" && response.url().includes("/api/v1/downstream/licenses/cards/") && response.url().includes("device_state=unbound") && response.url().includes("page=1"), { timeout: 15000 });
  await licensePagination.locator("[data-license-server-prev]").click();
  await previousPageResponse;
  await page.waitForFunction(() => document.querySelector('[data-record-view-scope="downstream-licenses"] [data-license-server-page]')?.textContent === "第 1 页", null, { timeout: 15000 });
  const clearFilterResponse = page.waitForResponse((response) => response.request().method() === "GET" && response.url().includes("/api/v1/downstream/licenses/cards/") && !response.url().includes("device_state=unbound"), { timeout: 15000 });
  await deviceFilter.selectOption("");
  await clearFilterResponse;
  const issuedIds = [...new Set([...filteredPageOneIds, ...filteredPageTwoIds])];

  const issuedDetail = page.locator(
    `[data-record-view-scope="downstream-licenses"] [data-record-panel="items"] tbody tr[data-public-id="${issuedIds[0]}"] [data-credential-detail]`,
  );
  await issuedDetail.waitFor({ state: "visible", timeout: 15000 });
  await issuedDetail.click();
  const credentialDialog = page.locator("#credentialDetailDialog");
  await credentialDialog.waitFor({ state: "visible" });
  await credentialDialog.locator("[data-credential-reveal]").click();
  await page.waitForFunction(() => document.querySelector("#credentialDetailDialog")?.dataset.revealed === "true");
  assert((await credentialDialog.locator("[data-credential-full]").textContent()).startsWith("LC-"), "B4 downstream reveal did not return a complete code");
  await credentialDialog.locator("[value='cancel']").last().click();
  await page.goto(`${base}/downstream.html#devices`, { waitUntil: "domcontentloaded" });
  const devicePanel = page.locator('[data-screen-panel="devices"]');
  await devicePanel.locator('[data-downstream-device-summary]').waitFor({ state: "visible", timeout: 15000 });
  const deviceApi = await page.evaluate(async () => {
    const response = await fetch("/api/v1/downstream/devices/?page_size=10", { credentials: "same-origin" });
    return { status: response.status, payload: await response.json() };
  });
  assert(deviceApi.status === 200 && Array.isArray(deviceApi.payload.items), `B4 downstream device API failed: ${JSON.stringify(deviceApi)}`);
  assert(await devicePanel.locator('tbody tr[data-device-license="LIC-••••-7H2K"]:visible').count() === 0, "B4 live downstream device page exposed static demo rows");
  assert(await devicePanel.locator('[data-downstream-device-pagination]').count() === 1 && await devicePanel.locator('.pagination').count() === 0, "B4 downstream device pagination is malformed");
  await page.locator('.header-actions .text-button').filter({ hasText: "退出" }).click();
  await page.waitForURL((url) => url.pathname.endsWith("/downstream-login.html"));

  await login(fixture.admin_username, "manage.html");
  await open("/manage.html#credits");
  await page.locator('[data-work-view="quota-cards"]').click();
  const quotaDownstreamFilter = page.locator('[data-record-view-scope="quota-cards"] [data-credential-filter="codeDownstream"]');
  await quotaDownstreamFilter.locator(`option[value="${fixture.downstream_a_username}"]`).waitFor({ state: "attached", timeout: 15000 });
  const quotaFilterResponse = page.waitForResponse(
    (response) => response.request().method() === "GET" && response.url().includes("/api/v1/manage/credits/") && response.url().includes(`redeemed_by=${encodeURIComponent(fixture.downstream_a_username)}`),
    { timeout: 15000 },
  );
  await quotaDownstreamFilter.selectOption(fixture.downstream_a_username);
  const quotaResponse = await quotaFilterResponse;
  assert(quotaResponse.ok(), `B4 quota downstream filter API failed: ${quotaResponse.status()}`);
  await quotaDownstreamFilter.selectOption("");
  await open("/manage.html#licenses");
  assert(
    await page.locator('[data-record-view-scope="management-licenses"] [data-record-view="batches"], [data-record-view-scope="management-licenses"] [data-record-panel="batches"]').count() === 0,
    "B4 management still exposes a batch view",
  );
  const adminRows = page.locator('[data-record-view-scope="management-licenses"] [data-record-panel="items"] tbody tr[data-public-id]');
  await page.waitForFunction(() => [...document.querySelectorAll('[data-record-view-scope="management-licenses"] [data-record-panel="items"] tbody tr[data-public-id]')].some((row) => !row.hidden), null, { timeout: 15000 });
  const adminRowData = await adminRows.evaluateAll((rows) => rows.map((row) => ({
    id: row.dataset.publicId,
    batch: row.dataset.recordBatch || "",
    full: row.dataset.fullCode || "",
    masked: row.dataset.searchValue || "",
  })));
  assert(adminRowData.length >= 2 && adminRowData.every((row) => !row.batch && !row.full), `B4 admin list exposed forbidden fields: ${JSON.stringify(adminRowData)}`);

  const search = page.locator('[data-record-view-scope="management-licenses"] [data-sensitive-search]');
  await search.fill(deliveredCodes[0]);
  const searchResponse = page.waitForResponse(
    (response) =>
      response.request().method() === "POST" &&
      response.url().includes("/api/v1/manage/licenses/cards/search/"),
    { timeout: 15000 },
  );
  await search.press("Enter");
  const searchHttpResponse = await searchResponse;
  assert(searchHttpResponse.ok(), `B4 exact search API failed: ${searchHttpResponse.status()}`);
  const searchPayload = await searchHttpResponse.json();
  const searchedPublicId = searchPayload.item?.public_id || "";
  assert(
    issuedIds.includes(searchedPublicId),
    `B4 exact search returned a card outside the issued set: issued=${JSON.stringify(issuedIds)} actual=${searchedPublicId} codes=${JSON.stringify(deliveredCodes)}`,
  );
  await page.waitForFunction(() => [...document.querySelectorAll('[data-record-view-scope="management-licenses"] [data-record-panel="items"] tbody tr[data-public-id]')].some((row) => !row.hidden), null, { timeout: 15000 });
  assert((await adminRows.count()) === 1, "B4 exact search did not narrow to one card");
  const adminDetail = page.locator(
    `[data-record-view-scope="management-licenses"] [data-record-panel="items"] tbody tr[data-public-id="${searchedPublicId}"] [data-credential-detail]`,
  );
  try {
    await adminDetail.waitFor({ state: "visible", timeout: 15000 });
  } catch (error) {
    const debugRows = await page.locator(
      '[data-record-view-scope="management-licenses"] [data-record-panel="items"] tbody tr[data-public-id]',
    ).evaluateAll((rows) => rows.map((row) => ({
      id: row.dataset.publicId || "",
      hidden: row.hidden,
      display: getComputedStyle(row).display,
      action: row.querySelector("[data-credential-detail]")?.outerHTML || "",
      actionDisplay: row.querySelector("[data-credential-detail]")
        ? getComputedStyle(row.querySelector("[data-credential-detail]")).display
        : "",
      rect: row.getBoundingClientRect().toJSON(),
      text: row.innerText,
    })));
    throw new Error(`B4 admin detail was not visible: target=${searchedPublicId} rows=${JSON.stringify(debugRows)}`);
  }
  await adminDetail.click();
  await page.locator("#credentialDetailDialog [data-credential-reveal]").click();
  await page.waitForFunction(() => document.querySelector("#credentialDetailDialog")?.dataset.revealed === "true");
  assert((await page.locator("#credentialDetailDialog [data-credential-full]").textContent()).startsWith("LC-"), "B4 admin reveal did not return a complete code");
  await page.locator("#credentialDetailDialog [value='cancel']").last().click();

  await search.fill("");
  await search.press("Enter");
  await page.waitForFunction((ids) => ids.every((id) => {
    const row = document.querySelector(`[data-record-view-scope="management-licenses"] [data-record-panel="items"] tbody tr[data-public-id="${id}"]`);
    return row && !row.hidden;
  }), pageOneIssuedIds, { timeout: 15000 });
  await page.waitForFunction(() => !document.querySelector('[data-record-view-scope="management-licenses"] [data-sensitive-search]')?.dataset.searchPending, null, { timeout: 15000 });
  await page.waitForTimeout(250);
  const visibleIssuedIds = pageOneIssuedIds;
  for (const id of visibleIssuedIds) {
    await page.locator(`[data-record-view-scope="management-licenses"] [data-record-panel="items"] tbody tr[data-public-id="${id}"] [data-reclaim-select]`).check();
  }
  const selectedCount = await page.locator('[data-record-view-scope="management-licenses"] [data-record-panel="items"] [data-reclaim-select]:checked').count();
  assert(selectedCount === visibleIssuedIds.length, `B4 admin selection did not retain visible issued cards: expected=${visibleIssuedIds.length}, actual=${selectedCount}`);
  const adminReclaimButton = page.locator('[data-record-view-scope="management-licenses"] [data-reclaim-selected]');
  await adminReclaimButton.waitFor({ state: "visible" });
  await page.waitForFunction(() => !document.querySelector('[data-record-view-scope="management-licenses"] [data-reclaim-selected]')?.disabled, null, { timeout: 15000 });
  for (const id of visibleIssuedIds) {
    await page.locator(`[data-record-view-scope="management-licenses"] [data-record-panel="items"] tbody tr[data-public-id="${id}"] [data-reclaim-select]`).uncheck();
  }
  const filteredReclaimButton = page.locator('[data-record-view-scope="management-licenses"] [data-reclaim-filtered]');
  await filteredReclaimButton.waitFor({ state: "visible", timeout: 15000 });
  await filteredReclaimButton.click();
  const reclaimDialog = page.locator("#adminReclaimDialog");
  await reclaimDialog.waitFor({ state: "visible" });
  assert((await reclaimDialog.locator("[data-admin-reclaim-count]").innerText()).includes("12"), "B4 filtered reclaim preview count is wrong");
  await reclaimDialog.locator("textarea[name='reason']").fill("B4 浏览器验收回收未激活卡");
  await reclaimDialog.locator("[data-reclaim-confirm]").click();
  await reclaimDialog.waitFor({ state: "hidden", timeout: 15000 });
  const reclaimed = await page.evaluate(async () => {
    const response = await fetch("/api/v1/manage/licenses/cards/?page_size=100&page=1", { credentials: "same-origin" });
    return { status: response.status, payload: await response.json() };
  });
  assert(reclaimed.status === 200, `B4 admin card refresh failed: ${JSON.stringify(reclaimed)}`);
  const reclaimedIssued = reclaimed.payload.items.filter((item) => issuedIds.includes(item.public_id));
  assert(reclaimedIssued.length === issuedIds.length && reclaimedIssued.every((item) => item.status === "reclaimed"), `B4 admin reclaim did not persist: ${JSON.stringify(reclaimed.payload.items)}`);

  const csrf = await page.evaluate(() => document.cookie.split(";").map((part) => part.trim()).find((part) => part.startsWith("csrftoken="))?.split("=")[1] || "");
  const forbiddenIssue = await page.evaluate(async (token) => {
    const response = await fetch("/api/v1/downstream/licenses/issue/", {
      method: "POST",
      credentials: "same-origin",
      headers: { "Content-Type": "application/json", "X-CSRFToken": token, "Idempotency-Key": "b4-admin-cannot-issue" },
      body: "{}",
    });
    return { status: response.status, payload: await response.json() };
  }, csrf);
  assert(forbiddenIssue.status === 403 && forbiddenIssue.payload.error.code === "FORBIDDEN", `B4 admin issue guard failed: ${JSON.stringify(forbiddenIssue)}`);
  await page.screenshot({ path: `${config.artifact_dir}/b4-frozen-8123.png`, fullPage: true });
}

async function b5Flow() {
  const targetDeviceId = config.fixture.device_id;
  const otherDeviceId = config.fixture.other_device_id;
  assert(targetDeviceId && otherDeviceId && targetDeviceId !== otherDeviceId, `B5 fixture must contain two distinct devices: ${JSON.stringify(config.fixture)}`);

  await login(config.fixture.downstream_a_username, "downstream.html");
  await open("/downstream.html#devices");
  const downstreamDeviceRows = page.locator('[data-screen-panel="devices"] tr[data-device-row]');
  await downstreamDeviceRows.first().waitFor({ state: "visible", timeout: 15000 });
  assert(await downstreamDeviceRows.count() === 2, `B5 downstream page did not render both live devices: ${await downstreamDeviceRows.count()}`);
  const downstreamResetRow = downstreamDeviceRows.nth(1);
  const downstreamResetExpiry = await downstreamResetRow.getAttribute("data-device-expires");
  const downstreamResetAuthorizationId = await downstreamResetRow.getAttribute("data-device-authorization-id");
  const downstreamResetActionRef = await downstreamResetRow.getAttribute("data-device-action-ref");
  await downstreamResetRow.locator("[data-reset-device]").click();
  const downstreamResetDialog = page.locator("#resetDeviceDialog");
  await downstreamResetDialog.waitFor({ state: "visible" });
  await downstreamResetDialog.locator("textarea[name='reason']").fill("B5 下游验收重置设备");
  await downstreamResetDialog.locator("[data-reset-device-confirm]").click();
  await downstreamResetDialog.waitFor({ state: "hidden", timeout: 15000 });
  await page.waitForFunction((expiry) => [...document.querySelectorAll('[data-screen-panel="devices"] tr[data-device-row]')].some((row) => row.dataset.deviceExpires === expiry && row.dataset.deviceBinding.includes("已解绑")), downstreamResetExpiry, { timeout: 15000 });
  const downstreamAfterReset = await page.evaluate(async () => {
    const response = await fetch("/api/v1/downstream/devices/?page_size=10", { credentials: "same-origin" });
    return { status: response.status, payload: await response.json() };
  });
  assert(downstreamAfterReset.status === 200 && downstreamAfterReset.payload.items.filter((item) => item.binding_state === "unbound").length === 1 && downstreamAfterReset.payload.items.filter((item) => item.binding_state === "active").length === 1, `B5 downstream reset scope did not persist: ${JSON.stringify(downstreamAfterReset)}`);

  await open("/downstream.html?b5-audit=1#activity");
  await page.waitForFunction(() => [...document.querySelectorAll('[data-screen-panel="activity"] tbody tr')].some((row) => row.innerText.includes("device.reset")), null, { timeout: 15000 });
  const downstreamActivityText = await page.locator('[data-screen-panel="activity"]').innerText();
  assert(downstreamActivityText.includes("device.reset"), "B5 downstream activity did not expose its own reset audit");
  await page.locator('.header-actions .text-button').filter({ hasText: "退出" }).click();
  await page.waitForURL((url) => url.pathname.endsWith("/downstream-login.html"));

  await login(config.fixture.downstream_b_username, "downstream.html");
  const otherDownstreamDevices = await page.evaluate(async () => {
    const response = await fetch("/api/v1/downstream/devices/?page_size=10", { credentials: "same-origin" });
    return { status: response.status, payload: await response.json() };
  });
  assert(otherDownstreamDevices.status === 200 && otherDownstreamDevices.payload.items.length === 0, `B5 cross-account downstream device leaked: ${JSON.stringify(otherDownstreamDevices)}`);
  const otherCsrf = await page.evaluate(() => {
    const raw = document.cookie.split(";").map((part) => part.trim()).find((part) => part.startsWith("csrftoken="));
    return raw ? decodeURIComponent(raw.slice("csrftoken=".length)) : "";
  });
  const crossAccountReset = await page.evaluate(async ({ authorizationId, actionRef, csrf }) => {
    const response = await fetch(`/api/v1/downstream/authorizations/${authorizationId}/devices/${actionRef}/reset/`, {
      method: "POST",
      credentials: "same-origin",
      headers: { "Content-Type": "application/json", "X-CSRFToken": csrf, "Idempotency-Key": "b5-cross-account-reset" },
      body: JSON.stringify({ reason: "B5 跨账号设备重置" }),
    });
    return { status: response.status, payload: await response.json() };
  }, { authorizationId: downstreamResetAuthorizationId, actionRef: downstreamResetActionRef, csrf: otherCsrf });
  assert(crossAccountReset.status === 400 && crossAccountReset.payload.error.code === "DEVICE_ACTION_REF_INVALID", `B5 cross-account reset was not rejected: ${JSON.stringify(crossAccountReset)}`);
  await page.locator('.header-actions .text-button').filter({ hasText: "退出" }).click();
  await page.waitForURL((url) => url.pathname.endsWith("/downstream-login.html"));

  await login(config.fixture.admin_username, "manage.html");
  await open("/manage.html#risk");
  const allDeviceRows = page.locator(`tr[data-device-row][data-authorization-id="${config.fixture.authorization_id}"]`);
  await allDeviceRows.first().waitFor({ state: "visible", timeout: 15000 });
  const riskPanel = page.locator('[data-screen-panel="risk"] .table-panel');
  assert(await riskPanel.locator(".pagination").count() === 0, "B5 device page still has a duplicate client-side pagination control");
  assert(await riskPanel.locator('[data-risk-server-pagination]:visible').count() === 1, "B5 device page is missing its single server pagination control");
  assert(await riskPanel.getByRole("button", { name: "上一页" }).count() === 1 && await riskPanel.getByRole("button", { name: "下一页" }).count() === 1, "B5 device page does not use the single 上一页/下一页 control");
  assert(await riskPanel.getByText("上一组", { exact: true }).count() === 0 && await riskPanel.getByText("下一组", { exact: true }).count() === 0, "B5 device page still exposes internal group pagination wording");
  const riskTableOrder = await page.locator('[data-screen-panel="risk"] table tbody tr').evaluateAll((rows) => {
    const visible = rows.filter((row) => !row.hidden);
    const realIndexes = visible.map((row, index) => ({ row, index })).filter((item) => !item.row.classList.contains("table-placeholder-row")).map((item) => item.index);
    const placeholderIndexes = visible.map((row, index) => ({ row, index })).filter((item) => item.row.classList.contains("table-placeholder-row")).map((item) => item.index);
    return { realIndexes, placeholderIndexes };
  });
  assert(
    riskTableOrder.realIndexes.length + riskTableOrder.placeholderIndexes.length === 10 &&
      (!riskTableOrder.realIndexes.length || !riskTableOrder.placeholderIndexes.length || Math.max(...riskTableOrder.realIndexes) < Math.min(...riskTableOrder.placeholderIndexes)),
    `B5 device rows do not preserve 10 fixed slots/order: ${JSON.stringify(riskTableOrder)}`,
  );
  const riskPaginationLayout = await riskPanel.evaluate((panel) => {
    const table = panel.querySelector("table").getBoundingClientRect();
    const controls = panel.querySelector("[data-risk-server-pagination]").getBoundingClientRect();
    const panelRect = panel.getBoundingClientRect();
    return { controlsBelowTable: controls.top >= table.bottom - 1, controlsRightAligned: controls.right >= panelRect.right - 24 };
  });
  assert(riskPaginationLayout.controlsBelowTable && riskPaginationLayout.controlsRightAligned, `B5 device pagination is not bottom-right: ${JSON.stringify(riskPaginationLayout)}`);
  const initialRow = allDeviceRows.filter({ hasText: "已绑定" }).first();
  const otherRow = allDeviceRows.filter({ hasText: "已解绑" }).first();
  await initialRow.waitFor({ state: "visible", timeout: 15000 });
  await otherRow.waitFor({ state: "visible", timeout: 15000 });
  const targetActionRef = await initialRow.getAttribute("data-device-id");
  const otherActionRef = await otherRow.getAttribute("data-device-id");
  const targetDeviceLabel = (await initialRow.getAttribute("data-device-binding") || "").split(" · ")[0];
  const otherDeviceLabel = (await otherRow.getAttribute("data-device-binding") || "").split(" · ")[0];
  const row = page.locator(`tr[data-device-row][data-authorization-id="${config.fixture.authorization_id}"]`).filter({ hasText: targetDeviceLabel }).first();
  assert(targetActionRef && otherActionRef && targetActionRef !== targetDeviceId, "B5 row exposed a raw device UUID instead of an action reference");
  assert(targetDeviceLabel && otherDeviceLabel, "B5 rows did not expose stable masked device labels");
  assert(await allDeviceRows.count() === 2, `B5 page did not render both device rows: ${await allDeviceRows.count()}`);

  const visibleBatchViews = await page.locator('[data-record-view="batches"], [data-record-panel="batches"]').count();
  assert(visibleBatchViews === 0, `B5 management page still exposes a batch view: ${visibleBatchViews}`);
  assert((await page.locator('a[href*="8143"], [data-href*="8143"]').count()) === 0, "B5 page introduced a 8143 entry");

  const initialRowData = await row.evaluate((element) => ({
    authorizationId: element.dataset.authorizationId,
    deviceId: element.dataset.deviceId,
    installationHash: element.dataset.installationHash || "",
    publicKey: element.dataset.devicePublicKey || "",
    text: element.innerText,
  }));
  assert(initialRowData.authorizationId === config.fixture.authorization_id, `B5 row authorization id mismatch: ${JSON.stringify(initialRowData)}`);
  assert(initialRowData.deviceId && initialRowData.deviceId !== targetDeviceId && initialRowData.deviceId !== otherDeviceId, `B5 row exposed a raw device UUID: ${JSON.stringify(initialRowData)}`);
  assert(!initialRowData.installationHash && !initialRowData.publicKey, `B5 row exposed device secret material: ${JSON.stringify(initialRowData)}`);

  const listResponse = await page.evaluate(async () => {
    const response = await fetch("/api/v1/manage/authorizations/?page_size=100", { credentials: "same-origin" });
    return { status: response.status, payload: await response.json() };
  });
  assert(listResponse.status === 200, `B5 management list failed: ${JSON.stringify(listResponse)}`);
  const listItem = listResponse.payload.items.find((item) => item.authorization_id === config.fixture.authorization_id);
  assert(listItem, `B5 list item missing stable authorization id: ${JSON.stringify(listResponse.payload)}`);
  assert(Array.isArray(listItem.devices) && listItem.devices.length === 2, `B5 list item did not expose two devices[] diagnostics: ${JSON.stringify(listItem)}`);
  const listedDeviceIds = listItem.devices.map((device) => device.device_id).sort();
  assert(listItem.devices.every((device) => device.device_action_ref && device.device_id !== targetDeviceId && device.device_id !== otherDeviceId), `B5 list exposed raw device identifiers: ${JSON.stringify(listItem.devices)}`);
  assert(listItem.devices.length === 2 && listedDeviceIds.every((value) => value.includes("…")), `B5 list item missing masked device references: ${JSON.stringify(listItem.devices)}`);
  assert(!("installation_hash" in listItem) && !("device_public_key" in listItem) && !("card_ciphertext" in listItem), `B5 API exposed sensitive fields: ${JSON.stringify(listItem)}`);

  const searchResponse = await page.evaluate(async (deviceId) => {
    const response = await fetch(`/api/v1/manage/authorizations/?page_size=100&q=${encodeURIComponent(deviceId)}`, { credentials: "same-origin" });
    return { status: response.status, payload: await response.json() };
  }, targetDeviceId);
  assert(searchResponse.status === 200 && searchResponse.payload.items.length === 1, `B5 device search did not locate the authorization: ${JSON.stringify(searchResponse)}`);

  const methodCheck = await page.evaluate(async () => {
    const response = await fetch("/api/v1/manage/authorizations/00000000-0000-0000-0000-000000000000/devices/00000000-0000-0000-0000-000000000000/reset/", { credentials: "same-origin" });
    return { status: response.status, payload: await response.json() };
  });
  assert(methodCheck.status === 405 && methodCheck.payload.error.code === "METHOD_NOT_ALLOWED", `B5 method guard failed: ${JSON.stringify(methodCheck)}`);

  const missingCsrf = await page.evaluate(async ({ authorizationId, deviceId }) => {
    const response = await fetch(`/api/v1/manage/authorizations/${authorizationId}/devices/${deviceId}/reset/`, {
      method: "POST",
      credentials: "same-origin",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ reason: "B5 missing csrf" }),
    });
    return { status: response.status, payload: await response.json() };
  }, { authorizationId: config.fixture.authorization_id, deviceId: targetActionRef });
  assert(missingCsrf.status === 403 && missingCsrf.payload.error.code === "CSRF_FAILED", `B5 CSRF guard failed: ${JSON.stringify(missingCsrf)}`);

  const csrfToken = await page.evaluate(() => {
    const raw = document.cookie.split(";").map((part) => part.trim()).find((part) => part.startsWith("csrftoken="));
    return raw ? decodeURIComponent(raw.slice("csrftoken=".length)) : "";
  });
  assert(csrfToken, "B5 browser fixture did not expose a CSRF cookie");
  const resetRoute = `/api/v1/manage/authorizations/${encodeURIComponent(config.fixture.authorization_id)}/devices/${encodeURIComponent(targetActionRef)}/reset/`;
  const missingIdempotency = await page.evaluate(async ({ route, csrf }) => {
    const response = await fetch(route, {
      method: "POST",
      credentials: "same-origin",
      headers: { "Content-Type": "application/json", "X-CSRFToken": csrf },
      body: JSON.stringify({ reason: "B5 missing idempotency" }),
    });
    return { status: response.status, payload: await response.json() };
  }, { route: resetRoute, csrf: csrfToken });
  assert(missingIdempotency.status === 400 && missingIdempotency.payload.error.code === "IDEMPOTENCY_REQUIRED", `B5 idempotency-required guard failed: ${JSON.stringify(missingIdempotency)}`);

  async function confirmAction(kind, reason) {
    const action = row.locator(`[data-device-action="${kind}"]`);
    await action.waitFor({ state: "visible", timeout: 15000 });
    await action.click();
    const dialog = page.locator("#managementActionDialog");
    await dialog.waitFor({ state: "visible" });
    await dialog.locator("textarea[name='reason']").fill(reason);
    await dialog.locator("[data-management-action-confirm]").click();
    await dialog.waitFor({ state: "hidden", timeout: 15000 });
    await page.waitForTimeout(250);
  }

  await confirmAction("reset", "B5 浏览器验收重置设备");
  let afterReset = await page.evaluate(async () => {
    const response = await fetch("/api/v1/manage/authorizations/?page_size=100", { credentials: "same-origin" });
    return { status: response.status, payload: await response.json() };
  });
  let item = afterReset.payload.items.find((entry) => entry.authorization_id === config.fixture.authorization_id);
  const resetDevice = item?.devices?.find((device) => device.device_label === targetDeviceLabel);
  const untouchedDevice = item?.devices?.find((device) => device.device_label === otherDeviceLabel);
  assert(afterReset.status === 200 && resetDevice?.binding_state === "unbound" && untouchedDevice?.binding_state === "unbound", `B5 reset scope did not persist exactly: ${JSON.stringify(afterReset)}`);
  await page.reload({ waitUntil: "domcontentloaded" });
  await page.waitForFunction((authorizationId) => [...document.querySelectorAll(`tr[data-device-row][data-authorization-id="${authorizationId}"]`)].some((item) => !item.hidden && item.innerText.includes("已解绑")), config.fixture.authorization_id, { timeout: 15000 });
  assert((await row.innerText()).includes("已解绑"), "B5 reset state disappeared after page reload");

  const idempotencyFirst = await page.evaluate(async ({ route, csrf }) => {
    const response = await fetch(route, {
      method: "POST",
      credentials: "same-origin",
      headers: { "Content-Type": "application/json", "X-CSRFToken": csrf, "Idempotency-Key": "b5-browser-reset-idempotency" },
      body: JSON.stringify({ reason: "B5 browser idempotent reset" }),
    });
    return { status: response.status, payload: await response.json() };
  }, { route: resetRoute, csrf: csrfToken });
  const idempotencyReplay = await page.evaluate(async ({ route, csrf }) => {
    const response = await fetch(route, {
      method: "POST",
      credentials: "same-origin",
      headers: { "Content-Type": "application/json", "X-CSRFToken": csrf, "Idempotency-Key": "b5-browser-reset-idempotency" },
      body: JSON.stringify({ reason: "B5 browser idempotent reset" }),
    });
    return { status: response.status, payload: await response.json() };
  }, { route: resetRoute, csrf: csrfToken });
  assert(idempotencyFirst.status === 200 && idempotencyReplay.status === 200, `B5 idempotent replay failed: ${JSON.stringify({ idempotencyFirst, idempotencyReplay })}`);
  assert(JSON.stringify(idempotencyFirst.payload) === JSON.stringify(idempotencyReplay.payload), `B5 idempotent replay changed response: ${JSON.stringify({ idempotencyFirst, idempotencyReplay })}`);
  const idempotencyConflict = await page.evaluate(async ({ route, csrf }) => {
    const response = await fetch(route, {
      method: "POST",
      credentials: "same-origin",
      headers: { "Content-Type": "application/json", "X-CSRFToken": csrf, "Idempotency-Key": "b5-browser-reset-idempotency" },
      body: JSON.stringify({ reason: "B5 browser conflicting reset" }),
    });
    return { status: response.status, payload: await response.json() };
  }, { route: resetRoute, csrf: csrfToken });
  assert(idempotencyConflict.status === 409 && idempotencyConflict.payload.error.code === "IDEMPOTENCY_CONFLICT", `B5 idempotency conflict guard failed: ${JSON.stringify(idempotencyConflict)}`);

  await confirmAction("block", "B5 浏览器验收封禁设备");
  const afterBlock = await page.evaluate(async () => {
    const response = await fetch("/api/v1/manage/authorizations/?page_size=100", { credentials: "same-origin" });
    return { status: response.status, payload: await response.json() };
  });
  item = afterBlock.payload.items.find((entry) => entry.authorization_id === config.fixture.authorization_id);
  assert(afterBlock.status === 200 && item?.devices?.find((device) => device.device_label === targetDeviceLabel)?.risk_state === "blocked" && item?.devices?.find((device) => device.device_label === otherDeviceLabel)?.binding_state === "unbound", `B5 block did not persist with exact scope: ${JSON.stringify(afterBlock)}`);
  await page.reload({ waitUntil: "domcontentloaded" });
  await page.waitForFunction((authorizationId) => [...document.querySelectorAll(`tr[data-device-row][data-authorization-id="${authorizationId}"]`)].some((item) => !item.hidden && item.innerText.includes("待复核")), config.fixture.authorization_id, { timeout: 15000 });
  assert((await row.innerText()).includes("待复核"), "B5 block state disappeared after page reload");

  await confirmAction("unblock", "B5 浏览器验收解除封禁");
  const afterUnblock = await page.evaluate(async () => {
    const response = await fetch("/api/v1/manage/authorizations/?page_size=100", { credentials: "same-origin" });
    return { status: response.status, payload: await response.json() };
  });
  item = afterUnblock.payload.items.find((entry) => entry.authorization_id === config.fixture.authorization_id);
  assert(afterUnblock.status === 200 && item?.devices?.find((device) => device.device_label === targetDeviceLabel)?.risk_state === "normal" && item?.devices?.find((device) => device.device_label === targetDeviceLabel)?.binding_state === "unbound" && item?.devices?.find((device) => device.device_label === otherDeviceLabel)?.binding_state === "unbound", `B5 unblock resurrected binding or failed: ${JSON.stringify(afterUnblock)}`);
  await page.reload({ waitUntil: "domcontentloaded" });
  await page.waitForFunction((authorizationId) => [...document.querySelectorAll(`tr[data-device-row][data-authorization-id="${authorizationId}"]`)].some((item) => !item.hidden && item.innerText.includes("已解绑")), config.fixture.authorization_id, { timeout: 15000 });
  assert((await row.innerText()).includes("已解绑"), "B5 unblock resurrected a binding after page reload");

  await confirmAction("revoke", "B5 浏览器验收撤销授权");
  const afterRevoke = await page.evaluate(async () => {
    const response = await fetch("/api/v1/manage/authorizations/?page_size=100", { credentials: "same-origin" });
    return { status: response.status, payload: await response.json() };
  });
  item = afterRevoke.payload.items.find((entry) => entry.authorization_id === config.fixture.authorization_id);
  assert(afterRevoke.status === 200 && item?.status === "revoked" && item?.card_status === "revoked", `B5 revoke did not persist: ${JSON.stringify(afterRevoke)}`);
  await page.reload({ waitUntil: "domcontentloaded" });
  await page.waitForFunction((authorizationId) => [...document.querySelectorAll(`tr[data-device-row][data-authorization-id="${authorizationId}"]`)].some((item) => !item.hidden && item.innerText.includes("已撤销")), config.fixture.authorization_id, { timeout: 15000 });
  assert((await row.innerText()).includes("已撤销"), "B5 revoke state disappeared after page reload");

  await open("/manage.html#audit");
  const auditPanel = page.locator('[data-screen-panel="audit"]');
  const auditDetailButton = auditPanel.locator('[data-audit-detail]').first();
  await auditDetailButton.waitFor({ state: "visible", timeout: 15000 });
  await auditDetailButton.click();
  const auditDetailDialog = page.locator("#auditDetailDialog");
  await auditDetailDialog.waitFor({ state: "visible", timeout: 10000 });
  assert((await auditDetailDialog.locator('[data-audit-detail-field="action"]').innerText()).length > 0, "B5 audit detail did not expose the event action");
  await auditDetailDialog.locator('[value="cancel"]').last().click();

  await page.locator('.header-actions .text-button').filter({ hasText: "退出" }).click();
  await page.waitForURL((url) => url.pathname.endsWith("/manage-login.html"));
  await login(config.fixture.downstream_a_username, "downstream.html");
  const downstreamDenied = await page.evaluate(async () => {
    const response = await fetch("/api/v1/manage/authorizations/", { credentials: "same-origin" });
    return { status: response.status, payload: await response.json() };
  });
  assert(downstreamDenied.status === 403 && downstreamDenied.payload.error.code === "FORBIDDEN", `B5 downstream permission guard failed: ${JSON.stringify(downstreamDenied)}`);
  await page.screenshot({ path: `${config.artifact_dir}/b5-frozen-8123.png`, fullPage: true });
}

if (!fixture.admin_username || !fixture.downstream_a_username || !fixture.downstream_b_username || !fixture.software_id) {
  throw new Error("B2.2 acceptance fixture is incomplete");
}

if (config.flow === "admin") {
  await adminFlow();
} else if (config.flow === "downstream-a") {
  await downstreamFlow(fixture.downstream_a_username, "Browser Acceptance Software", newSoftwareName, "downstream-a");
} else if (config.flow === "downstream-b") {
  await downstreamFlow(fixture.downstream_b_username, newSoftwareName, "Browser Acceptance Software", "downstream-b");
} else if (config.flow === "b4") {
  await b4Flow();
} else if (config.flow === "b5") {
  await b5Flow();
} else {
  throw new Error(`unknown B2.2 flow: ${config.flow}`);
}

const acceptanceLabel = config.flow === "b5" ? "B5" : config.flow === "b4" ? "B4" : "B2.2";
return `${acceptanceLabel} frozen 8123 acceptance passed: ${config.flow}`;
