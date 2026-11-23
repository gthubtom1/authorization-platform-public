const base = config.base.replace(/\/$/, "");
const screenshots = config.screenshot_dir;
const viewport = config.viewport;
const consoleErrors = [];
const apiRequests = [];
const STATIC_MARKERS = [
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
];

function assert(condition, message) {
  if (!condition) throw new Error(message);
}

page.on("console", (message) => {
  if (message.type() === "error") consoleErrors.push(message.text());
});
page.on("pageerror", (error) => consoleErrors.push(error.stack || error.message));
page.on("request", (request) => {
  if (request.url().includes("/api/")) apiRequests.push(request.url());
});
await page.setViewportSize(viewport);

async function waitForPreview() {
  await page.waitForTimeout(80);
}

async function captureSettled(name) {
  await page.evaluate(async () => {
    const finiteAnimations = document.getAnimations().filter((animation) => {
      const timing = animation.effect?.getComputedTiming?.();
      return timing?.iterations !== Infinity;
    });
    await Promise.all(finiteAnimations.map((animation) => animation.finished.catch(() => {})));
  });
  const runningFiniteAnimations = await page.evaluate(
    () =>
      document
        .getAnimations()
        .filter((animation) => {
          const timing = animation.effect?.getComputedTiming?.();
          return timing?.iterations !== Infinity && animation.playState === "running";
        }).length,
  );
  assert(runningFiniteAnimations === 0, `${name}: screenshot has running finite animations`);
  await page.screenshot({ path: `${screenshots}/${name}`, fullPage: true });
}

async function assertNoStaticMarkers(label) {
  const hits = await page.evaluate((markers) => {
    const source = document.documentElement.outerHTML;
    return markers.filter((marker) => source.includes(marker));
  }, STATIC_MARKERS);
  assert(hits.length === 0, `${label}: static fixture markers remain: ${hits.join(", ")}`);
}

async function assertNoBusinessRows(label) {
  const result = await page.evaluate(() => {
    const rows = [...document.querySelectorAll("tbody tr")].filter(
      (row) => !row.classList.contains("table-placeholder-row") && !row.hidden,
    );
    const businessRows = rows.filter((row) => !row.querySelector(".table-empty"));
    return {
      businessRows: businessRows.length,
      generatedRows: document.querySelectorAll("tbody tr[data-generated]").length,
      publicRows: document.querySelectorAll("tbody tr[data-public-id]").length,
      catalogRows: document.querySelectorAll("tbody tr[data-catalog-software-id]").length,
      downstreamRows: document.querySelectorAll("tbody tr[data-downstream-row]").length,
      deviceRows: document.querySelectorAll("tbody tr[data-device-row]").length,
      releaseRows: document.querySelectorAll("tbody tr[data-release-id]").length,
    };
  });
  assert(result.businessRows === 0, `${label}: visible business rows were rendered`);
  assert(result.generatedRows === 0, `${label}: generated rows were rendered`);
  assert(result.publicRows === 0, `${label}: public-id rows were rendered`);
  assert(result.catalogRows === 0, `${label}: catalog rows were rendered`);
  assert(result.downstreamRows === 0, `${label}: downstream rows were rendered`);
  assert(result.deviceRows === 0, `${label}: device rows were rendered`);
  assert(result.releaseRows === 0, `${label}: release rows were rendered`);
}

async function assertTables(label) {
  const tables = await page.evaluate(() =>
    [...document.querySelectorAll(".screen.is-visible .table-panel")]
      .filter((panel) => getComputedStyle(panel).display !== "none")
      .map((panel) => {
        const table = panel.querySelector("table");
        const slots = Number(table?.dataset.rowSlots || panel.dataset.rowSlots || 0);
        const rows = [...(table?.tBodies[0]?.rows || [])].filter((row) => !row.hidden);
        const pagination = panel.querySelector(".pagination");
        const tableRect = table?.getBoundingClientRect();
        const paginationRect = pagination?.getBoundingClientRect();
        return {
          slots,
          visibleRows: rows.length,
          realRows: rows.filter(
            (row) =>
              !row.classList.contains("table-placeholder-row") &&
              !row.querySelector(".table-empty"),
          ).length,
          pagination: Boolean(pagination),
          paginationBelow: Boolean(
            paginationRect && tableRect && paginationRect.top >= tableRect.bottom - 1,
          ),
          summary: panel.querySelector("[data-pagination-summary]")?.textContent || "",
        };
      }),
  );
  for (const [index, table] of tables.entries()) {
    assert(table.slots === 5 || table.slots === 10, `${label}: table ${index} has invalid row slots`);
    assert(table.visibleRows === table.slots, `${label}: table ${index} has ${table.visibleRows}/${table.slots} visible rows`);
    assert(table.realRows === 0, `${label}: table ${index} has a real row in the static preview`);
    assert(table.pagination, `${label}: table ${index} has no pagination skeleton`);
    assert(table.paginationBelow, `${label}: table ${index} pagination is not below the table`);
    assert(table.summary.includes(`每页 ${table.slots} 条`), `${label}: table ${index} lost its page-size summary`);
  }
}

async function assertScreen(screen) {
  const visible = await page.locator(".screen.is-visible").evaluateAll((items) =>
    items.map((item) => item.dataset.screenPanel),
  );
  assert(visible.length === 1 && visible[0] === screen, `${screen}: wrong visible screen ${visible.join(",")}`);
  await assertNoStaticMarkers(screen);
  await assertNoBusinessRows(screen);
  await assertTables(screen);
  const overflow = await page.evaluate(
    () => document.documentElement.scrollWidth - document.documentElement.clientWidth,
  );
  assert(overflow <= 1, `${screen}: horizontal overflow is ${overflow}px`);
}

async function openNavigationIfNeeded() {
  const toggle = page.locator(".nav-toggle");
  if ((await toggle.isVisible()) && (await toggle.getAttribute("aria-expanded")) === "false") {
    await toggle.click();
  }
}

async function exerciseNavigation(entry, defaultScreen) {
  await page.goto(`${base}/${entry}.html`, { waitUntil: "domcontentloaded" });
  await waitForPreview();
  await assertScreen(defaultScreen);
  const screens = await page
    .locator(".side-nav [data-screen]:not(.nav-secondary)")
    .evaluateAll((items) => items.map((item) => item.dataset.screen));
  for (const screen of screens) {
    await openNavigationIfNeeded();
    await page.locator(`.side-nav [data-screen="${screen}"]`).click();
    await waitForPreview();
    assert((await page.evaluate(() => window.location.hash)) === `#${screen}`, `${entry}/${screen}: hash did not update`);
    await assertScreen(screen);
  }
  return screens.length;
}

async function exerciseEmptySurfaces(entry, defaultScreen, secondaryScreens) {
  await page.goto(`${base}/${entry}.html`, { waitUntil: "domcontentloaded" });
  await waitForPreview();
  for (const screen of [defaultScreen, ...secondaryScreens]) {
    await page.goto(`${base}/${entry}.html#${screen}`, { waitUntil: "domcontentloaded" });
    await waitForPreview();
    await assertScreen(screen);
  }
}

async function exerciseEmptyFilters() {
  await page.goto(`${base}/manage.html#licenses`, { waitUntil: "domcontentloaded" });
  await waitForPreview();
  const managementItems = page.locator('[data-record-view-scope="management-licenses"] [data-record-panel="items"]');
  await managementItems.locator("input[type=search]").fill("不存在的凭证");
  await assertScreen("licenses");
  await managementItems.locator("input[type=search]").fill("");
  await managementItems.locator('[data-credential-filter="codeSoftware"]').selectOption("");
  await assertNoBusinessRows("management filters");

  await page.goto(`${base}/downstream.html#licenses`, { waitUntil: "domcontentloaded" });
  await waitForPreview();
  const downstreamItems = page.locator('[data-record-view-scope="downstream-licenses"] [data-record-panel="items"]');
  await downstreamItems.locator("input[type=search]").fill("不存在的凭证");
  await assertScreen("licenses");
  await downstreamItems.locator("input[type=search]").fill("");
  await assertNoBusinessRows("downstream filters");

  await page.goto(`${base}/manage.html#analytics`, { waitUntil: "domcontentloaded" });
  await waitForPreview();
  await page.locator("[data-analytics-apply]").click();
  assert(await page.locator("[data-analytics-empty]").isVisible(), "analytics did not expose its empty state");
  assert(await page.locator("[data-analytics-content]").isHidden(), "analytics kept stale content after empty query");

  await page.goto(`${base}/downstream.html`, { waitUntil: "domcontentloaded" });
  await waitForPreview();
  await page.locator("[data-downstream-metrics-disclosure] summary").click();
  await page.locator("[data-downstream-metrics-apply]").click();
  assert(await page.locator("[data-downstream-metrics-empty]").isVisible(), "downstream metrics did not expose its empty state");
  assert(await page.locator(".downstream-signals").isVisible(), "downstream empty window hid snapshot signals");
  await assertNoStaticMarkers("empty filters");
}


async function exerciseStaticLicenseDeviceCodeSearch() {
  await page.goto(`${base}/manage.html#licenses`, { waitUntil: "domcontentloaded" });
  await waitForPreview();
  await page.evaluate(() => {
    const body = document.querySelector('[data-record-view-scope="management-licenses"] [data-record-panel="items"] tbody');
    const row = document.createElement("tr");
    row.dataset.generated = "license";
    row.dataset.publicId = "static-device-search";
    row.dataset.searchValue = "••••-••••-ABCD ABCD GS-65FB-F502-B439-270C";
    row.dataset.codeDeviceCode = "GS-65FB-F502-B439-270C";
    row.dataset.codeDeviceUuid = "1067f3d6-0000-0000-0000-000000000000";
    row.innerHTML = '<td></td><td class="mono">••••-••••-ABCD</td><td><span class="status status-green">已激活</span></td><td>测试软件 / 长套餐名称 · 30 天 · 10 额度</td><td>激活后计时</td><td><button type="button" class="text-button">查看 / 交付</button></td>';
    body?.append(row);
    window.__previewRefreshTables?.();
  });
  const panel = page.locator('[data-record-view-scope="management-licenses"] [data-record-panel="items"]');
  await panel.locator('[data-sensitive-search]').fill("GS-65FB-F502-B439-270C");
  const row = page.locator('tr[data-public-id="static-device-search"]');
  assert(await row.isVisible(), "static license search did not match client device code");
  await page.evaluate(() => {
    document.querySelector('tr[data-public-id="static-device-search"]')?.remove();
    window.__previewRefreshTables?.();
  });
}

async function exerciseStaticActionGuards() {
  await page.goto(`${base}/manage.html#overview`, { waitUntil: "domcontentloaded" });
  await waitForPreview();
  assert(
    (await page.locator('[data-toast="需要处理列表已刷新。"]').count()) === 0,
    "overview still pretends to refresh the attention list",
  );

  await page.goto(`${base}/manage.html#software`, { waitUntil: "domcontentloaded" });
  await waitForPreview();
  await page.locator('[data-screen-panel="software"] [data-dialog="softwareDialog"]').click();
  const softwareDialog = page.locator("#softwareDialog");
  await softwareDialog.locator("#softwareName").fill("本次临时输入");
  await softwareDialog.locator("#softwareName").press("Enter");
  assert(await softwareDialog.isVisible(), "Enter in software name closed the dialog");
  assert(await softwareDialog.locator("#softwareCode").isVisible(), "software id still hidden until advanced opens");
  await softwareDialog.locator("[data-software-rules] summary").click();
  await softwareDialog.locator("#softwareAddPlan").check();
  await softwareDialog.locator("#softwareMaxDevices").fill("1");
  await softwareDialog.locator("#softwareVerifyInterval").fill("15");
  await softwareDialog.locator("#softwareOfflineGrace").fill("0");
  await softwareDialog.locator("#softwarePlanName").fill("临时套餐");
  await softwareDialog.locator("#softwarePlanDuration").fill("1");
  await softwareDialog.locator("#softwarePlanCost").fill("1");
  assert(await softwareDialog.locator("#softwareCode").getAttribute("readonly") !== null, "software identity must be generated by the server");
  await softwareDialog.locator("[data-software-advanced] summary").click();
  await softwareDialog.locator("#softwareProfile").fill("temporary-profile");
  await softwareDialog.locator("[data-software-save]").click();
  assert(await softwareDialog.locator('[data-software-stage="form"]').isVisible(), "static software action left the form");
  assert((await softwareDialog.locator("[data-form-error]").innerText()).includes("静态预览"), "static software action lacked a no-op message");
  await softwareDialog.locator('[value="cancel"]').filter({ visible: true }).last().click();
  await assertNoBusinessRows("software action");

  await page.goto(`${base}/manage.html#downstreams`, { waitUntil: "domcontentloaded" });
  await waitForPreview();
  await page.locator('[data-work-view-scope="downstream-management"] [data-work-view="invitations"]').click();
  await page.locator('[data-dialog="inviteDialog"]').click();
  assert((await page.locator("#inviteNote").count()) === 0, "invitation issue still shows a fake note field");
  await page.locator("#inviteQuantity").fill("1");
  await page.locator("[data-invite-generate]").click();
  assert(await page.locator('[data-invite-stage="form"]').isVisible(), "static invitation action left the form");
  assert((await page.locator("[data-invite-error]").innerText()).includes("静态预览"), "static invitation action lacked a no-op message");
  assert((await page.locator("[data-invite-codes] code").count()) === 0, "static preview generated an invitation code");
  await page.locator("#inviteDialog [value=cancel]").filter({ visible: true }).last().click();

  await page.goto(`${base}/manage.html#credits`, { waitUntil: "domcontentloaded" });
  await waitForPreview();
  const creditsPanel = page.locator('[data-screen-panel="credits"]');
  assert(await creditsPanel.locator(".balance-number").isVisible(), "credits balance missing");
  const creditsText = await creditsPanel.innerText();
  assert(!creditsText.includes("本月净消耗"), "credits panel still shows unwired month net consumed");
  assert(!creditsText.includes("活跃账户"), "credits panel still shows unwired active accounts");
  assert(creditsText.includes("未删除下游余额合计"), "credits panel lost operating-balance caption");
  await page.locator('[data-work-view-scope="credit-management"] [data-work-view="quota-cards"]').click();
  await page.locator('[data-dialog="quotaCardDialog"]').click();
  assert((await page.locator("#quotaCardNote").count()) === 0, "quota issue still shows a fake note field");
  await page.locator("#quotaCardAmount").fill("1");
  await page.locator("#quotaCardQuantity").fill("1");
  await page.locator("[data-quota-card-generate]").click();
  assert(await page.locator('[data-quota-card-stage="form"]').isVisible(), "static quota action left the form");
  assert((await page.locator("[data-quota-card-error]").innerText()).includes("静态预览"), "static quota action lacked a no-op message");
  assert((await page.locator("[data-quota-card-codes] code").count()) === 0, "static preview generated a quota code");
  await page.locator("#quotaCardDialog [value=cancel]").filter({ visible: true }).last().click();

  await page.goto(`${base}/downstream.html#licenses`, { waitUntil: "domcontentloaded" });
  await waitForPreview();
  await page.locator('[data-dialog="issueDialog"]').filter({ visible: true }).first().click();
  await page.locator("#issueQuantity").fill("1");
  await page.locator("#issueQuantity").press("Enter");
  assert(await page.locator("#issueDialog").isVisible(), "Enter in issue quantity closed the dialog");
  assert(await page.locator("#issueSubmit").isDisabled(), "static preview enabled license generation without an API catalog");
  assert((await page.locator("[data-issue-result]").count()) === 1 && await page.locator("[data-issue-result]").isHidden(), "license result was visible in empty preview");
  await page.locator("#issueDialog [value=cancel]").filter({ visible: true }).last().click();

  await page.goto(`${base}/manage.html#releases`, { waitUntil: "domcontentloaded" });
  await waitForPreview();
  await page.locator('[data-dialog="releaseDialog"]').click();
  await page.locator("#releasePackage").setInputFiles(config.release_fixtures.valid);
  await page.locator("#releaseDialog [data-release-next]").click();
  assert(await page.locator('[data-release-stage="upload"]').isVisible(), "static release action entered a fake verification stage");
  assert((await page.locator("[data-release-error]").innerText()).includes("静态预览"), "static release action lacked a no-op message");
  await page.locator("#releaseDialog [value=cancel]").filter({ visible: true }).last().click();

  await page.goto(`${base}/manage.html#risk`, { waitUntil: "domcontentloaded" });
  await waitForPreview();
  await page.evaluate(() => {
    const body = document.querySelector('[data-screen-panel="risk"] tbody');
    const row = document.createElement("tr");
    row.dataset.deviceRow = "";
    row.dataset.deviceLicense = "temporary-device";
    row.innerHTML = '<td>temporary-device</td><td>temporary product</td><td data-device-binding>temporary binding</td><td><span data-authorization-status>正常</span></td><td>正常</td><td data-device-expiry>—</td><td>—</td><td><button type="button" data-device-action="block">封禁</button></td>';
    body?.append(row);
    window.__previewRefreshTables?.();
  });
  const temporaryRiskRow = page.locator('tr[data-device-row=""]');
  await temporaryRiskRow.locator('[data-device-action="block"]').click();
  await page.locator("#managementActionDialog [data-management-action-confirm]").click();
  assert(await page.locator("#managementActionDialog").isVisible(), "static risk action closed its confirmation dialog");
  assert((await page.locator("#managementActionDialog [data-form-error]").innerText()).includes("静态预览"), "static risk action lacked a no-op message");
  assert((await temporaryRiskRow.locator("[data-authorization-status]").innerText()) === "正常", "static risk action changed a device row");
  await page.evaluate(() => {
    document.querySelector('tr[data-device-row=""]')?.remove();
    window.__previewRefreshTables?.();
    document.querySelector("#managementActionDialog")?.close("cancel");
  });

  await assertNoStaticMarkers("static action guards");
  await assertNoBusinessRows("static action guards");
  assert(apiRequests.length === 0, `static preview sent API requests: ${apiRequests.join(" | ")}`);
}

async function exerciseViewStates() {
  for (const [entry, screen] of [["manage", "licenses"], ["downstream", "workspace"]]) {
    await page.goto(`${base}/${entry}.html?view=loading#${screen}`, { waitUntil: "domcontentloaded" });
    await waitForPreview();
    assert(await page.locator("[data-injected-view-state]").isVisible(), `${entry}: loading state missing`);
    assert((await page.locator(`.screen.is-visible`).getAttribute("aria-busy")) === "true", `${entry}: loading state missing aria-busy`);
    await page.goto(`${base}/${entry}.html?view=empty#${screen}`, { waitUntil: "domcontentloaded" });
    await waitForPreview();
    assert(await page.locator("[data-injected-view-state]").isVisible(), `${entry}: empty state missing`);
  }
}

async function exerciseRedeemRefreshFailureCopy() {
  const consoleStart = consoleErrors.length;
  await page.goto(`${base}/downstream.html#ledger`, { waitUntil: "domcontentloaded" });
  await waitForPreview();
  await page.context().addCookies([{ name: "csrftoken", value: "preview-csrf", url: base }]);
  await page.route(/\/api\/v1\/downstream\/credits\/?/, async (route) => {
    if (route.request().method() === "POST") {
      await route.fulfill({
        status: 200,
        contentType: "application/json",
        body: JSON.stringify({
          repeated: false,
          account: { available_balance: 125 },
          entry: { amount: 100, balance_after: 125 },
          card: { status: "redeemed" },
        }),
      });
      return;
    }
    await route.fulfill({
      status: 500,
      contentType: "application/json",
      body: JSON.stringify({ error: { message: "账本读取失败，这句不能当成兑换失败。" } }),
    });
  });
  await page.evaluate(() => {
    window.__b1ApiActive = true;
  });
  await page.locator('[data-screen-panel="ledger"] [data-dialog="redeemDialog"]').click();
  const dialog = page.locator("#redeemDialog");
  assert(await dialog.isVisible(), "redeem dialog did not open");
  await dialog.locator('input[name="quota_code"]').fill("REDEEMFAIL1");
  await dialog.locator('[data-success-screen="ledger"]').click();
  await page.locator(".toast.is-visible").waitFor({ timeout: 5000 });
  const toastText = await page.locator(".toast").innerText();
  const formError = await dialog.locator("[data-form-error]").innerText();
  assert(!toastText.includes("兑换失败"), `ledger refresh failure reported as redeem failure in toast: ${toastText}`);
  assert(!formError.includes("兑换失败"), `ledger refresh failure reported as redeem failure in form: ${formError}`);
  assert(toastText.includes("已兑换"), `successful redeem was not shown after ledger refresh failure: ${toastText}`);
  assert(!(await dialog.isVisible()), "redeem dialog stayed open after successful POST");
  const balance = (await page.locator('[data-screen-panel="ledger"] .balance-number').innerText()).replace(/,/g, "");
  assert(balance === "125", `POST account balance was not applied: ${balance}`);
  await page.unroute(/\/api\/v1\/downstream\/credits\/?/);
  const mockedNetworkErrors = consoleErrors.splice(consoleStart);
  mockedNetworkErrors.forEach((text) => {
    if (!/downstream\/credits|status of 500|Failed to load resource/i.test(text)) {
      consoleErrors.push(text);
    }
  });
}

async function exerciseRedeemResetsLedgerPage() {
  const creditsGets = [];
  let posted = false;
  await page.goto(`${base}/downstream.html?fix016=ledger#ledger`, { waitUntil: "domcontentloaded" });
  await waitForPreview();
  await page.evaluate(() => {
    document.querySelector(".toast")?.classList.remove("is-visible");
  });
  await page.context().addCookies([{ name: "csrftoken", value: "preview-csrf", url: base }]);
  await page.route(/\/api\/v1\/downstream\/credits\/?/, async (route) => {
    if (route.request().method() === "POST") {
      posted = true;
      await route.fulfill({
        status: 200,
        contentType: "application/json",
        body: JSON.stringify({
          repeated: false,
          account: { available_balance: 200 },
          entry: { amount: 100, balance_after: 200 },
          card: { status: "redeemed" },
        }),
      });
      return;
    }
    const rawUrl = route.request().url();
    const pageMatch = rawUrl.match(/[?&]ledger_page=(\d+)/);
    const pageNumber = pageMatch ? pageMatch[1] : "1";
    creditsGets.push({ page: pageNumber, afterPost: posted });
    await route.fulfill({
      status: 200,
      contentType: "application/json",
      body: JSON.stringify({
        purchase_url: "",
        account: { available_balance: posted ? 200 : 100 },
        today_consumed: 0,
        ledger: [],
        ledger_pagination: {
          page: Number(pageNumber),
          total_pages: 2,
          has_previous: Number(pageNumber) > 1,
          has_next: Number(pageNumber) < 2,
          total: 6,
        },
      }),
    });
  });
  await page.evaluate(() => {
    window.__b1ApiActive = true;
  });
  const pageTwo = page.waitForResponse(
    (response) =>
      response.url().includes("/downstream/credits/") &&
      response.request().method() === "GET" &&
      /[?&]ledger_page=2(?:&|$)/.test(response.url()),
  );
  await page.evaluate(() => {
    const next = document.querySelector("[data-downstream-ledger-next]");
    if (next) {
      next.disabled = false;
      next.click();
    }
  });
  await pageTwo;
  assert(
    creditsGets.some((item) => item.page === "2" && !item.afterPost),
    `did not request ledger page 2 before redeem: ${JSON.stringify(creditsGets)}`,
  );
  await page.locator('[data-screen-panel="ledger"] [data-dialog="redeemDialog"]').click();
  const dialog = page.locator("#redeemDialog");
  assert(await dialog.isVisible(), "redeem dialog did not open for page-reset check");
  await dialog.locator('input[name="quota_code"]').fill("REDEEMPAGE1");
  const reloadWait = page.waitForResponse(
    (response) =>
      posted &&
      response.url().includes("/downstream/credits/") &&
      response.request().method() === "GET" &&
      /[?&]ledger_page=1(?:&|$)/.test(response.url()),
  );
  await dialog.locator('[data-success-screen="ledger"]').click();
  await reloadWait;
  await page.locator(".toast.is-visible").waitFor({ timeout: 5000 });
  const toastText = await page.locator(".toast").innerText();
  assert(toastText.includes("兑换成功"), `redeem page-reset toast was wrong: ${toastText}`);
  const afterPost = creditsGets.filter((item) => item.afterPost);
  assert(afterPost.length > 0, `redeem did not reload ledger: ${JSON.stringify(creditsGets)}`);
  assert(
    afterPost[0].page === "1",
    `redeem kept the current ledger page instead of page 1: ${JSON.stringify(creditsGets)}`,
  );
  await page.unroute(/\/api\/v1\/downstream\/credits\/?/);
}

async function exerciseQuotaRevokePartialSuccess() {
  const consoleStart = consoleErrors.length;
  const revokeIds = [];
  await page.goto(`${base}/manage.html#credits`, { waitUntil: "domcontentloaded" });
  await waitForPreview();
  await page.locator('[data-work-view-scope="credit-management"] [data-work-view="quota-cards"]').click();
  await waitForPreview();
  await page.context().addCookies([{ name: "csrftoken", value: "preview-csrf", url: base }]);
  await page.evaluate(() => {
    const body = document.querySelector("[data-quota-card-item-table]");
    if (!body) return;
    body.replaceChildren();
    ["card-a", "card-b", "card-c"].forEach((id) => {
      const row = document.createElement("tr");
      row.dataset.publicId = id;
      const cell = document.createElement("td");
      const box = document.createElement("input");
      box.type = "checkbox";
      box.checked = true;
      box.dataset.reclaimSelect = "";
      box.dataset.cardStatus = "issued";
      box.dataset.cardId = id;
      cell.append(box);
      row.append(cell);
      body.append(row);
    });
  });
  await page.route(/\/api\/v1\/manage\/credits/, async (route) => {
    const url = route.request().url();
    const method = route.request().method();
    const revokeMatch = url.match(/\/cards\/([^/?]+)\/revoke\/?/);
    if (method === "POST" && revokeMatch) {
      const id = decodeURIComponent(revokeMatch[1]);
      revokeIds.push(id);
      if (id === "card-b") {
        await route.fulfill({
          status: 409,
          contentType: "application/json",
          body: JSON.stringify({
            error: { code: "QUOTA_CARD_UNAVAILABLE", message: "只有未兑换的额度码可以作废。" },
          }),
        });
        return;
      }
      await route.fulfill({
        status: 200,
        contentType: "application/json",
        body: JSON.stringify({ public_id: id, status: "revoked" }),
      });
      return;
    }
    await route.fulfill({
      status: 200,
      contentType: "application/json",
      body: JSON.stringify({
        cards: [
          { public_id: "card-a", status: "revoked", amount: 100, masked_code: "••••-aaaa" },
          { public_id: "card-b", status: "issued", amount: 100, masked_code: "••••-bbbb" },
          { public_id: "card-c", status: "revoked", amount: 100, masked_code: "••••-cccc" },
        ],
        accounts: [],
        ledger: [],
        cards_pagination: { page: 1, total_pages: 1, count: 3 },
      }),
    });
  });
  await page.evaluate(() => {
    window.__b1ApiActive = true;
  });
  await page.locator("[data-quota-revoke-selected]").click();
  const dialog = page.locator("#quotaRevokeDialog");
  assert(await dialog.isVisible(), "quota revoke dialog did not open");
  await dialog.locator('textarea[name="reason"]').fill("测试作废半成功");
  await dialog.locator("[data-quota-revoke-confirm]").click();
  await page.locator(".toast.is-visible").waitFor({ timeout: 5000 });
  const toastText = await page.locator(".toast").innerText();
  const formError = await dialog.locator("[data-form-error]").innerText();
  assert(revokeIds.includes("card-a"), `first card was not revoked: ${revokeIds.join(",")}`);
  assert(revokeIds.includes("card-b"), `failed card was not attempted: ${revokeIds.join(",")}`);
  assert(revokeIds.includes("card-c"), `later card was skipped after 409: ${revokeIds.join(",")}`);
  assert(revokeIds.length === 3, `expected 3 revoke requests, got ${revokeIds.join(",")}`);
  assert(!toastText.includes("已作废 3 枚"), `partial revoke toasted full selection count: ${toastText}`);
  assert(
    toastText.includes("未成功") || formError.includes("未成功"),
    `partial revoke did not report per-card failure: toast=${toastText} form=${formError}`,
  );
  assert(await dialog.isVisible(), "quota revoke dialog closed after partial success");
  const failedStillIssued = await page.locator(
    '[data-quota-card-item-table] tr[data-public-id="card-b"] [data-reclaim-select][data-card-status="issued"]',
  ).count();
  assert(failedStillIssued === 1, "failed issued card did not remain in the list");
  const fifthColumn = async (id) =>
    page.locator(`[data-quota-card-item-table] tr[data-public-id="${id}"] td`).nth(4).innerText();
  const revokedA = await fifthColumn("card-a");
  const issuedB = await fifthColumn("card-b");
  const revokedC = await fifthColumn("card-c");
  assert(!revokedA.includes("可兑换"), `revoked card-a fifth column still looks redeemable: ${revokedA}`);
  assert(!revokedC.includes("可兑换"), `revoked card-c fifth column still looks redeemable: ${revokedC}`);
  assert(issuedB.includes("可兑换"), `issued card-b fifth column lost redeemable copy: ${issuedB}`);
  await dialog.locator("[value=cancel]").filter({ visible: true }).last().click();
  await page.unroute(/\/api\/v1\/manage\/credits/);
  const mockedNetworkErrors = consoleErrors.splice(consoleStart);
  mockedNetworkErrors.forEach((text) => {
    if (!/\/revoke\/|status of 409|Failed to load resource/i.test(text)) {
      consoleErrors.push(text);
    }
  });
}

async function exerciseExactSearchOverlayGuards() {
  const blocked = [];
  await page.route(/\/api\/v1\/.*\/(export|reclaim-preview)\/?/, async (route) => {
    blocked.push(`${route.request().method()} ${route.request().url()}`);
    await route.abort();
  });
  await page.goto(`${base}/manage.html#licenses`, { waitUntil: "domcontentloaded" });
  await waitForPreview();
  await page.evaluate(() => {
    document.querySelector('[data-record-view-scope="management-licenses"]')?.setAttribute("data-credential-search-overlay", "true");
    const search = document.querySelector('[data-record-view-scope="management-licenses"] [data-sensitive-search]');
    if (search) search.value = "";
  });
  await page.locator('[data-screen-panel="licenses"] [data-export-query="licenses"]').click();
  await page.locator(".toast.is-visible").waitFor({ timeout: 5000 });
  const licenseToast = await page.locator(".toast").innerText();
  assert(licenseToast.includes("精确搜索"), `license export during exact search was not blocked: ${licenseToast}`);
  const reclaimButton = page.locator('[data-record-view-scope="management-licenses"] [data-reclaim-filtered]');
  if (await reclaimButton.count()) {
    await reclaimButton.click();
    const reclaimToast = await page.locator(".toast").innerText();
    assert(reclaimToast.includes("精确搜索"), `filtered reclaim during exact search was not blocked: ${reclaimToast}`);
  }
  await page.goto(`${base}/manage.html#credits`, { waitUntil: "domcontentloaded" });
  await waitForPreview();
  await page.locator('[data-work-view-scope="credit-management"] [data-work-view="quota-cards"]').click();
  await page.evaluate(() => {
    document.querySelector('[data-record-view-scope="quota-cards"]')?.setAttribute("data-credential-search-overlay", "true");
  });
  await page.locator('[data-export-query="quota-cards"]').click();
  await page.locator(".toast.is-visible").waitFor({ timeout: 5000 });
  const quotaToast = await page.locator(".toast").innerText();
  assert(quotaToast.includes("精确搜索"), `quota export during exact search was not blocked: ${quotaToast}`);
  assert(blocked.length === 0, `exact-search overlay still sent export/reclaim requests: ${blocked.join(" | ")}`);
  await page.unroute(/\/api\/v1\/.*\/(export|reclaim-preview)\/?/);
}

function metricNumber(text) {
  return String(text || "").trim().replace(/,/g, "");
}

async function exerciseEmptyAnalyticsKeepsSnapshot() {
  const consoleStart = consoleErrors.length;
  const summaryGets = [];
  await page.goto(`${base}/manage.html#analytics`, { waitUntil: "domcontentloaded" });
  await waitForPreview();
  await page.context().addCookies([{ name: "csrftoken", value: "preview-csrf", url: base }]);
  await page.route(/\/api\/v1\/manage\/analytics\/summary\/?/, async (route) => {
    const url = route.request().url();
    if (url.includes("/export/")) {
      await route.fulfill({
        status: 200,
        contentType: "text/csv; charset=utf-8",
        body: "今日收入(额度),8\n",
      });
      return;
    }
    const empty = /[?&]window=empty(?:&|$)/.test(url);
    summaryGets.push(empty ? "empty" : "window");
    await route.fulfill({
      status: 200,
      contentType: "application/json",
      body: JSON.stringify(
        empty
          ? {
              has_data: false,
              active_authorizations: 1,
              activation_success_rate: null,
              quota_net_consumed: 0,
              risk_pending: 4,
              revenue: { today: 8, month: 8, total: 15 },
              trend: [{ date: "2036-09-01", revenue: 0, activations: 0 }],
              software_breakdown: [],
              generated_at: "2026-09-05T03:00:00Z",
              filters: { software: [], downstream: [] },
            }
          : {
              has_data: true,
              active_authorizations: 3,
              activation_success_rate: 100,
              quota_net_consumed: 10,
              risk_pending: 4,
              revenue: { today: 8, month: 8, total: 22 },
              trend: [{ date: "2026-09-01", revenue: 8, activations: 2 }],
              software_breakdown: [{ software_name: "Tool", activations: 2, revenue: 8 }],
              generated_at: "2026-09-05T03:00:00Z",
              filters: { software: [], downstream: [] },
            },
      ),
    });
  });
  await page.evaluate(() => {
    window.__b1ApiActive = true;
  });
  await page.locator('[name="analytics_window"]').selectOption("7d");
  await page.locator("[data-analytics-apply]").click();
  await page.waitForFunction(
    () => document.querySelector('[data-analytics-metric="active"]')?.textContent.replace(/,/g, "") === "3",
    null,
    { timeout: 10000 },
  );
  const overviewCredits = await page.locator('[data-overview-metric="credits"]').innerText();
  const overviewTotal = await page.locator('[data-revenue-metric="total"]').first().innerText();
  await page.locator('[name="analytics_window"]').selectOption("empty");
  await page.locator("[data-analytics-apply]").click();
  await page.locator("[data-analytics-empty]").waitFor({ state: "visible", timeout: 5000 });
  assert(await page.locator("[data-analytics-content]").isVisible(), "empty window hid snapshot analytics content");
  assert(await page.locator('[data-export-query="analytics"]').isVisible(), "empty window hid calendar export");
  assert(metricNumber(await page.locator('[data-analytics-metric="active"]').innerText()) === "1", "empty window did not write snapshot authorizations");
  assert(metricNumber(await page.locator('[data-analytics-metric="credits"]').innerText()) === "0", "empty window did not empty window net consumed");
  assert((await page.locator('[data-overview-metric="credits"]').innerText()) === overviewCredits, "empty window rewrote overview quota consumption");
  assert((await page.locator('[data-revenue-metric="total"]').first().innerText()) === overviewTotal, "empty window rewrote overview calendar revenue");
  const emptyText = await page.locator("[data-analytics-empty]").innerText();
  assert(emptyText.includes("时间窗口"), `empty copy did not stay local to the window: ${emptyText}`);
  assert(!emptyText.includes("没有运营数据"), `empty copy still claimed the platform had no operations: ${emptyText}`);
  const breakdownText = await page.locator("[data-analytics-breakdown]").innerText();
  assert(!breakdownText.includes("Tool"), `empty window kept the previous software breakdown: ${breakdownText}`);
  const chartValue = await page.locator(".bar-chart b").first().innerText();
  assert(metricNumber(chartValue) === "0", `empty window kept previous chart activations: ${chartValue}`);
  assert(summaryGets.includes("empty"), `empty window did not request summary: ${JSON.stringify(summaryGets)}`);
  await page.unroute(/\/api\/v1\/manage\/analytics\/summary\/?/);
  const mockedNetworkErrors = consoleErrors.splice(consoleStart);
  mockedNetworkErrors.forEach((text) => {
    if (!/manage\/analytics\/summary|Failed to load resource/i.test(text)) {
      consoleErrors.push(text);
    }
  });
}

async function exerciseEmptyDownstreamKeepsSignals() {
  const consoleStart = consoleErrors.length;
  await page.goto(`${base}/downstream.html`, { waitUntil: "domcontentloaded" });
  await waitForPreview();
  await page.context().addCookies([{ name: "csrftoken", value: "preview-csrf", url: base }]);
  await page.route(/\/api\/v1\/downstream\/analytics\/summary\/?/, async (route) => {
    const empty = /[?&]window=empty(?:&|$)/.test(route.request().url());
    await route.fulfill({
      status: 200,
      contentType: "application/json",
      body: JSON.stringify({
        has_data: !empty,
        revenue: { today: 8, month: 8, total: empty ? 15 : 22 },
        downstream: { balance: 85, active: 1, issued: 3, reclaimable: 2 },
        filters: { software: [] },
      }),
    });
  });
  await page.evaluate(() => {
    window.__b1ApiActive = true;
  });
  const disclosure = page.locator("[data-downstream-metrics-disclosure]");
  if (!(await disclosure.getAttribute("open"))) await disclosure.locator("summary").click();
  await page.locator('[name="downstream_metrics_window"]').selectOption("empty");
  await page.locator("[data-downstream-metrics-apply]").click();
  await page.locator("[data-downstream-metrics-empty]").waitFor({ state: "visible", timeout: 5000 });
  assert(await page.locator(".downstream-signals").isVisible(), "downstream empty window hid snapshot signals");
  assert(metricNumber(await page.locator('[data-downstream-metric="balance"]').innerText()) === "85", "downstream empty window hid or cleared balance");
  const emptyText = await page.locator("[data-downstream-metrics-empty]").innerText();
  assert(!emptyText.includes("没有经营数据"), `downstream empty copy still claimed no operating data: ${emptyText}`);
  await page.unroute(/\/api\/v1\/downstream\/analytics\/summary\/?/);
  const mockedNetworkErrors = consoleErrors.splice(consoleStart);
  mockedNetworkErrors.forEach((text) => {
    if (!/downstream\/analytics\/summary|Failed to load resource/i.test(text)) {
      consoleErrors.push(text);
    }
  });
}

async function exerciseRecentCardsStayUnfiltered() {
  await page.goto(`${base}/downstream.html`, { waitUntil: "domcontentloaded" });
  await waitForPreview();
  const heading = await page.locator('[data-screen-panel="workspace"] .panel-heading h2').filter({ hasText: "最近" }).innerText();
  assert(heading.includes("3"), `recent cards heading still unlabeled: ${heading}`);
  const skeleton = await page.locator("[data-downstream-recent-cards]").innerText();
  assert(!skeleton.includes("当前还没有授权卡密"), `recent empty copy still claims zero inventory: ${skeleton}`);
  assert(skeleton.includes("全部卡密"), `recent empty copy lost the full-list pointer: ${skeleton}`);
}

function licenseCardFixture(status, suffix, extra = {}) {
  return {
    public_id: `card-${suffix}`,
    status,
    status_label: status === "unused" ? "未激活" : status === "activated" ? "已激活" : status,
    masked_code: `••••-••••-${suffix}`,
    code_suffix: suffix,
    software_name: "DemoSoft",
    plan_name: "月卡",
    duration_label: "30 天",
    quota_cost: 10,
    activation_rule: status === "unused" ? "激活后 30 天" : "2026-10-01 到期",
    expires_at: extra.expires_at || null,
  };
}

async function exerciseLicenseStatusFilterAndChips() {
  const unusedItem = licenseCardFixture("unused", "UNUS");
  const activatedItem = licenseCardFixture("activated", "ACTV");
  const consoleStart = consoleErrors.length;
  const downstreamQueries = [];
  await page.goto(`${base}/downstream.html`, { waitUntil: "domcontentloaded" });
  await waitForPreview();
  const downstreamScope = page.locator('[data-record-view-scope="downstream-licenses"] [data-record-panel="items"]');
  assert((await downstreamScope.locator('[data-credential-filter="codeStatus"]').count()) === 1, "downstream license table missing status filter");
  assert((await downstreamScope.locator("thead").innerText()).includes("状态"), "downstream license table missing status column");
  const defaultSummary = await downstreamScope.locator("[data-record-scope-summary]").innerText();
  assert(!defaultSummary.includes("未激活"), `downstream summary still claims unused by default: ${defaultSummary}`);
  await page.route(/\/api\/v1\/downstream\/licenses\/cards\/?(?:\?.*)?$/, async (route) => {
    const href = route.request().url();
    if (href.includes("reclaim") || href.includes("search") || href.includes("export")) {
      await route.fallback();
      return;
    }
    const statusMatch = /[?&]status=([^&]*)/.exec(href);
    const status = statusMatch ? decodeURIComponent(statusMatch[1]) : "";
    downstreamQueries.push(status);
    const items = status === "unused" ? [unusedItem] : [unusedItem, activatedItem];
    await route.fulfill({
      status: 200,
      contentType: "application/json",
      body: JSON.stringify({
        items,
        pagination: { page: 1, page_size: 10, total: items.length, total_pages: 1, has_previous: false, has_next: false },
      }),
    });
  });
  await page.evaluate(() => {
    window.__b1ApiActive = true;
  });
  await page.locator('[data-screen-panel="workspace"] [data-target-credential-status]').click();
  await page.waitForFunction(
    () => {
      const rows = [...document.querySelectorAll('[data-record-view-scope="downstream-licenses"] [data-record-panel="items"] tbody tr[data-public-id]')];
      return rows.length === 1 && Boolean(rows[0].querySelector("span.status")?.textContent.includes("未激活"));
    },
    null,
    { timeout: 10000 },
  );
  assert(downstreamQueries.includes("unused"), `待回收 did not request unused cards: ${JSON.stringify(downstreamQueries)}`);
  assert(!downstreamQueries.includes("未激活"), `待回收 sent Chinese status to list API: ${JSON.stringify(downstreamQueries)}`);
  const unusedChip = await downstreamScope.locator("tbody tr[data-public-id] span.status").innerText();
  assert(unusedChip.includes("未激活"), `downstream chip missing unused label: ${unusedChip}`);
  const unusedSummary = await downstreamScope.locator("[data-record-scope-summary]").innerText();
  assert(unusedSummary.includes("未激活"), `downstream summary not unused after 待回收: ${unusedSummary}`);
  await page.unroute(/\/api\/v1\/downstream\/licenses\/cards\/?(?:\?.*)?$/);
  const adminQueries = [];
  await page.goto(`${base}/manage.html#licenses`, { waitUntil: "domcontentloaded" });
  await waitForPreview();
  const adminScope = page.locator('[data-record-view-scope="management-licenses"] [data-record-panel="items"]');
  assert((await adminScope.locator('[data-credential-filter="codeStatus"]').count()) === 1, "management license table missing status filter");
  assert((await adminScope.locator("thead").innerText()).includes("状态"), "management license table missing status column");
  await page.route(/\/api\/v1\/manage\/licenses\/cards\/?(?:\?.*)?$/, async (route) => {
    const href = route.request().url();
    if (href.includes("reclaim") || href.includes("search") || href.includes("export")) {
      await route.fallback();
      return;
    }
    const statusMatch = /[?&]status=([^&]*)/.exec(href);
    const status = statusMatch ? decodeURIComponent(statusMatch[1]) : "";
    adminQueries.push(status);
    const items = status === "activated" ? [activatedItem] : [unusedItem, activatedItem];
    await route.fulfill({
      status: 200,
      contentType: "application/json",
      body: JSON.stringify({
        items,
        scope: "current",
        pagination: { page: 1, page_size: 10, total: items.length, total_pages: 1, has_previous: false, has_next: false },
      }),
    });
  });
  await page.evaluate(() => {
    window.__b1ApiActive = true;
  });
  await adminScope.locator('[data-credential-filter="codeStatus"]').selectOption("已激活");
  await page.waitForFunction(
    () => {
      const rows = [...document.querySelectorAll('[data-record-view-scope="management-licenses"] [data-record-panel="items"] tbody tr[data-public-id]')];
      return rows.length === 1 && Boolean(rows[0].querySelector("span.status")?.textContent.includes("已激活"));
    },
    null,
    { timeout: 10000 },
  );
  assert(adminQueries.includes("activated"), `admin status filter did not request activated cards: ${JSON.stringify(adminQueries)}`);
  await page.unroute(/\/api\/v1\/manage\/licenses\/cards\/?(?:\?.*)?$/);
  const mockedNetworkErrors = consoleErrors.splice(consoleStart);
  mockedNetworkErrors.forEach((text) => {
    if (!/licenses\/cards|Failed to load resource/i.test(text)) {
      consoleErrors.push(text);
    }
  });
}

async function exerciseActivatedPastExpiryCanArchive() {
  const pastItem = licenseCardFixture("activated", "PAST", { expires_at: "2020-01-01T00:00:00Z" });
  const futureItem = licenseCardFixture("activated", "FUTR", { expires_at: "2036-01-01T00:00:00Z" });
  const consoleStart = consoleErrors.length;
  const archivePosts = [];
  await page.goto(`${base}/manage.html#licenses`, { waitUntil: "domcontentloaded" });
  await waitForPreview();
  await page.context().addCookies([{ name: "csrftoken", value: "preview-csrf", url: base }]);
  const adminScope = page.locator('[data-record-view-scope="management-licenses"] [data-record-panel="items"]');
  await page.route(/\/api\/v1\/manage\/licenses\/cards/, async (route) => {
    const href = String(route.request().url() || "");
    const method = String(route.request().method() || "GET").toUpperCase();
    if (href.includes("/archive") && method === "POST") {
      let payload = {};
      try {
        payload = JSON.parse(route.request().postData() || "{}");
      } catch {
        payload = {};
      }
      archivePosts.push(payload);
      await route.fulfill({
        status: 200,
        contentType: "application/json",
        body: JSON.stringify({ archived_count: Array.isArray(payload.card_ids) ? payload.card_ids.length : 0 }),
      });
      return;
    }
    if (href.includes("reclaim") || href.includes("/search") || href.includes("export")) {
      await route.fallback();
      return;
    }
    await route.fulfill({
      status: 200,
      contentType: "application/json",
      body: JSON.stringify({
        items: [pastItem, futureItem],
        scope: "current",
        pagination: { page: 1, page_size: 10, total: 2, total_pages: 1, has_previous: false, has_next: false },
      }),
    });
  });
  await page.evaluate(() => {
    window.__b1ApiActive = true;
  });
  await adminScope.locator('[data-credential-filter="codeStatus"]').selectOption("已激活");
  await page.waitForFunction(
    () =>
      document.querySelectorAll('[data-record-view-scope="management-licenses"] [data-record-panel="items"] tbody tr[data-public-id]').length === 2,
    null,
    { timeout: 10000 },
  );
  await adminScope.locator('tbody tr[data-public-id="card-PAST"] [data-reclaim-select]').check();
  await adminScope.locator("[data-archive-selected]").click();
  const dialog = page.locator("#licenseLifecycleDialog");
  await dialog.waitFor({ state: "visible", timeout: 5000 });
  await dialog.locator('textarea[name="reason"]').fill("到期归档测试");
  await dialog.locator("[data-license-lifecycle-confirm]").click();
  await page.waitForFunction(
    () => {
      const toast = document.querySelector(".toast");
      return Boolean(toast?.classList.contains("is-visible") && toast.textContent.includes("已归档"));
    },
    null,
    { timeout: 10000 },
  );
  assert(archivePosts.length === 1, `past-expiry activated archive did not POST: ${JSON.stringify(archivePosts)}`);
  const archivedIds = archivePosts[0].card_ids || [];
  assert(archivedIds.includes("card-PAST"), `archive POST missing past-expiry card: ${JSON.stringify(archivePosts[0])}`);
  assert(!archivedIds.includes("card-FUTR"), `archive POST included unexpired activated card: ${JSON.stringify(archivePosts[0])}`);
  await page.waitForFunction(
    () =>
      Boolean(
        document.querySelector(
          '[data-record-view-scope="management-licenses"] [data-record-panel="items"] tbody tr[data-public-id="card-FUTR"] [data-reclaim-select]',
        ),
      ),
    null,
    { timeout: 10000 },
  );
  const pastBox = adminScope.locator('tbody tr[data-public-id="card-PAST"] [data-reclaim-select]');
  if (await pastBox.count()) {
    await pastBox.uncheck();
  }
  await adminScope.locator('tbody tr[data-public-id="card-FUTR"] [data-reclaim-select]').check();
  await adminScope.locator("[data-archive-selected]").click();
  await page.waitForFunction(
    () => {
      const toast = document.querySelector(".toast");
      return Boolean(toast?.classList.contains("is-visible") && toast.textContent.includes("没有可归档"));
    },
    null,
    { timeout: 10000 },
  );
  assert(archivePosts.length === 1, `unexpired activated archive POSTed: ${JSON.stringify(archivePosts)}`);
  const dialogStillClosed = await page.evaluate(() => !document.getElementById("licenseLifecycleDialog")?.open);
  assert(dialogStillClosed, "unexpired activated archive opened confirm dialog");
  await page.unroute(/\/api\/v1\/manage\/licenses\/cards/);
  const mockedNetworkErrors = consoleErrors.splice(consoleStart);
  mockedNetworkErrors.forEach((text) => {
    if (!/licenses\/cards|Failed to load resource/i.test(text)) {
      consoleErrors.push(text);
    }
  });
}

function hrefQueryParam(href, name) {
  const match = String(href || "").match(new RegExp(`[?&]${name}=([^&]*)`));
  return match ? decodeURIComponent(match[1]) : "";
}

function authorizationRiskFixture(overrides = {}) {
  const deviceOverrides = overrides.devices;
  const item = {
    authorization_id: "auth-active",
    status: "active",
    status_label: "有效",
    masked_code: "••••-ACTV",
    software_name: "Risk Tool",
    plan_name: "月卡",
    downstream_username: "channel-risk",
    expires_at: "2036-01-01T00:00:00Z",
    activated_at: "2026-01-01T00:00:00Z",
    last_verified_at: "2026-01-01T00:00:00Z",
    audit_reference: "aud-risk",
    devices: [
      {
        device_id: "dev-active",
        device_uuid: "uuid-active",
        installation_id: "GS-RISK-65FB-F502",
        device_code: "GS-RISK-65FB-F502",
        device_label: "GS-RISK-65FB-F502",
        binding_state: "active",
        binding_state_label: "有效",
        risk_state: "normal",
        risk_state_label: "正常",
        action_ref: "ref-active",
        ip: "203.0.113.10",
        bound_at: "2026-01-01T00:00:00Z",
        last_seen_at: "2026-01-01T00:00:00Z",
        binding_history: [],
      },
    ],
    ...overrides,
  };
  if (deviceOverrides) item.devices = deviceOverrides;
  return item;
}

async function exerciseAuthorizationRiskFiltersAndPending() {
  const unboundItem = authorizationRiskFixture({
    authorization_id: "auth-unbound",
    devices: [
      {
        device_id: "dev-unbound",
        device_label: "已解绑设备",
        binding_state: "unbound",
        binding_state_label: "已解绑",
        risk_state: "normal",
        risk_state_label: "正常",
        action_ref: "ref-unbound",
        ip: "203.0.113.11",
        bound_at: "2026-01-01T00:00:00Z",
        last_seen_at: "2026-01-01T00:00:00Z",
        binding_history: [],
      },
    ],
  });
  const blockedBindingItem = authorizationRiskFixture({
    authorization_id: "auth-blocked-binding",
    devices: [
      {
        device_id: "dev-blocked-binding",
        device_label: "封禁绑定设备",
        binding_state: "blocked",
        binding_state_label: "已阻断",
        risk_state: "blocked",
        risk_state_label: "已阻断",
        action_ref: "ref-blocked-binding",
        ip: "203.0.113.12",
        bound_at: "2026-01-01T00:00:00Z",
        last_seen_at: "2026-01-01T00:00:00Z",
        binding_history: [],
      },
    ],
  });
  const instanceBlockedItem = authorizationRiskFixture({
    authorization_id: "auth-instance-blocked",
    status: "blocked",
    status_label: "已阻断",
    devices: [
      {
        device_id: "dev-rollback",
        device_label: "回退设备",
        binding_state: "blocked",
        binding_state_label: "已阻断",
        risk_state: "normal",
        risk_state_label: "正常",
        action_ref: "ref-rollback",
        ip: "203.0.113.13",
        bound_at: "2026-01-01T00:00:00Z",
        last_seen_at: "2026-01-01T00:00:00Z",
        binding_history: [],
      },
    ],
  });
  const consoleStart = consoleErrors.length;
  await page.goto(`${base}/manage.html#risk`, { waitUntil: "domcontentloaded" });
  await waitForPreview();
  await page.route(/\/api\/v1\/manage\/authorizations\/?(?:\?|$)/, async (route) => {
    const href = String(route.request().url() || "");
    const deviceState = hrefQueryParam(href, "device_state");
    const riskState = hrefQueryParam(href, "risk_state");
    const status = hrefQueryParam(href, "status");
    let items = [authorizationRiskFixture()];
    let total = 10;
    let hasNext = true;
    if (riskState === "blocked") {
      items = [];
      total = deviceState === "unbound" || status === "blocked" ? 0 : 2;
      hasNext = total > 0;
    } else if (deviceState === "unbound") {
      items = [unboundItem];
      total = 1;
      hasNext = false;
    } else if (status === "blocked") {
      items = [instanceBlockedItem];
      total = 1;
      hasNext = false;
    } else if (deviceState === "blocked") {
      items = [blockedBindingItem];
      total = 1;
      hasNext = false;
    }
    await route.fulfill({
      status: 200,
      contentType: "application/json",
      body: JSON.stringify({
        items,
        risk_signals: [],
        pagination: {
          page: 1,
          page_size: Number(hrefQueryParam(href, "page_size") || 10),
          total,
          total_pages: 1,
          has_previous: false,
          has_next: hasNext,
          query: hrefQueryParam(href, "q"),
        },
      }),
    });
  });
  await page.evaluate(() => {
    window.__b1ApiActive = true;
  });
  const panel = page.locator('[data-screen-panel="risk"]');
  await panel.locator('[data-risk-filter="device_state"]').selectOption("unbound");
  await page.waitForFunction(
    () => document.querySelectorAll('[data-screen-panel="risk"] tbody tr[data-device-row]').length === 1,
    null,
    { timeout: 10000 },
  );
  const unboundSnapshot = await page.evaluate(() =>
    [...document.querySelectorAll('[data-screen-panel="risk"] tbody tr[data-device-row]')].map((row) => ({
      deviceId: row.dataset.deviceId,
      deviceState: row.dataset.riskDevice,
      authorization: row.dataset.riskAuthorizationLabel,
    })),
  );
  assert(
    unboundSnapshot.every((row) => row.deviceId !== "ref-blocked-binding" && row.deviceState !== "已阻断"),
    `unbound filter still showed a blocked binding: ${JSON.stringify(unboundSnapshot)}`,
  );
  assert(
    unboundSnapshot.some((row) => row.deviceId === "ref-unbound" && row.deviceState === "已解绑"),
    `unbound filter missing unbound row: ${JSON.stringify(unboundSnapshot)}`,
  );
  await panel.locator('[data-risk-filter="device_state"]').selectOption("");
  await panel.locator('[data-risk-filter="status"]').selectOption("blocked");
  await page.waitForFunction(
    () => {
      const row = document.querySelector('[data-screen-panel="risk"] tbody tr[data-device-row]');
      return row?.dataset.authorizationId === "auth-instance-blocked";
    },
    null,
    { timeout: 10000 },
  );
  const blockedChip = await page.evaluate(
    () =>
      document.querySelector('[data-screen-panel="risk"] tbody tr[data-device-row]')?.dataset
        .riskAuthorizationLabel || "",
  );
  assert(!blockedChip.startsWith("正常"), `instance blocked chip still looks normal: ${blockedChip}`);
  assert(blockedChip === "已阻断", `instance blocked chip was ${blockedChip}`);
  await panel.locator('[data-risk-filter="status"]').selectOption("");
  await page.waitForFunction(
    () => {
      const summary = document.querySelector('[data-screen-panel="risk"] .table-result')?.textContent || "";
      return summary.includes("待处理 2");
    },
    null,
    { timeout: 10000 },
  );
  const pendingSummary = await page.evaluate(
    () => document.querySelector('[data-screen-panel="risk"] .table-result')?.textContent || "",
  );
  assert(!pendingSummary.includes("待处理 0"), `pending still counted this page: ${pendingSummary}`);
  const activeRiskRow = panel.locator('tbody tr[data-device-row]').first();
  assert((await activeRiskRow.getAttribute("data-device-code")) === "GS-RISK-65FB-F502", "risk table did not prefer the client device code");
  await activeRiskRow.locator('[data-risk-detail]').click();
  const riskDialog = page.locator("#riskDetailDialog");
  await riskDialog.waitFor({ state: "visible", timeout: 5000 });
  assert((await riskDialog.locator('[data-risk-detail="deviceCode"]').innerText()) === "GS-RISK-65FB-F502", "risk detail omitted the client device code");
  assert((await riskDialog.locator('[data-risk-detail="deviceUuid"]').innerText()) === "uuid-active", "risk detail omitted the platform device UUID");
  await riskDialog.locator('button[value="cancel"]').first().click();
  await page.unroute(/\/api\/v1\/manage\/authorizations\/?(?:\?|$)/);
  const mockedNetworkErrors = consoleErrors.splice(consoleStart);
  mockedNetworkErrors.forEach((text) => {
    if (!/authorizations|Failed to load resource/i.test(text)) {
      consoleErrors.push(text);
    }
  });
}

async function exerciseBlockedDeviceResetToast() {
  const consoleStart = consoleErrors.length;
  const resetPosts = [];
  await page.goto(`${base}/downstream.html#devices`, { waitUntil: "domcontentloaded" });
  await waitForPreview();
  await page.context().addCookies([{ name: "csrftoken", value: "preview-csrf", url: base }]);
  await page.route(/\/api\/v1\/downstream\/(?:devices\/|authorizations\/)/, async (route) => {
    const href = String(route.request().url() || "");
    const method = String(route.request().method() || "GET").toUpperCase();
    if (method === "POST" && href.includes("/reset/")) {
      resetPosts.push(route.request().postData() || "");
      await route.fulfill({
        status: 200,
        contentType: "application/json",
        body: JSON.stringify({
          repeated: true,
          authorization_id: "auth-blocked-reset",
          device: {
            device_id: "dev-masked",
            binding_state: "blocked",
            binding_state_label: "已阻断",
          },
        }),
      });
      return;
    }
    if (method === "GET" && /\/downstream\/devices\/?/.test(href)) {
      await route.fulfill({
        status: 200,
        contentType: "application/json",
        body: JSON.stringify({
          items: [
            {
              authorization_id: "auth-blocked-reset",
              masked_code: "••••-••••-ZZZZ",
              software_name: "测试软件",
              plan_name: "测试套餐",
              device_id: "dev-masked",
              device_action_ref: "ref-blocked-reset",
              binding_state: "blocked",
              binding_state_label: "已阻断",
              risk_state: "blocked",
              risk_state_label: "已阻断",
              last_verified_at: "2026-01-01T00:00:00Z",
              last_seen_at: "2026-01-01T00:00:00Z",
              bound_at: "2026-01-01T00:00:00Z",
              expires_at: "2026-12-01T00:00:00Z",
              status: "active",
              status_label: "有效",
              reset_allowed: true,
            },
          ],
          pagination: {
            page: 1,
            page_size: 10,
            total: 1,
            total_pages: 1,
            has_previous: false,
            has_next: false,
          },
        }),
      });
      return;
    }
    await route.fallback();
  });
  await page.evaluate(() => {
    window.__b1ApiActive = true;
  });
  await page.evaluate(() => {
    document.querySelector("[data-downstream-device-search]")?.dispatchEvent(new Event("change"));
  });
  await page.waitForFunction(
    () => Boolean(document.querySelector('[data-screen-panel="devices"] [data-reset-device]')),
    null,
    { timeout: 10000 },
  );
  await page.locator('[data-screen-panel="devices"] [data-reset-device]').click();
  const dialog = page.locator("#resetDeviceDialog");
  await dialog.waitFor({ state: "visible", timeout: 5000 });
  await dialog.locator('textarea[name="reason"]').fill("客户申请换机");
  await dialog.locator("[data-reset-device-confirm]").click();
  await page.waitForFunction(
    () => {
      const toast = document.querySelector(".toast");
      return Boolean(toast?.classList.contains("is-visible") && toast.textContent.includes("已阻断"));
    },
    null,
    { timeout: 10000 },
  );
  const toastText = await page.evaluate(() => document.querySelector(".toast")?.textContent || "");
  assert(!toastText.includes("已解绑"), `blocked reset toast still says unbound: ${toastText}`);
  assert(!toastText.includes("设备已重置"), `blocked reset toast still says reset: ${toastText}`);
  assert(toastText.includes("已阻断"), `blocked reset toast missing blocked copy: ${toastText}`);
  assert(resetPosts.length === 1, `blocked reset did not POST: ${JSON.stringify(resetPosts)}`);
  await page.unroute(/\/api\/v1\/downstream\/(?:devices\/|authorizations\/)/);
  const mockedNetworkErrors = consoleErrors.splice(consoleStart);
  mockedNetworkErrors.forEach((text) => {
    if (!/downstream\/devices|authorizations|Failed to load resource/i.test(text)) {
      consoleErrors.push(text);
    }
  });
}

async function exercisePlanManagerStatusCopy() {
  const consoleStart = consoleErrors.length;
  await page.goto(`${base}/manage.html#software`, { waitUntil: "domcontentloaded" });
  await waitForPreview();
  await page.context().addCookies([{ name: "csrftoken", value: "preview-csrf", url: base }]);
  await page.route(/\/api\/v1\/manage\/catalog\/?(?:\?|$)/, async (route) => {
    if (route.request().method() !== "GET") {
      await route.fallback();
      return;
    }
    await route.fulfill({
      status: 200,
      contentType: "application/json",
      body: JSON.stringify({
        items: [
          {
            software_id: "gate-software",
            name: "闸门软件",
            status: "active",
            client_connection: "not_connected",
            profiles: [
              {
                profile_id: "stable",
                status: "active",
                policies: [
                  {
                    status: "active",
                    max_devices: 2,
                    verify_interval_seconds: 600,
                    offline_grace_seconds: 3600,
                  },
                ],
              },
            ],
            plans: [
              {
                id: 11,
                name: "正式月卡",
                duration_seconds: 2592000,
                quota_cost: 100,
                test_only: false,
                status: "active",
                latest_snapshot: { snapshot_version: 1, test_only: false },
              },
              {
                id: 12,
                name: "一分钟测试",
                duration_seconds: 60,
                quota_cost: 0,
                test_only: true,
                status: "active",
                latest_snapshot: { snapshot_version: 1, test_only: true },
              },
              {
                id: 13,
                name: "已下架季卡",
                duration_seconds: 7776000,
                quota_cost: 200,
                test_only: false,
                status: "archived",
                latest_snapshot: { snapshot_version: 2, test_only: false },
              },
              {
                id: 14,
                name: "归档测试卡",
                duration_seconds: 60,
                quota_cost: 0,
                test_only: true,
                status: "archived",
                latest_snapshot: { snapshot_version: 1, test_only: true },
              },
            ],
          },
        ],
        pagination: {
          page: 1,
          page_size: 100,
          total: 1,
          total_pages: 1,
          has_previous: false,
          has_next: false,
        },
      }),
    });
  });
  await page.evaluate(() => {
    window.__b1ApiActive = true;
  });
  const loaded = await page.evaluate(async () => {
    if (typeof window.__previewLoadCatalog !== "function") return false;
    await window.__previewLoadCatalog();
    return true;
  });
  assert(loaded, "preview catalog reload hook is missing");
  await page.waitForFunction(
    () => Boolean(document.querySelector('[data-screen-panel="software"] tr[data-catalog-software-id="gate-software"]')),
    null,
    { timeout: 10000 },
  );
  const chips = await page.evaluate(() =>
    [...document.querySelectorAll('[data-screen-panel="software"] .plan-chip:not(.plan-chip-more)')].map(
      (chip) => chip.textContent.trim(),
    ),
  );
  assert(
    JSON.stringify(chips) === JSON.stringify(["正式月卡", "一分钟测试", "已下架季卡", "归档测试卡"]),
    `main table chips are not plan names only: ${JSON.stringify(chips)}`,
  );
  await page.locator('[data-screen-panel="software"] [data-dialog="planManagerDialog"]').click();
  const dialog = page.locator("#planManagerDialog");
  await dialog.waitFor({ state: "visible", timeout: 5000 });
  const rows = await page.evaluate(() =>
    [...document.querySelectorAll("[data-plan-manager-rows] tr[data-plan-manager-row]")].map((row) => ({
      name: row.cells[0]?.textContent.trim() || "",
      status: row.querySelector(".status")?.textContent.trim() || "",
    })),
  );
  const byName = Object.fromEntries(rows.map((row) => [row.name, row.status]));
  assert(byName["正式月卡"] === "可用", `active plan status was ${byName["正式月卡"]}`);
  assert(byName["一分钟测试"] === "仅测试", `test-only plan status was ${byName["一分钟测试"]}`);
  assert(byName["已下架季卡"] === "已归档", `archived plan status was ${byName["已下架季卡"]}`);
  assert(byName["归档测试卡"] === "已归档", `archived test-only plan status was ${byName["归档测试卡"]}`);
  assert(
    rows.every((row) => row.status !== "已暂停"),
    `plan manager still labels a row as paused: ${JSON.stringify(rows)}`,
  );
  await dialog.locator('[value="cancel"]').filter({ visible: true }).last().click();
  await page.unroute(/\/api\/v1\/manage\/catalog\/?(?:\?|$)/);
  const mockedNetworkErrors = consoleErrors.splice(consoleStart);
  mockedNetworkErrors.forEach((text) => {
    if (!/manage\/catalog|Failed to load resource/i.test(text)) {
      consoleErrors.push(text);
    }
  });
}

async function exerciseSoftwareCreateRefreshFailure() {
  const consoleStart = consoleErrors.length;
  await page.goto(`${base}/manage.html#software`, { waitUntil: "domcontentloaded" });
  await waitForPreview();
  await page.context().addCookies([{ name: "csrftoken", value: "preview-csrf", url: base }]);
  await page.locator('[data-screen-panel="software"] [data-dialog="softwareDialog"]').click();
  const dialog = page.locator("#softwareDialog");
  await dialog.waitFor({ state: "visible", timeout: 5000 });
  assert(await dialog.locator("#softwareCode").isVisible(), "software id still hidden until advanced opens");
  await dialog.locator("#softwareName").fill("闸门新建");
  assert(await dialog.locator("#softwareCode").getAttribute("readonly") !== null, "software identity must be generated by the server");
  await dialog.locator("[data-software-rules] summary").click();
  await dialog.locator("#softwareAddPlan").check();
  await dialog.locator("#softwareMaxDevices").fill("1");
  await dialog.locator("#softwareVerifyInterval").fill("15");
  await dialog.locator("#softwareOfflineGrace").fill("0");
  await dialog.locator("#softwarePlanName").fill("月卡");
  await dialog.locator("#softwarePlanDuration").fill("30");
  await dialog.locator("#softwarePlanCost").fill("1");
  await dialog.locator("[data-software-advanced] summary").click();
  await dialog.locator("#softwareProfile").fill("stable");
  await page.route(/\/api\/v1\/manage\/catalog\/?(?:\?|$)/, async (route) => {
    const method = String(route.request().method() || "GET").toUpperCase();
    if (method === "POST") {
      await route.fulfill({
        status: 201,
        contentType: "application/json",
        body: JSON.stringify({
          software: { name: "闸门新建", software_id: "gate-create", client_connection: "not_connected" },
          profile: { profile_id: "stable" },
          plan: { name: "月卡", duration_seconds: 2592000, quota_cost: 1 },
        }),
      });
      return;
    }
    await route.fulfill({
      status: 500,
      contentType: "application/json",
      body: JSON.stringify({ error: { message: "目录读取失败，这句不能当成保存失败。" } }),
    });
  });
  await page.evaluate(() => {
    window.__b1ApiActive = true;
  });
  await dialog.locator("[data-software-save]").click();
  await page.waitForFunction(
    () => {
      const result = document.querySelector('#softwareDialog [data-software-stage="result"]');
      const toast = document.querySelector(".toast");
      return Boolean(result && !result.hidden && toast?.classList.contains("is-visible"));
    },
    null,
    { timeout: 10000 },
  );
  const toastText = await page.evaluate(() => document.querySelector(".toast")?.textContent || "");
  const resultText = await dialog.locator('[data-software-stage="result"]').innerText();
  assert(resultText.includes("已保存"), `create result did not stay saved after catalog refresh failure: ${resultText}`);
  assert(toastText.includes("已保存"), `catalog refresh failure toast missing saved copy: ${toastText}`);
  assert(toastText.includes("请稍后重试"), `catalog refresh failure toast missing retry copy: ${toastText}`);
  assert(!toastText.includes("保存失败"), `catalog refresh failure still reported as save failure: ${toastText}`);
  await dialog.locator('[value="cancel"]').filter({ visible: true }).last().click();
  await page.unroute(/\/api\/v1\/manage\/catalog\/?(?:\?|$)/);
  const mockedNetworkErrors = consoleErrors.splice(consoleStart);
  mockedNetworkErrors.forEach((text) => {
    if (!/manage\/catalog|status of 500|Failed to load resource/i.test(text)) {
      consoleErrors.push(text);
    }
  });
}

async function exerciseEmptyPlanSoftwareCatalog() {
  const consoleStart = consoleErrors.length;
  const licensePosts = [];
  await page.goto(`${base}/downstream.html#software`, { waitUntil: "domcontentloaded" });
  await waitForPreview();
  await page.context().addCookies([{ name: "csrftoken", value: "preview-csrf", url: base }]);
  await page.route(/\/api\/v1\/downstream\/catalog\/?(?:\?|$)/, async (route) => {
    await route.fulfill({
      status: 200,
      contentType: "application/json",
      body: JSON.stringify({
        items: [
          {
            software_id: "gate-paid",
            name: "闸门正式",
            plans: [
              {
                id: 21,
                name: "月卡",
                duration_seconds: 2592000,
                quota_cost: 8,
                test_only: false,
                status: "active",
                latest_snapshot: { snapshot_version: 1, test_only: false },
              },
            ],
          },
          {
            software_id: "gate-empty",
            name: "闸门空套餐",
            plans: [],
          },
        ],
        pagination: {
          page: 1,
          page_size: 100,
          total: 2,
          total_pages: 1,
          has_previous: false,
          has_next: false,
        },
      }),
    });
  });
  await page.route(/\/api\/v1\/downstream\/licenses\/?/, async (route) => {
    if (String(route.request().method() || "GET").toUpperCase() === "POST") {
      licensePosts.push(route.request().url());
      await route.fulfill({
        status: 500,
        contentType: "application/json",
        body: JSON.stringify({ error: { message: "不应发出发卡请求。" } }),
      });
      return;
    }
    await route.fulfill({
      status: 200,
      contentType: "application/json",
      body: JSON.stringify({
        items: [],
        pagination: {
          page: 1,
          page_size: 10,
          total: 0,
          total_pages: 1,
          has_previous: false,
          has_next: false,
        },
      }),
    });
  });
  await page.evaluate(() => {
    window.__b1ApiActive = true;
  });
  const loaded = await page.evaluate(async () => {
    if (typeof window.__previewLoadCatalog !== "function") return false;
    await window.__previewLoadCatalog();
    return true;
  });
  assert(loaded, "preview catalog reload hook is missing");
  await page.waitForFunction(
    () => Boolean(document.querySelector('[data-plan-catalog] article[data-plan-software="gate-paid"]')),
    null,
    { timeout: 10000 },
  );
  await page.locator("[data-plan-catalog-context]").selectOption("gate-empty");
  const emptyText = await page.locator("[data-plan-catalog-empty]").innerText();
  assert(emptyText.includes("请联系管理员"), `empty software catalog missing next-step copy: ${emptyText}`);
  assert(!emptyText.includes("先建套餐"), `empty software catalog told downstream to create plans: ${emptyText}`);
  assert(
    !(await page.locator('[data-plan-catalog] article[data-plan-software="gate-paid"]').isVisible()),
    "paid software cards stayed visible after selecting a software with no plans",
  );
  await openNavigationIfNeeded();
  await page.locator('.side-nav [data-screen="licenses"]').click();
  await page.locator('[data-screen-panel="licenses"] [data-dialog="issueDialog"]').click();
  const dialog = page.locator("#issueDialog");
  await dialog.waitFor({ state: "visible", timeout: 5000 });
  await dialog.locator("#issueSoftware").selectOption("gate-empty");
  await dialog.locator("#issueQuantity").fill("1");
  const submit = dialog.locator("#issueSubmit");
  assert(await submit.isDisabled(), "issue submit stayed enabled without a plan");
  const issueError = await dialog.locator("[data-issue-error]").innerText();
  assert(issueError.includes("请联系管理员"), `empty plan issue error missing next-step copy: ${issueError}`);
  assert(!issueError.includes("先建套餐"), `issue dialog told downstream to create plans: ${issueError}`);
  const unitCost = await dialog.locator("#issueUnitCost").innerText();
  const totalCost = await dialog.locator("#issueCost").innerText();
  assert(unitCost.includes("—"), `empty plan still showed a unit cost: ${unitCost}`);
  assert(!unitCost.includes("0") || unitCost.includes("—"), `empty plan treated missing cost as zero: ${unitCost}`);
  assert(totalCost.includes("—"), `empty plan still showed a total cost: ${totalCost}`);
  await submit.click({ force: true });
  assert(licensePosts.length === 0, `empty plan still posted a license request: ${licensePosts.join(" | ")}`);
  await dialog.locator('[value="cancel"]').filter({ visible: true }).last().click();
  await page.unroute(/\/api\/v1\/downstream\/catalog\/?(?:\?|$)/);
  await page.unroute(/\/api\/v1\/downstream\/licenses\/?/);
  const mockedNetworkErrors = consoleErrors.splice(consoleStart);
  mockedNetworkErrors.forEach((text) => {
    if (!/downstream\/catalog|downstream\/licenses|status of 500|Failed to load resource/i.test(text)) {
      consoleErrors.push(text);
    }
  });
}

async function exerciseIssueGateUsesRedeemedBalance() {
  const consoleStart = consoleErrors.length;
  const previewPosts = [];
  await page.goto(`${base}/downstream.html#ledger`, { waitUntil: "domcontentloaded" });
  await waitForPreview();
  await page.context().addCookies([{ name: "csrftoken", value: "preview-csrf", url: base }]);
  await page.route(/\/api\/v1\/downstream\/credits\/?/, async (route) => {
    if (route.request().method() === "POST") {
      await route.fulfill({
        status: 200,
        contentType: "application/json",
        body: JSON.stringify({
          repeated: false,
          account: { available_balance: 1250 },
          entry: { amount: 1250, balance_after: 1250 },
          card: { status: "redeemed" },
        }),
      });
      return;
    }
    await route.fulfill({
      status: 500,
      contentType: "application/json",
      body: JSON.stringify({ error: { message: "账本读取失败。" } }),
    });
  });
  await page.route(/\/api\/v1\/downstream\/catalog\/?(?:\?|$)/, async (route) => {
    await route.fulfill({
      status: 200,
      contentType: "application/json",
      body: JSON.stringify({
        items: [
          {
            software_id: "gate-paid",
            name: "闸门正式",
            plans: [
              {
                id: 21,
                name: "月卡",
                duration_seconds: 2592000,
                quota_cost: 8,
                test_only: false,
                status: "active",
                latest_snapshot: { snapshot_version: 1, test_only: false },
              },
            ],
          },
        ],
        pagination: {
          page: 1,
          page_size: 100,
          total: 1,
          total_pages: 1,
          has_previous: false,
          has_next: false,
        },
      }),
    });
  });
  await page.route(/\/api\/v1\/downstream\/licenses\/?/, async (route) => {
    await route.fulfill({
      status: 200,
      contentType: "application/json",
      body: JSON.stringify({
        items: [],
        pagination: {
          page: 1,
          page_size: 10,
          total: 0,
          total_pages: 1,
          has_previous: false,
          has_next: false,
        },
      }),
    });
  });
  await page.route(/\/api\/v1\/downstream\/licenses\/preview\/?/, async (route) => {
    previewPosts.push(route.request().url());
    await route.fulfill({
      status: 200,
      contentType: "application/json",
      body: JSON.stringify({
        software_id: "gate-paid",
        snapshot_id: 21,
        quantity: 1,
        quota_cost_per_card: 8,
        total_quota_cost: 8,
        available_balance: 1250,
        sufficient_balance: true,
        balance_after: 1242,
        preview_token: "gate-preview",
      }),
    });
  });
  await page.evaluate(() => {
    window.__b1ApiActive = true;
  });
  const loaded = await page.evaluate(async () => {
    if (typeof window.__previewLoadCatalog !== "function") return false;
    await window.__previewLoadCatalog();
    return true;
  });
  assert(loaded, "preview catalog reload hook is missing");
  await page.locator('[data-screen-panel="ledger"] [data-dialog="redeemDialog"]').click();
  const redeem = page.locator("#redeemDialog");
  assert(await redeem.isVisible(), "redeem dialog did not open");
  await redeem.locator('input[name="quota_code"]').fill("REDEEMGATE1");
  await redeem.locator('[data-success-screen="ledger"]').click();
  await page.locator(".toast.is-visible").waitFor({ timeout: 5000 });
  await openNavigationIfNeeded();
  await page.locator('.side-nav [data-screen="licenses"]').click();
  await page.locator('[data-screen-panel="licenses"] [data-dialog="issueDialog"]').click();
  const dialog = page.locator("#issueDialog");
  await dialog.waitFor({ state: "visible", timeout: 5000 });
  await dialog.locator("#issueSoftware").selectOption("gate-paid");
  await dialog.locator("#issueQuantity").fill("1");
  const issueError = await dialog.locator("[data-issue-error]").innerText();
  assert(!issueError.includes("额度不足"), `redeemed balance still blocked paid issue: ${issueError}`);
  const submit = dialog.locator("#issueSubmit");
  await page.waitForFunction(
    () => {
      const button = document.querySelector("#issueSubmit");
      return Boolean(button) && !button.disabled;
    },
    null,
    { timeout: 5000 },
  );
  assert(!(await submit.isDisabled()), "paid issue stayed disabled after redeeming enough quota");
  const stored = await dialog.evaluate((node) => node.dataset.availableBalance || "");
  assert(stored === "1250", `issue gate stored locale or stale balance: ${stored}`);
  await dialog.locator('[value="cancel"]').filter({ visible: true }).last().click();
  await page.unroute(/\/api\/v1\/downstream\/credits\/?/);
  await page.unroute(/\/api\/v1\/downstream\/catalog\/?(?:\?|$)/);
  await page.unroute(/\/api\/v1\/downstream\/licenses\/preview\/?/);
  await page.unroute(/\/api\/v1\/downstream\/licenses\/?/);
  const mockedNetworkErrors = consoleErrors.splice(consoleStart);
  mockedNetworkErrors.forEach((text) => {
    if (!/downstream\/credits|downstream\/catalog|downstream\/licenses|status of 500|Failed to load resource/i.test(text)) {
      consoleErrors.push(text);
    }
  });
}

function catalogPagePayload(items) {
  return {
    items,
    count: items.length,
    pagination: {
      page: 1,
      page_size: 100,
      total: items.length,
      total_pages: 1,
      has_previous: false,
      has_next: false,
    },
  };
}

function gateReleaseItem(id, version, softwareId, softwareName) {
  return {
    release_id: id,
    version,
    channel: "stable",
    notes: "闸门发布",
    target: "windows",
    arch: "x64",
    status: "published",
    software_id: softwareId,
    software_name: softwareName,
    package_size: 2048,
    package_sha256: "abc",
    profile_id: "stable",
    signature: { status: "declared" },
  };
}

async function exerciseReleaseFilenameDoesNotPretendChecksum() {
  await page.goto(`${base}/manage.html#releases`, { waitUntil: "domcontentloaded" });
  await waitForPreview();
  await page.locator('[data-dialog="releaseDialog"]').click();
  const dialog = page.locator("#releaseDialog");
  await dialog.waitFor({ state: "visible", timeout: 5000 });
  const hashFail = config.release_fixtures.hash_fail || {
    name: "ordinary-hash-fail.zip",
    mimeType: "application/zip",
    buffer: Buffer.from("hash-fail-fixture"),
  };
  await page.locator("#releasePackage").setInputFiles(hashFail);
  const errorText = await dialog.locator("[data-release-error]").innerText();
  assert(!errorText.includes("SHA-256"), `filename heuristic still reported a checksum error: ${errorText}`);
  assert(!errorText.includes("签名验证失败"), `filename heuristic still reported a signature error: ${errorText}`);
  assert(!errorText.includes("Manifest 中的软件"), `filename heuristic still reported a manifest-scope error: ${errorText}`);
  assert(!errorText.includes("没有找到 client-release.v1"), `filename heuristic still reported a missing-manifest error: ${errorText}`);
  await dialog.locator("[data-release-next]").click();
  assert(await dialog.locator('[data-release-stage="upload"]').isVisible(), "hash-fail filename entered the verify stage");
  assert((await dialog.locator("[data-release-error]").innerText()).includes("静态预览"), "hash-fail filename skipped the static no-op");
  await dialog.locator("[value=cancel]").filter({ visible: true }).last().click();
}

async function exerciseReleaseUploadFollowsTableContext() {
  const consoleStart = consoleErrors.length;
  const uploadBodies = [];
  await page.goto(`${base}/manage.html#releases`, { waitUntil: "domcontentloaded" });
  await waitForPreview();
  await page.context().addCookies([{ name: "csrftoken", value: "preview-csrf", url: base }]);
  await page.route(/\/api\/v1\/manage\/catalog\/?(?:\?|$)/, async (route) => {
    if (String(route.request().method() || "GET").toUpperCase() !== "GET") {
      await route.fallback();
      return;
    }
    await route.fulfill({
      status: 200,
      contentType: "application/json",
      body: JSON.stringify(
        catalogPagePayload([
          {
            software_id: "gate-soft-a",
            name: "闸门软件甲",
            status: "active",
            client_connection: "not_connected",
            profiles: [{ profile_id: "stable", status: "active", client_id: "client-a", target: "windows", arch: "x64", channel: "stable" }],
          },
          {
            software_id: "gate-soft-b",
            name: "闸门软件乙",
            status: "active",
            client_connection: "not_connected",
            profiles: [{ profile_id: "stable", status: "active", client_id: "client-b", target: "windows", arch: "x64", channel: "stable" }],
          },
        ]),
      ),
    });
  });
  await page.route(/\/api\/v1\/manage\/releases\//, async (route) => {
    const method = String(route.request().method() || "GET").toUpperCase();
    const url = route.request().url();
    if (method === "POST" && !url.includes("/withdraw/")) {
      const raw = route.request().postData() || (route.request().postDataBuffer() ? Buffer.from(route.request().postDataBuffer()).toString("utf8") : "");
      uploadBodies.push(raw);
      await route.fulfill({
        status: 201,
        contentType: "application/json",
        body: JSON.stringify({
          item: {
            ...gateReleaseItem("rel-upload", "9.9.9", "gate-soft-b", "闸门软件乙"),
            status: "draft",
            package_sha256: "deadbeef",
          },
        }),
      });
      return;
    }
    await route.fulfill({
      status: 200,
      contentType: "application/json",
      body: JSON.stringify(catalogPagePayload([])),
    });
  });
  await page.evaluate(() => {
    window.__b1ApiActive = true;
  });
  const loaded = await page.evaluate(async () => {
    if (typeof window.__previewLoadCatalog !== "function") return false;
    await window.__previewLoadCatalog();
    return true;
  });
  assert(loaded, "preview catalog reload hook is missing");
  await page.waitForFunction(
    () => Boolean(document.querySelector("[data-release-context] option[value='gate-soft-b']")),
    null,
    { timeout: 10000 },
  );
  await page.locator("[data-release-context]").selectOption("gate-soft-b");
  await page.locator('[data-dialog="releaseDialog"]').click();
  const dialog = page.locator("#releaseDialog");
  await dialog.waitFor({ state: "visible", timeout: 5000 });
  const dialogSoftware = await page.locator("#releaseSoftware").inputValue();
  assert(dialogSoftware === "gate-soft-b", `upload dialog software was not copied from the table: ${dialogSoftware}`);
  await page.locator("#releasePackage").setInputFiles(config.release_fixtures.valid);
  await page.waitForFunction(
    () => {
      const button = document.querySelector("#releaseDialog [data-release-next]");
      return Boolean(button && !button.disabled);
    },
    null,
    { timeout: 5000 },
  );
  await dialog.locator("[data-release-next]").click();
  const uploadDeadline = Date.now() + 10000;
  while (Date.now() < uploadDeadline && uploadBodies.length === 0) {
    const err = await dialog.locator("[data-release-error]").innerText();
    if (err.includes("静态预览") || err.includes("校验失败")) break;
    await page.waitForTimeout(100);
  }
  const uploadError = await dialog.locator("[data-release-error]").innerText();
  const apiFlag = await page.evaluate(() => Boolean(window.__b1ApiActive));
  const body = uploadBodies.join("\n");
  assert(
    uploadBodies.length > 0,
    `upload POST missing; api=${apiFlag}; error=${uploadError}; recent=${apiRequests.slice(-8).join(" | ")}`,
  );
  assert(body.includes("gate-soft-b"), `upload POST did not follow the table software: ${body.slice(0, 500)}`);
  await dialog.locator("[value=cancel]").filter({ visible: true }).last().click();
  await page.unroute(/\/api\/v1\/manage\/catalog\/?(?:\?|$)/);
  await page.unroute(/\/api\/v1\/manage\/releases\//);
  const mockedNetworkErrors = consoleErrors.splice(consoleStart);
  mockedNetworkErrors.forEach((text) => {
    if (!/manage\/catalog|manage\/releases|Failed to load resource/i.test(text)) {
      consoleErrors.push(text);
    }
  });
}

async function exerciseWithdrawConfirmResets() {
  const consoleStart = consoleErrors.length;
  const withdrawPosts = [];
  await page.goto(`${base}/manage.html#releases`, { waitUntil: "domcontentloaded" });
  await waitForPreview();
  await page.context().addCookies([{ name: "csrftoken", value: "preview-csrf", url: base }]);
  await page.route(/\/api\/v1\/manage\/catalog\/?(?:\?|$)/, async (route) => {
    if (String(route.request().method() || "GET").toUpperCase() !== "GET") {
      await route.fallback();
      return;
    }
    await route.fulfill({
      status: 200,
      contentType: "application/json",
      body: JSON.stringify(
        catalogPagePayload([
          {
            software_id: "gate-soft-a",
            name: "闸门软件甲",
            status: "active",
            client_connection: "not_connected",
            profiles: [{ profile_id: "stable", status: "active", client_id: "client-a", target: "windows", arch: "x64", channel: "stable" }],
          },
        ]),
      ),
    });
  });
  await page.route(/\/api\/v1\/manage\/releases\//, async (route) => {
    const method = String(route.request().method() || "GET").toUpperCase();
    const url = route.request().url();
    if (method === "POST" && url.includes("/withdraw/")) {
      withdrawPosts.push(url);
      await route.fulfill({
        status: 200,
        contentType: "application/json",
        body: JSON.stringify({ status: "withdrawn", registry_fallback_version: null }),
      });
      return;
    }
    await route.fulfill({
      status: 200,
      contentType: "application/json",
      body: JSON.stringify(
        catalogPagePayload([
          gateReleaseItem("rel-one", "1.0.0", "gate-soft-a", "闸门软件甲"),
          gateReleaseItem("rel-two", "2.0.0", "gate-soft-a", "闸门软件甲"),
        ]),
      ),
    });
  });
  await page.evaluate(() => {
    window.__b1ApiActive = true;
  });
  const loaded = await page.evaluate(async () => {
    if (typeof window.__previewLoadCatalog !== "function") return false;
    await window.__previewLoadCatalog();
    return true;
  });
  assert(loaded, "preview catalog reload hook is missing");
  await page.waitForFunction(
    () => document.querySelectorAll('[data-release-table] [data-dialog="withdrawReleaseDialog"]').length >= 2,
    null,
    { timeout: 10000 },
  );
  await page.locator('[data-release-table] [data-dialog="withdrawReleaseDialog"]').nth(0).click();
  const dialog = page.locator("#withdrawReleaseDialog");
  await dialog.waitFor({ state: "visible", timeout: 5000 });
  await dialog.locator("textarea[name='reason']").fill("第一次撤回原因");
  await dialog.locator("[data-withdraw-confirm]").click();
  await page.waitForFunction(
    () => !document.getElementById("withdrawReleaseDialog")?.open,
    null,
    { timeout: 10000 },
  );
  assert(withdrawPosts.length === 1, `first withdraw did not post exactly once: ${withdrawPosts.join(" | ")}`);
  await page.locator('[data-release-table] [data-dialog="withdrawReleaseDialog"]').nth(1).click();
  await dialog.waitFor({ state: "visible", timeout: 5000 });
  assert(await dialog.locator("[data-withdraw-confirm]").isEnabled(), "withdraw confirm stayed disabled after the first success");
  await dialog.locator("textarea[name='reason']").fill("第二次撤回原因");
  await dialog.locator("[data-withdraw-confirm]").click();
  const secondDeadline = Date.now() + 10000;
  while (Date.now() < secondDeadline && withdrawPosts.length < 2) {
    await page.waitForTimeout(100);
  }
  assert(withdrawPosts.length === 2, `second withdraw did not post: ${withdrawPosts.join(" | ")}`);
  await page.evaluate(() => document.getElementById("withdrawReleaseDialog")?.close("cancel"));
  await page.unroute(/\/api\/v1\/manage\/catalog\/?(?:\?|$)/);
  await page.unroute(/\/api\/v1\/manage\/releases\//);
  const mockedNetworkErrors = consoleErrors.splice(consoleStart);
  mockedNetworkErrors.forEach((text) => {
    if (!/manage\/catalog|manage\/releases|Failed to load resource/i.test(text)) {
      consoleErrors.push(text);
    }
  });
}

async function exerciseReleaseCardPublishedFailureCopy() {
  const consoleStart = consoleErrors.length;
  await page.goto(`${base}/manage.html#releases`, { waitUntil: "domcontentloaded" });
  await waitForPreview();
  await page.context().addCookies([{ name: "csrftoken", value: "preview-csrf", url: base }]);
  await page.route(/\/api\/v1\/manage\/catalog\/?(?:\?|$)/, async (route) => {
    if (String(route.request().method() || "GET").toUpperCase() !== "GET") {
      await route.fallback();
      return;
    }
    await route.fulfill({
      status: 200,
      contentType: "application/json",
      body: JSON.stringify(
        catalogPagePayload([
          {
            software_id: "gate-soft-a",
            name: "闸门软件甲",
            status: "active",
            client_connection: "not_connected",
            profiles: [{ profile_id: "stable", status: "active", client_id: "client-a", target: "windows", arch: "x64", channel: "stable" }],
          },
        ]),
      ),
    });
  });
  await page.route(/\/api\/v1\/manage\/releases\//, async (route) => {
    const url = route.request().url();
    if (String(url).includes("status=published")) {
      await route.fulfill({
        status: 500,
        contentType: "application/json",
        body: JSON.stringify({ error: { message: "已发布列表读取失败。" } }),
      });
      return;
    }
    await route.fulfill({
      status: 200,
      contentType: "application/json",
      body: JSON.stringify(
        catalogPagePayload([gateReleaseItem("rel-live", "3.1.0", "gate-soft-a", "闸门软件甲")]),
      ),
    });
  });
  await page.evaluate(() => {
    window.__b1ApiActive = true;
  });
  const loaded = await page.evaluate(async () => {
    if (typeof window.__previewLoadCatalog !== "function") return false;
    await window.__previewLoadCatalog();
    return true;
  });
  assert(loaded, "preview catalog reload hook is missing");
  await page.waitForFunction(
    () => document.querySelectorAll("[data-release-table] tr[data-release-id]").length >= 1,
    null,
    { timeout: 10000 },
  );
  await page.waitForFunction(
    () => {
      const status = document.querySelector("[data-current-release-status]")?.textContent || "";
      const version = document.querySelector("[data-current-release]")?.textContent || "";
      return status.includes("读取失败") || version.includes("暂时无法读取");
    },
    null,
    { timeout: 10000 },
  );
  const statusText = await page.locator("[data-current-release-status]").innerText();
  const versionText = await page.locator("[data-current-release]").innerText();
  assert(!statusText.includes("暂无发布"), `published GET failure still painted as empty: ${statusText}`);
  assert(statusText.includes("读取失败"), `published GET failure missing failure chip: ${statusText}`);
  assert(!/^—$/.test(versionText.trim()), `published GET failure still used an empty version dash: ${versionText}`);
  assert(versionText.includes("暂时无法读取"), `published GET failure missing retry copy: ${versionText}`);
  await page.unroute(/\/api\/v1\/manage\/catalog\/?(?:\?|$)/);
  await page.unroute(/\/api\/v1\/manage\/releases\//);
  const mockedNetworkErrors = consoleErrors.splice(consoleStart);
  mockedNetworkErrors.forEach((text) => {
    if (!/manage\/catalog|manage\/releases|status of 500|Failed to load resource/i.test(text)) {
      consoleErrors.push(text);
    }
  });
}

async function exerciseStaleDownstreamSupportWrite() {
  const consoleStart = consoleErrors.length;
  const supportPosts = [];
  await page.goto(`${base}/downstream.html#support`, { waitUntil: "domcontentloaded" });
  await waitForPreview();
  await page.context().addCookies([{ name: "csrftoken", value: "preview-csrf", url: base }]);
  await page.route(/\/api\/v1\/downstream\/support\//, async (route) => {
    const method = String(route.request().method() || "GET").toUpperCase();
    const url = route.request().url();
    if (method === "POST") {
      supportPosts.push({
        url,
        body: route.request().postData() || "",
      });
      await route.fulfill({
        status: 200,
        contentType: "application/json",
        body: JSON.stringify({ ok: true }),
      });
      return;
    }
    const isA = url.includes("/support/gate-soft-a/");
    const payload = isA
      ? { support: { purchase_url: "https://gate-a.test/buy", qq: "11111" } }
      : { support: { purchase_url: "https://gate-b.test/buy", qq: "22222" } };
    if (isA) {
      await page.waitForTimeout(800);
    }
    await route.fulfill({
      status: 200,
      contentType: "application/json",
      body: JSON.stringify(payload),
    });
  });
  await page.evaluate(() => {
    window.__b1ApiActive = true;
    const select = document.querySelector("[data-support-context]");
    if (!select) return;
    select.replaceChildren(
      new Option("暂无可用软件", ""),
      new Option("闸门软件甲", "gate-soft-a"),
      new Option("闸门软件乙", "gate-soft-b"),
    );
  });
  const loader = await page.evaluate(() => typeof window.__previewLoadDownstreamSupport === "function");
  assert(loader, "preview downstream support reload hook is missing");
  await page.locator("[data-support-context]").selectOption("gate-soft-a");
  await page.locator("[data-support-save]").click();
  await page.waitForTimeout(200);
  assert(supportPosts.length === 0, `support POST fired before the form finished loading: ${JSON.stringify(supportPosts)}`);
  const pendingToast = await page.locator(".toast").innerText();
  assert(
    pendingToast.includes("还没加载完") || pendingToast.includes("请稍后再保存"),
    `pending support save missing wait copy: ${pendingToast}`,
  );
  await page.locator("[data-support-context]").selectOption("gate-soft-b");
  await page.waitForFunction(
    () => (document.querySelector("[data-support-purchase]")?.value || "").includes("gate-b.test"),
    null,
    { timeout: 10000 },
  );
  await page.waitForTimeout(1000);
  const purchase = await page.locator("[data-support-purchase]").inputValue();
  assert(purchase.includes("gate-b.test"), `stale software A overwrote software B purchase url: ${purchase}`);
  assert(!purchase.includes("gate-a.test"), `software A purchase url leaked into software B: ${purchase}`);
  await page.locator("[data-support-save]").click();
  const saveDeadline = Date.now() + 10000;
  while (Date.now() < saveDeadline && supportPosts.length === 0) {
    await page.waitForTimeout(100);
  }
  assert(supportPosts.length === 1, `expected one support POST after B loaded, got ${JSON.stringify(supportPosts)}`);
  assert(supportPosts[0].url.includes("gate-soft-b"), `support POST did not follow loaded software B: ${supportPosts[0].url}`);
  assert(!supportPosts[0].url.includes("gate-soft-a"), `support POST still targeted software A: ${supportPosts[0].url}`);
  assert(supportPosts[0].body.includes("gate-b.test"), `support POST body was not software B: ${supportPosts[0].body}`);
  assert(!supportPosts[0].body.includes("gate-a.test"), `support POST body still contained software A: ${supportPosts[0].body}`);
  await page.unroute(/\/api\/v1\/downstream\/support\//);
  const mockedNetworkErrors = consoleErrors.splice(consoleStart);
  mockedNetworkErrors.forEach((text) => {
    if (!/downstream\/support|Failed to load resource/i.test(text)) {
      consoleErrors.push(text);
    }
  });
}

async function exerciseInvitationUnusedUsedTime() {
  const consoleStart = consoleErrors.length;
  await page.goto(`${base}/manage.html#downstreams`, { waitUntil: "domcontentloaded" });
  await waitForPreview();
  await page.locator('[data-work-view-scope="downstream-management"] [data-work-view="invitations"]').click();
  await waitForPreview();
  await page.context().addCookies([{ name: "csrftoken", value: "preview-csrf", url: base }]);
  await page.route(/\/api\/v1\/manage\/invitations/, async (route) => {
    if (route.request().method() !== "GET") {
      await route.continue();
      return;
    }
    await route.fulfill({
      status: 200,
      contentType: "application/json",
      body: JSON.stringify({
        items: [
          {
            public_id: "inv-unused-1",
            masked_code: "••••-••••-ABCD",
            code_suffix: "ABCD",
            status: "issued",
            consumed_at: null,
            expires_at: null,
            consumed_username: "",
          },
          {
            public_id: "inv-unused-exp",
            masked_code: "••••-••••-EFGH",
            code_suffix: "EFGH",
            status: "issued",
            consumed_at: null,
            expires_at: "2099-01-01T00:00:00Z",
            consumed_username: "",
          },
          {
            public_id: "inv-used-1",
            masked_code: "••••-••••-IJKL",
            code_suffix: "IJKL",
            status: "consumed",
            consumed_at: "2026-09-01T12:00:00Z",
            expires_at: null,
            consumed_username: "channel-a",
          },
        ],
        pagination: { page: 1, total_pages: 1, has_previous: false, has_next: false },
      }),
    });
  });
  const loader = await page.evaluate(async () => {
    window.__b1ApiActive = true;
    if (typeof window.__previewLoadInvitations !== "function") return false;
    await window.__previewLoadInvitations(1);
    return true;
  });
  assert(loader, "preview invitation reload hook is missing");
  await page.waitForFunction(
    () => document.querySelectorAll("[data-invite-item-table] tr").length >= 3,
    null,
    { timeout: 10000 },
  );
  const unused = await page.locator("[data-invite-item-table] tr").nth(0).locator("td").nth(4).innerText();
  const unusedWithExpiry = await page.locator("[data-invite-item-table] tr").nth(1).locator("td").nth(4).innerText();
  const used = await page.locator("[data-invite-item-table] tr").nth(2).locator("td").nth(4).innerText();
  assert(!unused.includes("永久有效"), `unused invitation used-time still says permanent: ${unused}`);
  assert(unused.includes("尚未使用") || unused.trim() === "—", `unused invitation used-time is not empty-state copy: ${unused}`);
  assert(!unusedWithExpiry.includes("永久有效"), `unused invitation with expires_at still says permanent: ${unusedWithExpiry}`);
  assert(!unusedWithExpiry.includes("2099"), `unused invitation used-time reused expires_at: ${unusedWithExpiry}`);
  assert(used.includes("2026"), `consumed invitation used-time lost consumed_at: ${used}`);
  await page.unroute(/\/api\/v1\/manage\/invitations/);
  const mockedNetworkErrors = consoleErrors.splice(consoleStart);
  mockedNetworkErrors.forEach((text) => {
    if (!/manage\/invitations|Failed to load resource/i.test(text)) {
      consoleErrors.push(text);
    }
  });
}

async function exerciseDialogSkeletons() {
  const dialogs = [
    ["manage", "software", "softwareDialog"],
    ["manage", "downstreams", "downstreamCreateDialog"],
    ["manage", "credits", "quotaCardDialog"],
    ["downstream", "licenses", "issueDialog"],
    ["downstream", "ledger", "redeemDialog"],
  ];
  for (const [entry, screen, dialogId] of dialogs) {
    await page.goto(`${base}/${entry}.html#${screen}`, { waitUntil: "domcontentloaded" });
    await waitForPreview();
    const opener = page.locator(`[data-screen-panel="${screen}"] [data-dialog="${dialogId}"]`).filter({ visible: true }).first();
    if ((await opener.count()) === 0) continue;
    await opener.click();
    const dialog = page.locator(`#${dialogId}`);
    assert(await dialog.isVisible(), `${entry}/${dialogId}: dialog did not open`);
    await dialog.locator('[value="cancel"]').filter({ visible: true }).last().click();
  }
}

async function exerciseScreenshots() {
  const targets = [
    ["manage-login.html", "manage-login.png"],
    ["manage.html#backup", "manage-backup.png"],
    ["manage.html#audit", "manage-audit.png"],
    ["manage.html#downstreams", "manage-downstreams.png"],
    ["manage.html#credits", "manage-credit-ledger.png"],
    ["manage.html#analytics", "manage-analytics.png"],
    ["manage.html#licenses", "manage-license-registry.png"],
    ["downstream.html#software", "downstream-software.png"],
    ["downstream.html#devices", "downstream-devices.png"],
  ];
  for (const [url, name] of targets) {
    await page.goto(`${base}/${url}`, { waitUntil: "domcontentloaded" });
    await waitForPreview();
    await assertNoStaticMarkers(url);
    await captureSettled(name);
  }
}

const suite = config.suite;
let navigationCount = 0;

if (suite === "navigation") {
  navigationCount += await exerciseNavigation("manage", "overview");
  navigationCount += await exerciseNavigation("downstream", "workspace");
  await exerciseEmptySurfaces("manage", "overview", ["software", "downstreams", "credits", "licenses", "risk", "client", "releases", "audit", "backup"]);
  await exerciseEmptySurfaces("downstream", "workspace", ["licenses", "devices", "ledger", "software", "support", "activity"]);
} else if (suite === "catalog") {
  await exerciseStaticActionGuards();
  await exerciseDialogSkeletons();
  await exerciseRedeemRefreshFailureCopy();
  await exerciseRedeemResetsLedgerPage();
  await exerciseIssueGateUsesRedeemedBalance();
  await exerciseQuotaRevokePartialSuccess();
  await exerciseExactSearchOverlayGuards();
  await exerciseEmptyAnalyticsKeepsSnapshot();
  await exerciseEmptyDownstreamKeepsSignals();
  await exerciseRecentCardsStayUnfiltered();
  await exerciseLicenseStatusFilterAndChips();
  await exerciseActivatedPastExpiryCanArchive();
  await exerciseAuthorizationRiskFiltersAndPending();
  await exerciseBlockedDeviceResetToast();
  await exercisePlanManagerStatusCopy();
  await exerciseSoftwareCreateRefreshFailure();
  await exerciseEmptyPlanSoftwareCatalog();
  await exerciseReleaseFilenameDoesNotPretendChecksum();
  await exerciseReleaseUploadFollowsTableContext();
  await exerciseWithdrawConfirmResets();
  await exerciseReleaseCardPublishedFailureCopy();
  await exerciseStaleDownstreamSupportWrite();
  await exerciseInvitationUnusedUsedTime();
} else if (suite === "diagnostics") {
  await exerciseEmptyFilters();
  await exerciseStaticLicenseDeviceCodeSearch();
  await exerciseViewStates();
} else if (suite === "finish") {
  await exerciseDialogSkeletons();
  await exerciseScreenshots();
} else {
  throw new Error(`Unknown UI preview acceptance suite: ${suite}`);
}

assert(consoleErrors.length === 0, `browser console errors: ${consoleErrors.join(" | ")}`);
assert(suite !== "navigation" || navigationCount === 15, `expected 15 primary navigation entries, got ${navigationCount}`);
return `UI preview acceptance passed: ${suite} at ${viewport.width}x${viewport.height}`;
