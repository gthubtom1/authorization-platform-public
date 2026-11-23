(function () {
  "use strict";

  document.documentElement.classList.add("has-js");

  const toast = document.querySelector(".toast");
  const defaultScreen = document.body.dataset.defaultScreen || "overview";
  const navToggle = document.querySelector(".nav-toggle");
  const sideNav = document.querySelector(".side-nav");
  let toastTimer;
  let pendingDialogToast = "";

  function showToast(message, durationMs) {
    if (!toast || !message) return;
    const dialog = document.querySelector("dialog[open]");
    if (dialog) {
      let feedback = dialog.querySelector("[data-dialog-feedback]");
      if (!feedback) {
        feedback = document.createElement("p");
        feedback.className = "dialog-feedback";
        feedback.dataset.dialogFeedback = "";
        feedback.setAttribute("role", "status");
        feedback.setAttribute("aria-live", "polite");
        // Keep feedback outside wizard stages, including stages now hidden
        // after a committed write. The dialog title is visible in every step.
        const title = dialog.querySelector("h2");
        if (title) title.after(feedback);
        else (dialog.querySelector("form") || dialog).prepend(feedback);
      }
      feedback.textContent = message;
      toast.classList.remove("is-visible");
      window.clearTimeout(toastTimer);
      return;
    }
    toast.textContent = message;
    toast.classList.add("is-visible");
    window.clearTimeout(toastTimer);
    toastTimer = window.setTimeout(
      () => toast.classList.remove("is-visible"),
      Number(durationMs) > 0 ? Number(durationMs) : 2800,
    );
  }

  try {
    const restoreNotice = window.sessionStorage.getItem("restoreNotice");
    if (restoreNotice) {
      window.sessionStorage.removeItem("restoreNotice");
      showToast(restoreNotice, 8000);
    }
  } catch (_storageError) {
    /* ignore quota / private mode */
  }

  const API_ROOT = "/api/v1";
  const isStandaloneStaticPreview =
    ["127.0.0.1", "localhost"].includes(window.location.hostname) &&
    window.location.port !== "" &&
    window.location.port !== "8123";
  const isLiveProtectedPage =
    !isStandaloneStaticPreview &&
    (document.body.classList.contains("role-admin") ||
      document.body.classList.contains("role-downstream"));

  // Selection belongs to stable business IDs, independently of the current page.
  const recordSelections = new Map();
  const pendingUiWrites = new Map();

  function recordScope(panel) {
    return panel?.closest("[data-record-view-scope]")?.dataset.recordViewScope || "";
  }

  function recordSelection(panel) {
    const scope = recordScope(panel);
    if (!scope) return null;
    if (!recordSelections.has(scope)) recordSelections.set(scope, { rows: new Map(), generation: 0, busy: false });
    return recordSelections.get(scope);
  }

  function selectedRecordRows(panel) {
    return Array.from(recordSelection(panel)?.rows.values() || []);
  }

  function selectedRecordBoxes(panel) {
    return selectedRecordRows(panel).map((row) => row.querySelector("[data-reclaim-select]")).filter(Boolean);
  }

  function syncRecordSelection(panel) {
    const selection = recordSelection(panel);
    if (!selection) return;
    panel.querySelectorAll("tbody [data-reclaim-select]").forEach((box) => {
      const row = box.closest("tr");
      const id = row?.dataset.publicId;
      box.checked = !box.disabled && selection.rows.has(id);
      if (box.checked) selection.rows.set(id, row);
    });
    const count = selection.rows.size;
    const onPage = Array.from(panel.querySelectorAll("tbody [data-reclaim-select]:checked"))
      .filter((box) => !box.closest("tr").hidden).length;
    const summary = panel.querySelector("[data-record-selection-summary]");
    if (summary) summary.textContent = `已选 ${count} 条${count > onPage ? ` · 本页 ${onPage} 条` : ""}`;
    const boxes = selectedRecordBoxes(panel);
    const archiveStatuses = recordScope(panel) === "invitations" ? ["consumed","revoked","expired"] : recordScope(panel) === "quota-cards" ? ["redeemed","revoked"] : ["expired","reclaimed","revoked"];
    panel.querySelectorAll("[data-archive-selected]").forEach((button) => {
      button.disabled = selection.busy || !boxes.some((box) => archiveStatuses.includes(box.dataset.cardStatus) || (box.dataset.cardStatus === "activated" && licenseCardExpiryHasPassed(box)));
    });
    panel.querySelectorAll("[data-delete-selected]").forEach((button) => { button.disabled = selection.busy || !boxes.some((box) => box.dataset.cardStatus === "archived"); });
    panel.querySelectorAll("[data-record-clear]").forEach((button) => { button.disabled = count === 0 || selection.busy; });
    const reclaim = panel.querySelector("[data-reclaim-selected]");
    if (reclaim) reclaim.disabled = selection.busy || !selectedRecordBoxes(panel).some((box) => box.dataset.cardStatus === "unused");
    const revoke = panel.querySelector("[data-quota-revoke-selected], [data-invitation-revoke-selected]");
    if (revoke) revoke.disabled = selection.busy || !selectedRecordBoxes(panel).some((box) => box.dataset.cardStatus === "issued");
    const all = panel.querySelector("[data-record-select-filtered]");
    if (all) { all.disabled = selection.busy; all.textContent = selection.busy ? "正在读取选择范围…" : "选择全部筛选结果"; }
    syncGenericSelectAll(panel.querySelector("table"));
  }

  function clearRecordSelection(panel) {
    const selection = recordSelection(panel);
    if (!selection) return;
    selection.generation += 1;
    selection.busy = false;
    selection.rows.clear();
    syncRecordSelection(panel);
  }

  function clearCompletedRecordSelection(panel, ids) {
    const rows = recordSelection(panel)?.rows;
    (ids || []).forEach((id) => rows?.delete(String(id)));
    syncRecordSelection(panel);
  }

  function resumeDialogWrite(dialog, scope) {
    const pending = pendingUiWrites.get(scope);
    if (!pending) return false;
    Object.assign(dialog, pending.context);
    if (!dialog.open) dialog.showModal();
    restoreDialogWrite(dialog);
    return true;
  }

  function prepareDialogWrite(dialog, scope, ids) {
    dialog.__writeScope = scope;
    const pending = pendingUiWrites.get(scope);
    dialog.__selectedIds = pending ? pending.ids.slice() : ids.map(String);
    return pending;
  }

  function restoreDialogWrite(dialog) {
    const pending = pendingUiWrites.get(dialog.__writeScope);
    // A shared dialog can have displayed a different operation in between.
    // Restore the confirmation meaning together with the frozen request.
    if (pending) {
      if (dialog.__writeScope === "release:external") showReleaseStage("upload", 0);
      Object.entries(pending.context.__writePresentation || {}).forEach(([selector, text]) => {
        const element = dialog.querySelector(selector);
        if (element) element.textContent = text;
      });
    }
    dialog.querySelectorAll("input, select, textarea").forEach((field) => {
      if (field.type === "checkbox") return;
      const key = field.id || field.name;
      if (pending && Object.prototype.hasOwnProperty.call(pending.fields, key)) field.value = pending.fields[key];
      if (field.tagName === "SELECT") field.disabled = Boolean(pending);
      else field.readOnly = Boolean(pending);
    });
    let notice = document.querySelector(`[data-pending-write="${CSS.escape(dialog.__writeScope || "")}"]`);
    if (pending && !notice) {
      notice = document.createElement("button");
      notice.type = "button"; notice.className = "text-button pending-write-retry";
      notice.dataset.pendingWrite = dialog.__writeScope;
      notice.addEventListener("click", () => resumeDialogWrite(dialog, notice.dataset.pendingWrite));
      const active = document.querySelector(".screen.is-visible .selection-actions, .screen.is-visible .page-heading .heading-actions, .screen.is-visible .page-heading");
      active?.append(notice);
    }
    if (notice) {
      if (pending) notice.textContent = `重试待确认操作（${pending.ids.length} 条）`;
      else notice.remove();
    }
    if (pending) showToast("上次操作结果尚未确认。重试将使用原目标和原请求。", 8000);
  }

  async function submitDialogWrite(dialog, path, body, prefix) {
    const scope = dialog.__writeScope || path;
    let pending = pendingUiWrites.get(scope);
    if (!pending) {
      const fields = {};
      dialog.querySelectorAll("input, select, textarea").forEach((field) => {
        if (field.id || field.name) fields[field.id || field.name] = field.value;
      });
      const context = {};
      Object.keys(dialog).filter((key) => key.startsWith("__")).forEach((key) => { context[key] = dialog[key]; });
      pending = { path, body: JSON.stringify(body), key: requestIdempotencyKey(prefix), ids: (dialog.__selectedIds || []).slice(), fields, context };
      pendingUiWrites.set(scope, pending);
    }
    try {
      const payload = await apiRequest(pending.path, { method: "POST", body: pending.body, headers: { "Idempotency-Key": pending.key } });
      pendingUiWrites.delete(scope);
      restoreDialogWrite(dialog);
      return payload;
    } catch (error) {
      const definitive = error.status >= 400 && error.status < 500 && error.status !== 408 && !error.retryable;
      if (definitive) pendingUiWrites.delete(scope);
      restoreDialogWrite(dialog);
      if (!definitive) { error.operationUncertain = true; error.message = "操作结果尚未确认，请按原请求重试；请勿另建一次操作。"; }
      throw error;
    }
  }

  async function submitRecordRevocations(dialog, basePath, reason) {
    const scope = dialog.__writeScope;
    let pending = pendingUiWrites.get(scope);
    if (!pending) {
      const fields = {}, context = {};
      dialog.querySelectorAll("input, select, textarea").forEach((field) => { if (field.id || field.name) fields[field.id || field.name] = field.value; });
      Object.keys(dialog).filter((key) => key.startsWith("__")).forEach((key) => { context[key] = dialog[key]; });
      const ids = dialog.__selectedIds.slice();
      pending = { ids, fields, context, requests: ids.map((id) => ({id, path: typeof basePath === "function" ? basePath(id) : `${basePath}/${encodeURIComponent(id)}/revoke/`, key: requestIdempotencyKey("credential-revoke"), body: JSON.stringify({reason}), done:false})) };
      pendingUiWrites.set(scope,pending);
    }
    const panel = document.querySelector(`[data-record-view-scope="${scope.split(":")[0]}"] .table-panel`);
    for (const item of pending.requests) {
      if (item.done) continue;
      try {
        await apiRequest(item.path,{method:"POST",body:item.body,headers:{"Idempotency-Key":item.key}});
        item.done = true; item.success = true;
        clearCompletedRecordSelection(panel,[item.id]);
      } catch (error) {
        const definitive = error.status >= 400 && error.status < 500 && error.status !== 408 && !error.retryable;
        if (definitive) { item.done = true; item.error = apiErrorMessage(error,"请求被拒绝"); }
        else {
          restoreDialogWrite(dialog);
          error.operationUncertain = true;
          error.message = `已完成 ${pending.requests.filter((entry) => entry.success).length} 条，另有操作结果尚未确认。请按原请求重试，已完成记录不会重复执行。`;
          throw error;
        }
      }
    }
    pendingUiWrites.delete(scope); restoreDialogWrite(dialog);
    return {succeeded:pending.requests.filter((item) => item.success),failures:pending.requests.filter((item) => !item.success)};
  }

  function revealLiveApp() {
    if (isLiveProtectedPage) {
      document.documentElement.classList.remove("live-auth-pending");
    }
  }

  class ApiRequestError extends Error {
    constructor(message, status = 0, detail = {}) {
      super(message);
      this.name = "ApiRequestError";
      this.status = status;
      this.code = detail.code || "REQUEST_FAILED";
      this.fields = detail.fields || {};
      this.retryable = Boolean(detail.retryable);
      this.requestId = detail.request_id || "";
    }
  }

  function readCookie(name) {
    const prefix = `${name}=`;
    const item = document.cookie
      .split(";")
      .map((part) => part.trim())
      .find((part) => part.startsWith(prefix));
    return item ? decodeURIComponent(item.slice(prefix.length)) : "";
  }

  async function ensureCsrfToken() {
    const existing = readCookie("csrftoken");
    if (existing) return existing;
    const response = await window.fetch(`${API_ROOT}/session/`, {
      credentials: "same-origin",
      headers: {
        Accept: "application/json",
        "X-Request-Id": requestIdempotencyKey("web-request"),
      },
    });
    let payload = {};
    try {
      payload = await response.json();
    } catch {
      payload = {};
    }
    if (!response.ok) {
      throw new ApiRequestError(
        payload?.error?.message || "暂时无法连接授权平台。",
        response.status,
        payload?.error || {},
      );
    }
    const token = readCookie("csrftoken");
    if (!token) throw new ApiRequestError("授权平台没有返回 CSRF 凭证。", 0);
    return token;
  }

  // 「当前分发中版本」要翻完该软件的全部已发布版本才能算准（改版本号会把历史行
  // 提成最新），而列表每次翻页/搜索都会重新算一次。这里按软件缓存 60 秒，并在
  // 任何版本写操作成功后整体作废，避免翻页把同一个软件反复拉几十次。
  const publishedReleaseCache = new Map();
  const PUBLISHED_RELEASE_CACHE_MS = 60000;

  async function apiRequest(path, options = {}) {
    const method = (options.method || "GET").toUpperCase();
    const headers = {
      Accept: "application/json",
      "X-Request-Id": requestIdempotencyKey("web-request"),
      ...(options.headers || {}),
    };
    const requestOptions = {
      ...options,
      method,
      credentials: "same-origin",
      headers,
    };
    if (method !== "GET" && method !== "HEAD" && method !== "OPTIONS") {
      const isFormData =
        typeof FormData !== "undefined" && requestOptions.body instanceof FormData;
      if (!isFormData) headers["Content-Type"] = "application/json";
      headers["X-CSRFToken"] = await ensureCsrfToken();
      if (!headers["Idempotency-Key"]) {
        headers["Idempotency-Key"] = requestIdempotencyKey("web-mutation");
      }
    }
    const response = await window.fetch(`${API_ROOT}${path}`, requestOptions);
    let payload = {};
    try {
      payload = await response.json();
    } catch {
      payload = {};
    }
    if (!response.ok) {
      throw new ApiRequestError(
        payload?.error?.message || "请求没有完成，请稍后重试。",
        response.status,
        payload?.error || {},
      );
    }
    if (method !== "GET" && method !== "HEAD" && method !== "OPTIONS" && /^\/manage\/releases\//.test(path)) {
      publishedReleaseCache.clear();
    }
    return payload;
  }

  function apiErrorMessage(error, fallback = "请求没有完成，请稍后重试。") {
    if (error?.operationUncertain) return error.message;
    if (!(error instanceof ApiRequestError)) return fallback;
    const fieldMessages = Object.values(error.fields || {}).flat();
    if (fieldMessages.length) return fieldMessages[0];
    if (error.status === 401 && error.code !== "AUTHENTICATION_FAILED") {
      return "登录状态已失效，请重新登录。";
    }
    if (error.status === 403) return error.message || "当前账号没有执行此操作的权限。";
    if (error.status === 429 || error.retryable)
      return "尝试过于频繁，请稍后重试。";
    return error.message || fallback;
  }

  function shanghaiYmd(offsetDays = 0) {
    const parts = new Intl.DateTimeFormat("en-CA", {
      timeZone: "Asia/Shanghai",
      year: "numeric",
      month: "2-digit",
      day: "2-digit",
    }).formatToParts(new Date());
    const year = Number(parts.find((part) => part.type === "year")?.value);
    const month = Number(parts.find((part) => part.type === "month")?.value);
    const day = Number(parts.find((part) => part.type === "day")?.value);
    const shifted = new Date(Date.UTC(year, month - 1, day - offsetDays));
    const yy = shifted.getUTCFullYear();
    const mm = String(shifted.getUTCMonth() + 1).padStart(2, "0");
    const dd = String(shifted.getUTCDate()).padStart(2, "0");
    return `${yy}-${mm}-${dd}`;
  }

  function setFormError(form, message) {
    const target = form?.querySelector("[data-form-error]");
    if (target) target.textContent = message || "";
  }

  function workspaceLandingUrl(destination) {
    const raw = String(destination || "");
    const hashIndex = raw.indexOf("#");
    if (hashIndex >= 0) return raw;
    const path = raw.split("?")[0];
    const file = path.split("/").pop() || path;
    if (file === "manage.html") return `${raw}#overview`;
    if (file === "downstream.html") return `${raw}#workspace`;
    return raw;
  }

  function registeredLoginUrl(destination) {
    const raw = String(destination || "downstream-login.html");
    try {
      const url = new URL(raw, window.location.href);
      url.searchParams.set("registered", "1");
      const file = url.pathname.split("/").pop() || raw.split("?")[0].split("#")[0];
      return `${file}${url.search}${url.hash}`;
    } catch (error) {
      const [withoutHash, hash = ""] = raw.split("#");
      const joiner = withoutHash.includes("?") ? "&" : "?";
      return `${withoutHash}${joiner}registered=1${hash ? `#${hash}` : ""}`;
    }
  }

  function revealRegisteredNotice() {
    if (new URLSearchParams(window.location.search).get("registered") !== "1") return;
    document.querySelectorAll("[data-register-success]").forEach((node) => {
      node.hidden = false;
    });
  }

  revealRegisteredNotice();

  function offerRegistrationLogout(form, session) {
    if (!form || form.parentElement?.querySelector("[data-register-session-action]")) return;
    const button = document.createElement("button");
    button.type = "button";
    button.className = "button button-secondary access-submit";
    button.dataset.registerSessionAction = "";
    button.textContent = "退出当前账号并继续注册";
    button.addEventListener("click", async () => {
      button.disabled = true;
      try {
        await apiRequest("/auth/logout/", { method: "POST", body: "{}" });
        window.location.reload();
      } catch (error) {
        button.disabled = false;
        setFormError(form, apiErrorMessage(error, "当前账号退出失败，请重试。"));
      }
    });
    form.after(button);
    const roleLabel = session?.role === "platform_admin" ? "管理员" : "下游账号";
    setFormError(form, `当前浏览器已登录${roleLabel}。请先退出当前账号，再使用邀请码注册。`);
  }

  function requestIdempotencyKey(prefix) {
    if (window.crypto?.randomUUID) return `${prefix}-${window.crypto.randomUUID()}`;
    return `${prefix}-${Date.now()}-${Math.random().toString(16).slice(2)}`;
  }

  function updateQuery(updates) {
    const url = new URL(window.location.href);
    Object.entries(updates).forEach(([key, value]) => {
      if (value === null || value === undefined || value === "")
        url.searchParams.delete(key);
      else url.searchParams.set(key, String(value));
    });
    window.history.replaceState(window.history.state, "", url);
  }

  function clearTransientQuery() {
    updateQuery({
      page: null,
      q: null,
      filter: null,
      criteria: null,
      view: null,
      code: null,
      credential: null,
    });
  }

  const QUOTA_PURCHASE_KEY = "previewQuotaPurchaseUrl";

  function applyQuotaPurchaseLink(url, options = {}) {
    const resolved = url || "";
    if (options.keepOnEmpty && !resolved) return;
    const input = document.querySelector("[data-quota-purchase-input]");
    if (input && document.activeElement !== input) input.value = resolved;
    document.querySelectorAll("[data-quota-purchase-link]").forEach((link) => {
      const usable = /^https?:\/\//i.test(resolved);
      link.hidden = !usable;
      if (usable) link.href = resolved;
    });
    document.querySelectorAll("[data-quota-purchase-note]").forEach((note) => {
      note.hidden = !/^https?:\/\//i.test(resolved);
    });
  }

  applyQuotaPurchaseLink("");
  document
    .querySelector("[data-quota-purchase-save]")
    ?.addEventListener("click", async (event) => {
      const button = event.currentTarget;
      const input = document.querySelector("[data-quota-purchase-input]");
      const value = (input?.value || "").trim();
      if (value && !/^https?:\/\//i.test(value)) {
        showToast("购买链接必须是 http 或 https 地址。");
        return;
      }
      if (isStandaloneStaticPreview) {
        applyQuotaPurchaseLink("");
        showToast("静态预览不保存真实购买链接。");
        return;
      }
      button.disabled = true;
      try {
        const payload = await apiRequest("/manage/credits/settings/", {
          method: "POST",
          headers: { "Idempotency-Key": requestIdempotencyKey("quota-settings") },
          body: JSON.stringify({ purchase_url: value }),
        });
        window.localStorage.removeItem(QUOTA_PURCHASE_KEY);
        applyQuotaPurchaseLink(payload.purchase_url || "");
        showToast(value ? "给下游买额度的网站已保存，下游登录、注册和工作台会同步显示。" : "已清空给下游买额度的网站。");
      } catch (error) {
        showToast(apiErrorMessage(error, "给下游买额度的网站保存失败，请重试。"));
      } finally {
        button.disabled = false;
      }
    });

  function navigationLabel(link) {
    const copy = link.cloneNode(true);
    copy
      .querySelectorAll("[aria-hidden='true']")
      .forEach((item) => item.remove());
    return copy.textContent.trim();
  }

  document.querySelectorAll("[data-preview-destination]").forEach((form) => {
    const passwordBox = form.elements?.password;
    if (passwordBox && passwordBox.type === "password" && !form.querySelector("[data-password-toggle]")) {
      const toggle = document.createElement("button");
      toggle.type = "button";
      toggle.dataset.passwordToggle = "";
      toggle.className = "button button-secondary button-small";
      toggle.textContent = "显示密码";
      toggle.setAttribute("aria-label", "显示或隐藏密码");
      toggle.style.marginTop = "4px";
      toggle.addEventListener("click", () => {
        const show = passwordBox.type === "password";
        passwordBox.type = show ? "text" : "password";
        toggle.textContent = show ? "隐藏密码" : "显示密码";
      });
      passwordBox.after(toggle);
    }
    form.addEventListener("submit", async (event) => {
      event.preventDefault();
      const isRegister = Boolean(form.elements.invitation_code);
      if (isRegister && (form.dataset.registerInFlight === "1" || form.dataset.registerSucceeded === "1")) {
        return;
      }
      const error = form.querySelector("[data-form-error]");
      const password = form.elements.password;
      const confirmation = form.elements.password_confirm;
      if (!form.checkValidity()) {
        if (error) error.textContent = "请完整填写标记为必填的内容。";
        form.reportValidity();
        return;
      }
      const usernameBox = form.elements.username;
      if (usernameBox && !String(usernameBox.value || "").trim() && !isRegister) {
        if (error) error.textContent = "请完整填写标记为必填的内容。";
        usernameBox.focus();
        return;
      }
      const passwordBox = form.elements.password;
      if (passwordBox && !String(passwordBox.value || "").trim()) {
        if (error) error.textContent = "请完整填写标记为必填的内容。";
        passwordBox.focus();
        return;
      }
      if (confirmation && password.value !== confirmation.value) {
        confirmation.setCustomValidity("两次输入的密码不一致");
        if (error) error.textContent = "两次输入的密码不一致，请重新确认。";
        confirmation.reportValidity();
        return;
      }
      confirmation?.setCustomValidity("");
      if (error) error.textContent = "";
      const submit = form.querySelector('button[type="submit"]');
      if (isStandaloneStaticPreview) {
        if (isRegister) {
          form.dataset.registerSucceeded = "1";
          if (submit) submit.disabled = true;
          window.location.href = registeredLoginUrl(form.dataset.previewDestination);
        return;
      }
        window.location.href = workspaceLandingUrl(form.dataset.previewDestination);
        return;
      }
      const isAdmin = window.location.pathname.endsWith("manage-login.html");
      if (isRegister) form.dataset.registerInFlight = "1";
      const submitLabel = submit ? submit.textContent : "";
      if (submit) {
        submit.disabled = true;
        submit.dataset.busyLabel = submitLabel;
        submit.textContent = isRegister ? "注册中…" : "登录中…";
      }
      try {
        if (isRegister) {
          const session = await apiRequest("/session/");
          if (session.authenticated) {
            form.dataset.registerInFlight = "";
            offerRegistrationLogout(form, session);
            return;
          }
        }
        const payload = Object.fromEntries(new FormData(form).entries());
        const response = await apiRequest(
          isRegister ? "/auth/register/" : "/auth/login/",
          {
            method: "POST",
            body: JSON.stringify(
              isRegister
                ? payload
                : { ...payload, entrypoint: isAdmin ? "admin" : "downstream" },
            ),
          },
        );
        if (isRegister) {
          form.dataset.registerSucceeded = "1";
          window.location.href = registeredLoginUrl(response.redirect || form.dataset.previewDestination);
          return;
        }
        window.location.href = workspaceLandingUrl(response.redirect || form.dataset.previewDestination);
      } catch (requestError) {
        if (isRegister) form.dataset.registerInFlight = "";
        setFormError(form, apiErrorMessage(requestError, "暂时无法连接授权平台。"));
      } finally {
        if (submit && form.dataset.registerSucceeded !== "1") {
          submit.disabled = false;
          submit.textContent = submitLabel;
        }
      }
    });
    form.addEventListener("input", () => {
      form.elements.password_confirm?.setCustomValidity("");
      const error = form.querySelector("[data-form-error]");
      if (error) error.textContent = "";
    });
  });
  window.addEventListener("pageshow", () => {
    document.querySelectorAll('[data-preview-destination] button[type="submit"]').forEach((button) => {
      if (button.disabled && button.dataset.busyLabel !== undefined) {
        button.disabled = false;
        button.textContent = button.dataset.busyLabel;
        delete button.dataset.busyLabel;
      }
    });
  });

  function closeNavigation() {
    if (!navToggle || !sideNav) return;
    sideNav.classList.remove("is-open");
    navToggle.setAttribute("aria-expanded", "false");
    navToggle.setAttribute(
      "aria-label",
      navToggle.dataset.openLabel || "打开导航",
    );
  }

  let currentVisibleScreen = "";
  const workspaceReloaders = Object.create(null);
  let workspaceRefreshBusy = false;
  let lastWorkspaceRefreshAt = 0;

  function registerWorkspaceReloader(screen, loader) {
    if (!screen || typeof loader !== "function") return;
    workspaceReloaders[screen] = loader;
  }

  function activateScreen(name, options = {}) {
    const panels = document.querySelectorAll("[data-screen-panel]");
    const links = document.querySelectorAll(".side-nav [data-screen]");
    const panel = document.querySelector(`[data-screen-panel="${name}"]`);
    if (!panel) return false;
    for (const dialog of document.querySelectorAll("dialog[open]")) {
      if (!confirmUncopiedIssueClose(dialog)) return false;
    }
    if (currentVisibleScreen && currentVisibleScreen !== name) clearTransientQuery();
    currentVisibleScreen = name;
    const routeLink = document.querySelector(
      `.side-nav [data-screen="${name}"]`,
    );
    panels.forEach((item) =>
      item.classList.toggle("is-visible", item === panel),
    );
    links.forEach((link) => {
      const active = link.dataset.screen === name;
      link.classList.toggle("is-active", active);
      if (active) link.setAttribute("aria-current", "page");
      else link.removeAttribute("aria-current");
    });
    const label = document.querySelector("[data-page-label]");
    if (routeLink && label) label.textContent = navigationLabel(routeLink);
    if (options.history === "push" && window.location.hash !== `#${name}`) {
      window.history.pushState({ screen: name }, "", `#${name}`);
    }
    document.querySelectorAll("dialog[open]").forEach((dialog) => {
      dialog.dataset.codesCopied = "true";
      pendingDialogToast = "";
      dialog.close("cancel");
    });
    restoreListState(panel);
    applyRequestedViewState(panel);
    closeNavigation();
    window.scrollTo({
      top: 0,
      behavior: options.smooth === false ? "auto" : "smooth",
    });
    if (options.focus !== false) {
      const heading = panel.querySelector("h1");
      if (heading) {
        heading.tabIndex = -1;
        window.requestAnimationFrame(() =>
          heading.focus({ preventScroll: true }),
        );
      }
    }
    if (
      name === "workspace" &&
      document.body.classList.contains("role-downstream") &&
      window.__b1ApiActive
    ) {
      loadDownstreamRecentCards();
    }
    return true;
  }

  navToggle?.addEventListener("click", () => {
    if (!sideNav) return;
    const isOpen = sideNav.classList.toggle("is-open");
    navToggle.setAttribute("aria-expanded", String(isOpen));
    navToggle.setAttribute(
      "aria-label",
      isOpen
        ? navToggle.dataset.closeLabel || "关闭导航"
        : navToggle.dataset.openLabel || "打开导航",
    );
  });

  document.querySelectorAll(".side-nav [data-screen]").forEach((link) => {
    link.addEventListener("click", (event) => {
      event.preventDefault();
      clearTransientQuery();
      activateScreen(link.dataset.screen, { history: "push" });
    });
  });

  document.addEventListener("click", (event) => {
    const button = event.target.closest("[data-screen-target]");
    if (!button) return;
      clearTransientQuery();
      const screenName = button.dataset.screenTarget;
      const navScopeName = button.dataset.targetRecordScope;
      const hadOverlay = Boolean(navScopeName && hasCredentialSearchOverlay(navScopeName));
      if (hadOverlay) setCredentialSearchOverlay(navScopeName, false);
      activateScreen(screenName, { history: "push" });
      if (hadOverlay) {
        showToast("已清空精确搜索，正在重载完整列表。");
        if (navScopeName === "downstream-licenses" || navScopeName === "management-licenses") {
          loadLicenseCards(1).catch(() => {
            showToast("完整列表重载失败，请手动刷新。");
          });
        }
      }
      const targetPanel = document.querySelector(
        `[data-screen-panel="${screenName}"]`,
      );
      const scopeName = button.dataset.targetRecordScope;
      const recordView = button.dataset.targetRecordView;
      if (targetPanel && scopeName && recordView) {
        const scope = targetPanel.querySelector(
          `[data-record-view-scope="${scopeName}"]`,
        );
        scope?.__activateRecordView?.(recordView);
        const status = button.dataset.targetCredentialStatus;
        if (status) {
          const filter = scope?.querySelector(
            '[data-record-panel="items"] [data-credential-filter="codeStatus"]',
          );
          if (filter) {
            filter.value = status;
            filter.dispatchEvent(new Event("change", { bubbles: true }));
          }
        }
      }
  });

  document.querySelectorAll("[data-toast]").forEach((button) => {
    button.addEventListener("click", (event) => {
      if (window.__b1ApiActive && button.textContent.includes("退出")) return;
      if (button.tagName === "A") event.preventDefault();
      showToast(button.dataset.toast);
    });
  });

  document.querySelectorAll("[data-dismiss='closest']").forEach((button) => {
    button.addEventListener("click", () =>
      button.closest(".preview-banner")?.remove(),
    );
  });

  function dialogHasUncopiedGeneratedCodes(dialog) {
    if (!dialog || dialog.id !== "issueDialog") return false;
    try {
      const codes = JSON.parse(dialog.dataset.generatedCodes || "[]");
      return Array.isArray(codes) && codes.length > 0 && dialog.dataset.codesCopied !== "true";
    } catch {
      return false;
    }
  }

  function confirmUncopiedIssueClose(dialog) {
    if (!dialogHasUncopiedGeneratedCodes(dialog)) return true;
    const ok = window.confirm("请先复制完整码。还没有复制就关闭的话，完整码会从窗口消失。确定关闭？");
    if (ok) dialog.dataset.codesCopied = "true";
    return ok;
  }

  function focusOpenDialog(dialog) {
    if (dialog.id === "redeemDialog") {
      const form = dialog.querySelector("form");
      const error = form?.querySelector("[data-form-error]");
      const input = form?.elements?.quota_code;
      if (error) error.textContent = "";
      if (input) input.value = "";
    }
    const field = dialog.querySelector(
      "input:not([type=hidden]):not([disabled]), select:not([disabled]), textarea:not([disabled])",
    );
    if (field) {
      field.focus();
      return;
    }
    const title = dialog.querySelector("h2");
    if (title) {
      title.tabIndex = -1;
      title.focus({ preventScroll: true });
    }
  }

  function bindDialogChrome(dialog) {
    if (typeof dialog.showModal === "function" && !dialog.dataset.showModalPatched) {
      const nativeShowModal = dialog.showModal.bind(dialog);
      dialog.showModal = function showModalAndFocus() {
        dialog.querySelector("[data-dialog-feedback]")?.remove();
        nativeShowModal();
        window.requestAnimationFrame(() => focusOpenDialog(dialog));
      };
      dialog.dataset.showModalPatched = "true";
    }
    dialog.addEventListener("cancel", (event) => {
      if (dialog.dataset.operationPending === "true") {
        event.preventDefault();
        showToast("正在确认操作结果，请稍候。");
        return;
      }
      if (!dialogHasUncopiedGeneratedCodes(dialog)) return;
      event.preventDefault();
      if (window.confirm("请先复制完整码。还没有复制就关闭的话，完整码会从窗口消失。确定关闭？")) {
        dialog.dataset.codesCopied = "true";
        dialog.close("cancel");
      }
    });
    dialog.addEventListener("click", (event) => {
      const cancel = event.target.closest('[value="cancel"]');
      if (cancel) {
        event.preventDefault();
        if (dialog.dataset.operationPending === "true") {
          showToast("正在确认操作结果，请稍候。");
          return;
        }
        if (!confirmUncopiedIssueClose(dialog)) return;
        dialog.close("cancel");
      }
    });
    dialog.addEventListener("click", (event) => {
      const action = event.target.closest("[data-dialog-success]");
      if (action) pendingDialogToast = action.dataset.dialogSuccess;
    });
    dialog.addEventListener("close", () => {
      if (dialog.returnValue !== "cancel" && pendingDialogToast)
        showToast(pendingDialogToast);
      pendingDialogToast = "";
    });
    dialog.querySelectorAll("form").forEach((form) => {
      form.addEventListener("submit", (event) => {
        const submitter = event.submitter;
        if (!submitter || submitter.value === "cancel" || submitter.getAttribute("type") === "button") {
          event.preventDefault();
        }
      });
    });
  }

  document.querySelectorAll("dialog").forEach(bindDialogChrome);

  const DEFAULT_PAGE_SIZE = 10;
  const ALLOWED_PAGE_SIZES = new Set([5, 10]);
  const tableStates = new WeakMap();

  function tablePageSize(table, panel) {
    const requested = Number.parseInt(
      table.dataset.rowSlots || panel?.dataset.rowSlots || "",
      10,
    );
    const pageSize = ALLOWED_PAGE_SIZES.has(requested)
      ? requested
      : DEFAULT_PAGE_SIZE;
    table.dataset.rowSlots = String(pageSize);
    return pageSize;
  }

  function createPlaceholderRows(table, body, count) {
    const columns = Math.max(1, table.tHead?.rows[0]?.cells.length || 1);
    return Array.from({ length: count }, () => {
      const row = document.createElement("tr");
      row.className = "table-placeholder-row";
      row.setAttribute("aria-hidden", "true");
      row.hidden = true;
      for (let index = 0; index < columns; index += 1) {
        const cell = document.createElement("td");
        cell.innerHTML = "&nbsp;";
        row.append(cell);
      }
      body.append(row);
      return row;
    });
  }

  function initializeTableRecord(row) {
    row.dataset.tableRecord = "";
    if (!("queryMatch" in row.dataset)) row.dataset.queryMatch = "true";
    if (!("filterMatch" in row.dataset)) row.dataset.filterMatch = "true";
    if (!("criteriaMatch" in row.dataset)) row.dataset.criteriaMatch = "true";
  }

  function ensureTableState(table) {
    const existing = tableStates.get(table);
    if (existing) return existing;
    const panel = table.closest(".table-panel");
    const body = table.tBodies[0];
    if (!panel || !body) return null;
    body
      .querySelectorAll(":scope > .table-placeholder-row")
      .forEach((row) => row.remove());
    const screen = table.closest("[data-screen-panel]");
    const rows = [...body.rows];
    rows.forEach(initializeTableRecord);
    const pageSize = tablePageSize(table, panel);
    const placeholders = createPlaceholderRows(table, body, pageSize);
    const serverPaginated =
      panel.dataset.serverPaginated === "true" && !isStandaloneStaticPreview;

    let pagination = serverPaginated ? null : panel.querySelector(".pagination");
    let summary = null;
    let pageLabel = null;
    let previous = null;
    let next = null;
    if (serverPaginated) {
      const serverPagination = panel.querySelector(
        "[data-risk-server-pagination], [data-license-server-pagination], [data-downstream-device-pagination], [data-quota-card-server-pagination], [data-admin-audit-pagination], [data-downstream-activity-pagination], [data-release-server-pagination], [data-admin-ledger-pagination], [data-downstream-ledger-pagination]",
      );
      if (serverPagination) panel.append(serverPagination);
      panel.querySelectorAll(".pagination").forEach((item) => item.remove());
    } else {
      if (!pagination) {
        pagination = document.createElement("div");
        pagination.className = "pagination";
        panel.append(pagination);
      }
      pagination.replaceChildren();

      summary = document.createElement("span");
      summary.dataset.paginationSummary = "";
      const controls = document.createElement("div");
      controls.className = "pagination-controls";
      pageLabel = document.createElement("span");
      pageLabel.dataset.paginationPage = "";
      previous = document.createElement("button");
      previous.className = "icon-button";
      previous.type = "button";
      previous.setAttribute("aria-label", "上一页");
      previous.textContent = "←";
      next = document.createElement("button");
      next.className = "icon-button";
      next.type = "button";
      next.setAttribute("aria-label", "下一页");
      next.textContent = "→";
      controls.append(pageLabel, previous, next);
      pagination.append(summary, controls);
    }

    let empty = panel.querySelector("[data-table-empty]");
    if (!empty) {
      empty = document.createElement("p");
      empty.dataset.tableEmpty = "";
      empty.className = "table-empty";
      empty.textContent = "当前没有记录。";
      table.closest(".table-scroll")?.append(empty);
    }

    const state = {
      body,
      empty,
      next,
      page: 1,
      pageLabel,
      pageSize,
      panel,
      placeholders,
      previous,
      rows,
      screen,
      serverDataLoaded: panel.dataset.serverDataLoaded === "true",
      serverPaginated,
      summary,
    };
    tableStates.set(table, state);
    if (!serverPaginated) {
      previous.addEventListener("click", () => {
        state.page -= 1;
        renderTableState(state, true);
      });
      next.addEventListener("click", () => {
        state.page += 1;
        renderTableState(state, true);
      });
      renderTableState(state, false);
    } else {
      renderServerTableState(state);
    }
    return state;
  }

  function tableHasActiveFilter(state) {
    const panel = state.panel;
    if (!panel) return false;
    const search = panel.querySelector(
      ".search-field input, [data-sensitive-search], [data-downstream-device-search]",
    );
    if (search?.value?.trim()) return true;
    const activeChip = panel.querySelector(".filter-chips .chip.is-active");
    const chipValue =
      activeChip?.dataset.releaseStatus ||
      activeChip?.dataset.softwareStatus ||
      activeChip?.dataset.credentialStatus ||
      "";
    if (chipValue && chipValue !== "all") return true;
    return [...panel.querySelectorAll("select")].some((select) => {
      if (select.closest("dialog")) return false;
      const value = select.value || "";
      return value && value !== "all";
    });
  }

  function paintTableEmpty(state) {
    if (!state.empty) return;
    if (!state.empty.dataset.emptyIdle) {
      state.empty.dataset.emptyIdle = state.empty.textContent || "当前没有记录。";
    }
    const idle = state.empty.dataset.emptyIdle;
    const genericIdle =
      idle === "当前条件没有匹配的记录。" || idle === "当前没有记录。";
    state.empty.textContent = tableHasActiveFilter(state)
      ? "当前条件没有匹配的记录。"
      : genericIdle
        ? "当前没有记录。"
        : idle;
  }

  function matchingRows(state) {
    return state.rows.filter(
      (row) =>
        row.dataset.queryMatch !== "false" &&
        row.dataset.filterMatch !== "false" &&
        row.dataset.criteriaMatch !== "false",
    );
  }

  function showFixedPlaceholderRows(state, visibleCount) {
    const placeholderCount = Math.max(0, state.pageSize - visibleCount);
    state.placeholders.forEach((row, index) => {
      row.hidden = index >= placeholderCount;
    });
  }

  function renderServerTableState(state) {
    state.serverDataLoaded = state.serverDataLoaded || state.panel.dataset.serverDataLoaded === "true";
    if (!state.serverDataLoaded) {
      state.rows.forEach((row) => {
        row.hidden = true;
      });
      state.placeholders.forEach((row) => {
        row.hidden = false;
      });
      state.empty.hidden = true;
      return;
    }
    const matches = matchingRows(state);
    state.rows.forEach((row) => {
      row.hidden = true;
    });
    matches.forEach((row) => {
      row.hidden = false;
    });
    showFixedPlaceholderRows(state, matches.length);
    state.empty.hidden = matches.length !== 0;
    if (matches.length === 0) paintTableEmpty(state);
  }

  function renderTableState(state, syncUrl) {
    if (state.serverPaginated) {
      renderServerTableState(state);
      return;
    }
    const matches = matchingRows(state);
    const totalPages = Math.max(
      1,
      Math.ceil(matches.length / state.pageSize),
    );
    state.page = Math.max(1, Math.min(totalPages, state.page));
    const start = (state.page - 1) * state.pageSize;
    const end = Math.min(matches.length, start + state.pageSize);
    state.rows.forEach((row) => {
      row.hidden = true;
    });
    state.placeholders.forEach((row) => {
      row.hidden = true;
    });
    const visibleRecords = matches.slice(start, end);
    visibleRecords.forEach((row) => {
      row.hidden = false;
    });
    showFixedPlaceholderRows(state, visibleRecords.length);
    state.empty.hidden = matches.length !== 0;
    if (matches.length === 0) paintTableEmpty(state);
    state.summary.textContent = matches.length
      ? `${start + 1}–${end} / ${matches.length} 条 · 每页 ${state.pageSize} 条`
      : `0 条 · 每页 ${state.pageSize} 条`;
    state.pageLabel.textContent = `第 ${state.page} / ${totalPages} 页`;
    state.previous.disabled = state.page === 1;
    state.next.disabled = state.page === totalPages;
    if (syncUrl && state.screen?.classList.contains("is-visible"))
      updateQuery({ page: state.page === 1 ? null : state.page });
  }

  function tableStateForScreen(screen) {
    const table =
      screen?.querySelector('[data-record-panel="items"] table') ||
      screen?.querySelector(".table-panel table");
    return table ? ensureTableState(table) : null;
  }

  function tableStateForContext(context) {
    const panel = context?.matches?.(".table-panel")
      ? context
      : context?.closest?.(".table-panel");
    if (panel) return ensureTableState(panel.querySelector("table"));
    return tableStateForScreen(context);
  }

  function applyTablePreview(context, options = {}) {
    const state = tableStateForContext(context);
    if (!state) return;
    const screen = state.screen;
    const controls = state.panel;
    if (state.serverPaginated) {
      state.rows.forEach((row) => {
        row.dataset.queryMatch = "true";
        row.dataset.filterMatch = "true";
      });
      renderServerTableState(state);
      return;
    }
    const queryInput = controls.querySelector(".search-field input");
    const query =
      queryInput?.value.trim().toLocaleLowerCase("zh-CN") || "";
    const activeChip = controls.querySelector(".filter-chips .chip.is-active");
    const softwareStatusFilter = activeChip?.dataset.softwareStatus;
    const filterLabel =
      activeChip?.textContent.trim().replace(/\s+\d+$/, "") || "全部";
    state.rows.forEach((row) => {
      const text = `${row.textContent} ${row.dataset.searchValue || ""} ${row.dataset.filterTags || ""}`.toLocaleLowerCase("zh-CN");
      const catalogId = String(row.dataset.catalogSoftwareId || "").toLocaleLowerCase("zh-CN");
      const serverSearchMatch = row.dataset.serverSearchMatch === "true";
      row.dataset.queryMatch = String(!query || serverSearchMatch || text.includes(query) || Boolean(catalogId && catalogId.includes(query)));
      row.dataset.filterMatch = String(
        softwareStatusFilter
          ? softwareStatusFilter === "all" || row.dataset.softwareStatus === softwareStatusFilter
          : filterLabel.startsWith("全部") ||
          text.includes(filterLabel.toLocaleLowerCase("zh-CN")) ||
          (filterLabel === "可回收" && text.includes("未激活")),
      );
    });
    if (!options.preservePage) state.page = 1;
    renderTableState(state, options.syncUrl !== false);
    if (options.syncUrl !== false)
      updateQuery({
        q: queryInput?.matches("[data-sensitive-search]") ? null : query || null,
        filter: filterLabel.startsWith("全部") ? null : filterLabel,
        page: state.page === 1 ? null : state.page,
      });
  }

  function restoreListState(screen) {
    const state = tableStateForScreen(screen);
    if (!state) return;
    const params = new URLSearchParams(window.location.search);
    const input = [...screen.querySelectorAll(".search-field input")].find(
      (field) => !field.matches("[data-sensitive-search]"),
    );
    if (input) input.value = params.get("q") || "";
    const requestedFilter = params.get("filter");
    if (requestedFilter) {
      screen.querySelectorAll(".filter-chips .chip").forEach((chip) => {
        const active =
          chip.textContent.trim().replace(/\s+\d+$/, "") === requestedFilter;
        chip.classList.toggle("is-active", active);
        chip.setAttribute("aria-pressed", String(active));
      });
    }
    const requestedCriteria = (params.get("criteria") || "")
      .split("|")
      .filter(Boolean);
    const selects = [...screen.querySelectorAll(".filter-row select")];
    requestedCriteria.forEach((value, index) => {
      if (selects[index]?.querySelector(`option[value="${CSS.escape(value)}"]`))
        selects[index].value = value;
    });
    const requestedCredentialCriteria = (params.get("credential") || "").split("|");
    const credentialSelects = [
      ...screen.querySelectorAll("[data-credential-filters] [data-credential-filter]"),
    ];
    requestedCredentialCriteria.forEach((value, index) => {
      if (
        value &&
        credentialSelects[index]?.querySelector(`option[value="${CSS.escape(value)}"]`)
      )
        credentialSelects[index].value = value;
    });
    state.rows.forEach((row) => {
      row.dataset.criteriaMatch = String(
        requestedCriteria.every((value) => row.textContent.includes(value)),
      );
    });
    state.page = 1;
    applyTablePreview(screen, { preservePage: true, syncUrl: false });
    const credentialFilters = screen.querySelector("[data-credential-filters]");
    if (credentialFilters)
      applyCredentialFilters(credentialFilters, {
        notify: false,
        preservePage: true,
        preserveServer: true,
        syncUrl: false,
      });
  }

  document.querySelectorAll(".table-panel table").forEach(ensureTableState);
  window.__previewRefreshTables = () => {
    document.querySelectorAll(".table-panel table").forEach((table) => {
      const state = tableStates.get(table);
      if (!state) {
        ensureTableState(table);
        return;
      }
      state.rows = [...state.body.rows].filter(
        (row) => !row.classList.contains("table-placeholder-row"),
      );
      // 修复：API 渲染列表会整体 replaceChildren()，把占位行 DOM 删掉；
      // 这里检测到占位行已断开连接时重建，保证列表始终固定 rowSlots 个行位。
      const connectedPlaceholders = state.placeholders.filter((row) =>
        row.isConnected,
      );
      if (connectedPlaceholders.length !== state.pageSize) {
        connectedPlaceholders.forEach((row) => row.remove());
        state.placeholders = createPlaceholderRows(
          table,
          state.body,
          state.pageSize,
        );
      }
      state.rows.forEach(initializeTableRecord);
      applyTablePreview(state.panel, { preservePage: true, syncUrl: false });
      const credentialFilters = state.panel.querySelector(
        "[data-credential-filters]",
      );
      if (credentialFilters)
        applyCredentialFilters(credentialFilters, { notify: false, preserveServer: true, syncUrl: false });
    });
  };

  let workspaceTabId = 0;
  function bindKeyboardTabs(buttons, panels, key, activate) {
    buttons.forEach((button, index) => {
      const panel = panels.find((item) => item.dataset[key.replace("View", "Panel")] === button.dataset[key]);
      button.id ||= `workspace-tab-${++workspaceTabId}`;
      if (panel) {
        panel.id ||= `${button.id}-panel`;
        button.setAttribute("aria-controls", panel.id);
        panel.setAttribute("role", "tabpanel");
        panel.setAttribute("aria-labelledby", button.id);
      }
      button.addEventListener("keydown", (event) => {
        const enabled = buttons.filter((item) => !item.disabled && !item.hidden);
        const position = enabled.indexOf(button);
        let next;
        if (event.key === "ArrowRight") next = enabled[(position + 1) % enabled.length];
        if (event.key === "ArrowLeft") next = enabled[(position - 1 + enabled.length) % enabled.length];
        if (event.key === "Home") next = enabled[0];
        if (event.key === "End") next = enabled[enabled.length - 1];
        if (!next) return;
        event.preventDefault();
        activate(next.dataset[key]);
        next.focus();
      });
    });
  }

  document.querySelectorAll("[data-work-view-scope]").forEach((scope) => {
    const buttons = [...scope.querySelectorAll("[data-work-view]")];
    const panels = [...scope.querySelectorAll("[data-work-panel]")];
    const activateWorkView = (name) => {
      buttons.forEach((button) => {
        const active = button.dataset.workView === name;
        button.classList.toggle("is-active", active);
        button.setAttribute("aria-selected", String(active));
        button.tabIndex = active ? 0 : -1;
      });
      panels.forEach((panel) => {
        panel.hidden = panel.dataset.workPanel !== name;
      });
      panels
        .filter((panel) => panel.dataset.workPanel === name)
        .forEach((panel) =>
          panel.querySelectorAll("table").forEach(ensureTableState),
        );
    };
    scope.__activateWorkView = activateWorkView;
    bindKeyboardTabs(buttons, panels, "workView", activateWorkView);
    buttons.forEach((button) => {
      button.addEventListener("click", () =>
        activateWorkView(button.dataset.workView),
      );
    });
    activateWorkView(
      buttons.find((button) => button.getAttribute("aria-selected") === "true")
        ?.dataset.workView || buttons[0]?.dataset.workView,
    );
  });

  document.querySelectorAll("[data-record-view-scope]").forEach((scope) => {
    const buttons = [...scope.querySelectorAll("[data-record-view]")];
    const panels = [...scope.querySelectorAll("[data-record-panel]")];
    const activateRecordView = (name) => {
      buttons.forEach((button) => {
        const active = button.dataset.recordView === name;
        button.classList.toggle("is-active", active);
        button.setAttribute("aria-selected", String(active));
        button.tabIndex = active ? 0 : -1;
      });
      panels.forEach((panel) => {
        panel.hidden = panel.dataset.recordPanel !== name;
      });
      const visiblePanel = panels.find(
        (panel) => panel.dataset.recordPanel === name,
      );
      visiblePanel?.querySelectorAll("table").forEach(ensureTableState);
      if (name === "items" && visiblePanel) {
        const search = visiblePanel.querySelector(".search-field input");
        if (search) search.value = "";
        const state = tableStateForContext(visiblePanel);
        state?.rows.forEach((row) => {
          row.dataset.criteriaMatch = "true";
        });
        if (state) {
          state.page = 1;
          applyTablePreview(visiblePanel, { syncUrl: false });
        }
        const summary = visiblePanel.querySelector("[data-record-scope-summary]");
        if (summary) summary.textContent = summary.dataset.recordScopeDefault || "";
      }
    };
    scope.__activateRecordView = activateRecordView;
    bindKeyboardTabs(buttons, panels, "recordView", activateRecordView);
    buttons.forEach((button) => {
      button.addEventListener("click", () =>
        activateRecordView(button.dataset.recordView),
      );
    });
    scope.addEventListener("click", (event) => {
      const trigger = event.target.closest("[data-show-record-view]");
      if (!trigger || !scope.contains(trigger)) return;
      activateRecordView(trigger.dataset.showRecordView);
    });
    activateRecordView(
      buttons.find((button) => button.dataset.recordView === "items")
        ?.dataset.recordView ||
        buttons.find((button) => button.getAttribute("aria-selected") === "true")
          ?.dataset.recordView ||
        buttons[0]?.dataset.recordView ||
        "items",
    );
  });

  document.querySelectorAll(".search-field input").forEach((input) => {
    input.addEventListener("input", () =>
      applyTablePreview(input.closest(".table-panel") || input.closest(".screen")),
    );
  });

  document.querySelectorAll(".filter-chips").forEach((group) => {
    group.querySelectorAll(".chip").forEach((chip) => {
      chip.setAttribute(
        "aria-pressed",
        String(chip.classList.contains("is-active")),
      );
      chip.addEventListener("click", () => {
        if (chip.hasAttribute("data-activity-scope") || chip.hasAttribute("data-release-status")) return;
        group.querySelectorAll(".chip").forEach((item) => {
          item.classList.remove("is-active");
          item.setAttribute("aria-pressed", "false");
        });
        chip.classList.add("is-active");
        chip.setAttribute("aria-pressed", "true");
        applyTablePreview(group.closest(".table-panel") || group.closest(".screen"));
        showToast(`已选择“${chip.textContent.trim()}”。`);
      });
    });
  });

  function setCredentialSearchOverlay(scope, active) {
    const root = document.querySelector(`[data-record-view-scope="${scope}"]`);
    if (!root) return;
    if (active) root.dataset.credentialSearchOverlay = "true";
    else delete root.dataset.credentialSearchOverlay;
  }

  function hasCredentialSearchOverlay(scope) {
    return document.querySelector(`[data-record-view-scope="${scope}"]`)?.dataset.credentialSearchOverlay === "true";
  }

  function licenseSearchOverlayScope() {
    return document.body.classList.contains("role-admin") ? "management-licenses" : "downstream-licenses";
  }

  function normalizeCredentialQuery(query) {
    return String(query || "").replaceAll(/\s+/g, "").toUpperCase();
  }

  function looksLikePrefixedCredential(query, kind) {
    const prefix =
      kind === "license" ? "LC-" : kind === "invitation" ? "IN" + "V-" : kind === "quota" ? "QC-" : "";
    if (!prefix) return false;
    const normalized = normalizeCredentialQuery(query);
    if (!normalized.startsWith(prefix)) return false;
    const body = normalized.slice(prefix.length);
    return body.length >= 16 && /^[A-Z0-9]+$/.test(body);
  }

  function looksLikeLongSecretToken(query) {
    const raw = String(query || "");
    if (/[\u4e00-\u9fff]/.test(raw)) return false;
    const normalized = normalizeCredentialQuery(raw);
    return normalized.length >= 20 && /^[A-Z0-9-]+$/.test(normalized);
  }

  function shouldExactCredentialSearch(query, kind) {
    return looksLikePrefixedCredential(query, kind) || looksLikeLongSecretToken(query);
  }

  function nonSecretTableQuery(input, kind) {
    const query = input?.value.trim() || "";
    if (!query || looksLikePrefixedCredential(query, kind)) return "";
    return query;
  }

  function visibleSearchNeedle(query) {
    return String(query || "")
      .replaceAll(/[•*]/g, " ")
      .replaceAll("…", " ")
      .replaceAll("...", " ")
      .replaceAll(/\s+/g, " ")
      .trim();
  }

  async function resolveTableSearchQuery(raw, kind) {
    const trimmed = String(raw || "").trim();
    if (!trimmed) return "";
    if (!looksLikePrefixedCredential(trimmed, kind)) return visibleSearchNeedle(trimmed);
    try {
      const payload = await apiRequest(`${licenseCardsPrefix()}/search/`, {
        method: "POST",
        body: JSON.stringify({ code: trimmed }),
      });
      return payload.item?.public_id || "00000000-0000-0000-0000-000000000000";
    } catch (_error) {
      return "00000000-0000-0000-0000-000000000000";
    }
  }

  function credentialSearchOverlayToast(action = "再导出、翻页或按筛选操作") {
    showToast(`请先清空完整码精确搜索并重新加载列表，${action}。`);
  }

  const LICENSE_STATUS_FILTER_TO_API = {
    未激活: "unused",
    已激活: "activated",
    已过期: "expired",
    已回收: "reclaimed",
    已撤销: "revoked",
    unused: "unused",
    activated: "activated",
    expired: "expired",
    reclaimed: "reclaimed",
    revoked: "revoked",
  };

  function licenseApiStatusFromFilter(value) {
    return LICENSE_STATUS_FILTER_TO_API[value] || "";
  }

  function syncLicenseScopeSummary(panel, scope) {
    const summary = panel?.querySelector("[data-record-scope-summary]");
    if (!summary) return;
    const isAdmin = Boolean(panel.closest('[data-record-view-scope="management-licenses"]'));
    const statusLabel = panel.querySelector('[data-credential-filter="codeStatus"]')?.value || "";
    if (isAdmin) {
      const scopeText =
        { current: "当前授权卡密", archived: "归档授权卡密", all: "全部授权卡密" }[scope || "current"] ||
        "授权卡密";
      summary.textContent = statusLabel ? `${scopeText} · ${statusLabel}` : scopeText;
      return;
    }
    summary.textContent = statusLabel
      ? `当前下游${statusLabel}卡 · 默认脱敏`
      : "当前下游授权卡密 · 默认脱敏";
  }

  function licenseCardFilterQuery(panel) {
    const query = {};
    const keyMap = {
      recordScope: "scope",
      codeStatus: "status",
      codeSoftware: "software_name",
      codePlan: "plan_name",
      codeDeviceState: "device_state",
      codeExpiryState: "expiry_state",
    };
    panel?.querySelectorAll("[data-credential-filter]").forEach((select) => {
      const key = keyMap[select.dataset.credentialFilter];
      if (!key || !select.value) return;
      const value = select.value;
      if (key === "status") {
        const status = licenseApiStatusFromFilter(value);
        if (status) query.status = status;
        return;
      }
      query[key] =
        key === "device_state"
          ? value === "已绑定" ? "bound" : value === "未绑定" ? "unbound" : value
          : key === "expiry_state"
            ? value === "未开始" ? "not_started" : value
            : value;
    });
    return query;
  }

  const lastSuccessfulCredentialFilters = new WeakMap();

  function snapshotCredentialFilters(group) {
    if (!group) return;
    const state = {};
    group.querySelectorAll("[data-credential-filter]").forEach((select) => {
      state[select.dataset.credentialFilter] = select.value;
    });
    lastSuccessfulCredentialFilters.set(group, state);
  }

  function restoreCredentialFilters(group) {
    const state = lastSuccessfulCredentialFilters.get(group);
    if (!state) return;
    group.querySelectorAll("[data-credential-filter]").forEach((select) => {
      if (Object.prototype.hasOwnProperty.call(state, select.dataset.credentialFilter)) {
        select.value = state[select.dataset.credentialFilter];
      }
    });
  }

  function applyCredentialFilters(group, options = {}) {
    const panel = group.closest(".table-panel");
    const state = tableStateForContext(panel);
    if (!state) return;
    const isLiveLicenseList =
      panel?.dataset.serverPaginated === "true" &&
      (!isStandaloneStaticPreview || Boolean(window.__b1ApiActive)) &&
      Boolean(panel.closest('[data-record-view-scope="management-licenses"], [data-record-view-scope="downstream-licenses"]'));
    const isLiveInvitationList =
      state.serverPaginated &&
      !isStandaloneStaticPreview &&
      Boolean(panel.closest('[data-record-view-scope="invitations"]'));
    const isLiveQuotaList =
      state.serverPaginated &&
      !isStandaloneStaticPreview &&
      Boolean(panel.closest('[data-record-view-scope="quota-cards"]'));
    if (isLiveLicenseList || isLiveInvitationList || isLiveQuotaList) {
      const overlayScope = panel?.closest("[data-record-view-scope]")?.getAttribute("data-record-view-scope");
      if (!options.preserveServer && overlayScope && hasCredentialSearchOverlay(overlayScope)) {
        credentialSearchOverlayToast("再改筛选");
        return;
      }
      if (options.syncUrl !== false) {
        const values = [...group.querySelectorAll("[data-credential-filter]")].map(
          (select) => select.value || "",
        );
        updateQuery({ credential: values.some(Boolean) ? values.join("|") : null, page: null });
      }
      if (!options.preserveServer) {
        if (isLiveInvitationList) {
          invitationPage = 1;
          loadInvitations(1)
            .then(() => snapshotCredentialFilters(group))
            .catch((error) => {
              restoreCredentialFilters(group);
              showToast(apiErrorMessage(error, "邀请码筛选失败，请重试。"));
            });
        } else if (isLiveQuotaList) {
          quotaCardsPage = 1;
          loadAdminCredits(1)
            .then(() => snapshotCredentialFilters(group))
            .catch((error) => {
              restoreCredentialFilters(group);
              showToast(apiErrorMessage(error, "额度码筛选失败，请重试。"));
            });
        } else {
          syncLicenseCredentialFilters();
          licenseCardsPage = 1;
          loadLicenseCards(1)
            .then(() => snapshotCredentialFilters(group))
            .catch((error) => {
              restoreCredentialFilters(group);
              showToast(apiErrorMessage(error, "卡密筛选失败，请重试。"));
            });
        }
      }
      return;
    }
    const filters = [...group.querySelectorAll("[data-credential-filter]")]
      .map((select) => ({
        key: select.dataset.credentialFilter,
        value: select.value,
      }))
      .filter((item) => item.value && item.key !== "recordScope");
    const recordScope = group.querySelector('[data-credential-filter="recordScope"]')?.value || "current";
    state.rows.forEach((row) => {
      const cardStatus = row.dataset.cardStatus || "";
      const statusLabel = row.dataset.codeStatus || "";
      const scopeMatch =
        recordScope === "all" ||
        (recordScope === "archived"
          ? cardStatus === "archived" || statusLabel === "已归档"
          : cardStatus !== "archived" && statusLabel !== "已归档");
      row.dataset.criteriaMatch = String(
        scopeMatch &&
        filters.every((item) =>
          String(row.dataset[item.key] || "").includes(item.value),
        ),
      );
    });
    if (!options.preservePage) state.page = 1;
    if (state.serverPaginated) renderServerTableState(state);
    else renderTableState(state, false);
    if (options.syncUrl !== false) {
      const values = [...group.querySelectorAll("[data-credential-filter]")].map(
        (select) => select.value || "",
      );
      updateQuery({
        credential: values.some(Boolean) ? values.join("|") : null,
        page: state.page === 1 ? null : state.page,
      });
    }
    if (options.notify !== false)
      showToast(
        filters.length
          ? `筛选已应用，显示 ${matchingRows(state).length} 条单码。`
          : "已显示当前范围全部单码。",
      );
    syncLicenseScopeSummary(panel);
  }

  document.querySelectorAll("[data-credential-filters]").forEach((group) => {
    group
      .querySelectorAll("[data-credential-filter]")
      .forEach((select) =>
        select.addEventListener("change", () => applyCredentialFilters(group)),
      );
  });

  const credentialDialog = document.getElementById("credentialDetailDialog");
  let credentialDownloadButton = credentialDialog?.querySelector("[data-credential-download]");
  if (credentialDialog && !credentialDownloadButton) {
    const actions = credentialDialog.querySelector(".credential-secret .table-actions");
    if (actions) {
      credentialDownloadButton = document.createElement("button");
      credentialDownloadButton.className = "button button-secondary button-small";
      credentialDownloadButton.type = "button";
      credentialDownloadButton.dataset.credentialDownload = "";
      credentialDownloadButton.textContent = "下载当前码";
      actions.append(credentialDownloadButton);
    }
  }
  const credentialFieldMap = {
    type: "credentialType",
    status: "codeStatus",
    software: "codeSoftware",
    plan: "codePlan",
    downstream: "codeDownstream",
    deviceCode: "codeDeviceCode",
    deviceUuid: "codeDeviceUuid",
    device: "codeDevice",
    ip: "codeIp",
    activity: "codeActivity",
    expires: "codeExpires",
  };

  function maskCredential(value) {
    const tail = value.slice(-4);
    return `••••-••••-${tail}`;
  }

  function resetCredentialSecret() {
    if (!credentialDialog) return;
    const full = credentialDialog.querySelector("[data-credential-full]");
    const reveal = credentialDialog.querySelector("[data-credential-reveal]");
    const copy = credentialDialog.querySelector("[data-credential-copy]");
    const available = credentialDialog.dataset.codeAvailable !== "false";
    if (full)
      full.textContent = available
        ? credentialDialog.dataset.maskedCode || maskCredential(credentialDialog.dataset.fullCode || "CODE")
         : "点击“显示完整码”按需重新交付";
    if (reveal) {
      reveal.textContent = available ? "显示完整码" : "完整码暂不可用";
      reveal.disabled = !available;
    }
    if (copy) copy.disabled = true;
    if (credentialDownloadButton) credentialDownloadButton.disabled = true;
    credentialDialog.dataset.revealed = "false";
    credentialDialog.dataset.fullCode = "";
  }

  document.addEventListener("click", (event) => {
    const trigger = event.target.closest("[data-credential-detail]");
    if (!trigger || !credentialDialog) return;
    const row = trigger.closest("tr");
    if (!row) return;
    credentialDialog.dataset.publicId = row.dataset.publicId || "";
    credentialDialog.dataset.credentialType = row.dataset.credentialType || "授权卡密";
    credentialDialog.dataset.fullCode = "";
    const visibleCode = [...row.cells]
      .map((cell) => cell.textContent?.trim() || "")
      .find((value) => value.includes("••••") || /^(INV|QC|LC)-/.test(value));
    credentialDialog.dataset.maskedCode =
      visibleCode || row.dataset.searchValue?.split(" ")[0] || "••••-••••-????";
    credentialDialog.dataset.codeAvailable = row.dataset.codeAvailable || "true";
    Object.entries(credentialFieldMap).forEach(([field, key]) => {
      const target = credentialDialog.querySelector(`[data-detail-${field}]`);
      if (target)
        target.textContent =
          row.dataset[key] || (field === "software" || field === "plan" ? "不适用" : "尚未产生");
    });
    resetCredentialSecret();
    credentialDialog.showModal();
  });

  credentialDialog
    ?.querySelector("[data-credential-reveal]")
    ?.addEventListener("click", async () => {
      if (credentialDialog.dataset.codeAvailable === "false") {
        showToast("当前无可交付的完整码。");
        return;
      }
      const revealed = credentialDialog.dataset.revealed === "true";
      const full = credentialDialog.querySelector("[data-credential-full]");
      const reveal = credentialDialog.querySelector("[data-credential-reveal]");
      const copy = credentialDialog.querySelector("[data-credential-copy]");
      if (!full || !reveal || !copy) {
        showToast("弹窗结构异常，请刷新页面后重试。");
        return;
      }
      if (revealed) {
        credentialDialog.dataset.revealed = "false";
        full.textContent = credentialDialog.dataset.maskedCode || maskCredential("CODE");
        credentialDialog.dataset.fullCode = "";
        reveal.textContent = "显示完整码";
        copy.disabled = true;
        if (credentialDownloadButton) credentialDownloadButton.disabled = true;
        showToast("完整码已重新隐藏。");
        return;
      }
      const publicId = credentialDialog.dataset.publicId || "";
      if (!publicId) {
        showToast("缺少卡密标识，请刷新列表后重试。");
        return;
      }
      if (isStandaloneStaticPreview && !window.__b1ApiActive) {
        showToast("静态预览不揭示真实完整码。");
        return;
      }
      reveal.disabled = true;
      reveal.textContent = "交付中…";
      try {
        const isAdmin = document.body.classList.contains("role-admin");
        const credentialType = credentialDialog.dataset.credentialType || "授权卡密";
        const prefix = isAdmin ? "/manage/licenses/cards" : "/downstream/licenses/cards";
        const revealPath = credentialType === "邀请码"
          ? `/manage/invitations/${publicId}/reveal/`
          : credentialType === "额度兑换码"
            ? `/manage/credits/cards/${publicId}/reveal/`
            : `${prefix}/${publicId}/reveal/`;
        const payload = await apiRequest(revealPath, {
          method: "POST",
          body: "{}",
        });
        if (!payload.code) {
          full.textContent = "—";
          showToast("服务端未返回完整码，已保持脱敏显示。");
          return;
        }
        credentialDialog.dataset.fullCode = payload.code;
        credentialDialog.dataset.revealed = "true";
        full.textContent = payload.code;
        reveal.textContent = "隐藏完整码";
        copy.disabled = false;
        if (credentialDownloadButton) credentialDownloadButton.disabled = false;
        showToast("完整码已交付；显示、复制和下载不会记录“谁看过”审计。");
      } catch (error) {
        reveal.textContent = "显示完整码";
        showToast(apiErrorMessage(error, "完整码暂时无法交付，请稍后重试。"));
      } finally {
        reveal.disabled = false;
        if (credentialDialog.dataset.revealed !== "true") reveal.textContent = "显示完整码";
      }
    });

  credentialDialog
    ?.querySelector("[data-credential-copy]")
    ?.addEventListener("click", async () => {
      if (credentialDialog.dataset.revealed !== "true") {
        showToast("请先点显示完整码，揭示成功后再复制。");
        return;
      }
      try {
        await navigator.clipboard.writeText(credentialDialog.dataset.fullCode || "");
        showToast("完整码已复制；平台不会记录“谁看过”审计。");
      } catch {
        showToast("浏览器未允许剪贴板；完整码保持可见，可手动复制。");
      }
    });

  credentialDownloadButton?.addEventListener("click", () => {
    if (credentialDialog.dataset.revealed !== "true") {
      showToast("请先点显示完整码，揭示成功后再下载。");
      return;
    }
    const code = credentialDialog.dataset.fullCode || "";
    if (!code) {
      showToast("当前无可下载的完整码。");
      return;
    }
    const blob = new Blob([`${code}\r\n`], { type: "text/plain;charset=utf-8" });
    const url = URL.createObjectURL(blob);
    const link = document.createElement("a");
    link.href = url;
    link.download = "credential-code.txt";
    document.body.append(link);
    link.click();
    link.remove();
    setTimeout(() => URL.revokeObjectURL(url), 0);
    showToast("当前完整码已下载；平台不会记录“谁看过”审计。");
  });
  credentialDialog?.addEventListener("close", resetCredentialSecret);

  function syncLicenseReclaimSelection(panel) {
    syncRecordSelection(panel);
  }

  document.querySelectorAll("[data-reclaim-selected]").forEach((button) => {
    const panel = button.closest("[data-record-panel='items']");
    const selectedBoxes = () => selectedRecordBoxes(panel);
    panel.addEventListener("change", (event) => {
      if (event.target.matches("[data-reclaim-select]")) syncLicenseReclaimSelection(panel);
    });
    button.addEventListener("click", () => {
      const pendingDialog = document.getElementById(button.dataset.reclaimSelectionDialog);
      if (pendingDialog && resumeDialogWrite(pendingDialog, `${recordScope(panel)}:reclaim`)) return;
      const allBoxes = selectedBoxes();
      if (!allBoxes.length) return;
      const boxes = allBoxes.filter(
        (box) => box.dataset.cardStatus === "unused",
      );
      if (boxes.length !== allBoxes.length) {
        showToast(
          `回收只适用于未激活卡，已忽略 ${allBoxes.length - boxes.length} 张其他状态的卡。`,
        );
      }
      if (!boxes.length) return;
      const rows = boxes.map((box) => box.closest("tr"));
      const credits = boxes.reduce(
        (total, box) => total + Number(box.dataset.reclaimCredit || 0),
        0,
      );
      const downstreams = [
        ...new Set(rows.map((row) => row.dataset.codeDownstream).filter(Boolean)),
      ];
      const dialog = document.getElementById(button.dataset.reclaimSelectionDialog);
      if (!dialog) return;
      dialog.__selectedReclaimRows = rows;
      dialog.__reclaimCardIds = rows.map((row) => row.dataset.publicId).filter(Boolean);
      dialog.__reclaimSelection = "selected";
      dialog.__reclaimFilters = {};
      prepareDialogWrite(dialog, `${recordScope(panel)}:reclaim`, dialog.__reclaimCardIds);
      restoreDialogWrite(dialog);
      dialog.dataset.reclaimCredits = String(credits);
      if (dialog.id === "reclaimDialog") {
        document.getElementById("reclaimCount").textContent = `${boxes.length} 张`;
        document.getElementById("reclaimCredit").textContent = `+${credits} 额度`;
        const reclaimTarget = document.getElementById("reclaimBatch");
        if (reclaimTarget)
          reclaimTarget.textContent = formatJoinedSummary(
            rows.map((row) => row.dataset.codeSuffix || "卡密"),
            "未选择",
          );
        document.getElementById("reclaimSubmit").disabled = false;
      } else {
        const adminBatch = dialog.querySelector("[data-admin-reclaim-batch]");
        if (adminBatch)
          adminBatch.textContent = formatJoinedSummary(
            rows.map((row) => row.dataset.codeSuffix || "卡密"),
            "未选择",
          );
        dialog.querySelector("[data-admin-reclaim-count]").textContent = `${boxes.length} 张`;
        dialog.querySelector("[data-admin-reclaim-credit]").textContent = `+${credits} 额度`;
        dialog.querySelector("[data-admin-reclaim-downstream]").textContent =
          downstreams.join("、") || "原始下游";
      }
      dialog.showModal();
    });
    syncLicenseReclaimSelection(panel);
  });

  function currentReclaimFilters(panel) {
    const keyMap = {
      codeSoftware: "software_name",
      codePlan: "plan_name",
      codeDeviceState: "device_state",
      codeExpiryState: "expiry_state",
      recordScope: "scope",
    };
    const filters = { status: "unused" };
    panel?.querySelectorAll("[data-credential-filter]").forEach((select) => {
      const key = keyMap[select.dataset.credentialFilter];
      if (key && select.value) filters[key] = select.value;
    });
    return filters;
  }

  function currentFilteredReclaimRows(panel) {
    const state = tableStateForContext(panel);
    if (!state) return [];
    return matchingRows(state).filter((row) => {
      const checkbox = row.querySelector("[data-reclaim-select]");
      return checkbox && !checkbox.disabled && row.dataset.codeStatus === "未激活";
    });
  }

  function fillFilteredReclaimDialog(dialog, rows, payload) {
    dialog.__selectedReclaimRows = rows;
    dialog.__reclaimCardIds = (payload.card_ids || []).map(String);
    dialog.__reclaimSelection = "selected";
    dialog.__reclaimFilters = payload.filters || {};
    dialog.dataset.reclaimCredits = String(payload.refundable_quota || 0);
    const countLabel = `${payload.reclaimable_count || 0} 张`;
    const creditLabel = `+${payload.refundable_quota || 0} 额度`;
    if (dialog.id === "reclaimDialog") {
      document.getElementById("reclaimCount").textContent = countLabel;
      document.getElementById("reclaimCredit").textContent = creditLabel;
      document.getElementById("reclaimBatch").textContent = "当前筛选全部未激活卡";
      document.getElementById("reclaimSubmit").disabled = false;
    } else {
      dialog.querySelector("[data-admin-reclaim-batch]").textContent =
        "当前筛选全部未激活卡";
      dialog.querySelector("[data-admin-reclaim-count]").textContent = countLabel;
      dialog.querySelector("[data-admin-reclaim-credit]").textContent = creditLabel;
      dialog.querySelector("[data-admin-reclaim-downstream]").textContent =
        "确认后只回收预览锁定的这些卡";
    }
  }

  function selectionRowFromItem(scope, item) {
    const row = document.createElement("tr");
    const box = document.createElement("input");
    box.type = "checkbox";
    box.dataset.reclaimSelect = "";
    box.checked = true;
    box.dataset.cardStatus = item.status || "";
    box.dataset.expiresAt = item.expires_at || "";
    box.dataset.cardId = item.public_id || "";
    box.dataset.reclaimCredit = String(item.quota_cost || 0);
    row.dataset.publicId = item.public_id || "";
    row.dataset.codeSuffix = item.code_suffix || item.masked_code || "记录";
    row.dataset.codeDownstream = item.downstream_username || "";
    row.dataset.codeSoftware = item.software_name || "";
    row.dataset.codeStatus = ({unused:"未激活",activated:"已激活",expired:"已过期",reclaimed:"已回收",revoked:"已撤销",archived:"已归档",issued:scope === "invitations" ? "未使用" : "未兑换",consumed:"已使用",redeemed:"已兑换"})[item.status] || item.status;
    row.append(box);
    return row;
  }

  async function selectFilteredRecords(panel) {
    const selection = recordSelection(panel);
    if (!selection || selection.busy) return;
    const scope = recordScope(panel);
    if (hasCredentialSearchOverlay(scope)) {
      showToast("完整码搜索只选择已定位的记录；请清空搜索后再选筛选全集。");
      return;
    }
    if (isStandaloneStaticPreview && !window.__b1ApiActive) {
      showToast("静态预览没有业务记录可选。");
      return;
    }
    const generation = ++selection.generation;
    selection.busy = true;
    syncRecordSelection(panel);
    const items = [];
    const ids = new Set();
    const limit = 500;
    const selectionError = (message) => Object.assign(new Error(message), { selectionFailure: true });
    let expectedTotal = null;
    let expectedPages = null;
    try {
      let hasNext = true;
      // The server may clamp page_size (invitations use five rows). At least
      // one new stable ID per page bounds even one-row pages to 500 requests.
      for (let page = 1; hasNext && page <= limit; page += 1) {
        const query = new URLSearchParams({page: String(page), page_size: "100"});
        let path;
        if (scope === "invitations") {
          path = "/manage/invitations/";
          query.set("scope", panel.querySelector("[data-invitation-scope]")?.value || "current");
          const status = {"未使用":"issued","已使用":"consumed","已撤销":"revoked","已过期":"expired","已归档":"archived"}[panel.querySelector('[data-credential-filter="codeStatus"]')?.value];
          if (status) query.set("status", status);
        } else if (scope === "quota-cards") {
          path = "/manage/credits/";
          Object.entries(quotaCardFilterQuery(panel)).forEach(([key,value]) => query.set(key,value));
          query.set("card_page",String(page)); query.set("card_page_size","100"); query.set("ledger_page_size","1");
        } else {
          path = `${licenseCardsPrefix()}/`;
          Object.entries(licenseCardFilterQuery(panel)).forEach(([key,value]) => query.set(key,value));
          if (scope === "downstream-licenses") query.set("status","unused");
        }
        const kind = scope === "invitations" ? "invitation" : scope === "quota-cards" ? "quota" : "license";
        const search = nonSecretTableQuery(panel.querySelector("[data-sensitive-search]"),kind);
        if (search) query.set("q",search);
        const payload = await apiRequest(`${path}?${query}`);
        if (selection.generation !== generation) return;
        const pagination = scope === "quota-cards" ? payload.cards_pagination : payload.pagination;
        const batch = scope === "quota-cards" ? payload.cards : payload.items;
        if (!pagination || !Array.isArray(batch) || !Number.isSafeInteger(pagination.total) || pagination.total < 0 ||
            !Number.isSafeInteger(pagination.total_pages) || pagination.total_pages < 1 ||
            pagination.page !== page || typeof pagination.has_next !== "boolean") {
          throw selectionError("选择范围的分页信息不完整，请刷新列表后重试。");
        }
        if (pagination.total > limit) throw selectionError("一次最多选择 500 条，请缩小筛选范围后再选。");
        if (expectedTotal === null) { expectedTotal = pagination.total; expectedPages = pagination.total_pages; }
        if (pagination.total !== expectedTotal || pagination.total_pages !== expectedPages ||
            expectedPages > Math.max(1, expectedTotal) || page > expectedPages ||
            pagination.has_next !== (page < expectedPages)) {
          throw selectionError("选择范围在读取期间发生变化或分页不一致，请刷新列表后重试。");
        }
        for (const item of batch) {
          if (typeof item?.public_id !== "string" || !item.public_id.trim() || ids.has(item.public_id)) {
            throw selectionError("选择范围包含重复或缺失的记录编号，请刷新列表后重试。");
          }
          ids.add(item.public_id);
          items.push(item);
        }
        if (ids.size > limit) throw selectionError("一次最多选择 500 条，请缩小筛选范围后再选。");
        hasNext = pagination.has_next;
        if (ids.size > expectedTotal || (hasNext && (!batch.length || ids.size >= expectedTotal))) {
          throw selectionError("选择范围没有继续读取或记录数量不一致，请刷新列表后重试。");
        }
      }
      if (hasNext || ids.size !== expectedTotal) throw selectionError("选择范围尚未完整读取，请刷新列表或缩小范围后重试。");
      selection.rows.clear();
      items.forEach((item) => {
        if (scope === "downstream-licenses" && item.status !== "unused") return;
        if (item.public_id) selection.rows.set(String(item.public_id),selectionRowFromItem(scope,item));
      });
      showToast(`已选择筛选结果中的 ${selection.rows.size} 条。新增记录不会自动加入这次选择。`);
    } catch (error) {
      if (selection.generation === generation) showToast(error.selectionFailure ? error.message : apiErrorMessage(error,"选择范围读取失败，请重试。"));
    } finally {
      if (selection.generation === generation) { selection.busy = false; syncRecordSelection(panel); }
    }
  }

  document.addEventListener("change", (event) => {
    const box = event.target.closest?.("[data-reclaim-select]");
    if (box) {
      const panel = box.closest(".table-panel"), row = box.closest("tr"), selection = recordSelection(panel);
      if (!selection || !row?.dataset.publicId) return;
      selection.generation += 1; selection.busy = false;
      if (box.checked && !box.disabled) {
        if (selection.rows.size >= 500 && !selection.rows.has(row.dataset.publicId)) {
          box.checked = false; showToast("一次最多选择 500 条，请缩小范围。");
        } else selection.rows.set(row.dataset.publicId,row);
      } else selection.rows.delete(row.dataset.publicId);
      syncRecordSelection(panel);
      return;
    }
    const filter = event.target.closest?.("[data-credential-filter], [data-invitation-scope]");
    if (filter) clearRecordSelection(filter.closest(".table-panel"));
  }, true);
  document.addEventListener("input", (event) => {
    if (event.target.matches?.("[data-sensitive-search]")) clearRecordSelection(event.target.closest(".table-panel"));
  }, true);
  document.querySelectorAll("[data-record-select-filtered]").forEach((button) => button.addEventListener("click", () => selectFilteredRecords(button.closest(".table-panel"))));
  document.querySelectorAll("[data-record-clear]").forEach((button) => button.addEventListener("click", () => clearRecordSelection(button.closest(".table-panel"))));
  document.querySelectorAll("[data-record-selection-bar]").forEach((bar) => syncRecordSelection(bar.closest(".table-panel")));

  function licenseCardExpiryHasPassed(box) {
    const raw =
      box?.dataset.expiresAt || box?.closest("tr")?.dataset.expiresAt || "";
    if (!raw) return false;
    const expiry = Date.parse(raw);
    return Number.isFinite(expiry) && expiry <= Date.now();
  }

  function licenseCardMayArchive(box, config) {
    const status = box?.dataset.cardStatus || "";
    if ((config.archiveStatuses || []).includes(status)) return true;
    if (config.prefix !== "/manage/licenses/cards") return false;
    return status === "activated" && licenseCardExpiryHasPassed(box);
  }

  document.querySelectorAll("[data-archive-selected], [data-delete-selected]").forEach((button) => {
    button.addEventListener("click", () => {
      if (!isStandaloneStaticPreview || window.__b1ApiActive) return;
      const panel = button.closest(".table-panel") || button.closest("[data-record-view-scope]");
      const selected = [
        ...(panel?.querySelectorAll("tbody input[type='checkbox']:checked") || []),
      ];
      if (!selected.length) {
        showToast("请先勾选要处理的记录。");
        return;
      }
      const selectedRows = selected.map((checkbox) => checkbox.closest("tr")).filter(Boolean);
      if (button.hasAttribute("data-archive-selected")) {
        const archivable = selectedRows.filter((row) =>
          ["已过期", "已使用", "已撤销", "已回收", "已归档"].includes(row.dataset.codeStatus || ""),
        );
        if (archivable.length !== selectedRows.length) {
          showToast("有效未使用凭证需先撤销；已过期凭证可直接归档。归档后进入归档分类。 ");
          return;
        }
        archivable.forEach((row) => {
          row.dataset.codeStatus = "已归档";
          const status = row.querySelector(".status");
          if (status) {
            status.textContent = "已归档";
            status.className = "status status-gray";
          }
          const checkbox = row.querySelector("input[type='checkbox']");
          if (checkbox) {
            checkbox.checked = false;
            checkbox.disabled = true;
            checkbox.dataset.cardStatus = "archived";
          }
        });
        invitationScopeSelect?.dispatchEvent(new Event("change"));
        showToast(`已归档 ${archivable.length} 条，记录已移入归档分类。`);
        return;
      }
      const deletable = selectedRows.filter((row) => row.dataset.codeStatus === "已归档");
      if (deletable.length !== selectedRows.length) {
        showToast("删除只能处理已归档记录。请先归档，再执行删除。 ");
        return;
      }
      deletable.forEach((row) => {
        row.dataset.codeStatus = "已删除";
        const status = row.querySelector(".status");
        if (status) {
          status.textContent = "已删除";
          status.className = "status status-gray";
        }
      });
      invitationScopeSelect?.dispatchEvent(new Event("change"));
      showToast(`已删除 ${deletable.length} 条归档记录，并留下脱敏墓碑。审计和额度流水未改动。`);
    });
  });

  // 真实 API 模式：卡密 / 额度兑换码批量归档删除（仅平台管理员）。
  // 静态 8124 在 catalog mock 打开 __b1ApiActive 后也走这条路径，避免静态中文状态表冒充归档。
  {
    const lifecycleDialog = document.getElementById("licenseLifecycleDialog");
    const lifecycleScopes = {
      "management-licenses": {
        prefix: "/manage/licenses/cards",
        noun: "卡密",
        noun2: "授权卡密",
        idKey: "card_ids",
        archiveStatuses: ["expired", "revoked", "reclaimed"],
      },
      "quota-cards": {
        prefix: "/manage/credits/cards",
        noun: "额度兑换码",
        noun2: "额度兑换码",
        idKey: "card_ids",
        archiveStatuses: ["redeemed", "revoked"],
      },
      invitations: {
        prefix: "/manage/invitations",
        noun: "邀请码",
        noun2: "邀请码",
        idKey: "code_ids",
        archiveStatuses: ["consumed", "revoked", "expired"],
      },
    };
    const collectLifecycle = (button, action) => {
      const scopeElement = button.closest("[data-record-view-scope]");
      const scopeName =
        scopeElement?.dataset.recordViewScope || "management-licenses";
      const config = lifecycleScopes[scopeName];
      if (!config) return null;
      const panel = scopeElement?.querySelector('[data-record-panel="items"]');
      const boxes = selectedRecordBoxes(panel);
      if (!boxes.length) {
        showToast("请先勾选要处理的记录。");
        return null;
      }
      const rows = boxes.map((box) => box.closest("tr"));
      const candidates = boxes
        .filter((box) =>
          action === "archive"
            ? licenseCardMayArchive(box, config)
            : (box.dataset.cardStatus || "") === "archived",
        )
        .map((box) => box.closest("tr"));
      if (!candidates.length) {
        showToast(
          action === "archive"
            ? `所选${config.noun}中没有可归档项。未兑换额度码请先作废；授权卡密需处于终态。`
            : `所选${config.noun}中没有可删除的已归档${config.noun}。`,
        );
        return null;
      }
      return { config, scopeName, rows, candidates };
    };
    const openLicenseLifecycle = (button, action) => {
      if (!lifecycleDialog) return;
      const selectedScope = recordScope(button.closest(".table-panel"));
      if (resumeDialogWrite(lifecycleDialog, `${selectedScope}:${action}`)) return;
      const collected = collectLifecycle(button, action);
      if (!collected) return;
      const { config, scopeName, rows, candidates } = collected;
      const skipped = rows.length - candidates.length;
      const title = lifecycleDialog.querySelector(
        "[data-license-lifecycle-title]",
      );
      const impact = lifecycleDialog.querySelector(
        "[data-license-lifecycle-impact]",
      );
      const confirm = lifecycleDialog.querySelector(
        "[data-license-lifecycle-confirm]",
      );
      const error = lifecycleDialog.querySelector("[data-form-error]");
      lifecycleDialog.__lifecycleCandidates = candidates;
      lifecycleDialog.__lifecycleAction = action;
      lifecycleDialog.__lifecycleScope = scopeName;
      lifecycleDialog.__lifecycleConfig = config;
      prepareDialogWrite(lifecycleDialog, `${scopeName}:${action}`, candidates.map((row) => row.dataset.publicId));
      restoreDialogWrite(lifecycleDialog);
      if (title)
        title.textContent =
          action === "archive"
            ? `归档选中${config.noun}？`
            : `删除已归档${config.noun}？`;
      if (impact) {
        impact.textContent =
          action === "archive"
            ? `归档后停止继续使用，但保留记录与全部历史。本次可归档 ${candidates.length} 张${skipped ? `（另有 ${skipped} 张已忽略）` : ""}。`
            : `删除会移除${config.noun}记录并保留脱敏墓碑，不可恢复。本次可删除 ${candidates.length} 张${skipped ? `（另有 ${skipped} 张已忽略）` : ""}。`;
      }
      if (confirm)
        confirm.textContent = action === "archive" ? "确认归档" : "确认删除";
      lifecycleDialog.__writePresentation = {
        "[data-license-lifecycle-title]": title?.textContent || "",
        "[data-license-lifecycle-impact]": impact?.textContent || "",
        "[data-license-lifecycle-confirm]": confirm?.textContent || "",
      };
      const reason = lifecycleDialog.querySelector("textarea[name='reason']");
      if (reason) reason.value = "";
      if (error) error.textContent = "";
      lifecycleDialog.showModal();
    };
    document.querySelectorAll("[data-archive-selected]").forEach((button) =>
      button.addEventListener("click", () => {
        if (isStandaloneStaticPreview && !window.__b1ApiActive) return;
        openLicenseLifecycle(button, "archive");
      }),
    );
    document.querySelectorAll("[data-delete-selected]").forEach((button) =>
      button.addEventListener("click", () => {
        if (isStandaloneStaticPreview && !window.__b1ApiActive) return;
        openLicenseLifecycle(button, "delete");
      }),
    );
    lifecycleDialog
      ?.querySelector("[data-license-lifecycle-confirm]")
      ?.addEventListener("click", async () => {
        if (isStandaloneStaticPreview && !window.__b1ApiActive) return;
        const form = lifecycleDialog.querySelector("form");
        const error = lifecycleDialog.querySelector("[data-form-error]");
        if (!form?.checkValidity()) {
          if (error) error.textContent = "请填写至少 4 个字的可追溯原因。";
          form?.reportValidity();
          return;
        }
        const action = lifecycleDialog.__lifecycleAction;
        const config = lifecycleDialog.__lifecycleConfig;
        const cardIds = (lifecycleDialog.__lifecycleCandidates || []).map(
          (row) => row.dataset.publicId,
        );
        const reason = form.elements.reason.value.trim();
        const confirm = lifecycleDialog.querySelector(
          "[data-license-lifecycle-confirm]",
        );
        if (confirm) confirm.disabled = true;
        try {
          const payload = await submitDialogWrite(lifecycleDialog, `${config.prefix}/${action}/`, { [config.idKey]: cardIds, reason }, `${config.prefix}-${action}`);
          const sourcePanel = document.querySelector(`[data-record-view-scope="${lifecycleDialog.__lifecycleScope}"] .table-panel`);
          clearCompletedRecordSelection(sourcePanel, cardIds);
          lifecycleDialog.close("success");
          lifecycleDialog.__lifecycleCandidates = [];
          showToast(
            action === "archive"
              ? `已归档 ${payload.archived_count} 张${config.noun2}。`
              : `已删除 ${payload.deleted_count} 张${config.noun2}，并保留脱敏墓碑。`,
          );
          try {
          if (config.prefix.includes("/credits/")) {
            await loadAdminCredits();
          } else if (config.prefix.includes("/invitations")) {
            await loadInvitations();
          } else {
            await loadLicenseCards();
              if (!document.body.classList.contains("role-admin")) {
                await loadDownstreamRecentCards();
          }
            }
          } catch {
          showToast(
            action === "archive"
                ? `已归档 ${payload.archived_count} 张${config.noun2}，列表请稍后重试。`
                : `已删除 ${payload.deleted_count} 张${config.noun2}，列表请稍后重试。`,
          );
          }
        } catch (requestError) {
          if (error)
            error.textContent = apiErrorMessage(
              requestError,
              action === "archive"
                ? "归档请求未完成，请核对提示后重试。"
                : "删除请求未完成，请核对提示后重试。",
            );
        } finally {
          if (confirm) confirm.disabled = false;
        }
      });
  }

  document.querySelectorAll("[data-reclaim-confirm]").forEach((button) => {
    button.addEventListener("click", async () => {
      const dialog = button.closest("dialog");
      const form = button.closest("form");
      const error = form?.querySelector("[data-form-error]");
      if (!form?.checkValidity()) {
        if (error) error.textContent = "请填写至少 4 个字的可追溯原因。";
        form?.reportValidity();
        return;
      }
      if (error) error.textContent = "";
      const isAdmin = dialog?.id === "adminReclaimDialog";
      const rows = dialog?.__selectedReclaimRows || [];
      const cardIds = (dialog?.__reclaimCardIds || []).length
        ? dialog.__reclaimCardIds
        : rows.map((row) => row.dataset.publicId).filter(Boolean);
      if (!isStandaloneStaticPreview && !cardIds.length) return;
      const reason = form?.elements.reason?.value.trim() || "";
      if (reason.length < 4) {
        if (error) error.textContent = "请填写至少 4 个字的可追溯原因。";
        return;
      }
      if (isStandaloneStaticPreview) {
        if (error) error.textContent = "静态预览不执行真实卡密回收。";
        return;
      }
      button.disabled = true;
      try {
        const prefix = isAdmin ? "/manage/licenses/cards" : "/downstream/licenses/cards";
        const body = { card_ids: cardIds, reason };
        const payload = await submitDialogWrite(dialog, `${prefix}/reclaim/`, body, "license-reclaim");
        const sourcePanel = document.querySelector(`[data-record-view-scope="${isAdmin ? "management-licenses" : "downstream-licenses"}"] .table-panel`);
        clearCompletedRecordSelection(sourcePanel, cardIds);
        dialog.close("success");
        dialog.__selectedReclaimRows = [];
        dialog.__reclaimCardIds = [];
        try {
        await loadLicenseCards();
          if (!isAdmin) await loadDownstreamRecentCards();
        if (isAdmin) await loadAdminCredits();
          else await loadDownstreamCredits();
        } catch {
          showToast(
            isAdmin
              ? `管理员已完成 ${payload.reclaimed_count} 张卡的回收，返还 ${payload.refunded_quota} 额度。列表请稍后重试。`
              : `已回收 ${payload.reclaimed_count} 张未激活卡，返还 ${payload.refunded_quota} 额度。列表请稍后重试。`,
          );
          return;
        }
        showToast(
          isAdmin
            ? `管理员已完成 ${payload.reclaimed_count} 张卡的回收，返还 ${payload.refunded_quota} 额度。`
            : `已回收 ${payload.reclaimed_count} 张未激活卡，返还 ${payload.refunded_quota} 额度。`,
        );
      } catch (requestError) {
        if (error) error.textContent = apiErrorMessage(requestError, "回收请求未完成，请核对提示后重试。");
      } finally {
        button.disabled = false;
      }
    });
  });

  document
    .querySelectorAll(
      ".filter-row .button:not([data-analytics-apply]):not([data-downstream-metrics-apply]):not([data-audit-apply])",
    )
    .forEach((button) => {
      button.addEventListener("click", () => {
        const screen = button.closest(".screen");
        const state = tableStateForScreen(screen);
        if (!state) return;
        const selections = [
          ...button.closest(".filter-row").querySelectorAll("select"),
        ]
          .map((select) => select.value)
          .filter((value) => !value.startsWith("全部") && value !== "今天");
        state.rows.forEach((row) => {
          row.dataset.criteriaMatch = String(
            selections.every((selection) =>
              row.textContent.includes(selection),
            ),
          );
        });
        state.page = 1;
        renderTableState(state, true);
        updateQuery({ criteria: selections.join("|") || null, page: null });
        showToast(
          matchingRows(state).length
            ? `筛选已应用，显示 ${matchingRows(state).length} 条记录。`
            : "当前筛选没有匹配记录。",
        );
      });
    });

  function clearInjectedViewState(panel) {
    panel.querySelector("[data-injected-view-state]")?.remove();
    panel
      .querySelectorAll(":scope > [data-view-state-hidden]")
      .forEach((item) => {
        item.hidden = item.dataset.viewStateWasHidden === "true";
        delete item.dataset.viewStateHidden;
        delete item.dataset.viewStateWasHidden;
      });
    panel.removeAttribute("aria-busy");
  }

  function applyRequestedViewState(panel) {
    document
      .querySelectorAll("[data-screen-panel]")
      .forEach(clearInjectedViewState);
    const params = new URLSearchParams(window.location.search);
    const view = params.get("view");
    if (!view || !["loading", "empty", "error"].includes(view)) return;

    panel.querySelectorAll(":scope > :not(.page-heading)").forEach((item) => {
      item.dataset.viewStateWasHidden = String(item.hidden);
      item.dataset.viewStateHidden = "";
      item.hidden = true;
    });
    const state = document.createElement("section");
    state.className = `panel view-state is-${view}`;
    state.dataset.injectedViewState = "";
    const symbol = document.createElement("span");
    symbol.className = "state-symbol";
    symbol.setAttribute("aria-hidden", "true");
    const title = document.createElement("h2");
    const copy = document.createElement("p");
    state.append(symbol, title, copy);

    if (view === "loading") {
      panel.setAttribute("aria-busy", "true");
      state.setAttribute("role", "status");
      symbol.textContent = "";
      title.textContent = "正在读取最新数据";
      copy.textContent = "当前工作域会在服务端响应后更新，旧数据暂不提供操作。";
    } else if (view === "empty") {
      symbol.textContent = "∅";
      title.textContent = "当前范围没有记录";
      copy.textContent = "调整筛选范围，或返回第一页查看现有数据。";
      const reset = document.createElement("button");
      reset.className = "button button-primary";
      reset.type = "button";
      reset.textContent = "重置范围";
      reset.addEventListener("click", () => {
        updateQuery({
          view: null,
          code: null,
          page: null,
          q: null,
          filter: null,
        });
        applyRequestedViewState(panel);
      });
      state.append(reset);
    } else {
      const code = params.get("code") || "503";
      const definitions = {
        403: [
          "没有访问权限",
          "当前账号不能访问这个工作域。权限变化不会被当作登录失败。",
        ],
        409: [
          "数据已经发生变化",
          "页面中的状态已过期，请刷新最新数据后重新决定。",
        ],
        429: [
          "操作过于频繁",
          "服务端已限制当前请求，请按 Retry-After 指定的时间再试。",
        ],
        503: [
          "服务暂时不可用",
          "登录状态和当前范围已保留，可以重试读取，不会重复提交写操作。",
        ],
      };
      const [heading, message] = definitions[code] || definitions[503];
      state.setAttribute("role", "alert");
      state.dataset.errorCode = code;
      symbol.textContent = code;
      title.textContent = heading;
      copy.textContent = message;
      const action = document.createElement("button");
      action.className =
        code === "403" ? "button button-secondary" : "button button-primary";
      action.type = "button";
      if (code === "403") {
        action.textContent = "返回工作台";
        action.addEventListener("click", () => {
          updateQuery({ view: null, code: null });
          activateScreen(defaultScreen, { history: "push" });
        });
      } else if (code === "429") {
        action.textContent = "12 秒后可重试";
        action.disabled = true;
        window.setTimeout(() => {
          if (!action.isConnected) return;
          action.disabled = false;
          action.textContent = "重试读取";
          action.addEventListener(
            "click",
            () => {
              updateQuery({ view: "loading", code: null });
              applyRequestedViewState(panel);
              window.setTimeout(() => {
                updateQuery({ view: null, code: null });
                applyRequestedViewState(panel);
                showToast("最新数据已恢复。未重复执行任何写操作。");
              }, 220);
            },
            { once: true },
          );
        }, 12000);
      } else {
        action.textContent = code === "409" ? "刷新最新数据" : "重试读取";
        action.dataset.stateRetry = "";
        action.addEventListener("click", () => {
          updateQuery({ view: "loading", code: null });
          applyRequestedViewState(panel);
          window.setTimeout(() => {
            updateQuery({ view: null, code: null });
            applyRequestedViewState(panel);
            showToast("最新数据已恢复。未重复执行任何写操作。");
          }, 220);
        });
      }
      state.append(action);
    }
    panel.append(state);
  }

  function clearRuntimeReadError(panelSelector) {
    document.querySelector(`${panelSelector} [data-runtime-read-error]`)?.remove();
  }

  function showRuntimeReadError(panelSelector, message, retry) {
    const panel = document.querySelector(panelSelector);
    if (!panel) return;
    clearRuntimeReadError(panelSelector);
    const state = document.createElement("section");
    state.className = "panel view-state is-error runtime-error-state";
    state.dataset.runtimeReadError = "";
    state.setAttribute("role", "alert");
    const symbol = document.createElement("span");
    symbol.className = "state-symbol";
    symbol.setAttribute("aria-hidden", "true");
    symbol.textContent = "!";
    const title = document.createElement("h2");
    title.textContent = "当前工作域暂时无法读取";
    const copy = document.createElement("p");
    copy.textContent = message || "服务端没有返回可用数据，当前没有执行任何写操作。";
    const action = document.createElement("button");
    action.className = "button button-primary";
    action.type = "button";
    action.textContent = "重试读取";
    action.addEventListener("click", async () => {
      action.disabled = true;
      action.textContent = "读取中…";
      try {
        state.remove();
        await retry();
      } catch (error) {
        showRuntimeReadError(panelSelector, apiErrorMessage(error, "读取仍未完成，请稍后重试。"), retry);
      }
    });
    state.append(symbol, title, copy, action);
    const heading = panel.querySelector(":scope > .page-heading");
    if (heading) heading.insertAdjacentElement("afterend", state);
    else panel.prepend(state);
  }

  document
    .querySelector("[data-client-context]")
    ?.addEventListener("change", () => {
      if (isStandaloneStaticPreview) {
        [
          ["[data-client-title]", "当前软件配置"],
          ["[data-client-announcement]", "—"],
          ["[data-client-modules]", "—"],
          ["[data-client-support]", "—"],
          ["[data-client-version]", "—"],
          ["[data-client-release]", "暂无版本数据"],
        ].forEach(([selector, text]) => {
          const node = document.querySelector(selector);
          if (node) node.textContent = text;
        });
      }
    });

  // 管理端“客户端与版本”配置区：真实模式读取/保存 Profile 默认配置
  if (!isStandaloneStaticPreview && document.body.classList.contains("role-admin")) {
    const clientContextEl = document.querySelector("[data-client-context]");
    let clientCatalogPayload = { items: [] };
    function applyClientConfig(payload) {
      const cfg = (payload && payload.configuration) || {};
      const set = (sel, text) => {
        const node = document.querySelector(sel);
        if (node) node.textContent = text;
      };
      const selectedName =
        clientContextEl?.selectedOptions[0]?.textContent || payload?.software_id || "软件";
      const profileLabel = payload?.profile_id ? `（Profile ${payload.profile_id}）` : "";
      set("[data-client-title]", `${selectedName} 配置${profileLabel}`);
      if (!payload) {
        set("[data-client-announcement]", "暂无配置");
        set("[data-client-version]", "配置暂不可用");
        set("[data-client-release]", "等待重试");
        const publish = document.querySelector("[data-client-publish-status]");
        if (publish) {
          publish.textContent = "待读取";
          publish.className = "status status-gray";
        }
        return;
      }
      const announcement = cfg.announcement_enabled
        ? cfg.announcement_title || cfg.announcement_body || "已配置"
        : "未配置公告";
      set("[data-client-announcement]", announcement);
      set(
        "[data-client-version]",
        `Profile ${payload?.profile_id || "-"} · ${payload?.config_version || "-"}`,
      );
      set("[data-client-release]", "覆盖可逐层回退");
      const publish = document.querySelector("[data-client-publish-status]");
      if (publish) {
        publish.textContent = "已读取";
        publish.className = "status status-gray";
      }
    }
    function pickFirstProfile(softwareItem) {
      const profiles = softwareItem?.profiles || [];
      return (
        profiles.find((profile) => ["active", "testing"].includes(profile.status)) ||
        profiles[0]
      );
    }
    let clientConfigLoadGeneration = 0;
    async function loadSigningKeyId() {
      const node = document.querySelector("[data-signing-key-id]");
      if (!node) return;
      try {
        const payload = await apiRequest("/manage/authorization-signing-key/");
        node.textContent = payload.key_id || "—";
      } catch (_requestError) {
        node.textContent = "暂时无法读取";
      }
    }
    async function loadClientProfileConfig(softwareId) {
      const generation = ++clientConfigLoadGeneration;
      const dialog = document.getElementById("clientConfigDialog");
      const save = dialog?.querySelector("[data-client-config-save]");
      if (save) save.disabled = true;
      const softwareItem = (clientCatalogPayload.items || []).find(
        (item) => item.software_id === softwareId,
      );
      const profile = softwareItem ? pickFirstProfile(softwareItem) : null;
      if (!profile) {
        if (generation !== clientConfigLoadGeneration) return;
        applyClientConfig(null);
        return;
      }
      try {
        const payload = await apiRequest(
          `/manage/software/${encodeURIComponent(softwareId)}/profiles/${encodeURIComponent(profile.profile_id)}/configuration/`,
        );
        if (generation !== clientConfigLoadGeneration) return;
        const current = document.querySelector("[data-client-context]")?.value || softwareId;
        if (current && current !== softwareId) return;
        applyClientConfig(payload);
        const cfg = (payload && payload.configuration) || {};
        const dialog = document.getElementById("clientConfigDialog");
        if (dialog) {
          dialog.dataset.configSoftware = softwareId;
          dialog.dataset.configProfile = profile.profile_id;
          const announcement = dialog.querySelector('textarea[name="announcement"]');
          if (announcement)
            announcement.value = cfg.announcement_enabled
              ? cfg.announcement_body || cfg.announcement_title || ""
              : "";
        }
        if (profile?.profile_id) {
          try {
            const registryQuery = new URLSearchParams({
              client_id: profile.client_id || "",
              target: profile.target || "windows",
              arch: profile.arch || "x64",
              channel: profile.channel || "stable",
            });
            const registry = await apiRequest(
              `/public/software/${encodeURIComponent(softwareId)}/profiles/${encodeURIComponent(profile.profile_id)}/releases/?${registryQuery}`,
            );
            const publish = document.querySelector("[data-client-publish-status]");
            if (publish) {
              if (registry?.release) {
                publish.textContent = "已发布";
                publish.className = "status status-green";
                const releaseCopy = document.querySelector("[data-client-release]");
                if (releaseCopy) releaseCopy.textContent = `v${registry.release.version}`;
              } else {
                publish.textContent = "暂无发布";
                publish.className = "status status-gray";
              }
            }
          } catch (_registryError) {
            /* 配置已展示；发布徽章保持「已读取」，不盖回待读取。 */
          }
        }
        if (save) save.disabled = false;
      } catch (requestError) {
        if (generation !== clientConfigLoadGeneration) return;
        applyClientConfig(null);
        const failedDialog = document.getElementById("clientConfigDialog");
        const announcement = failedDialog?.querySelector('textarea[name="announcement"]');
        if (announcement) announcement.value = "";
        showRuntimeReadError(
          '[data-screen-panel="client"]',
          apiErrorMessage(requestError, "客户端配置暂时无法读取，请稍后重试。"),
          () => loadClientProfileConfig(clientContextEl?.value || ""),
        );
      }
    }
    (async () => {
      loadSigningKeyId();
      if (!clientContextEl) return;
      try {
        const collection = await fetchAllCollectionPages("/manage/catalog/", { label: "客户端配置软件" });
        clientCatalogPayload = { items: collection.items };
        clientContextEl.replaceChildren();
        collection.items.forEach((item) => {
          const option = document.createElement("option");
          option.value = item.software_id;
          option.textContent = item.name || item.software_id;
          clientContextEl.append(option);
        });
        if (clientContextEl.value) {
          loadClientProfileConfig(clientContextEl.value);
        }
      } catch (requestError) {
        applyClientConfig(null);
        const dialog = document.getElementById("clientConfigDialog");
        const announcement = dialog?.querySelector('textarea[name="announcement"]');
        if (announcement) announcement.value = "";
        showRuntimeReadError(
          '[data-screen-panel="client"]',
          apiErrorMessage(requestError, "软件目录暂时无法读取，请稍后重试。"),
          () => window.location.reload(),
        );
      }
    })();
    clientContextEl?.addEventListener("change", (event) => {
      const dialog = document.getElementById("clientConfigDialog");
      if (dialog) {
        delete dialog.dataset.configSoftware;
        delete dialog.dataset.configProfile;
        const announcement = dialog.querySelector('textarea[name="announcement"]');
        if (announcement) announcement.value = "";
        const save = dialog.querySelector("[data-client-config-save]");
        if (save) save.disabled = true;
      }
      applyClientConfig(null);
      if (event.target.value) loadClientProfileConfig(event.target.value);
    });
    document.querySelector("[data-copy-signing-key]")?.addEventListener("click", async (event) => {
      const button = event.currentTarget;
      button.disabled = true;
      try {
        const payload = await apiRequest("/manage/authorization-signing-key/");
        const text = [`key_id=${payload.key_id || ""}`, payload.public_key || ""].filter(Boolean).join("\n");
        if (!text) throw new ApiRequestError("当前验签公钥暂时无法读取。", 500);
        await navigator.clipboard.writeText(text);
        showToast("已复制当前验签公钥。这不是卡密。");
      } catch (requestError) {
        showToast(apiErrorMessage(requestError, "验签公钥暂时无法复制，请稍后重试。"));
      } finally {
        button.disabled = false;
      }
    });
    document
      .getElementById("clientConfigDialog")
      ?.querySelector("[data-client-config-save]")
      ?.addEventListener("click", async (event) => {
        const dialog = document.getElementById("clientConfigDialog");
        const softwareId = dialog?.dataset.configSoftware;
        const profileId = dialog?.dataset.configProfile;
        if (!softwareId || !profileId) {
          showToast("请先选择一个有 Profile 的软件。");
          return;
        }
        const announcement =
          dialog.querySelector('textarea[name="announcement"]')?.value.trim() || "";
        const button = event.currentTarget;
        const error = dialog.querySelector("[data-form-error]");
        if (!dialog.querySelector("form")?.checkValidity()) {
          if (error) error.textContent = "请填写完整且有效的必填内容。";
          dialog.querySelector("form")?.reportValidity();
          return;
        }
        if (error) error.textContent = "";
        button.disabled = true;
        try {
          const payload = await apiRequest(
            `/manage/software/${encodeURIComponent(softwareId)}/profiles/${encodeURIComponent(profileId)}/configuration/`,
            {
              method: "POST",
              headers: {
                "Idempotency-Key": requestIdempotencyKey(
                  `profile-config-${softwareId}-${profileId}`,
                ),
              },
              body: JSON.stringify({
                values: {
                  announcement_enabled: Boolean(announcement),
                  announcement_title: announcement ? "公告" : "",
                  announcement_body: announcement,
                },
              }),
            },
          );
          dialog.close("success");
          applyClientConfig(payload);
          showToast("客户端配置已保存，config_version 已递增并触发缓存失效。");
        } catch (requestError) {
          if (error)
            error.textContent = apiErrorMessage(
              requestError,
              "配置保存失败，请重试。",
            );
        } finally {
          button.disabled = false;
        }
      });
    registerWorkspaceReloader("client", async () => {
      await loadSigningKeyId();
      const softwareId = clientContextEl?.value || "";
      if (softwareId) await loadClientProfileConfig(softwareId);
      });
  }

  function fillSupportFields() {
    setSupportLoading("渠道支持");
  }

  function setSupportLoading(text) {
    const profile = document.querySelector("[data-support-profile]");
    const purchase = document.querySelector("[data-support-purchase]");
    const contact = document.querySelector("[data-support-contact]");
    if (purchase) purchase.value = "";
    if (contact) contact.value = "";
    if (profile) profile.textContent = text || "渠道支持";
  }

  let supportLoadGeneration = 0;
  let supportLoadedSoftwareId = "";
  let supportLoadPending = false;

  async function loadDownstreamSupport(softwareId) {
    if (!softwareId) return;
    const generation = ++supportLoadGeneration;
    supportLoadedSoftwareId = "";
    supportLoadPending = true;
    setSupportLoading("正在加载…");
    try {
      const payload = await apiRequest(
        `/downstream/support/${encodeURIComponent(softwareId)}/`,
      );
      if (generation !== supportLoadGeneration) return;
      const current = document.querySelector("[data-support-context]")?.value || "";
      if (current !== softwareId) return;
      const support = payload?.support || {};
      const purchase = document.querySelector("[data-support-purchase]");
      const contact = document.querySelector("[data-support-contact]");
      const profile = document.querySelector("[data-support-profile]");
      if (purchase) purchase.value = support.purchase_url || "";
      if (contact) contact.value = support.qq || "";
      if (profile) profile.textContent = softwareId;
      supportLoadedSoftwareId = softwareId;
      supportLoadPending = false;
    } catch (error) {
      if (generation !== supportLoadGeneration) return;
      supportLoadPending = false;
      supportLoadedSoftwareId = "";
      setSupportLoading("渠道支持暂时无法读取");
      showToast(apiErrorMessage(error, "渠道支持暂时无法读取，请稍后重试。"));
    }
  }
  window.__previewLoadDownstreamSupport = loadDownstreamSupport;

  document
    .querySelector("[data-support-context]")
    ?.addEventListener("change", (event) => {
      if (isStandaloneStaticPreview && !window.__b1ApiActive) {
        fillSupportFields(event.target.value);
        return;
      }
      loadDownstreamSupport(event.target.value);
    });

  if (!isStandaloneStaticPreview && document.body.classList.contains("role-downstream")) {
    (async () => {
      const select = document.querySelector("[data-support-context]");
      if (!select) return;
      try {
        const payload = await apiRequest("/downstream/catalog/");
        const softwareList = payload?.items || [];
        select.replaceChildren();
        softwareList.forEach((item) => {
          const id = item.software_id;
          const name = item.name || id;
          if (!id) return;
          const option = document.createElement("option");
          option.value = id;
          option.textContent = name;
          select.append(option);
        });
        if (!softwareList.length) {
          select.append(new Option("还没有可经营软件", ""));
        }
        if (select.value) loadDownstreamSupport(select.value);
      } catch (error) {
        setSupportLoading("软件目录暂时无法读取");
        select.replaceChildren(new Option("暂时无法读取", ""));
        showToast(apiErrorMessage(error, "软件目录暂时无法读取。"));
      }
    })();
  } else {
    fillSupportFields(
      document.querySelector("[data-support-context]")?.value || "",
    );
  }

  document
    .querySelector("[data-support-save]")
    ?.addEventListener("click", async (event) => {
      if (isStandaloneStaticPreview && !window.__b1ApiActive) {
        setSupportLoading("静态预览不保存配置");
        return;
      }
      const button = event.currentTarget;
      const select = document.querySelector("[data-support-context]");
      const selectedId = select?.value || "";
      if (!selectedId) {
        showToast("请先选择软件。");
        return;
      }
      if (supportLoadPending || supportLoadedSoftwareId !== selectedId) {
        showToast("当前软件的渠道支持还没加载完，请稍后再保存。");
        return;
      }
      const softwareId = supportLoadedSoftwareId;
      const purchase =
        document.querySelector("[data-support-purchase]")?.value.trim() || "";
      const contact =
        document.querySelector("[data-support-contact]")?.value.trim() || "";
      if (purchase && !/^https?:\/\//i.test(purchase)) {
        showToast("购买链接必须是 http 或 https 地址。");
        return;
      }
      button.disabled = true;
      try {
        await apiRequest(
          `/downstream/support/${encodeURIComponent(softwareId)}/`,
          {
            method: "POST",
            headers: {
              "Idempotency-Key": requestIdempotencyKey(
                `downstream-support-${softwareId}`,
              ),
            },
            body: JSON.stringify({
              values: { purchase_url: purchase, qq: contact },
            }),
          },
        );
        showToast("渠道支持已保存，随你发行卡密的授权页会显示这组信息。");
      } catch (requestError) {
        showToast(
          apiErrorMessage(requestError, "渠道支持保存失败，请稍后重试。"),
        );
      } finally {
        button.disabled = false;
      }
    });

  let pendingDeviceReset;
  let downstreamDevicePage = 1;

  function downstreamDevicesUseServer() {
    return !isStandaloneStaticPreview || Boolean(window.__b1ApiActive);
  }

  function downstreamDeviceResetToast(payload, expiry) {
    const device = payload?.device || {};
    if (device.binding_state === "blocked") {
      return `设备仍已阻断，没有可解绑的有效绑定。到期时间仍为 ${expiry}。`;
    }
    return `设备已重置，到期时间仍为 ${expiry}。`;
  }

  function setDownstreamDevicePagination(pagination = {}) {
    const panel = document.querySelector('[data-screen-panel="devices"]');
    const controls = panel?.querySelector("[data-downstream-device-pagination]");
    if (!controls) return;
    controls.hidden = isStandaloneStaticPreview;
    controls.querySelector("[data-downstream-device-prev]").disabled = !pagination.has_previous;
    controls.querySelector("[data-downstream-device-next]").disabled = !pagination.has_next;
    controls.querySelector("[data-downstream-device-page]").textContent = formatServerPageLabel(pagination);
    const summary = panel.querySelector("[data-downstream-device-summary]");
    if (summary) {
      const query = panel.querySelector("[data-downstream-device-search]")?.value.trim() || "";
      summary.textContent = pagination.total
        ? `共 ${pagination.total} 条设备绑定 · 当前 ${panel.querySelectorAll('tbody tr[data-device-row]').length} 条`
        : query
          ? "没有匹配的设备。可搜软件名、设备码。这里不搜卡密。"
        : "当前下游暂无已激活设备";
    }
  }

  function renderDownstreamDeviceRows(items, pagination = {}) {
    const panel = document.querySelector('[data-screen-panel="devices"]');
    const body = panel?.querySelector("table tbody");
    if (!body) return;
    body.replaceChildren();
    (Array.isArray(items) ? items : []).forEach((item) => {
      const row = document.createElement("tr");
      row.dataset.deviceRow = "";
      row.dataset.deviceLicense = item.masked_code || "授权卡密";
      row.dataset.deviceExpires = formatApiDate(item.expires_at);
      const deviceCode = item.device_code || item.installation_id || item.device_label || item.device_id || "尚未绑定";
      row.dataset.deviceBinding = `${deviceCode} · ${item.binding_state_label || "未知"}`;
      row.dataset.deviceCode = deviceCode;
      row.dataset.deviceUuid = item.device_uuid || item.device_id || "尚未产生";
      row.dataset.deviceIp = item.device_ip || "尚未产生";
      row.dataset.deviceAuthorizationId = item.authorization_id || "";
      row.dataset.deviceActionRef = item.device_action_ref || "";
      appendTextCell(row, item.masked_code || "••••-••••-????", "mono");
      appendSoftwareCell(row, item.software_name || "—");
      appendPlanCell(row, item.plan_name || "—", item.duration_label || "");
      appendTextCell(row, deviceCode, "mono");
      appendTextCell(row, row.dataset.deviceIp, "mono");
      appendTextCell(row, formatApiDate(item.last_verified_at), "mono");
      appendTextCell(row, formatApiDate(item.expires_at), "mono");
      const status = licenseCardWallClockExpired(item) || item.status === "expired"
        ? ["已过期", "status-gray"]
        : item.status === "blocked"
          ? [item.binding_state === "active" ? "已冻结（绑定保留）" : "授权已阻断", "status-red"]
        : item.status === "revoked"
          ? ["授权已撤销", "status-red"]
        : item.binding_state === "active"
          ? ["已绑定", "status-green"]
          : [item.binding_state_label || "已解绑", "status-warm"];
      appendStatusCell(row, status[0], status[1]);
      const actionCell = document.createElement("td");
      const actions = document.createElement("div");
      actions.className = "table-actions";
      const canReset = Boolean(item.reset_allowed && item.device_action_ref);
      const action = createTableButton("重置", {
        kind: "reset",
        disabled: !canReset,
        disabledReason: "当前设备不可重置（已解绑或已过期）",
        tooltip: "重置设备（只解绑，不受换机开关）：只解除当前设备绑定，不受换机开关限制，到期时间不变。旧电脑可能还要过一会儿才停。",
      });
      action.dataset.resetDevice = "";
      action.setAttribute("aria-label", "重置设备");
      actions.append(action);
      actionCell.append(actions);
      row.append(actionCell);
      body.append(row);
    });
    const tablePanel = panel.querySelector(".table-panel");
    if (tablePanel) tablePanel.dataset.serverDataLoaded = "true";
    window.__previewRefreshTables?.();
    setDownstreamDevicePagination(pagination);
  }

  async function loadDownstreamDevices(page = downstreamDevicePage) {
    const input = document.querySelector("[data-downstream-device-search]");
    const query = input?.value.trim() || "";
    const params = new URLSearchParams({ page_size: "10", page: String(Math.max(1, page)) });
    if (query) params.set("q", query);
    try {
      const payload = await apiRequest(`/downstream/devices/?${params.toString()}`);
      downstreamDevicePage = payload.pagination?.page || page;
      renderDownstreamDeviceRows(payload.items || [], payload.pagination || {});
      return payload;
    } catch (error) {
      renderDownstreamDeviceRows([]);
      showRuntimeReadError(
        '[data-screen-panel="devices"]',
        apiErrorMessage(error, "已激活设备暂时无法读取，请稍后重试。"),
        () => loadDownstreamDevices(downstreamDevicePage),
      );
      throw error;
    }
  }

  function openDownstreamResetDialog(row) {
        const dialog = document.querySelector("#resetDeviceDialog");
        if (!row || !dialog) return;
        pendingDeviceReset = row;
        dialog.querySelector("[data-reset-device-license]").textContent =
          row.dataset.deviceLicense || "—";
        dialog.querySelector("[data-reset-device-expiry]").textContent =
          row.dataset.deviceExpires || "—";
    const reason = dialog.querySelector("textarea[name='reason']");
    if (reason) reason.value = "";
    const error = dialog.querySelector("[data-form-error]");
    if (error) error.textContent = "";
        dialog.showModal();
  }

  function bindStaticDownstreamDeviceReset() {
    document.querySelectorAll("[data-reset-device]").forEach((button) => {
      button.addEventListener("click", () => {
        openDownstreamResetDialog(button.closest("[data-device-row]"));
      });
    });
  }

  if (document.body.classList.contains("role-downstream")) {
    const search = document.querySelector("[data-downstream-device-search]");
    const previous = document.querySelector("[data-downstream-device-prev]");
    const next = document.querySelector("[data-downstream-device-next]");
    const runSearch = () => {
      if (!downstreamDevicesUseServer()) return;
      downstreamDevicePage = 1;
      loadDownstreamDevices(1).catch(() => {});
    };
    search?.addEventListener("keydown", (event) => {
      if (event.key === "Enter") {
        event.preventDefault();
        runSearch();
      }
    });
    search?.addEventListener("change", runSearch);
    previous?.addEventListener("click", () => {
      if (!downstreamDevicesUseServer()) return;
      loadDownstreamDevices(Math.max(1, downstreamDevicePage - 1)).catch(() => {});
    });
    next?.addEventListener("click", () => {
      if (!downstreamDevicesUseServer()) return;
      loadDownstreamDevices(downstreamDevicePage + 1).catch(() => {});
    });
    document.addEventListener("click", (event) => {
      const button = event.target.closest('[data-screen-panel="devices"] [data-reset-device]');
      if (!button) return;
      openDownstreamResetDialog(button.closest("[data-device-row]"));
    });
  } else {
    bindStaticDownstreamDeviceReset();
  }

  document
    .querySelector("[data-reset-device-confirm]")
    ?.addEventListener("click", async (event) => {
      if (!pendingDeviceReset) return;
      const dialog = document.querySelector("#resetDeviceDialog");
      const form = dialog?.querySelector("form");
      const error = dialog?.querySelector("[data-form-error]");
      const reason = form?.elements.reason?.value.trim() || "";
      if (isStandaloneStaticPreview && !window.__b1ApiActive) {
        if (error) error.textContent = "静态预览不执行真实设备重置。";
        return;
      }
      if (!form?.checkValidity() || reason.length < 2) {
        if (error) error.textContent = "请填写至少 2 个字的重置原因。";
        form?.reportValidity();
        return;
      }
      const button = event.currentTarget;
      button.disabled = true;
      try {
        const payload = await apiRequest(
          `/downstream/authorizations/${encodeURIComponent(pendingDeviceReset.dataset.deviceAuthorizationId)}/devices/${encodeURIComponent(pendingDeviceReset.dataset.deviceActionRef)}/reset/`,
          {
            method: "POST",
            headers: { "Idempotency-Key": requestIdempotencyKey("downstream-device-reset") },
            body: JSON.stringify({ reason }),
          },
        );
        dialog.close();
        const expiry = pendingDeviceReset.dataset.deviceExpires || "—";
        pendingDeviceReset = undefined;
        try {
        await loadDownstreamDevices(downstreamDevicePage);
        } catch {
          showToast(`${downstreamDeviceResetToast(payload, expiry)} 设备列表请稍后重试。`);
          return;
        }
        showToast(downstreamDeviceResetToast(payload, expiry));
      } catch (requestError) {
        if (error) error.textContent = apiErrorMessage(requestError, "设备重置失败，请刷新后重试。");
      } finally {
        button.disabled = false;
      }
    });

  const analyticsScreen = document.querySelector(
    '[data-screen-panel="analytics"]',
  );
  const analyticsContent = analyticsScreen?.querySelector(
    "[data-analytics-content]",
  );
  const analyticsEmpty = analyticsScreen?.querySelector(
    "[data-analytics-empty]",
  );
  const analyticsFilters = analyticsScreen?.querySelector(
    "[data-analytics-filters]",
  );
  function selectedText(select) {
    return select?.selectedOptions[0]?.textContent.trim() || "";
  }

  function formatMetric(value) {
    if (value === null || value === undefined) return "—";
    return Number(value).toLocaleString("zh-CN");
  }

  function applyRevenueMetricGrids(revenue) {
    ["today", "month", "total"].forEach((name) => {
      const target = document.querySelector(`[data-revenue-metric="${name}"]`);
      if (!target) return;
      const value = revenue?.[name];
      target.textContent = value === undefined || value === null ? "—" : formatMetric(value);
    });
  }

  function replaceAnalyticsOptions(select, options, allLabel) {
    if (!select || !Array.isArray(options)) return;
    const current = select.value;
    const items = [new Option(allLabel, "all")];
    options.forEach((item) => items.push(new Option(item.name, item.id)));
    select.replaceChildren(...items);
    select.value = items.some((item) => item.value === current) ? current : "all";
  }

  function renderAttentionList(payload) {
    const list = document.querySelector('[data-screen-panel="overview"] .attention-list');
    if (!list) return;
    const pending = Number(payload?.risk_pending || 0);
    list.replaceChildren();
    if (!pending) {
      const empty = document.createElement("p");
      empty.className = "attention-empty";
      empty.textContent = "当前没有需要处理的事项。";
      list.append(empty);
      return;
    }
    const row = document.createElement("button");
    row.type = "button";
    row.className = "attention-row";
    row.dataset.screenTarget = "risk";
    row.textContent = `有 ${pending} 项风险待处理，请到设备与授权。`;
    list.append(row);
  }

  function renderOverviewCards(payload) {
    const metrics = {
      credits: payload?.quota_net_consumed ?? 0,
      authorizations: payload?.active_authorizations ?? 0,
      risk: payload?.risk_pending ?? 0,
    };
    Object.entries(metrics).forEach(([name, value]) => {
      const target = document.querySelector(`[data-overview-metric="${name}"]`);
      if (target) target.textContent = formatMetric(value);
    });
    const overview = document.querySelector('[data-screen-panel="overview"]');
    overview?.querySelector(".signal-credits .signal-label") && (overview.querySelector(".signal-credits .signal-label").textContent = "近 30 天 · 全平台");
    overview?.querySelector(".signal-license .signal-label") && (overview.querySelector(".signal-license .signal-label").textContent = "当前有效授权");
    overview?.querySelector(".signal-risk .signal-label") && (overview.querySelector(".signal-risk .signal-label").textContent = "含设备封禁与冻卡");
    renderAttentionList(payload);
    applyRevenueMetricGrids(payload?.revenue);
  }

  async function loadOverviewSnapshot() {
    const payload = await apiRequest(
      "/manage/analytics/summary/?software_id=all&downstream_id=all&window=30d",
    );
    renderOverviewCards(payload);
    return payload;
  }

  function applyAnalyticsPayload(payload) {
    if (!analyticsScreen || !analyticsContent || !analyticsEmpty) return;
    const hasData = Boolean(payload?.has_data);
    analyticsContent.hidden = false;
      const values = {
        active: formatMetric(payload.active_authorizations),
        success:
          payload.activation_success_rate === null || payload.activation_success_rate === undefined
            ? "—"
            : `${payload.activation_success_rate}%`,
        credits: formatMetric(payload.quota_net_consumed),
        risk: formatMetric(payload.risk_pending),
      };
      Object.entries(values).forEach(([name, value]) => {
        const target = analyticsScreen.querySelector(`[data-analytics-metric="${name}"]`);
        if (target) target.textContent = value;
      });
    analyticsEmpty.hidden = hasData;
    const windowChart = analyticsScreen.querySelector("[data-analytics-window-chart]");
    const windowTable = analyticsScreen.querySelector("[data-analytics-window-table]");
    if (windowChart) windowChart.hidden = !hasData;
    if (windowTable) windowTable.hidden = !hasData;
    const scope = analyticsScreen.querySelector("[data-analytics-scope]");
    if (scope) {
      const software = analyticsFilters?.querySelector('[name="analytics_software"]');
      const downstream = analyticsFilters?.querySelector('[name="analytics_downstream"]');
      const windowSelect = analyticsFilters?.querySelector('[name="analytics_window"]');
      scope.textContent = `${selectedText(software)} · ${selectedText(downstream)} · ${selectedText(windowSelect)}`;
    }
    const generated = analyticsScreen.querySelector(".analytics-scope .mono");
    if (generated && payload.generated_at) generated.textContent = formatApiDate(payload.generated_at);
    const trendBody = analyticsScreen.querySelector("[data-analytics-trend] tbody");
    if (trendBody && Array.isArray(payload.trend)) {
      trendBody.replaceChildren();
      payload.trend.forEach((item) => {
        const row = document.createElement("tr");
        appendTextCell(row, item.date, "mono");
        appendTextCell(row, formatMetric(item.revenue), "mono");
        appendTextCell(row, formatMetric(item.activations), "mono");
        trendBody.append(row);
      });
    }
    const chart = analyticsScreen.querySelector(".bar-chart");
    if (chart) {
      chart.replaceChildren();
      if (hasData) {
        const items = Array.isArray(payload.trend) ? payload.trend : [];
        const windowSelect = analyticsFilters?.querySelector('[name="analytics_window"]');
        const windowLabel = selectedText(windowSelect) || "所选范围";
        chart.setAttribute("aria-label", `${windowLabel}每日激活量柱状图`);
        const max = Math.max(1, ...items.map((item) => Number(item.activations) || 0));
        items.forEach((item) => {
          const bar = document.createElement("div");
          const mark = document.createElement("i");
          mark.style.height = `${Math.round(((Number(item.activations) || 0) / max) * 100)}%`;
          const label = document.createElement("span");
          label.textContent = String(item.date || "").slice(5);
          const value = document.createElement("b");
          value.textContent = formatMetric(item.activations);
          bar.append(mark, label, value);
          chart.append(bar);
        });
      } else {
        const emptyBar = document.createElement("div");
        const mark = document.createElement("i");
        mark.style.height = "0%";
        const label = document.createElement("span");
        label.textContent = "—";
        const value = document.createElement("b");
        value.textContent = "0";
        emptyBar.append(mark, label, value);
        chart.append(emptyBar);
      }
    }
    const breakdownBody = analyticsScreen.querySelector("[data-analytics-breakdown]");
    if (breakdownBody) {
      breakdownBody.replaceChildren();
      if (hasData) {
        (Array.isArray(payload.software_breakdown) ? payload.software_breakdown : []).forEach((item) => {
          const row = document.createElement("tr");
          appendTextCell(row, item.software_name || item.software_id || "—");
          appendTextCell(row, formatMetric(item.activations), "mono");
          appendTextCell(row, formatMetric(item.revenue), "mono");
          breakdownBody.append(row);
        });
      }
    }
    window.__previewRefreshTables?.();
  }

  async function applyAnalyticsRange() {
    if (
      !analyticsScreen ||
      !analyticsContent ||
      !analyticsEmpty ||
      !analyticsFilters
    )
      return;
    const software =
      analyticsFilters.elements?.analytics_software ||
      analyticsFilters.querySelector('[name="analytics_software"]');
    const downstream =
      analyticsFilters.elements?.analytics_downstream ||
      analyticsFilters.querySelector('[name="analytics_downstream"]');
    const windowSelect =
      analyticsFilters.elements?.analytics_window ||
      analyticsFilters.querySelector('[name="analytics_window"]');
    const trigger = analyticsFilters.querySelector("[data-analytics-apply]");

    if (isStandaloneStaticPreview && !window.__b1ApiActive) {
      analyticsScreen.setAttribute("aria-busy", "true");
      analyticsContent.hidden = true;
      analyticsEmpty.hidden = false;
      analyticsScreen.querySelectorAll("[data-analytics-metric]").forEach((target) => {
        target.textContent = "—";
      });
      updateQuery({
        asw: null,
        ads: null,
        aw: null,
      });
      analyticsScreen.removeAttribute("aria-busy");
      return null;
    }

    analyticsScreen.setAttribute("aria-busy", "true");
    if (trigger) {
      trigger.disabled = true;
      trigger.textContent = "读取中…";
    }
    try {
      const query = new URLSearchParams({
        software_id: software?.value || "all",
        downstream_id: downstream?.value || "all",
        window: windowSelect?.value || "7d",
      });
      const payload = await apiRequest(`/manage/analytics/summary/?${query.toString()}`);
      clearRuntimeReadError('[data-screen-panel="analytics"]');
      replaceAnalyticsOptions(software, payload.filters?.software, "全部软件");
      replaceAnalyticsOptions(downstream, payload.filters?.downstream, "全部下游");
      applyAnalyticsPayload(payload);
      updateQuery({
        asw: software?.value === "all" ? null : software?.value,
        ads: downstream?.value === "all" ? null : downstream?.value,
        aw: windowSelect?.value === "7d" ? null : windowSelect?.value,
      });
      return payload;
    } catch (requestError) {
      if (analyticsContent) analyticsContent.hidden = true;
      showRuntimeReadError(
        '[data-screen-panel="analytics"]',
        apiErrorMessage(requestError, "统计数据暂时无法读取。"),
        applyAnalyticsRange,
      );
      throw requestError;
    } finally {
      analyticsScreen.removeAttribute("aria-busy");
      if (trigger) {
        trigger.disabled = false;
        trigger.textContent = "应用范围";
      }
    }
  }

  if (analyticsFilters) {
    const params = new URLSearchParams(window.location.search);
    analyticsFilters.querySelector('[name="analytics_software"]').value =
      params.get("asw") || "all";
    analyticsFilters.querySelector('[name="analytics_downstream"]').value =
      params.get("ads") || "all";
    analyticsFilters.querySelector('[name="analytics_window"]').value =
      params.get("aw") || "7d";
    analyticsFilters
      .querySelector("[data-analytics-apply]")
      ?.addEventListener("click", applyAnalyticsRange);
    analyticsScreen
      .querySelector("[data-analytics-refresh]")
      ?.addEventListener("click", applyAnalyticsRange);
    analyticsScreen
      .querySelector("[data-analytics-reset]")
      ?.addEventListener("click", () => {
        analyticsFilters.querySelector('[name="analytics_software"]').value =
          "all";
        analyticsFilters.querySelector('[name="analytics_downstream"]').value =
          "all";
        analyticsFilters.querySelector('[name="analytics_window"]').value =
          "7d";
        applyAnalyticsRange().catch(() => {});
      });
    if (
      !params.has("view") &&
      (window.location.hash === "#analytics" ||
        params.has("asw") ||
        params.has("ads") ||
        params.has("aw"))
    )
      applyAnalyticsRange().catch(() => {});
  }

  const downstreamWorkspace = document.querySelector(
    '[data-screen-panel="workspace"]',
  );
  const downstreamMetricFilters = downstreamWorkspace?.querySelector(
    "[data-downstream-metrics-filters]",
  );
  function applyDownstreamMetricsPayload(payload) {
    if (!downstreamWorkspace || !downstreamMetricFilters) return;
    const values = payload?.downstream || {};
    const hasData = Boolean(payload?.has_data);
    const empty = downstreamWorkspace.querySelector("[data-downstream-metrics-empty]");
    Object.entries({
      balance: formatMetric(values.balance),
      active: formatMetric(values.active),
      issued: formatMetric(values.issued),
      reclaimable: formatMetric(values.reclaimable),
    }).forEach(([name, value]) => {
      const target = downstreamWorkspace.querySelector(`[data-downstream-metric="${name}"]`);
      if (target) target.textContent = value;
    });
    if (empty) empty.hidden = hasData;
    applyRevenueMetricGrids(payload?.revenue);
    downstreamWorkspace.querySelectorAll(".signal-label").forEach((label) => {
      label.textContent = "当前下游";
    });
  }

  async function applyDownstreamMetrics() {
    if (!downstreamWorkspace || !downstreamMetricFilters) return;
    const software = downstreamMetricFilters.querySelector(
      '[name="downstream_metrics_software"]',
    );
    const windowSelect = downstreamMetricFilters.querySelector(
      '[name="downstream_metrics_window"]',
    );
    const trigger = downstreamMetricFilters.querySelector("[data-downstream-metrics-apply]");

    if (isStandaloneStaticPreview && !window.__b1ApiActive) {
      applyDownstreamMetricsPayload({ has_data: false, downstream: {}, revenue: {} });
      updateQuery({ dsw: null, dw: null });
      return null;
    }

    if (trigger) trigger.disabled = true;
    try {
      const query = new URLSearchParams({
        software_id: software?.value || "all",
        window: windowSelect?.value || "7d",
      });
      const payload = await apiRequest(`/downstream/analytics/summary/?${query.toString()}`);
      clearRuntimeReadError('[data-screen-panel="workspace"]');
      replaceAnalyticsOptions(software, payload.filters?.software, "全部可经营软件");
      applyDownstreamMetricsPayload(payload);
      updateQuery({
        dsw: software?.value === "all" ? null : software?.value,
        dw: windowSelect?.value === "7d" ? null : windowSelect?.value,
      });
      return payload;
    } catch (requestError) {
      showRuntimeReadError(
        '[data-screen-panel="workspace"]',
        apiErrorMessage(requestError, "经营统计暂时无法读取。"),
        applyDownstreamMetrics,
      );
      throw requestError;
    } finally {
      if (trigger) trigger.disabled = false;
    }
  }

  if (downstreamMetricFilters) {
    const params = new URLSearchParams(window.location.search);
    downstreamMetricFilters.querySelector(
      '[name="downstream_metrics_software"]',
    ).value = params.get("dsw") || "all";
    downstreamMetricFilters.querySelector(
      '[name="downstream_metrics_window"]',
    ).value = params.get("dw") || "7d";
    downstreamMetricFilters
      .querySelector("[data-downstream-metrics-apply]")
      ?.addEventListener("click", () => {
        applyDownstreamMetrics().catch(() => {});
      });
    downstreamWorkspace
      .querySelector("[data-downstream-metrics-reset]")
      ?.addEventListener("click", () => {
        downstreamMetricFilters.querySelector(
          '[name="downstream_metrics_software"]',
        ).value = "all";
        downstreamMetricFilters.querySelector(
          '[name="downstream_metrics_window"]',
        ).value = "7d";
        applyDownstreamMetrics().catch(() => {});
      });
    if (params.has("dsw") || params.has("dw")) applyDownstreamMetrics().catch(() => {});
  }

  const releaseDialog = document.getElementById("releaseDialog");
  const releasePackage = document.getElementById("releasePackage");
  const releaseNext = releaseDialog?.querySelector("[data-release-next]");
  const releaseStages =
    releaseDialog?.querySelectorAll("[data-release-stage]") || [];
  const releaseSteps =
    releaseDialog?.querySelectorAll("[data-release-stepper] span") || [];
  let releaseFileState = null;
  let pendingDiscardReleaseId = null;
  let pendingWithdrawReleaseId = null;
  let pendingWithdrawIdempotencyKey = null;
  let pendingUpdateReleaseId = null;
  let pendingDeleteReleasePackageId = null;
  let releaseItems = [];

  function showReleaseStage(name, index) {
    releaseStages.forEach((stage) => {
      stage.hidden = stage.dataset.releaseStage !== name;
    });
    releaseSteps.forEach((step, stepIndex) => {
      step.classList.toggle("is-done", stepIndex < index);
      step.classList.toggle("is-current", stepIndex === index);
    });
  }

  function applyReleaseResult(payload) {
    const item = payload?.item || {};
    const software = releaseDialog?.querySelector("[data-release-result-software]");
    const version = releaseDialog?.querySelector("[data-release-result-version]");
    const heading = releaseDialog?.querySelector("[data-release-result-heading]");
    const status = releaseDialog?.querySelector("[data-release-result-status]");
    if (software) software.textContent = item.software_name || item.software_id || "—";
    if (version) version.textContent = item.version ? `v${item.version} · ${item.channel || "—"}` : "—";
    if (heading) heading.textContent = payload?.replaced ? "已覆盖旧链接" : "版本已发布";
    if (status) {
      status.textContent = payload?.replaced
        ? "已覆盖旧记录 · 版本号不变 · 可撤回"
        : "已发布 · 可撤回";
    }
  }

  function packageValidationError(file) {
    if (!file) return "请选择客户端 ZIP 构建包。";
    const name = file.name.toLocaleLowerCase("en-US");
    if (!name.endsWith(".zip")) return "文件类型不允许：只接受 ZIP 构建包。";
    if (file.size > 500 * 1024 * 1024) return "构建包超过 500 MB 上限。";
    return "";
  }

  function readReleaseFile() {
    if (!releaseDialog || !releaseNext) return;
    const file = releasePackage?.files[0];
    const error = releaseDialog.querySelector("[data-release-error]");
    const message = packageValidationError(file);
    releaseFileState = message || !file ? null : { file };
    releaseNext.disabled = Boolean(message);
    if (error) error.textContent = message;
  }

  releasePackage?.addEventListener("change", readReleaseFile);
  releaseNext?.addEventListener("click", async () => {
    readReleaseFile();
    if (!releaseFileState || !releaseDialog) return;
    const channel = document.getElementById("releaseChannel");
    const error = releaseDialog.querySelector("[data-release-error]");

    if (isStandaloneStaticPreview && !window.__b1ApiActive) {
      if (error) error.textContent = "静态预览不校验或发布真实构建包。";
      return;
    }

    releaseNext.disabled = true;
    if (error) error.textContent = "";
    try {
      const form = new FormData();
      form.append("software_id", releaseUploadSoftwareId());
      form.append("channel", channel?.value || "");
      form.append("release_package", releaseFileState.file);
      const payload = await apiRequest("/manage/releases/", {
        method: "POST",
        body: form,
        headers: { "Idempotency-Key": requestIdempotencyKey("release-upload") },
      });
      const item = payload.item;
      releaseFileState = { file: releaseFileState.file, item };
      pendingDiscardReleaseId = item.release_id || null;
      releaseDialog.querySelector("[data-release-version]").textContent = `v${item.version}`;
      releaseDialog.querySelector("[data-release-size]").textContent = `${Math.max(1, Math.ceil(item.package_size / 1024)).toLocaleString("zh-CN")} KB`;
      releaseDialog.querySelector("[data-release-hash]").textContent = item.package_sha256;
      releaseDialog.querySelector("[data-release-target]").textContent = `${item.target} · ${item.arch} · ${item.channel}`;
      const signature = releaseDialog.querySelector("[data-release-signature-status]");
      if (signature) {
        signature.textContent = item.signature?.status === "verified" ? "已验证" : "已声明，待受控公钥验证";
        signature.className = item.signature?.status === "verified" ? "status status-green" : "status status-warm";
      }
      releaseDialog.dataset.pendingVersion = item.version;
      releaseDialog.dataset.pendingSoftware = item.software_name;
      releaseDialog.dataset.pendingChannel = item.channel;
      showReleaseStage("verify", 1);
    } catch (requestError) {
      releaseNext.disabled = false;
      if (error) error.textContent = apiErrorMessage(requestError, "构建包校验失败，请修正后重试。");
    }
  });
  releaseDialog?.querySelector("[data-release-publish-link]")?.addEventListener("click", async (event) => {
    const button = event.currentTarget;
    const error = releaseDialog.querySelector("[data-release-link-error]");
    const softwareId = releaseUploadSoftwareId();
    const channel = document.getElementById("releaseChannel")?.value || "stable";
    const version = document.getElementById("releaseExternalVersion")?.value.trim() || "";
    const notes = document.getElementById("releaseExternalNotes")?.value.trim() || "";
    const url = document.getElementById("releaseExternalUrl")?.value.trim() || "";
    const sha = document.getElementById("releaseExternalSha256")?.value.trim() || "";
    if (!softwareId) {
      if (error) error.textContent = "请选择软件。";
      return;
    }
    if (!version) {
      if (error) error.textContent = "版本号必须是 1.2.3 这种三段数字。";
      return;
    }
    if (notes.length < 4) {
      if (error) error.textContent = "请填写至少 4 个字符的更新说明。";
      return;
    }
    if (!url) {
      if (error) error.textContent = "请填写网盘下载地址。";
      return;
    }
    if (sha && !/^[0-9a-fA-F]{64}$/.test(sha)) {
      if (error) error.textContent = "安装包 SHA-256 必须是 64 位十六进制散列值。";
      return;
    }
    if (isStandaloneStaticPreview && !window.__b1ApiActive) {
      if (error) error.textContent = "静态预览不发布真实网盘地址。";
      return;
    }
    if (button.disabled) return;
    button.disabled = true;
    if (error) error.textContent = "";
    try {
      if (releaseDialog.__writeScope !== "release:external") prepareDialogWrite(releaseDialog, "release:external", [softwareId]);
      const payload = await submitDialogWrite(releaseDialog, "/manage/releases/external/", {
        software_id: softwareId, channel, version, notes, external_download_url: url, package_sha256: sha || null,
      }, "release-external");
      const item = payload.item;
      pendingDiscardReleaseId = null;
      applyReleaseResult(payload);
      showReleaseStage("result", 2);
      try { await loadReleasesForSoftware(softwareId || item.software_id); }
      catch (_refreshError) { showToast("版本已发布，列表刷新失败。请刷新列表，无需重新发布。", 8000); }
      const resultHeading = releaseDialog.querySelector("[data-release-stage='result'] h3");
      if (resultHeading) {
        resultHeading.tabIndex = -1;
        resultHeading.focus({ preventScroll: true });
      }
    } catch (requestError) {
      if (error) error.textContent = apiErrorMessage(requestError, "网盘地址发布失败，请重试。");
      button.disabled = false;
    }
  });
  releaseDialog
    ?.querySelector("[data-release-back]")
    ?.addEventListener("click", () => {
      showReleaseStage("upload", 0);
      readReleaseFile();
    });
  releaseDialog
    ?.querySelector("[data-release-confirm]")
    ?.addEventListener("click", async (event) => {
      const notes = document.getElementById("releaseNotes");
      const error = releaseDialog.querySelector("[data-release-confirm-error]");
      if (!notes?.checkValidity()) {
        if (error) error.textContent = "请填写至少 4 个字符的更新说明。";
        notes?.reportValidity();
        return;
      }
      const button = event.currentTarget;
      if (button.disabled) return;
      button.disabled = true;
      if (error) error.textContent = "";
      try {
        const releaseId = releaseFileState?.item?.release_id;
        if (!releaseId) throw new ApiRequestError("上传结果已失效，请重新选择构建包。", 409);
        if (releaseDialog.__writeScope !== "release:publish") prepareDialogWrite(releaseDialog, "release:publish", [releaseId]);
        const payload = await submitDialogWrite(releaseDialog, `/manage/releases/${encodeURIComponent(releaseId)}/publish/`, { notes: notes.value.trim() }, "release-publish");
        const item = payload.item;
        pendingDiscardReleaseId = null;
        applyReleaseResult(payload);
        showReleaseStage("result", 2);
        try { await loadReleasesForSoftware(document.getElementById("releaseSoftware")?.value || item.software_id); }
        catch (_refreshError) { showToast("版本已发布，列表刷新失败。请刷新列表，无需重新发布。", 8000); }
        const resultHeading = releaseDialog.querySelector("[data-release-stage='result'] h3");
        if (resultHeading) {
          resultHeading.tabIndex = -1;
          resultHeading.focus({ preventScroll: true });
        }
      } catch (requestError) {
        if (error) error.textContent = apiErrorMessage(requestError, "版本发布失败，请重试。");
        button.disabled = false;
      }
    });
  releaseDialog?.addEventListener("close", () => {
    if (pendingUiWrites.has(releaseDialog.__writeScope)) return;
    const discardId = pendingDiscardReleaseId;
    pendingDiscardReleaseId = null;
    releasePackage && (releasePackage.value = "");
    releaseFileState = null;
    if (releaseNext) releaseNext.disabled = true;
    const confirm = releaseDialog.querySelector("[data-release-confirm]");
    if (confirm) confirm.disabled = false;
    const uploadError = releaseDialog.querySelector("[data-release-error]");
    if (uploadError) uploadError.textContent = "";
    const confirmError = releaseDialog.querySelector("[data-release-confirm-error]");
    if (confirmError) confirmError.textContent = "";
    const linkError = releaseDialog.querySelector("[data-release-link-error]");
    if (linkError) linkError.textContent = "";
    const linkButton = releaseDialog.querySelector("[data-release-publish-link]");
    if (linkButton) linkButton.disabled = false;
    const versionInput = document.getElementById("releaseExternalVersion");
    const notesInput = document.getElementById("releaseExternalNotes");
    const urlInput = document.getElementById("releaseExternalUrl");
    if (versionInput) versionInput.value = "";
    if (notesInput) notesInput.value = "";
    if (urlInput) urlInput.value = "";
    const shaInput = document.getElementById("releaseExternalSha256");
    if (shaInput) shaInput.value = "";
    applyReleaseResult({ item: {}, replaced: false });
    showReleaseStage("upload", 0);
    if (discardId && !(isStandaloneStaticPreview && !window.__b1ApiActive)) {
      apiRequest(`/manage/releases/${encodeURIComponent(discardId)}/discard/`, {
        method: "POST",
        body: "{}",
        headers: { "Idempotency-Key": requestIdempotencyKey("release-discard") },
      }).catch(() => {
        showToast("草稿自动丢弃失败，草稿已保留，请刷新版本表后手动处理。");
        loadReleasesForSoftware(releaseContext?.value || "all").catch(() => {});
      });
    }
  });

  const releaseContext = document.querySelector("[data-release-context]");
  function syncReleaseUploadSoftwareFromTable() {
    const tableSoftware = document.querySelector("[data-release-context]");
    const uploadSoftware = document.getElementById("releaseSoftware");
    if (!tableSoftware || !uploadSoftware) return;
    const selected = tableSoftware.value;
    if (selected && [...uploadSoftware.options].some((option) => option.value === selected)) {
      uploadSoftware.value = selected;
    }
  }

  function releaseUploadSoftwareId() {
    syncReleaseUploadSoftwareFromTable();
    return (
      document.querySelector("[data-release-context]")?.value ||
      document.getElementById("releaseSoftware")?.value ||
      ""
    );
  }

  function syncReleaseSoftwareOptions(items) {
    if ((isStandaloneStaticPreview && !window.__b1ApiActive) || !document.body.classList.contains("role-admin")) return;
    const selects = [
      document.querySelector("[data-release-context]"),
      document.getElementById("releaseSoftware"),
    ].filter(Boolean);
    const entries = (Array.isArray(items) ? items : [])
      .map((item) => ({
        id: String(item.software_id || ""),
        name: String(item.name || item.software_id || ""),
      }))
      .filter((item) => item.id && item.name);
    selects.forEach((select) => {
      const current = select.value;
      const options = entries.map((item) => {
        const option = document.createElement("option");
        option.value = item.id;
        option.textContent = item.name;
        return option;
      });
      select.replaceChildren(...options);
      select.value = entries.some((item) => item.id === current)
        ? current
        : (entries[0]?.id || "");
    });
    const context = document.querySelector("[data-release-context]");
    if (context && entries.length) context.dispatchEvent(new Event("change"));
    syncReleaseUploadSoftwareFromTable();
  }
  function releaseStatusCopy(status) {
    return {
      draft: ["草稿", "status-warm"],
      published: ["已发布", "status-green"],
      withdrawn: ["已撤回", "status-red"],
      archived: ["已归档", "status-gray"],
    }[status] || [status || "未知", "status-gray"];
  }

  function renderReleaseRows(items) {
    const body = document.querySelector("[data-release-table]");
    if (!body) return;
    body.replaceChildren();
    (items || []).forEach((item) => {
      const row = document.createElement("tr");
      row.dataset.releaseId = item.release_id;
      row.dataset.releaseVersion = item.version;
      row.dataset.releaseSoftware = item.software_id;
      const versionCell = document.createElement("td");
      const version = document.createElement("b");
      version.className = "mono";
      version.textContent = `v${item.version}`;
      const notes = document.createElement("small");
      notes.textContent = `${item.channel} · ${item.notes || "无更新说明"}`;
      versionCell.append(version, notes);
      row.append(versionCell);
      appendTextCell(row, `${item.target} · ${item.arch}`);
      const manifestCell = document.createElement("td");
      const manifestStatus = document.createElement("span");
      manifestStatus.className = "status status-green";
      manifestStatus.textContent = "client-release.v1";
      manifestCell.append(manifestStatus);
      row.append(manifestCell);
      const hashCell = document.createElement("td");
      const hash = document.createElement("b");
      const signature = document.createElement("small");
      if (item.external_download_url) {
        hash.textContent = "网盘地址";
        signature.textContent = "打开浏览器下载，不走本站流量";
      } else {
        hash.textContent = `${Math.max(1, Math.ceil(item.package_size / 1024)).toLocaleString("zh-CN")} KB / SHA-256`;
        signature.textContent = item.signature?.status === "verified" ? "发布签名已验证" : "发布签名已声明";
      }
      hashCell.append(hash, signature);
      row.append(hashCell);
      const [statusLabel, statusClass] = releaseStatusCopy(item.status);
      const statusCell = document.createElement("td");
      const status = document.createElement("span");
      status.className = `status ${statusClass}`;
      status.dataset.releaseRowStatus = "";
      status.textContent = statusLabel;
      statusCell.append(status);
      row.append(statusCell);
      const actionCell = document.createElement("td");
      const buildReleaseAction = (label, handler, { danger = false } = {}) => {
        const button = document.createElement("button");
        button.className = danger ? "text-button danger-link" : "text-button";
        button.type = "button";
        button.textContent = label;
        if (handler) button.addEventListener("click", handler);
        return button;
      };
      if (item.status === "draft") {
        const action = buildReleaseAction("继续发布 ↗");
        action.dataset.dialog = "releaseDialog";
        wrapTableActions(actionCell, action);
      } else if (item.status === "published") {
        const buttons = [];
        if (item.external_download_url) {
          const edit = buildReleaseAction("改地址");
          edit.dataset.dialog = "editReleaseUrlDialog";
          buttons.push(edit);
        }
        if (item.external_download_url) buttons.push(buildReleaseAction("改版本号", () => openRenameReleaseDialog(item)));
        buttons.push(buildReleaseAction("归档", () => openArchiveReleaseDialog(item)));
        const withdraw = buildReleaseAction("撤回 ↗", null, { danger: true });
        withdraw.dataset.dialog = "withdrawReleaseDialog";
        buttons.push(withdraw);
        wrapTableActions(actionCell, ...buttons);
      } else if (item.status === "withdrawn" || item.status === "archived") {
        const buttons = [];
        if (item.status === "withdrawn" && item.package_available) {
          const remove = buildReleaseAction("删文件", null, { danger: true });
          remove.dataset.dialog = "deleteReleasePackageDialog";
          remove.setAttribute("data-release-delete-package", "");
          buttons.push(remove);
        }
        if (item.status === "withdrawn") {
          buttons.push(buildReleaseAction("归档", () => openArchiveReleaseDialog(item)));
        }
        if (buttons.length) wrapTableActions(actionCell, ...buttons);
        else actionCell.textContent = "已归档，历史行仍保留";
      } else {
        actionCell.textContent = "已保留历史记录";
      }
      row.append(actionCell);
      body.append(row);
    });
    const panel = body.closest(".table-panel");
    if (panel) panel.dataset.serverDataLoaded = "true";
    bindDialogTriggers(body);
    window.__previewRefreshTables?.();
  }

  let archiveTargetReleaseId = "";
  let renameTargetReleaseId = "";

  function openArchiveReleaseDialog(item) {
    const dialog = document.getElementById("archiveReleaseDialog");
    if (!dialog || !item) return;
    if (resumeDialogWrite(dialog, "release:archive")) return;
    prepareDialogWrite(dialog, "release:archive", [item.release_id]);
    restoreDialogWrite(dialog);
    archiveTargetReleaseId = item.release_id;
    const target = dialog.querySelector("[data-archive-target]");
    if (target) target.textContent = `v${item.version} · ${item.channel} · ${releaseStatusCopy(item.status)[0]}`;
    const reason = dialog.querySelector('textarea[name="reason"]');
    if (reason) reason.value = "";
    const error = dialog.querySelector("[data-form-error]");
    if (error) error.textContent = "";
    dialog.showModal();
  }

  function openRenameReleaseDialog(item) {
    const dialog = document.getElementById("renameReleaseDialog");
    if (!dialog || !item) return;
    if (resumeDialogWrite(dialog, "release:version")) return;
    prepareDialogWrite(dialog, "release:version", [item.release_id]);
    restoreDialogWrite(dialog);
    renameTargetReleaseId = item.release_id;
    const target = dialog.querySelector("[data-rename-target]");
    if (target) target.textContent = `v${item.version} · ${item.channel} · ${item.target} · ${item.arch}`;
    const version = dialog.querySelector('input[name="version"]');
    if (version) version.value = "";
    const reason = dialog.querySelector('textarea[name="reason"]');
    if (reason) reason.value = "";
    const error = dialog.querySelector("[data-form-error]");
    if (error) error.textContent = "";
    dialog.showModal();
  }

  document.querySelector("[data-archive-confirm]")?.addEventListener("click", async (event) => {
    const dialog = document.getElementById("archiveReleaseDialog");
    const form = event.currentTarget.closest("form");
    const error = dialog?.querySelector("[data-form-error]");
    if (!archiveTargetReleaseId) {
      if (error) error.textContent = "版本记录已失效，请刷新后重试。";
      return;
    }
    const reason = form?.elements.reason?.value.trim() || "";
    if (reason.length < 4) {
      if (error) error.textContent = "请填写至少 4 个字符的归档原因。";
      return;
    }
    if (isStandaloneStaticPreview && !window.__b1ApiActive) {
      if (error) error.textContent = "静态预览不执行真实版本归档。";
      return;
    }
    event.currentTarget.disabled = true;
    if (error) error.textContent = "";
    try {
      const payload = await submitDialogWrite(dialog, `/manage/releases/${encodeURIComponent(dialog.__selectedIds[0])}/archive/`, { reason }, "release-archive");
      dialog?.close("success");
      try { await loadReleasesForSoftware(releaseContext?.value || "all"); }
      catch (_refreshError) { showToast("版本已归档，列表刷新失败。请刷新列表，无需再次归档。", 8000); return; }
      const fallback = payload?.registry_fallback_version;
      showToast(
        fallback
          ? `版本已归档，版本表默认列表里不再显示。公开目录会改指向 v${fallback}。历史行、版本号和审计都还保留。`
          : "版本已归档，版本表默认列表里不再显示。历史行、版本号和审计都还保留。",
      );
    } catch (requestError) {
      if (error) error.textContent = apiErrorMessage(requestError, "归档失败，请重试。");
    } finally {
      const confirm = dialog?.querySelector("[data-archive-confirm]");
      if (confirm) confirm.disabled = false;
    }
  });

  document.querySelector("[data-rename-confirm]")?.addEventListener("click", async (event) => {
    const dialog = document.getElementById("renameReleaseDialog");
    const form = event.currentTarget.closest("form");
    const error = dialog?.querySelector("[data-form-error]");
    if (!renameTargetReleaseId) {
      if (error) error.textContent = "版本记录已失效，请刷新后重试。";
      return;
    }
    const version = form?.elements.version?.value.trim() || "";
    const reason = form?.elements.reason?.value.trim() || "";
    if (!/^v?\d+\.\d+\.\d+$/.test(version)) {
      if (error) error.textContent = "版本号必须是三段数字，例如 2.0.9。";
      return;
    }
    if (reason.length < 4) {
      if (error) error.textContent = "请填写至少 4 个字符的改号原因。";
      return;
    }
    if (isStandaloneStaticPreview && !window.__b1ApiActive) {
      if (error) error.textContent = "静态预览不执行真实改版本号。";
      return;
    }
    event.currentTarget.disabled = true;
    if (error) error.textContent = "";
    try {
      await submitDialogWrite(dialog, `/manage/releases/${encodeURIComponent(dialog.__selectedIds[0])}/version/`, { version, reason }, "release-version");
      dialog?.close("success");
      try { await loadReleasesForSoftware(releaseContext?.value || "all"); }
      catch (_refreshError) { showToast("版本号已修改，列表刷新失败。请刷新列表，无需再次改号。", 8000); return; }
      showToast(`版本号已改成 ${version}。客户端下次检查就会看到更新，没有新增版本历史。`);
    } catch (requestError) {
      if (error) error.textContent = apiErrorMessage(requestError, "改版本号失败，请重试。");
    } finally {
      const confirm = dialog?.querySelector("[data-rename-confirm]");
      if (confirm) confirm.disabled = false;
    }
  });

  let releasePage = 1;
  let releaseListRequestGeneration = 0;
  let releaseContextRequestGeneration = 0;
  let releaseStatusFilter = "all";

  function setReleasePagination(payload) {
    const controls = document.querySelector("[data-release-server-pagination]");
    const summary = document.querySelector("[data-release-count]");
    const pagination = payload?.pagination || {};
    const total = Number(payload?.count ?? pagination.total ?? 0);
    const page = Number(pagination.page || 1);
    const totalPages = Number(pagination.total_pages || 0);
    if (summary) summary.textContent = `共 ${total} 条版本`;
    if (!controls) return;
    controls.hidden = totalPages <= 1;
    const prev = controls.querySelector("[data-release-prev]");
    const next = controls.querySelector("[data-release-next]");
    const pageLabel = controls.querySelector("[data-release-page]");
    if (prev) prev.disabled = !pagination.has_previous;
    if (next) next.disabled = !pagination.has_next;
    if (pageLabel) pageLabel.textContent = `第 ${page} / ${totalPages} 页 · 共 ${total} 条`;
  }

  function compareReleaseVersions(left, right) {
    const parts = (value) =>
      String(value || "")
        .split(/[.+-]/)
        .map((part) => {
          const numeric = Number.parseInt(part, 10);
          return Number.isFinite(numeric) ? numeric : 0;
        });
    const first = parts(left);
    const second = parts(right);
    const size = Math.max(first.length, second.length);
    for (let index = 0; index < size; index += 1) {
      const delta = (first[index] || 0) - (second[index] || 0);
      if (delta) return delta;
    }
    return 0;
  }

  function highestPublishedRelease(items) {
    return (items || [])
      .slice()
      .sort((left, right) => compareReleaseVersions(right.version, left.version))[0] || null;
  }

  async function loadPublishedReleases(softwareId) {
    if ((isStandaloneStaticPreview && !window.__b1ApiActive) || !softwareId || softwareId === "all") return [];
    const cached = publishedReleaseCache.get(softwareId);
    if (cached && Date.now() - cached.at < PUBLISHED_RELEASE_CACHE_MS) {
      return cached.items;
    }
    const items = [];
    const pageSize = 100;
    // 顶卡要显示"当前分发中"的最高版本。改版本号会把历史行提成最新，
    // 所以第 1 页（按创建时间倒序）不再保证包含最高版本，必须翻完。
    const maxPages = 200;
    for (let page = 1; page <= maxPages; page += 1) {
      const query = new URLSearchParams({
        software_id: softwareId,
        status: "published",
        page: String(page),
        page_size: String(pageSize),
      });
      const payload = await apiRequest(`/manage/releases/?${query.toString()}`);
      const batch = Array.isArray(payload.items) ? payload.items : [];
      items.push(...batch);
      if (!payload.pagination?.has_next || batch.length === 0) break;
    }
    publishedReleaseCache.set(softwareId, { at: Date.now(), items });
    return items;
  }

  function paintReleaseUpdateCopy(current, failed, softwareId) {
    const updateCopy = document.querySelector("[data-update-copy]");
    if (!updateCopy) return;
    if (!softwareId || softwareId === "all") {
      updateCopy.textContent = "请先选择软件。";
      return;
    }
    if (failed) {
      updateCopy.textContent = "暂时无法读取已发布版本。";
      return;
    }
    if (!current) {
      updateCopy.textContent = "当前软件没有已发布版本。";
      return;
    }
    updateCopy.textContent = `当前分发中 v${current.version}。点重新检查会打公共 registry。`;
  }

  async function applyReleaseContext(softwareId) {
    const currentTarget = document.querySelector("[data-current-release]");
    const updateTarget = document.querySelector("[data-update-target]");
    const statusTarget = document.querySelector("[data-current-release-status]");
    if (statusTarget) statusTarget.onclick = null;
    const generation = ++releaseContextRequestGeneration;
    const contextIsCurrent = () =>
      generation === releaseContextRequestGeneration &&
      (releaseContext?.value || "all") === (softwareId || "all");
    if (!softwareId || softwareId === "all") {
      if (!contextIsCurrent()) return;
      if (currentTarget) currentTarget.textContent = "请选择软件";
      if (updateTarget) updateTarget.textContent = "—";
      if (statusTarget) {
        statusTarget.textContent = "暂无发布";
        statusTarget.className = "status status-gray";
      }
      paintReleaseUpdateCopy(null, false, softwareId);
      return;
    }
    try {
      const current = highestPublishedRelease(await loadPublishedReleases(softwareId));
      if (!contextIsCurrent()) return;
      if (currentTarget) currentTarget.textContent = current ? `v${current.version}` : "—";
      if (updateTarget) updateTarget.textContent = current ? `v${current.version}` : "—";
    if (statusTarget) {
      statusTarget.textContent = current ? "分发中" : "暂无发布";
      statusTarget.className = current ? "status status-green" : "status status-gray";
      }
      paintReleaseUpdateCopy(current, false, softwareId);
    } catch (_requestError) {
      if (!contextIsCurrent()) return;
      if (currentTarget) currentTarget.textContent = "暂时无法读取";
      if (updateTarget) updateTarget.textContent = "—";
      if (statusTarget) {
        statusTarget.textContent = "读取失败";
        statusTarget.className = "status status-red";
        statusTarget.onclick = () => {
          applyReleaseContext(softwareId).catch(() => {});
        };
      }
      paintReleaseUpdateCopy(null, true, softwareId);
    }
  }

  function fillReleaseSignatureStatus(item) {
    const signature = document.querySelector("[data-release-signature-status]");
    if (!signature) return;
    if (item?.signature?.status === "verified") {
      signature.textContent = "已验证";
      signature.className = "status status-green";
      return;
    }
    if (item?.signature?.status) {
      signature.textContent = "已声明，待受控公钥验证";
      signature.className = "status status-warm";
      return;
    }
    signature.textContent = "待校验";
    signature.className = "status status-gray";
  }

  async function loadReleasesForSoftware(softwareId, page = releasePage) {
    if (isStandaloneStaticPreview && !window.__b1ApiActive) return null;
    if (!document.body.classList.contains("role-admin")) return null;
    const requestedSoftware = softwareId || "all";
    const generation = ++releaseListRequestGeneration;
    const query = new URLSearchParams({
      software_id: requestedSoftware,
      page: String(Math.max(1, Number(page) || 1)),
      page_size: "10",
    });
    if (releaseStatusFilter && releaseStatusFilter !== "all") query.set("status", releaseStatusFilter);
    const releaseSearch = document.querySelector("[data-release-search]")?.value.trim() || "";
    if (releaseSearch) query.set("q", releaseSearch);
    try {
      clearRuntimeReadError('[data-screen-panel="releases"]');
      const payload = await apiRequest(`/manage/releases/?${query.toString()}`);
      if (generation !== releaseListRequestGeneration) return null;
      const currentSoftware = releaseContext?.value || "all";
      if (requestedSoftware !== currentSoftware) return null;
    releaseItems = payload.items || [];
      releasePage = payload.pagination?.page || page;
    renderReleaseRows(releaseItems);
      await applyReleaseContext(softwareId);
      if (generation !== releaseListRequestGeneration) return null;
      setReleasePagination(payload);
    return payload;
    } catch (requestError) {
      if (generation !== releaseListRequestGeneration) return null;
      if (requestError instanceof ApiRequestError && requestError.status === 404) return null;
      try {
        await applyReleaseContext(softwareId);
      } catch (_contextError) {}
      showRuntimeReadError(
        '[data-screen-panel="releases"]',
        apiErrorMessage(requestError, "版本列表暂时无法读取。"),
        () => loadReleasesForSoftware(softwareId, page),
      );
      throw requestError;
    }
  }

  function catalogSoftwareForRelease(softwareId) {
    const catalog = [
      ...(typeof catalogItems !== "undefined" && Array.isArray(catalogItems) ? catalogItems : []),
      ...((typeof clientCatalogPayload !== "undefined" && clientCatalogPayload.items) || []),
    ];
    return catalog.find((item) => item.software_id === softwareId) || null;
  }

  function firstLiveProfile(softwareItem) {
    const profiles = softwareItem?.profiles || [];
    return (
      profiles.find((profile) => ["active", "testing"].includes(profile.status)) ||
      profiles[0] ||
      null
    );
  }

  async function recheckPublicReleaseRegistry(softwareId) {
    const software = catalogSoftwareForRelease(softwareId);
    const profile = firstLiveProfile(software);
    const updateTarget = document.querySelector("[data-update-target]");
    const updateCopy = document.querySelector("[data-update-copy]");
    if (!software || !profile?.profile_id) {
      if (updateCopy) updateCopy.textContent = "当前软件没有可查询的 Profile，无法检查 registry。";
      throw new ApiRequestError("当前软件没有可查询的 Profile。", 404);
    }
    const query = new URLSearchParams({
      client_id: profile.client_id || "",
      target: profile.target || "windows",
      arch: profile.arch || "x64",
      channel: profile.channel || "stable",
    });
    const payload = await apiRequest(
      `/public/software/${encodeURIComponent(software.software_id)}/profiles/${encodeURIComponent(profile.profile_id)}/releases/?${query}`,
    );
    if (payload?.release) {
      if (updateTarget) updateTarget.textContent = `v${payload.release.version}`;
      if (updateCopy) {
        updateCopy.textContent = `registry 当前发布 v${payload.release.version}。客户端要用自己的版本号比较是否有更新。`;
      }
    } else {
      if (updateTarget) updateTarget.textContent = "—";
      if (updateCopy) updateCopy.textContent = "registry 没有可下载的已发布版本。";
    }
    return payload;
  }

  document.querySelectorAll("[data-release-status]").forEach((chip) => {
    chip.addEventListener("click", () => {
      document.querySelectorAll("[data-release-status]").forEach((other) => {
        other.classList.toggle("is-active", other === chip);
        other.setAttribute("aria-pressed", String(other === chip));
      });
      releaseStatusFilter = chip.dataset.releaseStatus || "all";
      releasePage = 1;
      if (!isStandaloneStaticPreview || window.__b1ApiActive) {
        loadReleasesForSoftware(releaseContext?.value || "all", 1).catch(() => {});
      }
    });
  });
  document.querySelector("[data-release-prev]")?.addEventListener("click", () => {
    loadReleasesForSoftware(releaseContext?.value || "all", Math.max(1, releasePage - 1)).catch(() => {});
  });
  document.querySelector("[data-release-next]")?.addEventListener("click", () => {
    loadReleasesForSoftware(releaseContext?.value || "all", releasePage + 1).catch(() => {});
  });
  bindDebouncedSearch(document.querySelector("[data-release-search]"), () => {
    loadReleasesForSoftware(releaseContext?.value || "all", 1).catch(() => {});
  });

  releaseContext?.addEventListener("change", async () => {
    const screen = releaseContext.closest(".screen");
    if (isStandaloneStaticPreview && !window.__b1ApiActive) {
      if (screen) {
        screen.querySelector(".release-current h2").textContent = "当前软件 · 当前通道";
        screen.querySelector("[data-current-release]").textContent = "—";
        screen.querySelector("[data-update-target]").textContent = "—";
        screen.querySelector("[data-update-copy]").textContent = "暂无可用版本数据。";
        renderReleaseRows([]);
      }
      return;
    }
    releasePage = 1;
    try {
      await loadReleasesForSoftware(releaseContext.value, 1);
    } catch (requestError) {
      if (requestError instanceof ApiRequestError && requestError.status === 404) return;
    }
    syncReleaseUploadSoftwareFromTable();
  });
  releaseContext?.dispatchEvent(new Event("change"));

  // 下游操作记录：真实 API 加载（全部 / 我的操作 / 客户端）
  if (!isStandaloneStaticPreview && document.body.classList.contains("role-downstream")) {
    let downstreamActivityGeneration = 0;
    let downstreamActivityScope = "all";
    let downstreamActivityPage = 1;
    function setDownstreamActivityPagination(payload) {
      const controls = document.querySelector("[data-downstream-activity-pagination]");
      const summary = document.querySelector("[data-activity-count]");
      const total = Number(payload?.count || 0);
      const page = Number(payload?.page || 1);
      const totalPages = Number(payload?.total_pages || 0);
      if (summary) summary.textContent = `共 ${total} 条操作记录`;
      if (!controls) return;
      const visible = totalPages > 1;
      controls.hidden = !visible;
      const prev = controls.querySelector("[data-downstream-activity-prev]");
      const next = controls.querySelector("[data-downstream-activity-next]");
      const pageLabel = controls.querySelector("[data-downstream-activity-page]");
      if (prev) prev.disabled = !payload?.has_previous;
      if (next) next.disabled = !payload?.has_next;
      if (pageLabel) pageLabel.textContent = `第 ${page} / ${totalPages} 页 · 共 ${total} 条`;
    }
    function renderDownstreamActivityRows(items) {
      const panel = document.querySelector('[data-screen-panel="activity"] .table-panel');
      const table = panel?.querySelector("table");
      const body = table?.tBodies[0];
      if (!body) return;
      body.replaceChildren();
      (Array.isArray(items) ? items : []).forEach((item) => {
        const row = document.createElement("tr");
        const success = item.outcome === "成功";
        const actorName = auditActorLabel(item.actor_label, { downstream: true });
        const actorRole = item.actor_role || "";
        const actorText = actorRole && actorRole !== "—" && actorRole !== "downstream" ? `${actorName} · ${actorRole}` : actorName;
        appendTextCell(row, formatApiDate(item.occurred_at), "mono");
        appendTextCell(row, actorText, actorName.startsWith("GS-") ? "mono" : "");
        appendTextCell(row, auditHumanAction(item));
        appendTextCell(row, auditHumanObject(item));
        const resultCell = document.createElement("td");
        const status = document.createElement("span");
        status.className = `status ${success ? "status-green" : "status-red"}`;
        status.textContent = item.outcome || "—";
        resultCell.append(status);
        row.append(resultCell);
        const detailCell = document.createElement("td");
        const actions = document.createElement("div");
        actions.className = "table-actions";
        const detailBtn = createTableButton("详情", {
          kind: "detail",
          tooltip: `请求标识：${item.request_id || "未记录"} · 对象：${item.object_summary || "—"}`,
          onClick: () => {
            showToast(`操作详情：${auditHumanAction(item)} · 请求ID: ${item.request_id || "未记录"}`);
          },
        });
        actions.append(detailBtn);
        detailCell.append(actions);
        row.append(detailCell);
        body.append(row);
      });
      if (panel) panel.dataset.serverDataLoaded = "true";
      window.__previewRefreshTables?.();
    }
    async function loadDownstreamActivity(page = downstreamActivityPage) {
      const generation = ++downstreamActivityGeneration;
      const requestedPage = Math.max(1, Number(page) || 1);
      try {
        clearRuntimeReadError('[data-screen-panel="activity"]');
        const query = new URLSearchParams({
          scope: downstreamActivityScope,
          page: String(requestedPage),
          page_size: "10",
        });
        const search = document.querySelector("[data-activity-search]")?.value.trim() || "";
        if (search) query.set("q", search);
        const payload = await apiRequest(`/downstream/audit/?${query.toString()}`);
        if (generation !== downstreamActivityGeneration) return;
        downstreamActivityPage = payload.page || requestedPage;
        renderDownstreamActivityRows(payload.items || []);
        setDownstreamActivityPagination(payload);
      } catch (error) {
        if (generation !== downstreamActivityGeneration) return;
        showRuntimeReadError(
          '[data-screen-panel="activity"]',
          apiErrorMessage(error, "操作记录暂时无法读取，当前列表未改动。"),
          () => loadDownstreamActivity(downstreamActivityPage),
        );
      }
    }
    bindDebouncedSearch(document.querySelector("[data-activity-search]"), () => loadDownstreamActivity(1));
    document.querySelectorAll("[data-activity-scope]").forEach((chip) => {
      chip.addEventListener("click", () => {
        downstreamActivityScope = chip.dataset.activityScope;
        document.querySelectorAll("[data-activity-scope]").forEach((other) => {
          const active = other === chip;
          other.classList.toggle("is-active", active);
          other.setAttribute("aria-pressed", String(active));
          other.removeAttribute("aria-selected");
        });
        loadDownstreamActivity(1);
      });
    });
    document.querySelector("[data-downstream-activity-prev]")?.addEventListener("click", () => {
      loadDownstreamActivity(Math.max(1, downstreamActivityPage - 1));
    });
    document.querySelector("[data-downstream-activity-next]")?.addEventListener("click", () => {
      loadDownstreamActivity(downstreamActivityPage + 1);
    });
    document
      .querySelector('[data-screen-panel="activity"] [data-activity-export]')
      ?.addEventListener("click", async (event) => {
        const button = event.currentTarget;
        button.disabled = true;
        try {
          const response = await window.fetch(
            (() => {
              const params = new URLSearchParams({ scope: downstreamActivityScope });
              const search = document.querySelector("[data-activity-search]")?.value.trim() || "";
              if (search) params.set("q", search);
              return `${API_ROOT}/downstream/audit/export/?${params.toString()}`;
            })(),
            { credentials: "same-origin" },
          );
          if (!response.ok) {
            throw new Error(`export failed: ${response.status}`);
          }
          const blob = await response.blob();
          const url = URL.createObjectURL(blob);
          const link = document.createElement("a");
          link.href = url;
          link.download = "activity-log.csv";
          document.body.append(link);
          link.click();
          link.remove();
          setTimeout(() => URL.revokeObjectURL(url), 0);
          showToast(
            response.headers.get("X-Export-Truncated") === "1"
              ? `操作记录已导出脱敏摘要，已截断为最多 1000 条（服务端共 ${response.headers.get("X-Export-Total") || "多"} 条）。`
              : "当前操作记录已导出，仅包含脱敏摘要。",
          );
        } catch (exportError) {
          showToast(
            apiErrorMessage(exportError, "操作记录导出失败，请稍后重试。"),
          );
        } finally {
          button.disabled = false;
        }
      });
    loadDownstreamActivity(1);
    registerWorkspaceReloader("activity", () =>
      loadDownstreamActivity(downstreamActivityPage),
    );
  }

  // 管理端审计记录：真实 API 加载与筛选
  if (!isStandaloneStaticPreview && document.body.classList.contains("role-admin")) {
    let adminAuditRequestGeneration = 0;
    let adminAuditPage = 1;
    function adminAuditQuery(page = adminAuditPage) {
      const filterPanel = document.querySelector(
        '[data-screen-panel="audit"] .filter-panel',
      );
      const params = new URLSearchParams({
        page: String(Math.max(1, Number(page) || 1)),
        page_size: "10",
      });
      if (!filterPanel) return params.toString();
      const range =
        filterPanel.querySelector('[data-audit-filter="range"]')?.value || "";
      if (range === "today") params.set("from_date", shanghaiYmd(0));
      else if (range === "7d") params.set("from_date", shanghaiYmd(6));
      else if (range === "30d") params.set("from_date", shanghaiYmd(29));
      const action =
        filterPanel.querySelector('[data-audit-filter="action"]')?.value.trim() ||
        "";
      if (action) params.set("action", action);
      const outcome =
        filterPanel.querySelector('[data-audit-filter="outcome"]')?.value || "";
      if (outcome) params.set("outcome", outcome);
      const subject =
        filterPanel.querySelector('[data-audit-filter="subject"]')?.value || "";
      if (subject === "me") params.set("actor", "me");
      const source =
        filterPanel.querySelector('[data-audit-filter="source"]')?.value || "";
      const roles = [];
      if (subject === "client") roles.push("anonymous");
      if (source) roles.push(source);
      const uniqueRoles = [...new Set(roles)];
      if (uniqueRoles.length === 1) params.set("actor_role", uniqueRoles[0]);
      else if (uniqueRoles.length > 1) {
        params.set("actor_role", "unknown");
        params.set("actor", "me");
      }
      const downstream =
        filterPanel.querySelector('[data-audit-filter="downstream"]')?.value.trim() ||
        "";
      if (downstream) params.set("downstream_public_id", downstream);
      const software =
        filterPanel.querySelector('[data-audit-filter="software"]')?.value.trim() ||
        "";
      if (software) params.set("software_id", software);
      const search =
        document.querySelector("[data-audit-search]")?.value.trim() || "";
      if (search) params.set("q", search);
      return params.toString();
    }
    let appliedAdminAuditQuery = "";
    function appliedOrLiveAdminAuditQuery(page = adminAuditPage) {
      if (!appliedAdminAuditQuery) return adminAuditQuery(page);
      const params = new URLSearchParams(appliedAdminAuditQuery);
      params.set("page", String(Math.max(1, Number(page) || 1)));
      return params.toString();
    }
    function setAdminAuditPagination(payload) {
      const controls = document.querySelector("[data-admin-audit-pagination]");
      const summary = document.querySelector(
        '[data-screen-panel="audit"] [data-audit-count]',
      );
      const total = Number(payload?.count || 0);
      const page = Number(payload?.page || 1);
      const totalPages = Number(payload?.total_pages || 0);
      if (summary) summary.textContent = `共 ${total} 条审计记录`;
      if (!controls) return;
      controls.hidden = totalPages <= 1;
      const prev = controls.querySelector("[data-admin-audit-prev]");
      const next = controls.querySelector("[data-admin-audit-next]");
      const pageLabel = controls.querySelector("[data-admin-audit-page]");
      if (prev) prev.disabled = !payload?.has_previous;
      if (next) next.disabled = !payload?.has_next;
      if (pageLabel) pageLabel.textContent = `第 ${page} / ${totalPages} 页 · 共 ${total} 条`;
    }
    function renderAdminAuditRows(items) {
      const panel = document.querySelector('[data-screen-panel="audit"] .table-panel');
      const table = panel?.querySelector("table");
      const body = table?.tBodies[0];
      if (!body) return;
      body.replaceChildren();
      (Array.isArray(items) ? items : []).forEach((item) => {
        const row = document.createElement("tr");
        const metadata = (item.metadata || [])
          .map((entry) => `${entry.label}：${entry.value}`)
          .join("；");
        const outcome = ["success", "成功"].includes(item.outcome)
          ? ["成功", "status-green"]
          : ["failure", "失败"].includes(item.outcome)
            ? ["失败", "status-red"]
            : [item.outcome || "未知", "status-gray"];
        const actorName = item.actor_label || "—";
        const actorRole = item.actor_role || "";
        const actorText = actorRole && actorRole !== "—" ? `${actorName} · ${actorRole}` : actorName;
        appendTextCell(row, formatApiDate(item.occurred_at), "mono");
        appendTextCell(row, actorText, actorName.startsWith("GS-") ? "mono" : "");
        appendTextCell(row, auditHumanAction(item));
        appendTextCell(row, auditHumanObject(item));
        appendStatusCell(row, outcome[0], outcome[1]);
        const detailCell = document.createElement("td");
        const actions = document.createElement("div");
        actions.className = "table-actions";
        const detail = createTableButton("详情", {
          kind: "detail",
          tooltip: "查看该条审计记录完整技术字段与请求参数",
        });
        detail.dataset.auditDetail = "";
        actions.append(detail);
        detailCell.append(actions);
        row.append(detailCell);
        row.__auditItem = { ...item, metadata };
        body.append(row);
      });
      if (panel) panel.dataset.serverDataLoaded = "true";
      window.__previewRefreshTables?.();
    }
    async function loadAdminAudit(page = adminAuditPage) {
      const generation = ++adminAuditRequestGeneration;
      const requestedPage = Math.max(1, Number(page) || 1);
      const query = appliedOrLiveAdminAuditQuery(requestedPage);
      const summary = document.querySelector(
        '[data-screen-panel="audit"] [data-audit-count]',
      );
      if (summary) summary.textContent = "正在加载审计记录…";
      try {
        clearRuntimeReadError('[data-screen-panel="audit"]');
        const payload = await apiRequest(`/manage/audit/?${query}`);
        if (generation !== adminAuditRequestGeneration) return;
        adminAuditPage = payload.page || requestedPage;
        renderAdminAuditRows(payload.items || []);
        setAdminAuditPagination(payload);
      } catch (error) {
        if (generation !== adminAuditRequestGeneration) return;
        if (summary) summary.textContent = "审计记录读取失败";
        showRuntimeReadError(
          '[data-screen-panel="audit"]',
          apiErrorMessage(error, "审计记录暂时无法读取，当前列表未改动。"),
          () => loadAdminAudit(adminAuditPage),
        );
      }
    }
    document
      .querySelector('[data-screen-panel="audit"] [data-audit-apply]')
      ?.addEventListener("click", () => {
        appliedAdminAuditQuery = adminAuditQuery(1);
        loadAdminAudit(1);
      });
    bindDebouncedSearch(document.querySelector("[data-audit-search]"), () => {
      appliedAdminAuditQuery = adminAuditQuery(1);
      loadAdminAudit(1);
    });
    document.querySelector("[data-admin-audit-prev]")?.addEventListener("click", () => {
      loadAdminAudit(Math.max(1, adminAuditPage - 1));
    });
    document.querySelector("[data-admin-audit-next]")?.addEventListener("click", () => {
      loadAdminAudit(adminAuditPage + 1);
    });
    document
      .querySelector('[data-screen-panel="audit"] [data-audit-export]')
      ?.addEventListener("click", async (event) => {
        const button = event.currentTarget;
        button.disabled = true;
        try {
          const filters = new URLSearchParams(appliedOrLiveAdminAuditQuery(1));
          filters.delete("page");
          filters.delete("page_size");
          const response = await window.fetch(
            `${API_ROOT}/manage/audit/export/?${filters.toString()}`,
            { credentials: "same-origin" },
          );
          if (!response.ok) {
            throw new Error(`export failed: ${response.status}`);
          }
          const blob = await response.blob();
          const url = URL.createObjectURL(blob);
          const link = document.createElement("a");
          link.href = url;
          link.download = "audit-events.csv";
          document.body.append(link);
          link.click();
          link.remove();
          setTimeout(() => URL.revokeObjectURL(url), 0);
          showToast(
            response.headers.get("X-Export-Truncated") === "1"
              ? `审计导出已截断为最多 1000 条（服务端共 ${response.headers.get("X-Export-Total") || "多"} 条），导出动作已记录审计。`
              : "审计导出已下载，导出动作本身也已记录审计。",
          );
        } catch (exportError) {
          showToast(apiErrorMessage(exportError, "审计导出失败，请稍后重试。"));
        } finally {
          button.disabled = false;
        }
      });
    appliedAdminAuditQuery = adminAuditQuery(1);
    loadAdminAudit(1);
    const auditDetailDialog = document.getElementById("auditDetailDialog");
    document.addEventListener("click", (event) => {
      const trigger = event.target.closest("[data-audit-detail]");
      if (!trigger || !auditDetailDialog) return;
      const item = trigger.closest("tr")?.__auditItem;
      if (!item) return;
      const outcome = item.outcome === "success" ? "成功" : item.outcome === "failure" ? "失败" : item.outcome || "未知";
      const metadata = item.reason_code
        ? `原因码 ${item.reason_code}${item.metadata ? `；${item.metadata}` : ""}`
        : item.metadata || "—";
      const values = {
        occurred: formatApiDate(item.occurred_at),
        actor: `${item.actor_label || "—"} / ${item.actor_role || "—"}`,
        action: item.action && AUDIT_ACTION_COPY[item.action]
          ? `${auditActionLabel(item.action)}（${item.action}）`
          : item.action || "—",
        outcome,
        object: auditObjectDetail(item),
        ip: item.ip_address || "—",
        request: item.request_id || "—",
        metadata,
      };
      auditDetailDialog.querySelectorAll("[data-audit-detail-field]").forEach((target) => {
        target.textContent = values[target.dataset.auditDetailField] || "—";
      });
      auditDetailDialog.showModal();
    });
    registerWorkspaceReloader("audit", () => loadAdminAudit(adminAuditPage));
  }

  const backupRunCopy = {
    pending: ["排队中", "status-warm"],
    accepted: ["已接收", "status-warm"],
    running: ["执行中", "status-warm"],
    succeeded: ["成功", "status-green"],
    failed: ["失败", "status-red"],
  };
  const backupTypeCopy = { full: "全量", diff: "增量" };
  let backupPolicyLoaded = false;
  let backupPolicyDirty = false;

  function setBackupPolicyLoadState(loaded) {
    backupPolicyLoaded = Boolean(loaded);
    const form = document.querySelector("[data-backup-form]");
    const button = form?.querySelector("[data-backup-save]");
    if (button && !isStandaloneStaticPreview) button.disabled = !backupPolicyLoaded;
    form?.querySelectorAll("[data-backup-run], [data-backup-probe]").forEach((action) => {
      if (!isStandaloneStaticPreview) action.disabled = !backupPolicyLoaded;
    });
  }

  function toggleBackupDestinationFields() {
    const panel = document.querySelector('[data-screen-panel="backup"]');
    if (!panel) return;
    const githubOn = Boolean(panel.querySelector('[name="github_enabled"]')?.checked);
    panel.querySelectorAll("[data-backup-github-fields]").forEach((node) => {
      node.hidden = !githubOn;
    });
    toggleBackupMasterFields();
  }

  function toggleBackupMasterFields() {
    const panel = document.querySelector('[data-screen-panel="backup"]');
    if (!panel) return;
    const masterOn = Boolean(panel.querySelector('[name="enabled"]')?.checked);
    const schedule = panel.querySelector('[name="schedule_enabled"]');
    if (schedule) {
      schedule.disabled = !masterOn;
      if (!masterOn) setTableTooltip(schedule, "请先打开备份总开关。");
      else {
        schedule.removeAttribute("title");
        delete schedule.dataset.tableTooltip;
      }
    }
  }

  function formatBackupBytes(size) {
    const value = Number(size);
    if (!Number.isFinite(value) || value < 0) return "—";
    if (value < 1024) return `${value} B`;
    if (value < 1024 * 1024) return `${Math.round(value / 102.4) / 10} KB`;
    return `${Math.round(value / 104857.6) / 10} MB`;
  }

  function setBackupMetric(name, value) {
    const target = document.querySelector(`[data-backup-metric="${name}"]`);
    if (target) target.textContent = value || "—";
  }

  function applyBackupPolicy(policy) {
    const form = document.querySelector("[data-backup-form]");
    if (!form || !policy) return;
    const assignCheck = (name, checked) => {
      if (form.elements[name]) form.elements[name].checked = Boolean(checked);
    };
    const assignValue = (name, value) => {
      if (form.elements[name]) form.elements[name].value = value ?? "";
    };
    assignCheck("enabled", policy.enabled);
    assignCheck("schedule_enabled", policy.schedule_enabled);
    assignCheck("github_enabled", policy.github_enabled);
    assignCheck("database_enabled", policy.database_enabled);
    assignCheck("cleanup_enabled", policy.cleanup_enabled);
    assignValue("full_time", policy.schedule?.full_time || "");
    assignValue("diff_interval_hours", policy.schedule?.diff_interval_hours ?? "");
    assignValue("retention_full", policy.retention_full ?? "");
    assignValue("retention_diff", policy.retention_diff ?? "");
    assignValue("retention_archive", policy.retention_archive ?? "");
    assignValue("github_repository", policy.github_repository || "");
    assignValue("github_token", "");
    const retention = Number(policy.github_retention_count);
    window.__backupDownloadRetention =
      Number.isInteger(retention) && retention >= 1 ? retention : 1;
    if (form.elements.github_token) {
      form.elements.github_token.placeholder = policy.github_token_configured
        ? "已记下，留空不改（不是已上传）"
        : "填写后保存，不会立刻上传";
    }
    backupPolicyDirty = false;
    toggleBackupDestinationFields();
  }

  function collectBackupPolicy() {
    const form = document.querySelector("[data-backup-form]");
    const payload = {
      enabled: Boolean(form.elements.enabled?.checked),
      schedule_enabled: Boolean(form.elements.schedule_enabled?.checked),
      full_time: String(form.elements.full_time?.value || "").trim(),
      diff_interval_hours: String(form.elements.diff_interval_hours?.value || "").trim(),
      github_enabled: Boolean(form.elements.github_enabled?.checked),
      github_repository: String(form.elements.github_repository?.value || "").trim(),
    };
    const githubToken = String(form.elements.github_token?.value || "");
    if (githubToken) payload.github_token = githubToken;
    return payload;
  }

  function renderBackupRuns(items) {
    const body = document.querySelector("[data-backup-run-table]");
    if (!body) return;
    body.replaceChildren();
    (Array.isArray(items) ? items : []).forEach((item) => {
      const row = document.createElement("tr");
      const status = backupRunCopy[item.status] || [item.status || "未知", "status-gray"];
      appendTextCell(row, formatApiDate(item.created_at), "mono");
      appendTextCell(row, backupTypeCopy[item.backup_type] || item.backup_type || "—");
      appendStatusCell(row, status[0], status[1]);
      appendTextCell(row, item.message || "—");
      body.append(row);
    });
    window.__previewRefreshTables?.();
    const empty = body.closest(".table-scroll")?.querySelector("[data-table-empty]");
    if (empty) empty.textContent = "还没有备份记录。这是备份运行记录，和「下载加密备份」页签里的磁盘 .enc 不是同一张表。";
  }

  function renderBackupDownloads(items) {
    const body = document.querySelector("[data-backup-download-table]");
    if (!body) return;
    body.replaceChildren();
    const files = Array.isArray(items) ? items : [];
    const retention = Math.max(1, Number(window.__backupDownloadRetention || 1));
    const atFloor = files.length <= retention;
    files.forEach((item) => {
      const row = document.createElement("tr");
      appendTextCell(row, item.name || "—", "mono");
      appendTextCell(row, formatBackupBytes(item.size));
      appendTextCell(row, formatApiDate(item.modified_at), "mono");
      appendTextCell(row, item.sha256_suffix || "—", "mono");
      const downloadAction = appendActionCell(row, "下载");
      downloadAction.dataset.backupDownload = item.name || "";
      const deleteAction = document.createElement("button");
      deleteAction.className = "text-button";
      deleteAction.type = "button";
      deleteAction.className = "table-btn table-btn-danger";
      deleteAction.textContent = "删除";
      deleteAction.setAttribute("data-backup-download-delete", item.name || "");
      deleteAction.disabled = atFloor;
      setTableTooltip(
        deleteAction,
        atFloor
          ? `下载目录至少留 ${retention} 份，现在不能再删。`
          : `删除后至少留 ${retention} 份。`
      );
      downloadAction.parentElement?.append(deleteAction);
      body.append(row);
    });
    window.__previewRefreshTables?.();
    const empty = body.closest(".table-scroll")?.querySelector("[data-table-empty]");
    if (empty) empty.textContent = "还没有可下载的加密包";
  }

  function applyBackupDashboard(payload, options) {
    const policy = payload?.policy || {};
    const status = payload?.status || {};
    const preservePolicyEdits = Boolean(options?.preservePolicyEdits);
    if (!preservePolicyEdits || !backupPolicyDirty) applyBackupPolicy(policy);
    clearRuntimeReadError('[data-screen-panel="backup"]');
    const resultCopy = { success: "上次：成功", failure: "上次：失败", missing: "尚无程序记录" };
    setBackupMetric("last-result", resultCopy[status.last_result] || status.last_result || "—");
    setBackupMetric("last-success", formatApiDate(status.last_success_at_utc));
    setBackupMetric("auto", policy.enabled ? "开" : "关");
    setBackupMetric("schedule", policy.schedule_enabled ? "开" : "关");
    setBackupMetric("retention", policy.github_retention_count ?? "—");
    const health = status.health?.status || "unknown";
    const healthReasons = Array.isArray(status.health?.reasons) ? status.health.reasons : [];
    const healthNode = document.querySelector("[data-backup-health-status]");
    if (healthNode) {
      if (policy.enabled === false) {
        healthNode.className = "status status-warm";
        healthNode.textContent = "计划已关";
      } else {
      healthNode.className = `status ${
        health === "ok" ? "status-green" : health === "critical" ? "status-red" : "status-warm"
      }`;
      const staleOnly =
        status.last_result === "success" &&
        health === "critical" &&
        healthReasons.includes("backup_success_stale") &&
        !healthReasons.includes("backup_success_proof_missing_or_invalid");
      healthNode.textContent =
        status.last_result === "missing"
          ? "尚未确认"
          : staleOnly
            ? "上次验收已过期"
          : status.last_result === "success" && health === "critical"
            ? "程序记录成功，证明未齐"
          : health === "ok"
            ? "上次证明正常"
            : health === "critical"
              ? "上次证明异常"
              : "尚未确认";
      if (status.last_result === "missing") {
        healthNode.className = "status status-warm";
      }
      }
    }
    const dest = document.querySelector("[data-backup-dest-copy]");
    if (dest) {
      const places = ["这台服务器"];
      if (policy.github_enabled) places.push("GitHub");
      dest.textContent = `打开总开关后，整份账本（软件、套餐、卡密、下游、额度、发版和网盘地址、审计）打成加密包，写到：${places.join("、")}。不含本站安装包文件。网盘更新靠地址，恢复后地址还在。`;
    }
    const runs = payload?.runs || [];
    const waiting = runs.some((item) => item.status === "pending" || item.status === "running");
    renderBackupRuns(runs);
    setBackupMetric("queue", waiting ? "排队等待执行" : "无");
    renderBackupDownloads(payload?.downloads || []);
    applyBackupRestoreGate(payload?.restore || {});
  }

  function backupRestoreFileToken(file) {
    if (!file) return "";
    return `${file.name}:${file.size}:${file.lastModified}`;
  }

  function resetBackupRestoreConfirm(panel) {
    const confirmBox = panel?.querySelector("[data-backup-restore-confirm]");
    const timeNode = panel?.querySelector("[data-backup-restore-time]");
    const restoreForm = panel?.querySelector("[data-backup-restore-form]");
    const applyButton = panel?.querySelector("[data-backup-restore-apply]");
    if (timeNode) timeNode.textContent = "";
    if (confirmBox) {
      confirmBox.hidden = true;
      confirmBox.dataset.stagingId = "";
      confirmBox.dataset.backupTime = "";
    }
    if (restoreForm?.elements.confirmed_backup_time) restoreForm.elements.confirmed_backup_time.value = "";
    if (applyButton) applyButton.disabled = true;
  }

  function applyBackupRestoreGate(restore) {
    const note = document.querySelector("[data-backup-restore-gate]");
    if (note) {
      const blocked = !restore.site_empty;
      note.classList.toggle("backup-restore-blocked", blocked);
      note.textContent = blocked
        ? restore.message || "当前有业务数据，不能导入。"
        : "当前没有业务数据，可以核对应导入的备份。";
    }
    const confirmBox = document.querySelector("[data-backup-restore-confirm]");
    if (confirmBox && !restore.site_empty) {
      confirmBox.hidden = true;
      confirmBox.dataset.stagingId = "";
    }
  }

  async function loadAdminBackup() {
    setBackupPolicyLoadState(false);
    try {
      const payload = await apiRequest("/manage/backup/", { method: "GET" });
      applyBackupDashboard(payload);
      setBackupPolicyLoadState(true);
      return payload;
    } catch (error) {
      setBackupPolicyLoadState(false);
      throw error;
    }
  }

  async function downloadBackupFile(name) {
    const response = await window.fetch(
      `${API_ROOT}/manage/backup/downloads/${encodeURIComponent(name)}/`,
      {
        credentials: "same-origin",
        headers: { "X-Request-Id": requestIdempotencyKey("web-request") },
      },
    );
    let errorPayload = {};
    if (!response.ok) {
      try {
        errorPayload = await response.json();
      } catch {
        errorPayload = {};
      }
      throw new ApiRequestError(
        errorPayload?.error?.message || "备份下载失败。",
        response.status,
        errorPayload?.error || {},
      );
    }
    const blob = await response.blob();
    const url = URL.createObjectURL(blob);
    const link = document.createElement("a");
    link.href = url;
    link.download = name;
    document.body.append(link);
    link.click();
    link.remove();
    window.setTimeout(() => URL.revokeObjectURL(url), 0);
  }

  function installAdminBackup() {
    const panel = document.querySelector('[data-screen-panel="backup"]');
    if (!panel || panel.dataset.backupBound === "true") return;
    panel.dataset.backupBound = "true";
    panel.querySelector('[name="github_enabled"]')?.addEventListener("change", toggleBackupDestinationFields);
    panel.querySelector('[name="enabled"]')?.addEventListener("change", toggleBackupMasterFields);
    toggleBackupDestinationFields();
    setBackupPolicyLoadState(isStandaloneStaticPreview);
    const backupForm = panel.querySelector("[data-backup-form]");
    let backupSaveKey = "";
    let backupSaveBody = "";
    backupForm?.addEventListener("input", () => {
      if (backupPolicyLoaded) backupPolicyDirty = true;
    });
    backupForm?.addEventListener("change", () => {
      if (backupPolicyLoaded) backupPolicyDirty = true;
    });
    backupForm?.addEventListener("submit", async (event) => {
      event.preventDefault();
      const form = event.currentTarget;
      setFormError(form, "");
      if (isStandaloneStaticPreview) {
        showToast("静态预览不保存备份设置。");
        return;
      }
      if (!backupPolicyLoaded) {
        const message = "备份策略尚未成功读取，不能保存默认值。请先重试读取。";
        setFormError(form, message);
        showToast(message);
        return;
      }
      const button = form.querySelector("[data-backup-save]");
      if (button) button.disabled = true;
      const body = JSON.stringify(collectBackupPolicy());
      if (body !== backupSaveBody) {
        backupSaveBody = body;
        backupSaveKey = requestIdempotencyKey("backup-policy");
      }
      try {
        const payload = await apiRequest("/manage/backup/", {
          method: "POST",
          body,
          headers: { "Idempotency-Key": backupSaveKey },
        });
        backupSaveKey = "";
        backupSaveBody = "";
        applyBackupDashboard(payload);
        showToast(
          payload?.policy?.enabled
            ? payload?.policy?.github_enabled
              ? payload?.policy?.schedule_enabled
                ? "总开关已开。有变动会备份到这台服务器和 GitHub；也会按北京时间计划检查。"
                : "总开关已开。有变动会备份到这台服务器和 GitHub。"
              : payload?.policy?.schedule_enabled
                ? "总开关已开。有变动会备份到这台服务器；也会按北京时间计划检查。"
                : "总开关已开。有变动会备份到这台服务器。"
            : "总开关关着，账本有变动也不会备份。",
        );
      } catch (error) {
        setFormError(form, apiErrorMessage(error, "备份设置没有保存。"));
        showToast(apiErrorMessage(error, "备份设置没有保存。"));
      } finally {
        if (button) button.disabled = !backupPolicyLoaded;
      }
    });
    panel.querySelectorAll("[data-backup-run]").forEach((button) => {
      button.addEventListener("click", async () => {
        if (isStandaloneStaticPreview) {
          showToast("静态预览不执行真实备份。");
          return;
        }
        if (!backupPolicyLoaded) {
          showToast("备份策略尚未成功读取，不能执行备份。请先重试读取。");
          return;
        }
        button.disabled = true;
        try {
          const payload = await apiRequest("/manage/backup/runs/", {
            method: "POST",
            body: JSON.stringify({ backup_type: button.dataset.backupRun || "full" }),
          });
          applyBackupDashboard(payload, { preservePolicyEdits: true });
          showToast(
            backupPolicyDirty
              ? "已排队备份。未保存的备份设置仍保留在表单中。"
              : "已排队备份。先写到这台服务器；打开了 GitHub 会再拷一份。",
          );
        } catch (error) {
          if (error instanceof ApiRequestError && error.code === "BACKUP_RUN_PENDING") {
            showToast(apiErrorMessage(error, "已有备份在排队，已立即叫醒备份程序。"));
            try {
              applyBackupDashboard(
                await apiRequest("/manage/backup/", { method: "GET" }),
                { preservePolicyEdits: true },
              );
            } catch (_ignored) {
              /* keep the queued toast */
            }
          } else {
            showToast(apiErrorMessage(error, "现在备份没有受理。"));
          }
        } finally {
          button.disabled = !backupPolicyLoaded;
        }
      });
    });
    panel.querySelector("[data-backup-probe]")?.addEventListener("click", async () => {
      if (isStandaloneStaticPreview) {
        showToast("静态预览不试连。");
        return;
      }
      if (!backupPolicyLoaded) {
        showToast("备份策略尚未成功读取，不能试连。请先重试读取。");
        return;
      }
      const button = panel.querySelector("[data-backup-probe]");
      if (button) button.disabled = true;
      try {
        const payload = await apiRequest("/manage/backup/destinations/probe/", {
          method: "POST",
          body: "{}",
        });
        showToast(payload?.message || (payload?.ok ? "连通正常。没有上传备份。" : "试连失败。"));
      } catch (error) {
        showToast(apiErrorMessage(error, "试连没有完成。"));
      } finally {
        if (button) button.disabled = !backupPolicyLoaded;
      }
    });
    panel.addEventListener("click", async (event) => {
      const trigger = event.target.closest("[data-backup-download]");
      if (!trigger) return;
      const name = trigger.dataset.backupDownload;
      if (!name) return;
      if (isStandaloneStaticPreview) {
        showToast("静态预览不下载真实备份文件。");
        return;
      }
      trigger.disabled = true;
      try {
        await downloadBackupFile(name);
        showToast("加密备份已开始下载。");
      } catch (error) {
        showToast(apiErrorMessage(error, "备份下载失败，请稍后重试。"));
      } finally {
        trigger.disabled = false;
      }
    });
    const downloadDeleteDialog = document.getElementById("backupDownloadDeleteDialog");
    panel.addEventListener("click", (event) => {
      const trigger = event.target.closest("[data-backup-download-delete]");
      if (!trigger) return;
      const name = trigger.dataset.backupDownloadDelete;
      if (!name) return;
      if (isStandaloneStaticPreview) {
        showToast("静态预览不删除真实备份文件。");
        return;
      }
      const retention = Math.max(1, Number(window.__backupDownloadRetention || 1));
      const summary = downloadDeleteDialog?.querySelector("[data-backup-download-delete-summary]");
      const error = downloadDeleteDialog?.querySelector("[data-form-error]");
      if (error) error.textContent = "";
      if (summary) {
        summary.textContent = `将删除 ${name}。下载目录至少留 ${retention} 份（当前 GitHub 密文份数）。只删加密账本，不含安装包。此操作不可撤销。`;
      }
      if (downloadDeleteDialog) downloadDeleteDialog.dataset.deleteName = name;
      downloadDeleteDialog?.showModal();
    });
    downloadDeleteDialog
      ?.querySelector("[data-backup-download-delete-confirm]")
      ?.addEventListener("click", async (event) => {
        const button = event.currentTarget;
        const error = downloadDeleteDialog.querySelector("[data-form-error]");
        const name = downloadDeleteDialog.dataset.deleteName || "";
        if (!name) return;
        button.disabled = true;
        if (error) error.textContent = "";
        try {
          const payload = await apiRequest(`/manage/backup/downloads/${encodeURIComponent(name)}/delete/`, {
            method: "POST",
            body: JSON.stringify({ confirmed: true }),
          });
          downloadDeleteDialog.close("success");
          showToast(payload?.message || `已删除 ${name}。`);
          await loadAdminBackup();
        } catch (requestError) {
          if (error) error.textContent = apiErrorMessage(requestError, "删除备份失败，请稍后重试。");
        } finally {
          button.disabled = false;
        }
      });
    const restoreForm = panel.querySelector("[data-backup-restore-form]");
    restoreForm?.elements.backup_file?.addEventListener("change", () => {
      panel.dataset.restoreInspectGeneration = String(
        Number(panel.dataset.restoreInspectGeneration || "0") + 1,
      );
      resetBackupRestoreConfirm(panel);
    });
    restoreForm?.elements.confirmed_backup_time?.addEventListener("input", () => {
      const applyButton = panel.querySelector("[data-backup-restore-apply]");
      const confirmBox = panel.querySelector("[data-backup-restore-confirm]");
      const expected = confirmBox?.dataset.backupTime || "";
      const typed = String(restoreForm.elements.confirmed_backup_time?.value || "").trim();
      if (applyButton) applyButton.disabled = !expected || typed !== expected;
    });
    restoreForm?.addEventListener("submit", async (event) => {
      event.preventDefault();
      setFormError(restoreForm, "");
      if (isStandaloneStaticPreview) {
        showToast("静态预览不核对真实备份。");
        return;
      }
      const file = restoreForm.elements.backup_file?.files?.[0];
      const passphrase = String(restoreForm.elements.passphrase?.value || "");
      if (!file) {
        setFormError(restoreForm, "请选择加密备份文件。");
        return;
      }
      const submittedGeneration = panel.dataset.restoreInspectGeneration || "0";
      const submittedToken = backupRestoreFileToken(file);
      const inspectButton = restoreForm.querySelector("[data-backup-restore-inspect]");
      if (inspectButton) inspectButton.disabled = true;
      try {
        const body = new FormData();
        body.append("file", file);
        body.append("passphrase", passphrase);
        const payload = await apiRequest("/manage/backup/restore/inspect/", {
          method: "POST",
          body,
        });
        const currentFile = restoreForm.elements.backup_file?.files?.[0];
        if (
          (panel.dataset.restoreInspectGeneration || "0") !== submittedGeneration ||
          backupRestoreFileToken(currentFile) !== submittedToken
        ) {
          resetBackupRestoreConfirm(panel);
          setFormError(restoreForm, "备份文件已更换，请重新核对。");
          showToast("备份文件已更换，请重新核对。");
          return;
        }
        const confirmBox = panel.querySelector("[data-backup-restore-confirm]");
        const timeNode = panel.querySelector("[data-backup-restore-time]");
        const applyButton = panel.querySelector("[data-backup-restore-apply]");
        if (!payload?.can_restore) {
          resetBackupRestoreConfirm(panel);
          setFormError(restoreForm, payload?.message || "文件和口令对，但当前有业务数据，不能导入。");
          showToast(payload?.message || "文件和口令对，但当前有业务数据，不能导入。");
          return;
        }
        if (timeNode) {
          timeNode.textContent = payload?.backup_time_beijing
            ? `这份备份的时间是 ${payload.backup_time_beijing}（北京时间）。`
            : "";
        }
        if (confirmBox) {
          confirmBox.hidden = false;
          confirmBox.dataset.stagingId = payload?.staging_id || "";
          confirmBox.dataset.backupTime = payload?.backup_time_beijing || "";
          confirmBox.scrollIntoView({ block: "center", behavior: "smooth" });
        }
        if (restoreForm.elements.confirmed_backup_time) restoreForm.elements.confirmed_backup_time.value = "";
        if (applyButton) applyButton.disabled = true;
        restoreForm.elements.confirmed_backup_time?.focus?.();
        showToast(payload?.message || "备份已核对。请再抄一遍备份时间后确认。");
      } catch (error) {
        resetBackupRestoreConfirm(panel);
        setFormError(restoreForm, apiErrorMessage(error, "备份没有核对成功。"));
        showToast(apiErrorMessage(error, "备份没有核对成功。"));
      } finally {
        if (inspectButton) inspectButton.disabled = false;
      }
    });
    panel.querySelector("[data-backup-restore-apply]")?.addEventListener("click", async (event) => {
      const button = event.currentTarget;
      if (isStandaloneStaticPreview) {
        showToast("静态预览不导入真实备份。");
        return;
      }
      const confirmBox = panel.querySelector("[data-backup-restore-confirm]");
      const stagingId = confirmBox?.dataset.stagingId || "";
      const confirmed = String(restoreForm?.elements.confirmed_backup_time?.value || "").trim();
      const passphrase = String(restoreForm?.elements.passphrase?.value || "");
      setFormError(restoreForm, "");
      if (!stagingId) {
        setFormError(restoreForm, "请先核对备份。");
        return;
      }
      button.disabled = true;
      try {
        const payload = await apiRequest("/manage/backup/restore/", {
          method: "POST",
          body: JSON.stringify({
            staging_id: stagingId,
            passphrase,
            confirmed_backup_time: confirmed,
          }),
        });
        showToast(payload?.message || "导入命令已结束，尚未做隔离恢复核对。", 8000);
        try {
          window.sessionStorage.setItem(
            "restoreNotice",
            payload?.message || "导入命令已结束，尚未做隔离恢复核对。",
          );
        } catch (_storageError) {
          /* ignore quota / private mode */
        }
        window.setTimeout(() => {
          window.location.href = "manage-login.html";
        }, 4000);
      } catch (error) {
        setFormError(restoreForm, apiErrorMessage(error, "没有导入。数据库可能已被部分改写，不要当成成功。"));
        showToast(apiErrorMessage(error, "没有导入。数据库可能已被部分改写，不要当成成功。"));
        button.disabled = false;
      }
    });
  }

  if (document.body.classList.contains("role-admin")) {
    installAdminBackup();
  }

  document
    .querySelector("[data-release-check]")
    ?.addEventListener("click", async (event) => {
      const button = event.currentTarget;
      button.disabled = true;
      button.textContent = "检查中…";
      if (isStandaloneStaticPreview) {
        window.setTimeout(() => {
          button.disabled = false;
          button.textContent = "↻ 重新检查";
          showToast("更新检查预览已刷新。没有执行下载或安装。 ");
        }, 180);
        return;
      }
      try {
        await recheckPublicReleaseRegistry(releaseContext?.value || "");
        showToast("已从真实版本 registry 刷新检查结果。下载、验签和安装仍由授权 A 负责。 ");
      } catch (requestError) {
        showToast(apiErrorMessage(requestError, "版本检查失败，请稍后重试。"));
      } finally {
        button.disabled = false;
        button.textContent = "↻ 重新检查";
      }
    });

  document.addEventListener("click", (event) => {
    const trigger = event.target.closest("[data-dialog='withdrawReleaseDialog']");
    if (trigger) {
      const row = trigger.closest("tr");
      pendingWithdrawReleaseId = row?.dataset.releaseId || null;
      pendingWithdrawIdempotencyKey = requestIdempotencyKey(`release-withdraw-${pendingWithdrawReleaseId || "unknown"}`);
      const item = releaseItems.find((candidate) => candidate.release_id === pendingWithdrawReleaseId);
      const dialog = document.getElementById("withdrawReleaseDialog");
      const reasonBox = dialog?.querySelector('textarea[name="reason"]');
      if (reasonBox) reasonBox.value = "";
      const formError = dialog?.querySelector("[data-form-error]");
      if (formError) formError.textContent = "";
      const software = dialog?.querySelector("[data-withdraw-software]");
      const channel = dialog?.querySelector("[data-withdraw-channel]");
      const status = dialog?.querySelector("[data-withdraw-status]");
      const fallback = dialog?.querySelector("[data-withdraw-fallback]");
      resetWithdrawConfirm();
      if (software) software.textContent = item?.software_name || item?.software_id || "—";
      if (channel) channel.textContent = item?.channel || "—";
      if (status) status.textContent = item ? releaseStatusCopy(item.status)[0] : "—";
      if (fallback) fallback.textContent = "正在读取回退候选…";
      const openedWithdrawId = pendingWithdrawReleaseId;
      (async () => {
        if (!item?.software_id) {
          if (fallback && pendingWithdrawReleaseId === openedWithdrawId) fallback.textContent = "撤回后客户端将没有可下载版本";
          return;
        }
        try {
          const published = await loadPublishedReleases(item.software_id);
          if (pendingWithdrawReleaseId !== openedWithdrawId) return;
          const remaining = published.filter(
            (candidate) =>
              candidate.release_id !== openedWithdrawId &&
              candidate.profile_id === item.profile_id &&
              candidate.channel === item.channel &&
              (String(candidate.external_download_url || "").trim() !== "" || candidate.package_available === true),
          );
          const previous = highestPublishedRelease(remaining);
          if (fallback) {
            fallback.textContent = previous
              ? `v${previous.version}`
              : "撤回后客户端将没有可下载版本";
          }
        } catch (_requestError) {
          if (fallback && pendingWithdrawReleaseId === openedWithdrawId) fallback.textContent = "回退候选暂时无法读取";
        }
      })();
      return;
    }
    const editUrlTrigger = event.target.closest("[data-dialog='editReleaseUrlDialog']");
    if (editUrlTrigger) {
      const row = editUrlTrigger.closest("tr");
      pendingUpdateReleaseId = row?.dataset.releaseId || null;
      const item = releaseItems.find((candidate) => candidate.release_id === pendingUpdateReleaseId);
      const dialog = document.getElementById("editReleaseUrlDialog");
      const software = dialog?.querySelector("[data-edit-url-software]");
      const version = dialog?.querySelector("[data-edit-url-version]");
      const channel = dialog?.querySelector("[data-edit-url-channel]");
      const input = dialog?.querySelector("#releaseEditUrl");
      const error = dialog?.querySelector("[data-form-error]");
      if (error) error.textContent = "";
      if (software) software.textContent = item?.software_name || item?.software_id || "—";
      if (version) version.textContent = item?.version ? `v${item.version}` : "—";
      if (channel) channel.textContent = item?.channel || "—";
      if (input) input.value = item?.external_download_url || "";
      const shaInput = dialog?.querySelector("#releaseEditSha256");
      if (shaInput) {
        shaInput.value = "";
        shaInput.placeholder = item?.package_sha256
          ? `当前 ${String(item.package_sha256).slice(0, 12)}…，留空保留，换文件请填新值`
          : "64 位十六进制，留空保留";
      }
      const shaClearBox = dialog?.querySelector("#releaseEditSha256Clear");
      if (shaClearBox) shaClearBox.checked = false;
      const confirm = dialog?.querySelector("[data-edit-url-confirm]");
      if (confirm) confirm.disabled = false;
      return;
    }
    const deletePackageTrigger = event.target.closest("[data-dialog='deleteReleasePackageDialog']");
    if (deletePackageTrigger) {
      const row = deletePackageTrigger.closest("tr");
      pendingDeleteReleasePackageId = row?.dataset.releaseId || null;
      const item = releaseItems.find((candidate) => candidate.release_id === pendingDeleteReleasePackageId);
      const dialog = document.getElementById("deleteReleasePackageDialog");
      const software = dialog?.querySelector("[data-delete-package-software]");
      const version = dialog?.querySelector("[data-delete-package-version]");
      const error = dialog?.querySelector("[data-form-error]");
      if (error) error.textContent = "";
      if (software) software.textContent = item?.software_name || item?.software_id || "—";
      if (version) version.textContent = item?.version ? `v${item.version}` : "—";
      return;
    }
    const draftTrigger = event.target.closest("[data-dialog='releaseDialog']");
    const draftId = draftTrigger?.closest("tr")?.dataset.releaseId;
    if (!draftId) return;
    const item = releaseItems.find((candidate) => candidate.release_id === draftId);
    if (!item || item.status !== "draft") return;
    releaseFileState = { item, file: null };
    releaseDialog.querySelector("[data-release-version]").textContent = `v${item.version}`;
    releaseDialog.querySelector("[data-release-size]").textContent = `${Math.max(1, Math.ceil(item.package_size / 1024)).toLocaleString("zh-CN")} KB`;
    releaseDialog.querySelector("[data-release-hash]").textContent = item.package_sha256;
    releaseDialog.querySelector("[data-release-target]").textContent = `${item.target} · ${item.arch} · ${item.channel}`;
    fillReleaseSignatureStatus(item);
    releaseDialog.dataset.pendingVersion = item.version;
    releaseDialog.dataset.pendingSoftware = item.software_name;
    releaseDialog.dataset.pendingChannel = item.channel;
    showReleaseStage("verify", 1);
  });

  function resetWithdrawConfirm() {
    const confirm = document.querySelector("#withdrawReleaseDialog [data-withdraw-confirm]");
    if (confirm) {
      confirm.disabled = false;
      confirm.textContent = "确认撤回";
    }
  }

  document.getElementById("withdrawReleaseDialog")?.addEventListener("close", () => {
    resetWithdrawConfirm();
  });

  function resetDeletePackageConfirm() {
    const confirm = document.querySelector("#deleteReleasePackageDialog [data-release-delete-package-confirm]");
    if (confirm) confirm.disabled = false;
  }

  document.getElementById("deleteReleasePackageDialog")?.addEventListener("close", () => {
    resetDeletePackageConfirm();
  });

  document
    .querySelector("[data-release-delete-package-confirm]")
    ?.addEventListener("click", async (event) => {
      const dialog = event.currentTarget.closest("dialog");
      const form = event.currentTarget.closest("form");
      const error = form?.querySelector("[data-form-error]");
      if (!pendingDeleteReleasePackageId) {
        if (error) error.textContent = "版本记录已失效，请刷新后重试。";
        return;
      }
      if (isStandaloneStaticPreview && !window.__b1ApiActive) {
        if (error) error.textContent = "静态预览不删除真实安装包。";
        return;
      }
      event.currentTarget.disabled = true;
      try {
        await apiRequest(`/manage/releases/${encodeURIComponent(pendingDeleteReleasePackageId)}/delete-package/`, {
          method: "POST",
          body: JSON.stringify({ confirmed: true }),
        });
        dialog?.close("success");
        try { await loadReleasesForSoftware(releaseContext?.value || "all"); }
        catch (_refreshError) {
          showToast("安装包已删除，列表刷新失败。请刷新列表，无需再次删除。", 8000);
          return;
        }
        showToast("已删除安装包 ZIP。版本历史仍保留，状态仍是已撤回，版本号不能再用来上传。");
      } catch (requestError) {
        if (error) error.textContent = apiErrorMessage(requestError, "删除安装包失败，请重试。");
      } finally {
        resetDeletePackageConfirm();
      }
  });

  document
    .querySelector("[data-withdraw-confirm]")
    ?.addEventListener("click", async (event) => {
      const dialog = event.currentTarget.closest("dialog");
      const form = event.currentTarget.closest("form");
      const error = form?.querySelector("[data-form-error]");
      if (!form?.checkValidity()) {
        if (error) error.textContent = "请填写至少 4 个字符的撤回原因。";
        form?.reportValidity();
        return;
      }
      if (!pendingWithdrawReleaseId) {
        if (error) error.textContent = "版本记录已失效，请刷新后重试。";
        return;
      }
      if (isStandaloneStaticPreview && !window.__b1ApiActive) {
        if (error) error.textContent = "静态预览不执行真实版本撤回。";
        return;
      }
      event.currentTarget.disabled = true;
      event.currentTarget.textContent = "撤回中…";
      try {
        if (!pendingWithdrawIdempotencyKey) pendingWithdrawIdempotencyKey = requestIdempotencyKey(`release-withdraw-${pendingWithdrawReleaseId || "unknown"}`);
        const withdrawn = await apiRequest(`/manage/releases/${encodeURIComponent(pendingWithdrawReleaseId)}/withdraw/`, {
          method: "POST",
          body: JSON.stringify({ reason: form.elements.reason.value.trim() }),
          headers: { "Idempotency-Key": pendingWithdrawIdempotencyKey },
        });
        dialog?.close("success");
        pendingWithdrawIdempotencyKey = null;
        const fallbackVersion = withdrawn?.registry_fallback_version;
        showToast(
          fallbackVersion
            ? `版本已撤回。已安装的不会被卸掉。安装包 ZIP 仍留在磁盘。公开目录会改指向 v${fallbackVersion}。审计记录已保留。`
            : "版本已撤回。已安装的不会被卸掉。安装包 ZIP 仍留在磁盘。客户端现在没有可下载的已发布版本。审计记录已保留。",
        );
        try {
          await loadReleasesForSoftware(releaseContext?.value || "all");
        } catch (_reloadError) {
          showToast("版本列表刷新失败，撤回已成功，请手动刷新页面。");
        }
      } catch (requestError) {
        if (error) error.textContent = apiErrorMessage(requestError, "版本撤回失败，请重试。");
      } finally {
        resetWithdrawConfirm();
      }
    });

  document.getElementById("editReleaseUrlDialog")?.addEventListener("close", () => {
    const confirm = document.querySelector("#editReleaseUrlDialog [data-edit-url-confirm]");
    if (confirm) confirm.disabled = false;
    const shaClearBox = document.getElementById("releaseEditSha256Clear");
    if (shaClearBox) shaClearBox.checked = false;
  });

  document.getElementById("releaseEditUrl")?.addEventListener("keydown", (event) => {
    if (event.key !== "Enter") return;
    event.preventDefault();
    document.querySelector("[data-edit-url-confirm]")?.click();
  });

  document.getElementById("releaseEditSha256")?.addEventListener("keydown", (event) => {
    if (event.key !== "Enter") return;
    event.preventDefault();
    document.querySelector("[data-edit-url-confirm]")?.click();
  });

  document
    .querySelector("[data-edit-url-confirm]")
    ?.addEventListener("click", async (event) => {
      const dialog = event.currentTarget.closest("dialog");
      const form = event.currentTarget.closest("form");
      const error = form?.querySelector("[data-form-error]");
      const url = document.getElementById("releaseEditUrl")?.value.trim() || "";
      const shaRaw = document.getElementById("releaseEditSha256")?.value ?? "";
      const sha = shaRaw.trim();
      const shaClear = document.getElementById("releaseEditSha256Clear")?.checked === true;
      if (shaClear && sha) {
        if (error) error.textContent = "清空与新哈希只能二选一：要清空请先删掉输入框里的哈希。";
        return;
      }
      if (!pendingUpdateReleaseId) {
        if (error) error.textContent = "版本记录已失效，请刷新后重试。";
        return;
      }
      if (!url) {
        if (error) error.textContent = "请填写网盘下载地址。";
        return;
      }
      if (!/^https?:\/\/.+\..+/.test(url)) {
        if (error) error.textContent = "网盘地址必须是 http(s) 开头的完整链接。";
        return;
      }
      if (sha && !/^[0-9a-fA-F]{64}$/.test(sha)) {
        if (error) error.textContent = "安装包 SHA-256 必须是 64 位十六进制，留空保留旧值。";
        return;
      }
      if (isStandaloneStaticPreview && !window.__b1ApiActive) {
        if (error) error.textContent = "静态预览不修改真实网盘地址。";
        return;
      }
      event.currentTarget.disabled = true;
      event.currentTarget.textContent = "保存中…";
      if (error) error.textContent = "";
      try {
        const updateBody = { external_download_url: url };
        if (document.getElementById("releaseEditSha256")) {
          if (sha) updateBody.package_sha256 = sha;
          else if (shaClear) updateBody.package_sha256 = "";
        }
        await apiRequest(`/manage/releases/${encodeURIComponent(pendingUpdateReleaseId)}/external-url/`, {
          method: "POST",
          body: JSON.stringify(updateBody),
          headers: { "Idempotency-Key": requestIdempotencyKey("release-update-url") },
        });
        dialog?.close("success");
        showToast("网盘地址已更新。客户下次检查更新会打开新链接。版本号不变。");
        try {
          await loadReleasesForSoftware(releaseContext?.value || "all");
        } catch (_reloadError) {
          showToast("版本列表刷新失败，改地址已成功，请手动刷新页面。");
        }
      } catch (requestError) {
        if (error) error.textContent = apiErrorMessage(requestError, "改地址失败，请重试。");
      } finally {
        const confirm = document.querySelector("#editReleaseUrlDialog [data-edit-url-confirm]");
        if (confirm) {
          confirm.disabled = false;
          confirm.textContent = "保存新地址";
        }
      }
    });

  const storageScanButton = document.querySelector("[data-storage-scan]");
  const storageExecuteButton = document.querySelector("[data-storage-cleanup]");
  const storageCleanupDialog = document.getElementById("storageCleanupDialog");
  storageScanButton?.removeAttribute("data-toast");
  storageExecuteButton?.removeAttribute("data-toast");
  storageScanButton?.addEventListener("click", async () => {
    storageScanButton.disabled = true;
    if (isStandaloneStaticPreview) {
      showToast("静态预览不执行真实文件扫描。");
      storageScanButton.disabled = false;
      return;
    }
    try {
      const payload = await apiRequest("/manage/storage/cleanup/");
      showToast(`已扫描 ${payload.candidate_count || 0} 个可清理文件，共 ${formatMetric(payload.candidate_bytes || 0)} 字节。不含下载表 .enc。审计与额度流水不会删除。`);
    } catch (requestError) {
      showToast(apiErrorMessage(requestError, "存储扫描失败，请稍后重试。"));
    } finally {
      storageScanButton.disabled = false;
    }
  });
  storageExecuteButton?.addEventListener("click", async () => {
    if (isStandaloneStaticPreview) {
      showToast("静态预览不执行真实文件清理。");
      return;
    }
    const error = storageCleanupDialog?.querySelector("[data-form-error]");
    const summary = storageCleanupDialog?.querySelector("[data-storage-cleanup-summary]");
    const confirmButton = storageCleanupDialog?.querySelector("[data-storage-cleanup-confirm]");
    if (error) error.textContent = "";
    if (summary) summary.textContent = "正在读取本次可清理数量…";
    if (confirmButton) confirmButton.disabled = true;
    storageExecuteButton.disabled = true;
    try {
      const payload = await apiRequest("/manage/storage/cleanup/");
      const count = Number(payload.candidate_count || 0);
      const bytes = Number(payload.candidate_bytes || 0);
      if (summary) {
        const windowNote = payload.truncated
          ? "因 1000 条或 5GiB 窗口未列入全部候选，确认只删本窗这些。"
          : "";
        summary.textContent = `本次扫描 ${count} 个可清理文件，共 ${formatMetric(bytes)} 字节。不含下载表 .enc。${windowNote}`.trim();
      }
      if (confirmButton) confirmButton.disabled = count < 1;
      storageCleanupDialog?.showModal();
    } catch (requestError) {
      if (summary) summary.textContent = "本次扫描失败，不能确认清理。";
      if (confirmButton) confirmButton.disabled = true;
      if (error) error.textContent = apiErrorMessage(requestError, "存储扫描失败，请稍后重试。");
      showToast(apiErrorMessage(requestError, "存储扫描失败，请稍后重试。"));
    } finally {
      storageExecuteButton.disabled = false;
    }
  });
  storageCleanupDialog
    ?.querySelector("[data-storage-cleanup-confirm]")
    ?.addEventListener("click", async (event) => {
      const button = event.currentTarget;
      const error = storageCleanupDialog.querySelector("[data-form-error]");
      button.disabled = true;
      if (error) error.textContent = "";
    try {
      const payload = await apiRequest("/manage/storage/cleanup/", {
        method: "POST",
        body: JSON.stringify({}),
      });
        storageCleanupDialog.close("success");
        showToast(`已清理 ${payload.deleted_count || 0} 个文件，共 ${formatMetric(payload.deleted_bytes || 0)} 字节。不含下载表 .enc。审计记录已保留。`);
    } catch (requestError) {
        if (error) error.textContent = apiErrorMessage(requestError, "存储清理失败，请稍后重试。");
    } finally {
        button.disabled = false;
    }
  });

  const softwareNames = Object.create(null);
  const plans = Object.create(null);
  let catalogItems = [];
  let catalogApiReady = false;
  const licenseIssueApiAvailable = !document.body.classList.contains("role-admin");
  let activeLicensePreview = null;
  let issuePreviewTimer = 0;
  let issuePreviewExpiryTimer = 0;
  let issuePreviewSequence = 0;

  function stopIssuePreviewCountdown() {
    window.clearInterval(issuePreviewExpiryTimer);
    issuePreviewExpiryTimer = 0;
  }

  function startIssuePreviewCountdown() {
    stopIssuePreviewCountdown();
    const ttlEl = document.querySelector("[data-issue-preview-ttl]");
    const tick = () => {
      if (!activeLicensePreview) {
        if (ttlEl) ttlEl.textContent = "—";
        stopIssuePreviewCountdown();
        return;
      }
      const remainMs = Number(activeLicensePreview.expiresAt) - Date.now();
      if (!(remainMs > 0)) {
        if (ttlEl) ttlEl.textContent = "已失效";
        stopIssuePreviewCountdown();
        activeLicensePreview = null;
        if (issueDialog?.open && licenseIssueApiAvailable) queueLicensePreview();
        return;
      }
      if (ttlEl) ttlEl.textContent = `${Math.ceil(remainMs / 1000)} 秒`;
    };
    tick();
    issuePreviewExpiryTimer = window.setInterval(tick, 1000);
  }

  function formatPlanDuration(seconds) {
    const value = Number(seconds);
    if (!Number.isInteger(value) || value < 1) return "有效期待定";
    if (value % 86400 === 0) return `${value / 86400} 天`;
    if (value % 3600 === 0) return `${value / 3600} 小时`;
    if (value % 60 === 0) return `${value / 60} 分钟`;
    return `${value} 秒`;
  }

  function normalizeCatalogPlan(softwareId, item) {
    const snapshot = item.latest_snapshot || {};
    const policy = snapshot.policy || {};
    const duration = formatPlanDuration(item.duration_seconds || snapshot.duration_seconds);
    const cost = Number(item.quota_cost ?? snapshot.quota_cost ?? 0);
    const devices = Number(policy.max_devices || 0);
    return {
      ...item,
      value: String(item.id),
      softwareId,
      duration,
      devices,
      cost,
      testOnly: Boolean(item.test_only || snapshot.test_only),
      label: item.test_only || snapshot.test_only
        ? `${item.name} · ${duration} · ${cost} 额度 · 仅测试`
        : `${item.name} · ${duration} · ${cost} 额度`,
    };
  }

  function setCatalogItems(items) {
    catalogItems = Array.isArray(items) ? items : [];
    Object.keys(softwareNames).forEach((key) => delete softwareNames[key]);
    Object.keys(plans).forEach((key) => delete plans[key]);
    catalogItems.forEach((softwareItem) => {
      const softwareId = String(softwareItem.software_id);
      softwareNames[softwareId] = softwareItem.name;
      plans[softwareId] = (softwareItem.plans || []).map((item) =>
        normalizeCatalogPlan(softwareId, item),
      );
    });
  }

  const standaloneCatalogItems = [];

  function applyPlanCatalogFilter(catalog, softwareId) {
    const selected = softwareId || "all";
    const scoped = selected !== "all";
    catalog.dataset.currentSoftware = selected;
    catalog.querySelectorAll("[data-plan-software]").forEach((item) => {
      item.hidden = scoped && item.dataset.planSoftware !== selected;
    });
    catalog.querySelectorAll("[data-plan-group-software]").forEach((group) => {
      group.hidden = ![...group.querySelectorAll("[data-plan-software]")].some(
        (item) => !item.hidden,
      );
    });
    catalog.querySelector("[data-plan-catalog-empty]")?.remove();
    const visiblePlans = [...catalog.querySelectorAll("[data-plan-software]")].some(
      (item) => !item.hidden,
    );
    if (visiblePlans) return;
    const empty = document.createElement("p");
    empty.className = "table-empty";
    empty.dataset.planCatalogEmpty = scoped ? selected : "all";
    empty.textContent = !catalogApiReady
      ? "目录正在加载，暂时没有可用套餐。"
      : scoped
        ? "当前软件暂时没有可发卡的套餐，请联系管理员或换一个软件。"
        : "还没有可经营软件，请联系管理员开通。";
    catalog.append(empty);
  }

  function renderPlanCatalog(items = catalogItems) {
    document.querySelectorAll("[data-plan-catalog]").forEach((catalog) => {
      catalog.replaceChildren();
      const softwareEntries = (Array.isArray(items) ? items : []).map((softwareItem) => [
        softwareItem.software_id,
        plans[softwareItem.software_id] || [],
      ]);
      softwareEntries.forEach(([softwareKey, softwarePlans]) => {
        if (!softwarePlans.length) return;
        const group = document.createElement("section");
        group.className = "package-group";
        group.dataset.planGroupSoftware = softwareKey;
        const groupHeading = document.createElement("div");
        groupHeading.className = "package-group-heading";
        const groupTitle = document.createElement("h2");
        groupTitle.textContent = softwareNames[softwareKey];
        const groupCount = document.createElement("span");
        groupCount.textContent = `${softwarePlans.length} 个套餐`;
        groupHeading.append(groupTitle, groupCount);
        group.append(groupHeading);
        softwarePlans.forEach((item) => {
          const article = document.createElement("article");
          article.className = "package-row";
          article.dataset.planSource = isStandaloneStaticPreview ? "shared" : "api";
          article.dataset.planId = item.value;
          article.dataset.planSoftware = softwareKey;
          article.dataset.planCost = String(item.cost);
          article.dataset.planDuration = item.duration;
          article.dataset.planDevices = String(item.devices);
          const description = document.createElement("div");
          const heading = document.createElement("h2");
          heading.textContent = item.name;
          const copy = document.createElement("p");
          copy.textContent = `${item.duration} · ${item.devices || "—"} 台设备 · ${item.testOnly ? "仅测试" : "在线验证"}`;
          description.append(heading, copy);
          const price = document.createElement("strong");
          price.className = "mono";
          price.textContent = String(item.cost);
          const unit = document.createElement("small");
          unit.textContent = "额度 / 张";
          price.append(" ", unit);
          const action = document.createElement("button");
          action.className = "button button-secondary button-small";
          action.type = "button";
          action.dataset.issueSoftware = softwareKey;
          action.dataset.issuePlan = item.value;
          if (document.body.classList.contains("role-admin")) {
            action.disabled = true;
            setTableTooltip(action, "管理端只能监管和回收授权卡密");
            action.textContent = "管理端不可发卡";
          } else {
            action.dataset.dialog = "issueDialog";
            action.textContent = "生成";
          }
          article.append(description, price, action);
          group.append(article);
        });
        catalog.append(group);
      });
      bindDialogTriggers(catalog);
      applyPlanCatalogFilter(
        catalog,
        document.querySelector("[data-plan-catalog-context]")?.value || "all",
      );
    });
  }
  renderPlanCatalog([]);

  document.querySelectorAll("[data-plan-catalog-context]").forEach((control) => {
    const applyPlanCatalogContext = () => {
      document.querySelectorAll("[data-plan-catalog]").forEach((catalog) => {
        applyPlanCatalogFilter(catalog, control.value);
      });
    };
    control.addEventListener("change", applyPlanCatalogContext);
    applyPlanCatalogContext();
  });

  const issueDialog = document.getElementById("issueDialog");
  const issueDownstream = document.getElementById("issueDownstream");
  const software = document.getElementById("issueSoftware");
  const plan = document.getElementById("issuePlan");
  const quantity = document.getElementById("issueQuantity");
  const cost = document.getElementById("issueCost");
  const unitCost = document.getElementById("issueUnitCost");
  const balance = document.getElementById("issueBalance");
  const issueSubmit = document.getElementById("issueSubmit");
  const issueForm = document.querySelector("[data-issue-form]");
  const issueResult = document.querySelector("[data-issue-result]");
  const issueError = document.querySelector("[data-issue-error]");

  function renderPlans(selectedPlan) {
    if (!software || !plan) return;
    const availablePlans = plans[software.value] || [];
    plan.replaceChildren(
      ...availablePlans.map((item) => {
        const option = document.createElement("option");
        option.value = item.value;
        option.dataset.cost = String(item.cost);
        option.dataset.duration = item.duration;
        option.dataset.devices = String(item.devices);
        option.dataset.planSource = isStandaloneStaticPreview ? "shared" : "api";
        option.textContent = item.label;
        return option;
      }),
    );
    if (
      selectedPlan &&
      availablePlans.some((item) => item.value === selectedPlan)
    )
      plan.value = selectedPlan;
  }

  function updateIssuePreview() {
    if (
      !issueDialog ||
      !plan ||
      !quantity ||
      !cost ||
      !unitCost ||
      !balance ||
      !issueSubmit
    )
      return;
    if (!catalogApiReady) {
      issueSubmit.disabled = true;
      issueSubmit.setAttribute("aria-disabled", "true");
      if (issueError) issueError.textContent = "目录正在加载，请稍候。";
      return;
    }
    if (!licenseIssueApiAvailable) {
      issueSubmit.disabled = true;
      issueSubmit.setAttribute("aria-disabled", "true");
      if (issueError) issueError.textContent = "管理端只能监管和回收授权卡密，不能代下游发卡。";
      return;
    }
    if (isStandaloneStaticPreview && !window.__b1ApiActive) {
      activeLicensePreview = null;
      quantity.setCustomValidity("");
      unitCost.textContent = "—";
      cost.textContent = "—";
      balance.textContent = "—";
      issueSubmit.disabled = true;
      issueSubmit.setAttribute("aria-disabled", "true");
      if (issueError) issueError.textContent = "静态预览不执行真实发卡。";
      return;
    }
    const selectedOption = plan.selectedOptions[0];
    if (!software?.value || !plan.value || !selectedOption) {
      issuePreviewSequence += 1;
      activeLicensePreview = null;
      quantity.setCustomValidity("");
      unitCost.textContent = "—";
      cost.textContent = "—";
      balance.textContent = "—";
      issueSubmit.disabled = true;
      issueSubmit.setAttribute("aria-disabled", "true");
      if (issueError) {
        const hasSoftwareOption = [...(software?.options || [])].some((option) => option.value);
        issueError.textContent = software?.value
          ? "当前软件暂时没有可发卡的套餐，请联系管理员或换一个软件。"
          : hasSoftwareOption
            ? "请选择软件和套餐后再生成。"
            : "还没有可经营软件，请联系管理员开通后再生成。";
      }
      return;
    }
    const selectedDownstreamBalance = issueDownstream?.selectedOptions[0]?.dataset.balance;
    if (selectedDownstreamBalance)
      issueDialog.dataset.availableBalance = selectedDownstreamBalance;
    const availableBalance = Number.parseInt(issueDialog.dataset.availableBalance || "0", 10);
    const selectedCost = Number.parseInt(selectedOption.dataset.cost, 10);
    if (!Number.isFinite(selectedCost) || selectedCost < 0) {
      activeLicensePreview = null;
      unitCost.textContent = "—";
      cost.textContent = "—";
      balance.textContent = "—";
      issueSubmit.disabled = true;
      issueSubmit.setAttribute("aria-disabled", "true");
      if (issueError) issueError.textContent = "当前软件暂时没有可发卡的套餐，请联系管理员或换一个软件。";
      return;
    }
    const rawQuantity = Number(quantity.value);
    const validQuantity =
      Number.isInteger(rawQuantity) && rawQuantity >= 1 && rawQuantity <= 1000;
    const total = validQuantity ? rawQuantity * selectedCost : 0;
    const canGenerate = validQuantity && total <= availableBalance;
    quantity.setCustomValidity(
      validQuantity ? "" : "数量必须是 1 至 1000 之间的整数",
    );
    if (issueError) {
      if (!validQuantity)
        issueError.textContent = "数量必须是 1 至 1000 之间的整数。";
      else if (total > availableBalance)
        issueError.textContent = `额度不足：当前还差 ${(total - availableBalance).toLocaleString("zh-CN")} 额度。`;
      else issueError.textContent = "";
    }
    unitCost.textContent = selectedCost.toLocaleString("zh-CN");
    cost.textContent = validQuantity ? total.toLocaleString("zh-CN") : "—";
    balance.textContent = validQuantity
      ? (availableBalance - total).toLocaleString("zh-CN")
      : "—";
    issueSubmit.disabled = !canGenerate;
    issueSubmit.setAttribute("aria-disabled", String(!canGenerate));
    if (licenseIssueApiAvailable && canGenerate) {
      queueLicensePreview();
    }
  }

  function queueLicensePreview() {
    window.clearTimeout(issuePreviewTimer);
    issuePreviewTimer = window.setTimeout(() => {
      requestLicensePreview();
    }, 180);
  }

  async function requestLicensePreview() {
    if (!licenseIssueApiAvailable || !catalogApiReady || !software || !plan || !quantity || !issueSubmit)
      return null;
    const rawQuantity = Number(quantity.value);
    if (!software.value || !plan.value || !Number.isInteger(rawQuantity) || rawQuantity < 1) {
      activeLicensePreview = null;
      stopIssuePreviewCountdown();
      return null;
    }
    const sequence = ++issuePreviewSequence;
    issueSubmit.disabled = true;
    issueSubmit.setAttribute("aria-disabled", "true");
    if (issueError) issueError.textContent = "正在重新计算成本…";
    try {
      const payload = await apiRequest("/downstream/licenses/preview/", {
        method: "POST",
        body: JSON.stringify({
          software_id: software.value,
          plan_id: Number(plan.value),
          quantity: rawQuantity,
        }),
      });
      if (sequence !== issuePreviewSequence) return null;
      const ttlSeconds = Number(payload.expires_in);
      activeLicensePreview = {
        ...payload,
        expiresAt: Date.now() + (Number.isFinite(ttlSeconds) && ttlSeconds > 0 ? ttlSeconds : 600) * 1000,
      };
      startIssuePreviewCountdown();
      unitCost.textContent = Number(payload.quota_cost_per_card).toLocaleString("zh-CN");
      cost.textContent = Number(payload.total_quota_cost).toLocaleString("zh-CN");
      balance.textContent = payload.sufficient_balance && payload.balance_after !== null
        ? Number(payload.balance_after).toLocaleString("zh-CN")
        : "—";
      issueDialog.dataset.availableBalance = String(payload.available_balance);
      if (!payload.sufficient_balance) {
        issueError.textContent = `额度不足：当前还差 ${(Number(payload.total_quota_cost) - Number(payload.available_balance)).toLocaleString("zh-CN")} 额度。`;
        issueSubmit.disabled = true;
      } else {
        issueError.textContent = "";
        issueSubmit.disabled = false;
      }
      issueSubmit.setAttribute("aria-disabled", String(issueSubmit.disabled));
      return payload;
    } catch (error) {
      if (sequence !== issuePreviewSequence) return null;
      activeLicensePreview = null;
      stopIssuePreviewCountdown();
      // A failed preview is retryable: leaving the button disabled would trap
      // the user on a dead dialog with no way to re-request the cost preview.
      issueSubmit.disabled = false;
      issueSubmit.setAttribute("aria-disabled", "false");
      if (issueError) issueError.textContent = apiErrorMessage(error, "成本预览失败，请稍后重试。 ");
      return null;
    }
  }

  function licensePreviewMatchesCurrent() {
    return Boolean(
      activeLicensePreview &&
      activeLicensePreview.software_id === software?.value &&
      String(activeLicensePreview.plan_id) === String(plan?.value) &&
      Number(activeLicensePreview.quantity) === Number(quantity?.value) &&
      Number(activeLicensePreview.expiresAt) > Date.now(),
    );
  }

  software?.addEventListener("change", () => {
    renderPlans();
    updateIssuePreview();
  });
  plan?.addEventListener("change", updateIssuePreview);
  quantity?.addEventListener("input", updateIssuePreview);
  issueDownstream?.addEventListener("change", updateIssuePreview);

  function syncManagementIssueScope() {
    if (!issueDownstream || !software) return;
    const allowed = new Set(
      (issueDownstream.selectedOptions[0]?.dataset.softwareScope || "")
        .split(",")
        .filter(Boolean),
    );
    [...software.options].forEach((option) => {
      option.disabled = allowed.size > 0 && !allowed.has(option.value);
    });
    if (software.selectedOptions[0]?.disabled) {
      const firstAllowed = [...software.options].find((option) => !option.disabled);
      if (firstAllowed) software.value = firstAllowed.value;
    }
    renderPlans();
    updateIssuePreview();
  }
  if (issueDownstream) {
    issueDownstream.removeEventListener("change", updateIssuePreview);
    issueDownstream.addEventListener("change", syncManagementIssueScope);
  }

  function addGeneratedLicenseRecords(items) {
    const scopeName = issueDownstream ? "management-licenses" : "downstream-licenses";
    const scope = document.querySelector(`[data-record-view-scope="${scopeName}"]`);
    if (!scope) return;
    const itemBody = scope.querySelector('[data-record-panel="items"] tbody');
    items.slice().reverse().forEach((item) => {
      const row = document.createElement("tr");
      row.dataset.generated = "license";
      row.dataset.publicId = item.public_id;
      row.dataset.searchValue = [
        item.masked_code,
        item.code_suffix,
        item.device_code,
        item.installation_id,
        item.device_label,
        item.device,
      ].filter(Boolean).join(" ");
      row.dataset.credentialType = "授权卡密";
      row.dataset.fullCode = "";
      row.dataset.codeSuffix = item.code_suffix || "";
      row.dataset.codeAvailable = String(item.code_available !== false);
      row.dataset.cardStatus = item.status || "";
      const status = licenseCardDisplayStatus(item);
      row.dataset.codeStatus = status[0];
      row.dataset.codeSoftware = item.software_name || "—";
      row.dataset.codePlan = `${item.plan_name} · ${item.duration_label} · ${item.quota_cost} 额度`;
      row.dataset.codeDownstream = item.downstream_username || "当前下游";
      row.dataset.codeDeviceCode = item.device_code || item.installation_id || item.device_label || item.device || "尚未绑定";
      row.dataset.codeDeviceUuid = item.device_uuid || item.device_id || "尚未产生";
      row.dataset.codeDevice = item.device_state || "未绑定";
      row.dataset.codeDeviceState = item.device_state || "未绑定";
      row.dataset.codeIp = item.ip || "尚未产生";
      row.dataset.codeActivity = item.activated_at ? formatApiDate(item.activated_at) : "尚未激活";
      row.dataset.codeExpires = licenseActivationRuleLabel(item);
      row.dataset.codeExpiryState = item.status === "unused" ? "未开始" : (item.status_label || "已处理");
      const selectCell = document.createElement("td");
      if (item.status === "unused") {
        const checkbox = document.createElement("input");
        checkbox.type = "checkbox";
        checkbox.dataset.reclaimSelect = "";
        checkbox.dataset.reclaimCredit = String(item.quota_cost);
        checkbox.dataset.cardId = item.public_id;
        checkbox.setAttribute("aria-label", `选择 ${item.masked_code}`);
        selectCell.append(checkbox);
      }
      row.append(selectCell);
      appendTextCell(row, item.masked_code || `••••-••••-${item.code_suffix}`, "mono");
      appendStatusCell(row, status[0], status[1]);
      appendTextCell(row, `${item.software_name} / ${item.plan_name} · ${item.duration_label} · ${item.quota_cost} 额度`, "", { kind: "compound" });
      if (issueDownstream) appendTextCell(row, item.downstream_username || "当前下游");
      appendTextCell(row, licenseActivationRuleLabel(item));
      const detailAction = appendActionCell(row, "查看 / 交付");
      detailAction.dataset.credentialDetail = "";
      itemBody?.prepend(row);
    });
    window.__previewRefreshTables?.();
  }

  issueSubmit?.addEventListener("click", async () => {
    if (
      !issueDialog ||
      !software ||
      !plan ||
      !quantity ||
      !issueForm ||
      !issueResult
    )
      return;
    updateIssuePreview();
    if (issueSubmit.disabled) return;
    if (!plan.value) {
      if (issueError) issueError.textContent = "当前软件暂时没有可发卡的套餐，请联系管理员或换一个软件。";
      return;
    }
    issueSubmit.disabled = true;
    quantity.disabled = true;
    if (issueError) issueError.textContent = "正在生成授权卡密…";
    let issuePosted = false;
    let issueRequestStarted = false;
    try {
    if (!licensePreviewMatchesCurrent()) {
      activeLicensePreview = await requestLicensePreview();
    }
      if (!activeLicensePreview || !licensePreviewMatchesCurrent() || !activeLicensePreview.sufficient_balance) {
        return;
      }
    const selectedPlan = (plans[software.value] || []).find((item) => item.value === plan.value);
    if (!selectedPlan) {
      if (issueError) issueError.textContent = "当前套餐已不可用，请刷新目录后重试。";
      return;
    }
      issueRequestStarted = true;
      let payload = await apiRequest("/downstream/licenses/issue/", {
        method: "POST",
        headers: { "Idempotency-Key": issueDialog.dataset.issueKey || (issueDialog.dataset.issueKey = requestIdempotencyKey("license-issue")) },
        body: JSON.stringify({
          software_id: activeLicensePreview.software_id,
          plan_snapshot_id: activeLicensePreview.snapshot_id,
          quantity: activeLicensePreview.quantity,
          preview_token: activeLicensePreview.preview_token,
        }),
      });
      issuePosted = true;
      const items = payload.items || [];
      const codes = items.map((item) => item.code).filter(Boolean);
      const total = Number(payload.total_quota_cost || 0);
      const remaining = Number(payload.balance_after || 0);
      const targetDownstream = "当前下游";
      issueDialog.dataset.generatedCodes = JSON.stringify(codes);
      issueDialog.dataset.codesCopied = "false";
      issueDialog.dataset.downloadFilename = "license-codes.txt";
      const codeList = issueResult.querySelector("[data-issue-codes]");
      codeList?.replaceChildren(...codes.map((code) => {
        const output = document.createElement("code");
        output.className = "mono";
        output.textContent = code;
        return output;
      }));
      issueResult.querySelector("[data-issue-result-plan]").textContent =
        `${software.selectedOptions[0].textContent} / ${selectedPlan.name}`;
      issueResult.querySelector("[data-issue-result-cost]").textContent =
        `${items.length} 张 / ${total.toLocaleString("zh-CN")} 额度`;
      issueResult.querySelector("[data-issue-result-balance]").textContent =
        remaining.toLocaleString("zh-CN");
      const targetOutput = issueResult.querySelector("[data-issue-result-downstream]");
      if (targetOutput) targetOutput.textContent = targetDownstream;
      const deliverySummary = issueResult.querySelector("[data-issue-delivery-summary]");
      if (deliverySummary) deliverySummary.textContent = `${items.length} 张完整码已准备交付`;
      addGeneratedLicenseRecords(items);
      issueDialog.dataset.availableBalance = String(remaining);
      issueDialog.dataset.issueKey = "";
      activeLicensePreview = null;
      stopIssuePreviewCountdown();
      issueForm.hidden = true;
      issueResult.hidden = false;
      try {
      if (!isStandaloneStaticPreview) {
        await loadLicenseCards();
          await loadDownstreamRecentCards();
        await loadDownstreamCredits();
        }
      } catch {
        showToast("授权卡密已生成，列表请稍后重试。");
      }
      const resultHeading = issueResult.querySelector("h3");
      if (resultHeading) {
        resultHeading.tabIndex = -1;
        resultHeading.focus({ preventScroll: true });
      }
    } catch (error) {
      if (error instanceof ApiRequestError && error.code === "PREVIEW_EXPIRED") {
        activeLicensePreview = null;
        stopIssuePreviewCountdown();
        if (issueError) issueError.textContent = apiErrorMessage(error, "成本预览已失效，请重新预览。");
        queueLicensePreview();
      } else if (issueRequestStarted && !issuePosted && !(error instanceof ApiRequestError && error.status)) {
        if (issueError) issueError.textContent = "可能已经发出，去列表看";
      } else if (issueError) {
        issueError.textContent = apiErrorMessage(error, "授权卡密生成失败，额度和数据没有改变。 ");
      }
    } finally {
      issueSubmit.disabled = false;
      quantity.disabled = false;
      if (issuePosted) updateIssuePreview();
    }
  });

  issueDialog
    ?.querySelector("[data-copy-issued]")
    ?.addEventListener("click", async () => {
      const codes = JSON.parse(issueDialog.dataset.generatedCodes || "[]");
      if (!codes.length) {
        showToast("当前无可复制的完整卡密。");
        return;
      }
      try {
        await navigator.clipboard.writeText(codes.join("\n"));
        issueDialog.dataset.codesCopied = "true";
        showToast(`已复制 ${codes.length} 张完整卡密，复制与下载均不记审计。`);
      } catch {
        showToast("浏览器未允许剪贴板；完整码仍显示在交付区。 ");
      }
    });

  document
    .querySelector("[data-issue-view-batch]")
    ?.addEventListener("click", async () => {
      if (!confirmUncopiedIssueClose(issueDialog)) return;
      issueDialog?.close("cancel");
      try {
        await loadLicenseCards(1);
      } catch {
        showToast("单卡列表刷新失败，显示的可能是旧数据，可手动刷新。");
      }
      activateScreen("licenses", { history: "push" });
      const scope = document.querySelector(
        `[data-record-view-scope="${issueDownstream ? "management-licenses" : "downstream-licenses"}"]`,
      );
      scope?.__activateRecordView?.("items");
      showToast("已进入单卡列表；列表默认重新脱敏。");
    });

  const softwareDialog = document.getElementById("softwareDialog");
  const softwareStages =
    softwareDialog?.querySelectorAll("[data-software-stage]") || [];
  const softwareName = document.getElementById("softwareName");
  const softwareCode = document.getElementById("softwareCode");
  const softwarePlatform = document.getElementById("softwarePlatform");
  const softwareProfile = document.getElementById("softwareProfile");
  const softwarePolicy = document.getElementById("softwarePolicy");
  const softwareMaxDevices = document.getElementById("softwareMaxDevices");
  const softwareVerifyInterval = document.getElementById(
    "softwareVerifyInterval",
  );
  const softwareOfflineGrace = document.getElementById("softwareOfflineGrace");
  const softwareAddPlan = document.getElementById("softwareAddPlan");
  const softwareArch = document.getElementById("softwareArch");
  const softwareChannel = document.getElementById("softwareChannel");
  function toggleSoftwarePlan() {
    const enabled = Boolean(softwareAddPlan?.checked);
    const panel = document.getElementById("softwareOptionalPlan");
    if (!panel) return;
    panel.hidden = !enabled;
    panel.querySelectorAll("input, select").forEach((field) => { field.disabled = !enabled; field.required = enabled; });
  }
  softwareAddPlan?.addEventListener("change", toggleSoftwarePlan);
  function syncSoftwareSummaries() {
    const rules = softwareDialog?.querySelector("[data-software-rules] summary");
    if (rules) rules.textContent = `授权规则 · ${softwareMaxDevices?.value || "—"} 台设备 / 每 ${softwareVerifyInterval?.value || "—"} 分钟验证`;
    const advanced = softwareDialog?.querySelector("[data-software-advanced] summary");
    if (advanced) advanced.textContent = `高级接入 · ${softwarePlatform?.selectedOptions[0]?.textContent || "—"} / ${softwareArch?.value || "—"} / ${softwareProfile?.value || "—"}`;
  }
  softwareDialog?.addEventListener("input", syncSoftwareSummaries);
  softwareDialog?.addEventListener("change", syncSoftwareSummaries);
  const softwarePlanName = document.getElementById("softwarePlanName");
  const softwarePlanDuration = document.getElementById("softwarePlanDuration");
  const softwarePlanDurationUnit = document.getElementById(
    "softwarePlanDurationUnit",
  );
  const softwarePlanCost = document.getElementById("softwarePlanCost");
  const softwareSwitchLimit = document.getElementById("softwareSwitchLimit");
  const softwareAllowSwitch = document.getElementById("softwareAllowSwitch");

  function showSoftwareStage(name) {
    softwareStages.forEach((stage) => {
      stage.hidden = stage.dataset.softwareStage !== name;
    });
  }

  softwareDialog
    ?.querySelector("[data-software-save]")
    ?.addEventListener("click", async (event) => {
      const saveButton = event.currentTarget;
      const error = softwareDialog.querySelector("[data-form-error]");
      const fields = [
        softwareName,
        softwareArch,
        softwareChannel,
        softwarePlatform,
        softwareProfile,
        softwarePolicy,
        softwareMaxDevices,
        softwareVerifyInterval,
        softwareOfflineGrace,
        softwarePlanName,
        softwarePlanDuration,
        softwarePlanDurationUnit,
        softwarePlanCost,
        softwareSwitchLimit,
      ];
      const invalid = fields.find((field) => !field?.checkValidity());
      if (!softwareName.value.trim()) { error.textContent = "请填写软件名称。"; softwareName.focus(); return; }
      if (invalid) {
        const advanced = invalid.closest("details");
        if (advanced) advanced.open = true;
        error.textContent = "请检查软件参数、授权规则和首个套餐。";
        invalid.reportValidity();
        return;
      }
      if (softwareDialog.dataset.softwareMode === "edit" && !isStandaloneStaticPreview) {
        error.textContent = "现有软件资料暂为只读；本切片只支持从唯一入口新建软件与首个套餐。";
        return;
      }
      if (!catalogApiReady) {
        error.textContent = "目录接口尚未就绪，请稍后重试。";
        return;
      }
      if (isStandaloneStaticPreview && !window.__b1ApiActive) {
          error.textContent = "静态预览不保存真实软件目录。";
          return;
        }
      saveButton.disabled = true;
      error.textContent = "";
      let payload;
      try {
        const body = {
          name: softwareName.value.trim(),
          target: softwarePlatform.value,
          profile_id: softwareProfile.value,
          contract_version: "authorization.v1",
          arch: softwareArch.value,
          channel: softwareChannel.value,
          adapter_key: "generic-online-v1",
          adapter_version: "1",
          policy_version: "policy-1",
          max_devices: Number(softwareMaxDevices.value),
          allow_device_switch: Boolean(softwareAllowSwitch?.checked),
          device_switch_limit: softwareAllowSwitch?.checked ? Number(softwareSwitchLimit.value) : 0,
          device_proof_required: true,
          verify_interval_minutes: Number(softwareVerifyInterval.value),
          offline_grace_hours: Number(softwareOfflineGrace.value),
          create_plan: Boolean(softwareAddPlan?.checked),
        };
        if (body.create_plan) Object.assign(body, {
          plan_name: softwarePlanName.value.trim(),
          duration_value: Number(softwarePlanDuration.value),
          duration_unit: softwarePlanDurationUnit.value,
          quota_cost: Number(softwarePlanCost.value),
          test_only: false,
          capability_values: {},
        });
        if (body.create_plan && !body.plan_name) { error.textContent = "请填写套餐名称。"; saveButton.disabled = false; return; }
        const serialized = JSON.stringify(body);
        if (softwareDialog.dataset.createBody !== serialized) {
          softwareDialog.dataset.createBody = serialized;
          softwareDialog.dataset.createKey = requestIdempotencyKey("catalog-create");
        }
        payload = await apiRequest("/manage/catalog/", {
          method: "POST",
          headers: { "Idempotency-Key": softwareDialog.dataset.createKey },
          body: serialized,
        });
      } catch (requestError) {
        error.textContent = apiErrorMessage(requestError, "软件创建失败，请重试。");
        saveButton.disabled = false;
        return;
      }
        const result = payload.software || {};
        softwareDialog.querySelector("[data-software-result-id]").textContent = result.software_id || "—";
        const downloadButton = softwareDialog.querySelector("[data-integration-download]");
        if (downloadButton) {
          downloadButton.dataset.integrationSoftware = result.software_id || "";
          downloadButton.dataset.integrationProfile = payload.profile?.profile_id || "";
          downloadButton.disabled = !result.software_id || !payload.profile?.profile_id;
        }
        softwareDialog.querySelector("[data-software-result-name]").textContent =
          result.name || softwareName.value;
        softwareDialog.querySelector(
          "[data-software-result-profile]",
        ).textContent = payload.profile?.profile_id || softwareProfile.value;
        softwareDialog.querySelector("[data-software-result-plan]").textContent =
          payload.plan ? `${payload.plan.name} · ${formatPlanDuration(payload.plan.duration_seconds)} · ${Number(payload.plan.quota_cost).toLocaleString("zh-CN")} 额度` : "尚未创建，可在软件列表添加";
        softwareDialog.querySelector(
          "[data-software-result-connection]",
        ).textContent = result.client_connection === "connected"
          ? "已接通"
          : "待客户端联调 · 未接通";
        showSoftwareStage("result");
      try {
        await loadCatalog();
        showToast(payload.plan ? "软件和首个套餐已保存，可下载接入配置。" : "软件已保存，可下载接入配置；套餐可稍后添加。");
      } catch {
        showToast("软件已保存，目录列表请稍后重试。");
      } finally {
        saveButton.disabled = false;
      }
        const resultHeading = softwareDialog.querySelector(".result-state h3");
        if (resultHeading) {
          resultHeading.tabIndex = -1;
          resultHeading.focus({ preventScroll: true });
      }
    });

  document.addEventListener("click", async (event) => {
    const button = event.target.closest("[data-integration-download]");
    if (!button || button.disabled) return;
    if (isStandaloneStaticPreview) { showToast("静态预览不下载真实接入配置。"); return; }
    const softwareId = button.dataset.integrationSoftware || "";
    const profileId = button.dataset.integrationProfile || "";
    if (!softwareId || !profileId) { showToast("软件身份未加载，请刷新后重试。"); return; }
    button.disabled = true;
    const label = button.textContent;
    button.textContent = "下载中…";
    try {
      const payload = await apiRequest(`/manage/catalog/software/${encodeURIComponent(softwareId)}/integration-config/?profile_id=${encodeURIComponent(profileId)}`);
      if (payload.schema !== "software-bind.v2" || payload.software?.software_id !== softwareId || payload.software?.profile_id !== profileId || !payload.platform?.authorization_public_key) throw new Error("invalid integration response");
      const blob = new Blob([JSON.stringify(payload, null, 2) + "\n"], { type: "application/json;charset=utf-8" });
      const url = URL.createObjectURL(blob);
      const link = document.createElement("a");
      link.href = url;
      link.download = `${softwareId}-${profileId}-integration.json`;
      document.body.append(link);
      link.click();
      link.remove();
      setTimeout(() => URL.revokeObjectURL(url), 1000);
      showToast("已发起接入配置下载。请将 JSON 和授权模板副本放进软件项目；尚未代表客户端已接通。");
    } catch (error) { showToast(apiErrorMessage(error, "配置下载失败，请重试。")); }
    finally { button.disabled = false; button.textContent = label; }
  });

  function prepareSoftwareDialog(button) {
    const editing = button.dataset.softwareMode === "edit";
    softwareDialog.dataset.softwareMode = editing ? "edit" : "create";
    softwareDialog.querySelector("[data-software-dialog-title]").textContent =
      editing ? "编辑软件配置" : "新建软件";
    softwareName.value = button.dataset.softwareName || "";
    softwareCode.value = editing ? (button.dataset.softwareCode || "") : "";
    softwareDialog.dataset.createBody = "";
    softwareDialog.dataset.createKey = "";
    softwarePlatform.value = button.dataset.softwarePlatform || "windows";
    softwareProfile.value =
      button.dataset.softwareProfile || "stable";
    softwareMaxDevices.value = button.dataset.softwareDevices || "1";
    softwareVerifyInterval.value = button.dataset.softwareVerify || "1";
    softwareOfflineGrace.value = button.dataset.softwareGrace || "0";
    if (softwareAddPlan) softwareAddPlan.checked = false;
    if (softwareArch) softwareArch.value = "x64";
    if (softwareChannel) softwareChannel.value = "stable";
    toggleSoftwarePlan();
    softwareDialog.querySelector("[data-software-rules]")?.removeAttribute("open");
    softwarePlanName.value = "";
    softwarePlanDuration.value = "";
    softwarePlanDurationUnit.value = "day";
    softwarePlanCost.value = "";
    if (softwareSwitchLimit) softwareSwitchLimit.value = "5";
    if (softwareAllowSwitch) softwareAllowSwitch.checked = true;
    softwarePolicy.value = "generic-online-v1";
    softwareDialog
      .querySelectorAll(".form-error")
      .forEach((error) => (error.textContent = ""));
    softwareDialog
      .querySelector("[data-software-advanced]")
      ?.removeAttribute("open");
    const connection = softwareDialog.querySelector(
      "[data-client-connection-status] .status",
    );
    if (connection) {
      connection.textContent = editing
        ? "接入状态需要复核"
        : "尚未接通客户端";
      connection.className = "status status-warm";
    }
    syncSoftwareSummaries();
    showSoftwareStage("form");
  }

  const planManagerDialog = document.getElementById("planManagerDialog");
  let planManagerPage = 1;
  function bindPlanManagerPagination() {
    const previous = planManagerDialog?.querySelector("[data-plan-manager-prev]");
    const next = planManagerDialog?.querySelector("[data-plan-manager-next]");
    if (previous && !previous.dataset.bound) {
      previous.dataset.bound = "true";
      previous.addEventListener("click", () => {
        planManagerPage = Math.max(1, planManagerPage - 1);
        preparePlanManagerDialog({ dataset: { planManagerSoftware: planManagerDialog.dataset.planManagerSoftware } }, planManagerPage);
      });
    }
    if (next && !next.dataset.bound) {
      next.dataset.bound = "true";
      next.addEventListener("click", () => {
        planManagerPage += 1;
        preparePlanManagerDialog({ dataset: { planManagerSoftware: planManagerDialog.dataset.planManagerSoftware } }, planManagerPage);
      });
    }
  }
  function setPlanManagerPagination(totalPages) {
    const controls = planManagerDialog?.querySelector("[data-plan-manager-pagination]");
    if (!controls) return;
    controls.hidden = totalPages <= 1;
    controls.querySelector("[data-plan-manager-prev]").disabled = planManagerPage <= 1;
    controls.querySelector("[data-plan-manager-next]").disabled = planManagerPage >= totalPages;
    controls.querySelector("[data-plan-manager-page]").textContent = `第 ${planManagerPage} / ${totalPages} 页`;
  }
  const planDialog = document.getElementById("planDialog");
  const planFormStage = planDialog?.querySelector('[data-plan-stage="form"]');
  const planResultStage = planDialog?.querySelector(
    '[data-plan-stage="result"]',
  );
  const planSoftware = document.getElementById("planSoftware");
  const planName = document.getElementById("planName");
  const planDuration = document.getElementById("planDuration");
  const planDurationUnit = document.getElementById("planDurationUnit");
  const planQuotaCost = document.getElementById("planQuotaCost");
  const planStatus = document.getElementById("planStatus");

  function syncPlanQuotaCostMinimum() {
    if (!planQuotaCost) return;
    planQuotaCost.min = planStatus?.value === "test" ? "0" : "1";
  }
  planStatus?.addEventListener("change", syncPlanQuotaCostMinimum);

  function preparePlanDialog(button) {
    const planMode = button.dataset.planMode || (button.dataset.planId || isStandaloneStaticPreview ? "edit" : "create");
    const editing = planMode === "edit";
    planFormStage.hidden = false;
    planResultStage.hidden = true;
    planSoftware.value = button.dataset.planSoftware || "";
    // The dialog is opened from a software row; keep the software scope fixed.
    planSoftware.disabled = true;
    planName.value = button.dataset.planName || "";
    planDuration.value = button.dataset.planDuration || "";
    planDurationUnit.value = button.dataset.planUnit || "day";
    planQuotaCost.value = button.dataset.planCost || "";
    planStatus.value = button.dataset.planTestOnly === "true" ? "test" : "active";
    syncPlanQuotaCostMinimum();
    planDialog.dataset.planMode = planMode;
    planDialog.dataset.planLifecycleStatus = button.dataset.planStatus || "active";
    planDialog.dataset.planId = button.dataset.planId || "";
    planDialog.dataset.planSoftwareId = button.dataset.planSoftwareId || planSoftware.value;
    planDialog.dataset.planProfileId = button.dataset.planProfileId || "";
    planDialog.dataset.planPolicyVersion = button.dataset.planPolicyVersion || "";
    planDialog.querySelector("[data-plan-error]").textContent = "";
    planDialog.querySelector("#planDialogTitle").textContent = editing ? "套餐定价" : "新增套餐";
    planDialog.querySelector("[data-plan-save]").textContent = editing ? "保存套餐定价" : "保存新套餐";
    planResultStage.querySelector("h3").textContent = editing ? "套餐定价已保存" : "套餐已创建";
  }

  function configurePlanEditorTrigger(button, softwareItem, planItem = null) {
    const profile = softwareItem?.profiles?.find((item) => ["testing", "active"].includes(item.status)) || softwareItem?.profiles?.[0];
    const policy = profile?.policies?.find((item) => item.status === "active") || profile?.policies?.[0] || {};
    const seconds = Number(planItem?.duration_seconds || 0);
    button.dataset.planMode = planItem ? "edit" : "create";
    button.dataset.planId = planItem ? String(planItem.id) : "";
    button.dataset.planSoftwareId = softwareItem?.software_id || "";
    button.dataset.planSoftware = softwareItem?.software_id || "";
    button.dataset.planProfileId = planItem?.profile_id || profile?.profile_id || "";
    button.dataset.planName = planItem?.name || "";
    button.dataset.planDuration = seconds
      ? String(seconds % 86400 === 0 ? seconds / 86400 : seconds % 3600 === 0 ? seconds / 3600 : Math.max(1, Math.floor(seconds / 60)))
      : "30";
    button.dataset.planUnit = seconds % 86400 === 0 ? "day" : seconds % 3600 === 0 ? "hour" : "minute";
    button.dataset.planCost = String(planItem?.quota_cost ?? 0);
    button.dataset.planStatus = planItem?.status || "active";
    button.dataset.planTestOnly = String(Boolean(planItem?.test_only));
    button.dataset.planPolicyVersion = policy.version || planItem?.latest_snapshot?.policy_version || "";
  }

  function openPlanEditor(button) {
    if (!planDialog) return;
    preparePlanDialog(button);
    planDialog.showModal();
  }

  const planLifecycleDialog = document.getElementById("planLifecycleDialog");
  let pendingPlanLifecycle;

  function openPlanLifecycle(planItem, softwareItem, mode) {
    if (!planLifecycleDialog || !planItem) return;
    const deleting = mode === "delete";
    const restoring = !deleting && planItem.status === "archived";
    pendingPlanLifecycle = {
      planId: String(planItem.id),
      softwareId: String(softwareItem?.software_id || planItem.software_id || ""),
      mode: deleting ? "delete" : "status",
      targetStatus: restoring ? "active" : "archived",
    };
    planLifecycleDialog.querySelector("[data-plan-lifecycle-title]").textContent = deleting
      ? "删除套餐"
      : restoring
        ? "恢复套餐"
        : "归档套餐";
    planLifecycleDialog.querySelector("[data-plan-lifecycle-target]").textContent = `${softwareItem?.name || "当前软件"} · ${planItem.name || "套餐"}`;
    planLifecycleDialog.querySelector("[data-plan-lifecycle-impact]").textContent = deleting
      ? "套餐从列表消失，不能再恢复。这个套餐发出的未激活卡会作废（有额度的退回原下游），已激活卡会撤销失效，客户下次验证会停。额度流水和审计留下。"
      : restoring
        ? "重新允许新发卡和下游目录读取"
        : "停止新发卡和下游目录读取，已发出的卡仍有效";
    planLifecycleDialog.querySelector("textarea[name='reason']").value = "";
    planLifecycleDialog.querySelector("[data-plan-lifecycle-error]").textContent = "";
    const confirm = planLifecycleDialog.querySelector("[data-plan-lifecycle-confirm]");
    confirm.textContent = deleting ? "确认删除套餐" : restoring ? "确认恢复套餐" : "确认归档套餐";
    confirm.className = restoring ? "button button-primary" : "button button-danger";
    planLifecycleDialog.showModal();
  }

  function preparePlanManagerDialog(button, requestedPage) {
    if (!planManagerDialog) return;
    if (requestedPage === undefined) planManagerPage = 1;
    bindPlanManagerPagination();
    const softwareId = button.dataset.planManagerSoftware || "";
    const softwareItem = catalogItems.find((item) => String(item.software_id) === String(softwareId));
    const softwarePlans = (softwareItem?.plans || []).filter((item) => item.status !== "deleted");
    const totalPages = Math.max(1, Math.ceil(softwarePlans.length / 5));
    planManagerPage = Math.max(1, Math.min(totalPages, Number(requestedPage || planManagerPage) || 1));
    const visiblePlans = softwarePlans.slice((planManagerPage - 1) * 5, planManagerPage * 5);
    planManagerDialog.dataset.planManagerSoftware = softwareId;
    planManagerDialog.querySelector("[data-plan-manager-context]").textContent = softwareItem?.name || "软件目录尚未读取";
    planManagerDialog.querySelector("[data-plan-manager-count]").textContent = `${softwarePlans.length} 个套餐`;
    planManagerDialog.querySelector("[data-plan-manager-error]").textContent = "";

    const addButton = planManagerDialog.querySelector("[data-plan-manager-add]");
    if (addButton) {
      configurePlanEditorTrigger(addButton, softwareItem);
      addButton.onclick = () => openPlanEditor(addButton);
    }

    const rows = planManagerDialog.querySelector("[data-plan-manager-rows]");
    rows.replaceChildren();
    if (!softwareItem || !softwarePlans.length) {
      const emptyRow = document.createElement("tr");
      const emptyCell = document.createElement("td");
      emptyCell.colSpan = 6;
      emptyCell.className = "plan-manager-empty";
      emptyCell.textContent = softwareItem ? "这个软件还没有套餐。点击右上角新增。" : "软件目录暂时无法读取。";
      emptyRow.append(emptyCell);
      rows.append(emptyRow);
      for (let index = 1; index < 5; index += 1) {
        const placeholder = document.createElement("tr");
        placeholder.className = "table-placeholder-row";
        placeholder.setAttribute("aria-hidden", "true");
        for (let cellIndex = 0; cellIndex < 6; cellIndex += 1) {
          const cell = document.createElement("td");
          cell.innerHTML = "&nbsp;";
          placeholder.append(cell);
        }
        rows.append(placeholder);
      }
      setPlanManagerPagination(totalPages);
      return;
    }

    visiblePlans.forEach((planItem) => {
      const row = document.createElement("tr");
      row.dataset.planManagerRow = String(planItem.id);
      appendTextCell(row, planItem.name);
      appendTextCell(row, formatPlanDuration(planItem.duration_seconds));
      appendTextCell(row, `${Number(planItem.quota_cost ?? 0).toLocaleString("zh-CN")} 额度`, "mono");
      const testOnly = Boolean(planItem.test_only || planItem.testOnly);
      let statusLabel = "可用";
      let statusClass = "status-green";
      if (planItem.status === "archived") {
        statusLabel = "已归档";
        statusClass = "status-gray";
      } else if (planItem.status === "draft") {
        statusLabel = "草稿";
        statusClass = "status-gray";
      } else if (testOnly) {
        statusLabel = "仅测试";
        statusClass = "status-warm";
      }
      appendStatusCell(row, statusLabel, statusClass);
      appendTextCell(row, `v${planItem.latest_snapshot?.snapshot_version || 1}`, "mono");
      const actionCell = document.createElement("td");
      const editButton = document.createElement("button");
      editButton.className = "text-button";
      editButton.type = "button";
      editButton.textContent = "修改";
      configurePlanEditorTrigger(editButton, softwareItem, planItem);
      editButton.addEventListener("click", () => openPlanEditor(editButton));
      const lifecycleButton = document.createElement("button");
      lifecycleButton.className = "text-button";
      lifecycleButton.type = "button";
      lifecycleButton.textContent = planItem.status === "archived" ? "恢复" : "归档";
      lifecycleButton.addEventListener("click", () => openPlanLifecycle(planItem, softwareItem));
      const deleteButton = document.createElement("button");
      deleteButton.className = "text-button";
      deleteButton.type = "button";
      deleteButton.textContent = "删除";
      deleteButton.addEventListener("click", () => openPlanLifecycle(planItem, softwareItem, "delete"));
      if (planItem.status === "archived") {
        wrapTableActions(actionCell, editButton, lifecycleButton, deleteButton);
      } else {
        wrapTableActions(actionCell, editButton, lifecycleButton);
      }
      row.append(actionCell);
      rows.append(row);
    });
    for (let index = visiblePlans.length; index < 5; index += 1) {
      const placeholder = document.createElement("tr");
      placeholder.className = "table-placeholder-row";
      placeholder.setAttribute("aria-hidden", "true");
      for (let cellIndex = 0; cellIndex < 6; cellIndex += 1) {
        const cell = document.createElement("td");
        cell.innerHTML = "&nbsp;";
        placeholder.append(cell);
      }
      rows.append(placeholder);
    }
    setPlanManagerPagination(totalPages);
  }

  planLifecycleDialog
    ?.querySelector("[data-plan-lifecycle-confirm]")
    ?.addEventListener("click", async (event) => {
      if (!pendingPlanLifecycle) return;
      const form = planLifecycleDialog.querySelector("form");
      const error = planLifecycleDialog.querySelector("[data-plan-lifecycle-error]");
      const reason = form.elements.reason?.value.trim() || "";
      if (!form.checkValidity() || reason.length < 4) {
        error.textContent = "请填写至少 4 个字的可追溯原因。";
        form.reportValidity();
        return;
      }
      const confirm = event.currentTarget;
      confirm.disabled = true;
      error.textContent = "";
      const request = pendingPlanLifecycle;
      try {
        if (isStandaloneStaticPreview) {
          error.textContent = "静态预览不修改真实套餐目录。";
          confirm.disabled = false;
          return;
        }
        if (request.mode === "delete") {
          const payload = await apiRequest(`/manage/catalog/plans/${encodeURIComponent(request.planId)}/delete/`, {
            method: "POST",
            headers: { "Idempotency-Key": requestIdempotencyKey("catalog-plan-delete") },
            body: JSON.stringify({ reason }),
          });
          planLifecycleDialog.close("success");
          pendingPlanLifecycle = undefined;
          const invalidated = payload?.invalidated || {};
          const unused = Number(invalidated.unused || 0);
          const activated = Number(invalidated.activated || 0);
          const refunded = Number(invalidated.quota_refunded || 0);
          showToast(
            `套餐已删除。已作废未激活 ${unused} 张${refunded ? `（退回 ${refunded} 额度）` : ""}，已撤销已激活 ${activated} 张。`,
          );
        } else {
          await apiRequest(`/manage/catalog/plans/${encodeURIComponent(request.planId)}/status/`, {
            method: "POST",
            headers: { "Idempotency-Key": requestIdempotencyKey(`catalog-plan-${request.targetStatus}`) },
            body: JSON.stringify({ status: request.targetStatus, reason }),
          });
          planLifecycleDialog.close("success");
          pendingPlanLifecycle = undefined;
          showToast(request.targetStatus === "active" ? "套餐已恢复，新的发卡和下游目录已重新开放。" : "套餐已归档，新的发卡和下游目录已停止；已发出的卡仍有效。 ");
        }
        await loadCatalog();
        if (planManagerDialog?.open) {
          preparePlanManagerDialog(
            { dataset: { planManagerSoftware: planManagerDialog.dataset.planManagerSoftware } },
            planManagerPage,
          );
        } else if (planManagerDialog) {
          planManagerDialog.showModal();
        }
      } catch (requestError) {
        error.textContent = apiErrorMessage(
          requestError,
          request.mode === "delete" ? "套餐删除失败，服务端状态未改变。 " : "套餐状态更新失败，服务端状态未改变。 ",
        );
      } finally {
        confirm.disabled = false;
      }
    });

  planDialog
    ?.querySelector("[data-plan-save]")
    ?.addEventListener("click", async (event) => {
      const saveButton = event.currentTarget;
      const fields = [
        planSoftware,
        planName,
        planDuration,
        planDurationUnit,
        planQuotaCost,
        planStatus,
      ];
      const invalid = fields.find((field) => !field?.checkValidity());
      const error = planDialog.querySelector("[data-plan-error]");
      if (invalid) {
        error.textContent = "请完整填写软件、卡种、有效期和单卡额度成本。";
        invalid.reportValidity();
        return;
      }
      if (planStatus.value !== "test" && Number(planQuotaCost.value) < 1) {
        error.textContent = "正式套餐额度成本至少为 1。测试套餐才可以填 0。";
        planQuotaCost.reportValidity();
        return;
      }
      const planMode = planDialog.dataset.planMode || "edit";
      const editing = planMode === "edit";
      const planId = planDialog.dataset.planId;
      if (!catalogApiReady || (editing && !planId && !isStandaloneStaticPreview)) {
        error.textContent = "当前套餐还没有真实服务端标识，不能保存。";
        return;
      }
      saveButton.disabled = true;
      error.textContent = "";
      try {
        if (isStandaloneStaticPreview) {
          error.textContent = "静态预览不修改真实套餐目录。";
          saveButton.disabled = false;
          return;
        }
        const requestBody = {
          name: planName.value,
          duration_value: Number(planDuration.value),
          duration_unit: planDurationUnit.value,
          quota_cost: Number(planQuotaCost.value),
          test_only: planStatus.value === "test",
          status: editing ? planDialog.dataset.planLifecycleStatus || "active" : "active",
          policy_version: planDialog.dataset.planPolicyVersion || undefined,
          capability_values: {},
        };
        const endpoint = editing
          ? `/manage/catalog/plans/${encodeURIComponent(planId)}/revise/`
          : "/manage/catalog/plans/";
        if (!editing) {
          requestBody.software_id = planDialog.dataset.planSoftwareId || planSoftware.value;
          requestBody.profile_id = planDialog.dataset.planProfileId || undefined;
        }
        const payload = await apiRequest(endpoint, {
          method: "POST",
          headers: { "Idempotency-Key": requestIdempotencyKey(editing ? "catalog-revise" : "catalog-create-plan") },
          body: JSON.stringify(requestBody),
        });
        planDialog.querySelector("[data-plan-result-summary]").textContent =
          `${planSoftware.selectedOptions[0].textContent} · ${payload.plan?.name || planName.value} · ${formatPlanDuration(payload.plan?.duration_seconds)} · ${Number(payload.plan?.quota_cost ?? planQuotaCost.value).toLocaleString("zh-CN")} 额度`;
        planFormStage.hidden = true;
        planResultStage.hidden = false;
        await loadCatalog();
        if (planManagerDialog?.open) {
          preparePlanManagerDialog(
            { dataset: { planManagerSoftware: planManagerDialog.dataset.planManagerSoftware } },
            planManagerPage,
          );
        }
        showToast(editing ? "套餐已修订；历史快照保持不变。 " : "套餐已创建；同一软件现在可以同时维护多个套餐。 ");
        planResultStage.querySelector("h3")?.focus({ preventScroll: true });
      } catch (requestError) {
        error.textContent = apiErrorMessage(requestError, editing ? "套餐修订失败。" : "新增套餐失败。");
      } finally {
        saveButton.disabled = false;
      }
    });

  const inviteDialog = document.getElementById("inviteDialog");
  const inviteFormStage = inviteDialog?.querySelector(
    '[data-invite-stage="form"]',
  );
  const inviteResultStage = inviteDialog?.querySelector(
    '[data-invite-stage="result"]',
  );
  const inviteQuantity = document.getElementById("inviteQuantity");

  function prepareInviteDialog() {
    inviteFormStage.hidden = false;
    inviteResultStage.hidden = true;
    inviteDialog.querySelector("[data-invite-error]").textContent = "";
    inviteDialog.dataset.generatedCodes = "[]";
    inviteDialog.querySelector("[data-invite-codes]")?.replaceChildren();
  }

  function wrapTableActions(cell, ...nodes) {
    const actions = document.createElement("div");
    actions.className = "table-actions";
    nodes.forEach((node) => {
      if (node) actions.append(node);
    });
    cell.append(actions);
    return actions;
  }

  let tableHoverTooltip;

  function tableTooltipElement() {
    if (tableHoverTooltip) return tableHoverTooltip;
    tableHoverTooltip = document.createElement("div");
    tableHoverTooltip.className = "table-hover-tooltip";
    tableHoverTooltip.hidden = true;
    tableHoverTooltip.setAttribute("role", "tooltip");
    document.body.append(tableHoverTooltip);
    return tableHoverTooltip;
  }

  function hideTableTooltip() {
    if (!tableHoverTooltip) return;
    tableHoverTooltip.hidden = true;
    tableHoverTooltip.textContent = "";
  }

  function showTableTooltip(target) {
    const text = target?.dataset?.tableTooltip || "";
    if (!text) return;
    if (target?.hasAttribute?.("title")) {
      target.removeAttribute("title");
    }
    const tooltip = tableTooltipElement();
    tooltip.textContent = text;
    tooltip.hidden = false;
    const targetRect = target.getBoundingClientRect();
    const tooltipRect = tooltip.getBoundingClientRect();
    const gutter = 10;
    const left = Math.min(
      Math.max(gutter, targetRect.left),
      Math.max(gutter, window.innerWidth - tooltipRect.width - gutter),
    );
    const below = targetRect.bottom + 8;
    const top = below + tooltipRect.height <= window.innerHeight - gutter
      ? below
      : Math.max(gutter, targetRect.top - tooltipRect.height - 8);
    tooltip.style.left = `${left}px`;
    tooltip.style.top = `${top}px`;
  }

  document.addEventListener("pointerover", (event) => {
    const target = event.target.closest?.("[data-table-tooltip]");
    if (target) {
      if (target.hasAttribute("title")) target.removeAttribute("title");
      showTableTooltip(target);
    }
  });
  document.addEventListener("pointerout", (event) => {
    const target = event.target.closest?.("[data-table-tooltip]");
    const next = event.relatedTarget?.closest?.("[data-table-tooltip]");
    if (target && target !== next) hideTableTooltip();
  });
  document.addEventListener("focusin", (event) => {
    const target = event.target.closest?.("[data-table-tooltip]");
    if (target) {
      if (target.hasAttribute("title")) target.removeAttribute("title");
      showTableTooltip(target);
    }
  });
  document.addEventListener("focusout", (event) => {
    if (event.target.closest?.("[data-table-tooltip]")) hideTableTooltip();
  });
  window.addEventListener("scroll", hideTableTooltip, true);
  window.addEventListener("resize", hideTableTooltip);

  function setTableTooltip(target, fullText, displayText = fullText) {
    const text = fullText == null ? "" : String(fullText);
    if (!target || !text) return target;
    target.dataset.tableTooltip = text;
    target.removeAttribute("title");
    target.setAttribute("aria-label", text);
    if (displayText !== text) {
      target.classList.add("table-token");
      target.tabIndex = 0;
    }
    return target;
  }

  function tableValueLooksLikeDate(text) {
    return /^(?:\d{4}-\d{2}-\d{2}|\d{4}\/\d{2}\/\d{2})(?:[ T].*)?$/.test(text);
  }

  function shortenTableText(text, { kind = "", maxLength = 18 } = {}) {
    const value = String(text || "");
    if (!value || value.length <= maxLength || tableValueLooksLikeDate(value)) return value;
    if (kind === "compound") {
      const parts = value.split(/\s*(?:\/|·)\s*/).filter(Boolean);
      if (parts.length > 1) {
        const first = shortenTableText(parts[0], { maxLength: 10 });
        const second = shortenTableText(parts[1], { maxLength: 9 });
        return `${first} · ${second}${parts.length > 2 ? " …" : ""}`;
      }
    }
    if (kind === "id" || kind === "credential" || /^[A-Za-z0-9_.:-]+$/.test(value.replace(/\s/g, ""))) {
      return `${value.slice(0, 6)}…${value.slice(-4)}`;
    }
    return `${value.slice(0, Math.max(6, maxLength - 1))}…`;
  }

  const SOFTWARE_COLOR_CLASSES = [
    "badge-software-blue",
    "badge-software-purple",
    "badge-software-teal",
    "badge-software-amber",
    "badge-software-rose",
  ];

  function softwareColorClass(name) {
    if (!name || name === "—") return "badge-software-blue";
    let hash = 0;
    const str = String(name);
    for (let i = 0; i < str.length; i++) {
      hash = (hash << 5) - hash + str.charCodeAt(i);
      hash |= 0;
    }
    return SOFTWARE_COLOR_CLASSES[Math.abs(hash) % SOFTWARE_COLOR_CLASSES.length];
  }

  function appendSoftwareCell(row, name) {
    const cell = document.createElement("td");
    const rawName = String(name || "—").trim();
    if (rawName === "—" || !rawName) {
      cell.textContent = "—";
      row.append(cell);
      return cell;
    }
    const badge = document.createElement("span");
    badge.className = `badge-software ${softwareColorClass(rawName)}`;
    const display = rawName.length > 12 ? `${rawName.slice(0, 10)}…` : rawName;
    badge.textContent = display;
    if (display !== rawName) {
      setTableTooltip(badge, rawName, display);
    }
    cell.append(badge);
    row.append(cell);
    return cell;
  }

  function extractPlanShortType(planName) {
    const name = String(planName || "").trim();
    if (!name || name === "—") return "标准套餐";
    if (name.includes("测试") || name.toLowerCase().includes("test")) return "测试卡";
    if (name.includes("天") || name.includes("日") || name.toLowerCase().includes("day")) return "日卡";
    if (name.includes("月") || name.toLowerCase().includes("month")) return "月卡";
    if (name.includes("季") || name.toLowerCase().includes("quarter")) return "季卡";
    if (name.includes("年") || name.toLowerCase().includes("year")) return "年卡";
    if (name.length <= 6) return name;
    return `${name.slice(0, 5)}…`;
  }

  function planBadgeClass(shortType) {
    if (shortType.includes("测试")) return "badge-plan-test";
    if (shortType.includes("日")) return "badge-plan-day";
    if (shortType.includes("月")) return "badge-plan-month";
    if (shortType.includes("季")) return "badge-plan-quarter";
    if (shortType.includes("年")) return "badge-plan-year";
    return "badge-plan-test";
  }

  function appendPlanCell(row, planName, fullRule = "") {
    const cell = document.createElement("td");
    const rawName = String(planName || "—").trim();
    if (rawName === "—" || !rawName) {
      cell.textContent = "—";
      row.append(cell);
      return cell;
    }
    const shortType = extractPlanShortType(rawName);
    const badge = document.createElement("span");
    badge.className = `badge-plan ${planBadgeClass(shortType)}`;
    badge.textContent = shortType;
    const tooltipText = fullRule ? `${rawName} · ${fullRule}` : rawName;
    setTableTooltip(badge, tooltipText, shortType);
    cell.append(badge);
    row.append(cell);
    return cell;
  }

  function createTableButton(label, { kind = "detail", disabled = false, disabledReason = "", tooltip = "", onClick = null } = {}) {
    const button = document.createElement("button");
    button.type = "button";
    button.className = `table-btn table-btn-${kind}${disabled ? " is-disabled" : ""}`;
    button.textContent = label;
    if (disabled) {
      button.disabled = true;
      const tip = disabledReason || tooltip || "当前不可操作";
      setTableTooltip(button, tip, label);
    } else {
      if (tooltip) {
        setTableTooltip(button, tooltip, label);
      }
      if (typeof onClick === "function") {
        button.addEventListener("click", onClick);
      }
    }
    return button;
  }

  function configureTableAction(button, label, shortLabel = "") {
    const fullLabel = String(label || "");
    const inferredShortLabel = fullLabel.includes("（")
      ? fullLabel.split("（", 1)[0].trim()
      : shortenTableText(fullLabel, { maxLength: 10 });
    const displayLabel = shortLabel || inferredShortLabel;
    button.textContent = displayLabel;
    if (displayLabel !== fullLabel) {
      setTableTooltip(button, fullLabel, displayLabel);
      button.classList.remove("table-token");
      button.removeAttribute("tabindex");
      button.classList.add("table-action-compact");
    } else {
      button.setAttribute("aria-label", fullLabel);
    }
    return button;
  }

  function appendActionCell(row, label, action) {
    const cell = document.createElement("td");
    const actions = document.createElement("div");
    actions.className = "table-actions";
    const button = document.createElement("button");
    button.className = "table-btn table-btn-detail";
    button.type = "button";
    configureTableAction(button, label);
    if (action) button.addEventListener("click", action);
    actions.append(button);
    cell.append(actions);
    row.append(cell);
    return button;
  }

  function formatJoinedSummary(items, emptyLabel) {
    const values = (items || []).map((item) => String(item || "").trim()).filter(Boolean);
    if (!values.length) return emptyLabel;
    if (values.length <= 6) return values.join("、");
    return `${values.slice(0, 6).join("、")} 等 ${values.length} 项`;
  }

  function appendTextCell(row, value, className = "", options = {}) {
    const cell = document.createElement("td");
    const text = value == null ? "" : String(value);
    if (className) cell.className = className;
    const inferredKind = options.kind || (className.includes("mono") ? "id" : "");
    const displayText = options.displayText || shortenTableText(text, {
      kind: inferredKind,
      maxLength: Number(options.maxLength) || (inferredKind === "id" ? 16 : 20),
    });
    if (displayText !== text) {
      const token = document.createElement("span");
      token.textContent = displayText;
      setTableTooltip(token, text, displayText);
      cell.append(token);
    } else {
      cell.textContent = text;
      if (text.length > 24) setTableTooltip(cell, text);
    }
    row.append(cell);
    return cell;
  }

  function appendStatusCell(row, value, className) {
    const cell = document.createElement("td");
    const status = document.createElement("span");
    status.className = `status ${className}`;
    status.textContent = value;
    cell.append(status);
    row.append(cell);
    return cell;
  }

  inviteDialog
    ?.querySelector("[data-invite-generate]")
    ?.addEventListener("click", () => {
      if (window.__b1ApiActive || !isStandaloneStaticPreview) return;
      const error = inviteDialog.querySelector("[data-invite-error]");
      if (error) error.textContent = "静态预览不生成真实邀请码。";
    });

  const quotaCardDialog = document.getElementById("quotaCardDialog");
  const quotaCardFormStage = quotaCardDialog?.querySelector(
    '[data-quota-card-stage="form"]',
  );
  const quotaCardResultStage = quotaCardDialog?.querySelector(
    '[data-quota-card-stage="result"]',
  );
  const quotaCardAmount = document.getElementById("quotaCardAmount");
  const quotaCardQuantity = document.getElementById("quotaCardQuantity");

  function prepareQuotaCardDialog() {
    quotaCardFormStage.hidden = false;
    quotaCardResultStage.hidden = true;
    quotaCardDialog.querySelector("[data-quota-card-error]").textContent = "";
    quotaCardDialog.dataset.generatedCodes = "[]";
    quotaCardDialog.querySelector("[data-quota-card-codes]")?.replaceChildren();
  }

  const quotaIssuedDisplay = "\u53ef\u5151\u6362";
  const quotaCardStatusCopy = {
    issued: ["未兑换", "status-green"],
    redeemed: ["已兑换", "status-gray"],
    revoked: ["已作废", "status-gray"],
    archived: ["已归档", "status-gray"],
  };

  function renderQuotaCardRows(items, { serverSearch = false } = {}) {
    const body = document.querySelector("[data-quota-card-item-table]");
    if (!body) return;
    body.replaceChildren();
    items.forEach((item) => {
      const row = document.createElement("tr");
      row.dataset.publicId = item.public_id || "";
      if (item.generated) row.dataset.generated = item.generated;
      const [statusLabel, statusClass] = quotaCardStatusCopy[item.status] || [item.status, "status-gray"];
      const masked = item.masked_code || (item.code ? maskCredential(item.code) : "");
      const suffix = item.code_suffix || (item.code ? String(item.code).slice(-4) : "");
      row.dataset.searchValue = `${masked} ${suffix}`.trim();
      row.dataset.codeSuffix = suffix;
      row.dataset.codeAvailable = "true";
      row.dataset.credentialType = "额度兑换码";
      row.dataset.cardStatus = item.status || "";
      if (serverSearch) row.dataset.serverSearchMatch = "true";
      row.dataset.codeStatus = statusLabel;
      row.dataset.codePlan = `${Number(item.amount).toLocaleString("zh-CN")} 额度`;
      row.dataset.codeDownstream = item.redeemed_by || "尚未兑换";
      row.dataset.codeActivity = formatApiDate(item.redeemed_at);
      row.dataset.codeIp = item.redeemed_ip_digest || "尚未产生";
      row.dataset.codeExpires = item.status === "issued" ? "永久有效" : "已消费";
      const selectCell = document.createElement("td");
      if (document.body.classList.contains("role-admin")) {
        const checkbox = document.createElement("input");
        checkbox.type = "checkbox";
        checkbox.dataset.reclaimSelect = "";
        checkbox.dataset.cardStatus = item.status || "";
        checkbox.dataset.cardId = item.public_id || "";
        checkbox.setAttribute(
          "aria-label",
          `选择额度兑换码 ${String(item.public_id).slice(-4)}`,
        );
        selectCell.append(checkbox);
      }
      row.append(selectCell);
      appendTextCell(row, masked || (suffix ? `••••-••••-${suffix}` : "—"), "mono");
      appendTextCell(row, Number(item.amount).toLocaleString("zh-CN"), "mono");
      appendStatusCell(row, statusLabel, statusClass);
      appendTextCell(row, item.redeemed_by || (item.status === "issued" ? quotaIssuedDisplay : "尚未兑换"));
      appendTextCell(row, item.redeemed_at ? formatApiDate(item.redeemed_at) : "—", "mono");
      const actionCell = document.createElement("td");
      const actions = document.createElement("div");
      actions.className = "table-actions";
      const detailAction = createTableButton("详情", {
        kind: "detail",
        tooltip: "查看该张额度兑换码完整详情",
      });
      detailAction.dataset.credentialDetail = "";
      actions.append(detailAction);
      actionCell.append(actions);
      row.append(actionCell);
      body.append(row);
    });
    const panel = body.closest(".table-panel");
    if (panel) panel.dataset.serverDataLoaded = "true";
    setCredentialSearchOverlay("quota-cards", Boolean(serverSearch));
    syncRecordSelection(body.closest(".table-panel"));
    window.__previewRefreshTables?.();
  }

  quotaCardDialog
    ?.querySelector("[data-quota-card-generate]")
    ?.addEventListener("click", async () => {
      const fields = [
        quotaCardAmount,
        quotaCardQuantity,
      ];
      const invalid = fields.find((field) => !field?.checkValidity());
      const error = quotaCardDialog.querySelector("[data-quota-card-error]");
      if (invalid) {
        error.textContent = "请填写有效的单码额度和生成数量。";
        invalid.reportValidity();
        return;
      }
      if (isStandaloneStaticPreview) {
        error.textContent = "静态预览不生成真实额度兑换码。";
        return;
      }
      const amountValue = Number(quotaCardAmount.value);
      const quantityValue = Number(quotaCardQuantity.value);
      error.textContent = "";
      const button = quotaCardDialog.querySelector("[data-quota-card-generate]");
      button.disabled = true;
      try {
        const payload = await apiRequest("/manage/credits/cards/", {
          method: "POST",
          headers: {
            "Idempotency-Key":
              quotaCardDialog.dataset.quotaKey ||
              (quotaCardDialog.dataset.quotaKey = requestIdempotencyKey("quota-card-issue")),
          },
          body: JSON.stringify({ amount: amountValue, quantity: quantityValue }),
        });
        const items = payload.items || [];
        const quotaCodes = items.map((item) => item.code).filter(Boolean);
        quotaCardDialog.dataset.generatedCodes = JSON.stringify(quotaCodes);
        quotaCardDialog.dataset.downloadFilename = "quota-codes.txt";
        quotaCardDialog.querySelector("[data-quota-card-result-total]").textContent = `${Number(payload.total_amount || 0).toLocaleString("zh-CN")} 额度`;
        const quotaCodeList = quotaCardDialog.querySelector("[data-quota-card-codes]");
        quotaCodeList?.replaceChildren(
          ...quotaCodes.map((code) => {
            const output = document.createElement("code");
            output.className = "mono";
            output.textContent = code;
            return output;
          }),
        );
        quotaCardFormStage.hidden = true;
        quotaCardResultStage.hidden = false;
        quotaCardResultStage.querySelector("h3")?.focus({ preventScroll: true });
        quotaCardDialog.dataset.quotaKey = "";
        await loadAdminCredits();
        showToast(`已生成 ${items.length} 枚额度兑换码；之后可在单码详情中按需重复查看。`);
      } catch (requestError) {
        error.textContent = apiErrorMessage(requestError, "额度兑换码生成失败，请重试。");
      } finally {
        button.disabled = false;
      }
    });

  function openQuotaRevokeDialog(publicIds) {
    const dialog = document.getElementById("quotaRevokeDialog");
    const ids = [...new Set((publicIds || []).filter(Boolean))];
    if (dialog && resumeDialogWrite(dialog, "quota-cards:revoke")) return;
    if (!dialog || !ids.length) {
      showToast("请先勾选未兑换的额度兑换码。");
      return;
    }
    prepareDialogWrite(dialog, "quota-cards:revoke", ids);
    restoreDialogWrite(dialog);
    dialog.__quotaRevokeIds = ids;
    dialog.__quotaRevokeKeys = {};
    const count = dialog.querySelector("[data-quota-revoke-count]");
    if (count) count.textContent = `${ids.length} 张`;
    const form = dialog.querySelector("form");
    if (form?.elements.reason) form.elements.reason.value = "";
    const error = dialog.querySelector("[data-form-error]");
    if (error) error.textContent = "";
    dialog.showModal();
  }

  document.addEventListener("click", (event) => {
    const rowButton = event.target.closest("[data-quota-revoke]");
    if (!rowButton) return;
    event.preventDefault();
    openQuotaRevokeDialog([rowButton.dataset.cardId || rowButton.closest("tr")?.dataset.publicId]);
  });

  document.querySelector("[data-quota-revoke-selected]")?.addEventListener("click", () => {
    const panel = document.querySelector('[data-record-view-scope="quota-cards"] .table-panel');
    const boxes = selectedRecordBoxes(panel).filter((box) => box.dataset.cardStatus === "issued");
    openQuotaRevokeDialog(boxes.map((box) => box.dataset.cardId || box.closest("tr")?.dataset.publicId));
  });

  document.querySelector("[data-quota-revoke-confirm]")?.addEventListener("click", async (event) => {
    const dialog = document.getElementById("quotaRevokeDialog"), form = dialog?.querySelector("form");
    const error = form?.querySelector("[data-form-error]"), reason = form?.elements.reason?.value.trim() || "";
    if (isStandaloneStaticPreview && !window.__b1ApiActive) { if (error) error.textContent = "静态预览不执行真实作废。"; return; }
    if (!dialog.__selectedIds?.length || !form?.checkValidity() || reason.length < 2) { if (error) error.textContent = "请填写至少 2 个字的作废原因。"; return; }
    const button = event.currentTarget; button.disabled = true; if (error) error.textContent = "";
    try {
      const result = await submitRecordRevocations(dialog,"/manage/credits/cards",reason);
      if (!result.failures.length) { dialog.close("success"); showToast(`已作废 ${result.succeeded.length} 枚额度码。`); }
      else { if (error) error.textContent = `已作废 ${result.succeeded.length} 枚，${result.failures.length} 枚被拒绝：${result.failures.map((item) => item.error).slice(0,3).join("；")}`; dialog.__selectedIds = result.failures.map((item) => item.id); }
      try { await loadAdminCredits(); } catch (_) { showToast("作废结果已确认，列表刷新失败。请刷新列表，无需重复操作。",8000); }
    } catch (requestError) { if (error) error.textContent = apiErrorMessage(requestError,"作废未完成，请重试。"); }
    finally { button.disabled = false; }
  });

  document.querySelectorAll("[data-copy-generated-codes]").forEach((button) => {
    button.addEventListener("click", async () => {
      const dialog = button.closest("dialog");
      const codes = JSON.parse(dialog?.dataset.generatedCodes || "[]");
      if (!codes.length) return;
      try {
        await navigator.clipboard.writeText(codes.join("\n"));
        showToast(`已复制 ${codes.length} 枚完整码；显示、复制和下载不会记录“谁看过”审计。`);
      } catch {
        showToast("浏览器未允许剪贴板；完整码仍显示在交付区。");
      }
    });
  });

  document
    .querySelectorAll(
      "[data-download-generated-codes], [data-download-issued-codes]",
    )
    .forEach((button) => {
      button.addEventListener("click", () => {
        const dialog = button.closest("dialog");
        const codes = JSON.parse(dialog?.dataset.generatedCodes || "[]");
        if (!codes.length) {
          showToast("当前无可下载的完整码。");
          return;
        }
        const blob = new Blob([`${codes.join("\r\n")}\r\n`], {
          type: "text/plain;charset=utf-8",
        });
        const url = URL.createObjectURL(blob);
        const link = document.createElement("a");
        link.href = url;
        link.download = dialog.dataset.downloadFilename || "credential-codes.txt";
        document.body.append(link);
        link.click();
        link.remove();
        setTimeout(() => URL.revokeObjectURL(url), 0);
        showToast(`已下载 ${codes.length} 枚完整码；显示、复制和下载不会记录“谁看过”审计。`);
        if (dialog?.id === "issueDialog") dialog.dataset.codesCopied = "true";
      });
    });

  const managementActionDialog = document.getElementById("managementActionDialog");
  let pendingManagementAction;
  const riskManagementAttempts = new Map();
  function riskManagementRoute(row, kind) {
    const authorizationId = row.dataset.authorizationId;
    const deviceId = row.dataset.deviceId;
    if (kind === "recover") kind = "unblock";
    return kind === "revoke"
      ? `/manage/authorizations/${encodeURIComponent(authorizationId)}/revoke/`
      : `/manage/authorizations/${encodeURIComponent(authorizationId)}/devices/${encodeURIComponent(deviceId)}/${kind}/`;
  }
  function riskManagementOperationKey(row, kind) {
    return JSON.stringify([
      row.dataset.authorizationId,
      kind === "recover" ? "unblock" : kind,
      kind === "revoke" ? "" : row.dataset.riskActionDeviceUuid || row.dataset.deviceUuid,
    ]);
  }
  const managementActionCopy = {
    pause: ["暂停下游账号", "暂停后不能登录、不能发卡、兑换额度或新建授权。已有授权按软件策略继续验证。"],
    resume: ["恢复下游账号", "恢复后下游可再次登录并开展新业务。"],
    archive: ["归档对象", "归档后停止业务；已激活仍可用；只有归档对象才允许删除。"],
    delete: ["删除归档对象", "删除后保留最小脱敏墓碑与审计引用，不能恢复。已激活仍可用。"],
    reset: ["重置设备绑定", "只解除当前设备绑定，不受换机开关限制，不重置到期时间、套餐快照或收入事实。旧电脑可能还要过一会儿才停。"],
    block: ["冻结这张卡", "冻结后任何电脑都不能再激活这张卡；已占用的座位保持占用；同一电脑上的其他卡仍能用。"],
    unblock: ["解冻这张卡", "解冻后原绑定仍占用座位，旧电脑可继续验证，不必重新激活。"],
    recover: ["恢复时间阻断", "先确认服务器时间已经恢复正常。只恢复本授权由时间异常阻断的绑定，不延长到期时间；仍被封禁的物理设备不会因此恢复。"],
    revoke(row) {
      const seconds = Number(row?.dataset?.verifyIntervalSeconds || 0);
      const duration = formatVerifyRemain(seconds);
      return [
        "撤销授权",
        duration
          ? `后台立刻已撤销。电脑大约还能开 ${duration}（按现行验证间隔），等到下一次校验才停。`
          : "后台立刻已撤销。电脑大约还能开到这张卡自己的下一次校验，等到下一次校验才停。",
      ];
    },
  };

  function formatVerifyRemain(seconds) {
    const value = Number(seconds);
    if (!Number.isFinite(value) || value <= 0) return "";
    if (value >= 3600) return `${Math.max(1, Math.round(value / 3600))} 小时`;
    return `${Math.max(1, Math.round(value / 60))} 分钟`;
  }

  function setRowStatus(row, selector, text, className) {
    const status = row.querySelector(selector);
    if (!status) return;
    status.textContent = text;
    status.className = `status ${className}`;
  }

  function openManagementAction(row, kind, scope) {
    if (!managementActionDialog || !row || !managementActionCopy[kind]) return;
    pendingManagementAction = { row, kind, scope };
    const copy = managementActionCopy[kind];
    const [title, impact] = typeof copy === "function" ? copy(row) : copy;
    managementActionDialog.querySelector("[data-management-action-title]").textContent = title;
    managementActionDialog.querySelector("[data-management-action-target]").textContent =
      scope === "downstream"
        ? row.dataset.downstream || "下游账号"
        : `${row.dataset.deviceLicense || "授权设备"} · ${row.dataset.riskSoftware || "—"} · ${row.dataset.riskCustomer || "—"} · ${row.dataset.riskDeviceCode || "—"}`;
    const interval = scope === "device" && kind === "block" ? formatVerifyRemain(row.dataset.verifyIntervalSeconds) : "";
    managementActionDialog.querySelector("[data-management-action-impact]").textContent = interval
      ? `${impact} 已运行的软件约在下次验证时停用，现行验证间隔 ${interval}。` : impact;
    const inventory = managementActionDialog.querySelector("[data-management-action-inventory]");
    const reason = managementActionDialog.querySelector("textarea[name='reason']");
    const error = managementActionDialog.querySelector("[data-form-error]");
    const confirm = managementActionDialog.querySelector("[data-management-action-confirm]");
    const recovery = managementActionDialog.querySelector("[data-time-recovery-confirm]");
    if (recovery) {
      recovery.hidden = kind !== "recover";
      const check = recovery.querySelector("input");
      check.checked = false;
      check.required = kind === "recover";
    }
    if (reason) {
      reason.value = "";
      reason.readOnly = false;
    }
    if (error) error.textContent = "";
    const showsInventory = scope === "downstream" && ["pause", "archive", "delete"].includes(kind);
    if (inventory) {
      if (showsInventory) {
        const activeCount = Number(row.dataset.activeAuthorizationCount || 0);
        const unusedCount = Number(row.dataset.unusedCardCount || 0);
        const balance = Number(row.dataset.availableBalance || 0);
        inventory.textContent = `在役授权 ${activeCount} 张，未激活 ${unusedCount} 张，余额 ${balance}。`;
      } else {
        inventory.textContent = "—";
      }
    }
    if (confirm) {
      confirm.textContent = title;
      const leftover = showsInventory && ["archive", "delete"].includes(kind) && Number(row.dataset.availableBalance || 0) > 0;
      confirm.disabled = leftover;
      if (leftover && error) error.textContent = "请先把可用额度扣光，未清完不能归档或删除。";
    }
    const attempt = scope === "device" ? riskManagementAttempts.get(riskManagementOperationKey(row, kind)) : null;
    if (attempt) {
      reason.value = attempt.reason;
      reason.readOnly = true;
      if (error) error.textContent = "上次操作结果尚未确认。重试会使用原目标、原因和请求，不会新建操作。";
      if (confirm) confirm.textContent = "按原请求重试";
    }
    managementActionDialog.showModal();
  }

  const riskDetailDialog = document.getElementById("riskDetailDialog");

  function openAuthorizationRiskDetail(row) {
    if (!riskDetailDialog || !row) return;
    const values = {
      customer: row.dataset.riskCustomer || row.cells[0]?.textContent.trim() || "—",
      card: row.dataset.riskCard || "—",
      software: row.dataset.riskSoftwarePlan || row.cells[1]?.textContent.trim() || "—",
      plan: row.dataset.riskPlan || "—",
      authorization: row.dataset.riskAuthorizationLabel || row.cells[3]?.textContent.trim() || "—",
      deviceCode: row.dataset.riskDeviceCode || "—",
      deviceUuid: row.dataset.riskDeviceUuid || "—",
      device: row.dataset.riskDeviceLabel || row.cells[2]?.textContent.trim() || "—",
      risk: row.dataset.riskRiskLabel || row.cells[4]?.textContent.trim() || "—",
      ip: row.dataset.riskIp || "—",
      activated: row.dataset.riskActivated || "—",
      bound: row.dataset.riskBound || "—",
      verified: row.dataset.riskVerified || row.cells[6]?.textContent.trim() || "—",
      seen: row.dataset.riskSeen || "—",
      expires: row.dataset.riskExpires || row.cells[5]?.textContent.trim() || "—",
      renewal: row.dataset.riskRenewal || "无",
      audit: row.dataset.riskAudit || "—",
      history: row.dataset.riskHistory || "暂无绑定历史",
    };
    riskDetailDialog.querySelectorAll("[data-risk-detail]").forEach((target) => {
      target.textContent = values[target.dataset.riskDetail] || "—";
      target.style.whiteSpace = "pre-wrap";
      target.style.overflowWrap = "anywhere";
    });
    riskDetailDialog.showModal();
  }

  document.addEventListener("click", (event) => {
    const riskDetail = event.target.closest("[data-risk-detail]");
    if (riskDetail) {
      openAuthorizationRiskDetail(riskDetail.closest("[data-device-row]"));
      return;
    }
    const downstreamAction = event.target.closest("[data-management-action]");
    if (downstreamAction) {
      openManagementAction(
        downstreamAction.closest("[data-downstream-row]"),
        downstreamAction.dataset.managementAction,
        "downstream",
      );
      return;
    }
    const deviceAction = event.target.closest("[data-device-action]");
    if (deviceAction)
      openManagementAction(
        deviceAction.closest("[data-device-row]"),
        deviceAction.dataset.deviceAction,
        "device",
      );
  });

  managementActionDialog
    ?.querySelector("[data-management-action-confirm]")
    ?.addEventListener("click", () => {
      const form = managementActionDialog.querySelector("form");
      const error = managementActionDialog.querySelector("[data-form-error]");
      if (isStandaloneStaticPreview) {
        if (error) error.textContent = "静态预览不执行真实管理操作。";
        return;
      }
      if (window.__b1ApiActive && ["downstream", "device"].includes(pendingManagementAction?.scope)) return;
      if (!pendingManagementAction || !form?.checkValidity()) {
        if (error) error.textContent = "请填写至少 4 个字的可追溯原因。";
        form?.reportValidity();
        return;
      }
      const { row, kind, scope } = pendingManagementAction;
      if (scope === "downstream") {
        const actions = row.querySelector(".table-actions");
        if (kind === "pause") {
          row.dataset.downstreamState = "已暂停";
          setRowStatus(row, ".status", "已暂停", "status-warm");
          if (actions) actions.innerHTML = '<button class="text-button" type="button" data-management-action="resume">恢复</button><button class="text-button" type="button" data-management-action="archive">归档</button>';
        } else if (kind === "resume") {
          row.dataset.downstreamState = "正常";
          setRowStatus(row, ".status", "正常", "status-green");
          if (actions) actions.innerHTML = '<button class="text-button" type="button" data-management-action="pause">暂停</button><button class="text-button" type="button" data-management-action="archive">归档</button>';
        } else if (kind === "archive") {
          row.dataset.downstreamState = "已归档";
          setRowStatus(row, ".status", "已归档", "status-gray");
          if (actions) actions.innerHTML = '<button class="text-button" type="button" data-management-action="delete">删除</button>';
        } else if (kind === "delete") {
          row.dataset.downstreamState = "已删除墓碑";
          setRowStatus(row, ".status", "已删除墓碑", "status-gray");
          if (actions) actions.textContent = "脱敏墓碑保留";
        }
      } else {
        const binding = row.querySelector("[data-device-binding]");
        const authorization = row.querySelector("[data-authorization-status]");
        const actions = row.querySelector(".table-actions");
        const expiry = row.dataset.deviceExpires || "—";
        if (kind === "reset") {
          if (binding) binding.textContent = "已解除 · 等待重新激活";
          row.dataset.deviceBinding = "已解除 · 等待重新激活";
          setRowStatus(row, "[data-authorization-status]", "正常 / 等待激活", "status-warm");
          if (actions) actions.textContent = "等待客户重新激活";
          row.querySelector("[data-device-expiry]").textContent = expiry;
        } else if (kind === "block") {
          if (binding) binding.textContent = "当前绑定 · 已冻结占座";
          row.dataset.deviceBinding = "当前绑定 · 已冻结占座";
          setRowStatus(row, "[data-authorization-status]", "已阻断 / 已冻结", "status-red");
          if (actions) actions.innerHTML = '<button class="text-button" type="button" data-device-action="unblock">解冻这张卡</button><button class="text-button" type="button" data-device-action="revoke">撤销授权</button>';
        } else if (kind === "unblock") {
          if (binding) binding.textContent = "当前绑定 · 占用中";
          row.dataset.deviceBinding = "当前绑定 · 占用中";
          setRowStatus(row, "[data-authorization-status]", "正常 / 占用中", "status-green");
          if (actions) actions.innerHTML = '<button class="text-button" type="button" data-device-action="block">冻结这张卡</button><button class="text-button" type="button" data-device-action="revoke">撤销授权</button>';
        } else if (kind === "revoke") {
          if (binding) binding.textContent = "授权撤销 · 设备已失效";
          setRowStatus(row, "[data-authorization-status]", "已撤销 / 设备失效", "status-red");
          if (actions) actions.innerHTML = '<button class="text-button" type="button" data-device-action="archive">归档</button>';
        } else if (kind === "archive") {
          setRowStatus(row, "[data-authorization-status]", "已归档", "status-gray");
          if (actions) actions.innerHTML = '<button class="text-button" type="button" data-device-action="delete">删除</button>';
        } else if (kind === "delete") {
          setRowStatus(row, "[data-authorization-status]", "已删除墓碑", "status-gray");
          if (actions) actions.textContent = "脱敏墓碑保留";
        }
        if (authorization && kind === "reset") authorization.dataset.expiryPreserved = expiry;
      }
      managementActionDialog.close("success");
      showToast(`${managementActionCopy[kind][0]}已完成，原因和审计引用已记录。`);
      pendingManagementAction = undefined;
    });

  function bindDialogTriggers(root = document) {
    root.querySelectorAll("[data-dialog]").forEach((button) => {
      if (button.dataset.dialogBound) return;
      button.dataset.dialogBound = "true";
      button.addEventListener("click", () => {
      const dialog = document.getElementById(button.dataset.dialog);
      if (dialog === issueDialog && software && plan) {
        if (
          button.dataset.issueSoftware &&
          plans[button.dataset.issueSoftware]
        ) {
          software.value = button.dataset.issueSoftware;
        }
        if (issueDownstream) syncManagementIssueScope();
        else {
          renderPlans(button.dataset.issuePlan || plan.value);
          updateIssuePreview();
        }
      }
      if (dialog === softwareDialog) prepareSoftwareDialog(button);
      if (dialog === planDialog) preparePlanDialog(button);
      if (dialog === planManagerDialog) preparePlanManagerDialog(button);
      if (dialog?.id === "policyDialog") preparePolicyDialog(button);
      if (dialog?.id === "softwareUnlistDialog") prepareSoftwareUnlistDialog(button);
      if (dialog === inviteDialog) prepareInviteDialog();
      if (dialog === quotaCardDialog) prepareQuotaCardDialog();
      if (dialog === releaseDialog) {
        if (pendingUiWrites.has(dialog.__writeScope)) restoreDialogWrite(dialog);
        else { syncReleaseUploadSoftwareFromTable(); showReleaseStage("upload", 0); }
      }
      if (dialog?.id === "passwordResetDialog") preparePasswordResetDialog(button);
      if (dialog?.id === "reclaimDialog") {
        const hasTarget = Boolean(button.dataset.reclaimBatch);
        const reclaimSubmit = document.getElementById("reclaimSubmit");
        document.getElementById("reclaimBatch").textContent =
          button.dataset.reclaimBatch || "未选择";
        document.getElementById("reclaimCount").textContent =
          `${button.dataset.reclaimCount || "0"} 张`;
        document.getElementById("reclaimCredit").textContent =
          `+${button.dataset.reclaimCredit || "0"} 额度`;
        reclaimSubmit.disabled = !hasTarget;
      }
      if (dialog?.id === "adminReclaimDialog") {
        dialog.querySelector("[data-admin-reclaim-batch]").textContent =
          button.dataset.reclaimBatch || "未选择";
        dialog.querySelector("[data-admin-reclaim-count]").textContent =
          `${button.dataset.reclaimCount || "0"} 张`;
        dialog.querySelector("[data-admin-reclaim-credit]").textContent =
          `+${button.dataset.reclaimCredit || "0"} 额度`;
        dialog.querySelector("[data-admin-reclaim-downstream]").textContent =
          button.dataset.reclaimDownstream || "未选择";
      }
      if (dialog?.id === "creditAdjustDialog") fillCreditAdjustDialog();
      if (dialog?.id === "creditRecoverDeletedDialog") fillCreditRecoverDeletedDialog(quotaAccountsCache);
      if (dialog?.showModal) dialog.showModal();
      });
    });
  }
  bindDialogTriggers();

  document.querySelector("[data-admin-ledger-prev]")?.addEventListener("click", () => {
    adminLedgerPage = Math.max(1, adminLedgerPage - 1);
    loadAdminCredits(quotaCardsPage).catch((error) => showToast(apiErrorMessage(error, "额度流水分页读取失败，请重试。")));
  });
  document.querySelector("[data-admin-ledger-next]")?.addEventListener("click", () => {
    adminLedgerPage += 1;
    loadAdminCredits(quotaCardsPage).catch((error) => showToast(apiErrorMessage(error, "额度流水分页读取失败，请重试。")));
  });
  document.querySelector("[data-downstream-ledger-prev]")?.addEventListener("click", () => {
    loadDownstreamCredits(Math.max(1, downstreamLedgerPage - 1)).catch((error) => showToast(apiErrorMessage(error, "额度流水分页读取失败，请重试。")));
  });
  document.querySelector("[data-downstream-ledger-next]")?.addEventListener("click", () => {
    loadDownstreamCredits(downstreamLedgerPage + 1).catch((error) => showToast(apiErrorMessage(error, "额度流水分页读取失败，请重试。")));
  });
  bindDebouncedSearch(document.querySelector("[data-admin-ledger-search]"), () => {
    adminLedgerPage = 1;
    loadAdminCredits(quotaCardsPage).catch((error) => showToast(apiErrorMessage(error, "额度流水搜索失败，请重试。")));
  });
  bindDebouncedSearch(document.querySelector("[data-downstream-ledger-search]"), () => {
    loadDownstreamCredits(1).catch((error) => showToast(apiErrorMessage(error, "额度流水搜索失败，请重试。")));
  });

  document.querySelector("[data-credit-adjust-confirm]")?.addEventListener("click", async (event) => {
    const dialog = document.getElementById("creditAdjustDialog");
    const form = dialog?.querySelector("form");
    const error = form?.querySelector("[data-form-error]");
    if (!form) return;
    if (isStandaloneStaticPreview) {
      if (error) error.textContent = "静态预览不执行真实额度调整。";
      return;
    }
    if (!form.checkValidity()) {
      if (error) error.textContent = "请选择下游并填写数量和可追溯原因。";
      form.reportValidity();
      return;
    }
    const adjustmentType = form.elements.adjustment_type.value;
    const amount = Number(form.elements.amount.value);
    const typeControl = form.elements.adjustment_type;
    const previousTypeDisabled = typeControl.disabled;
    typeControl.disabled = true;
    const button = event.currentTarget;
    button.disabled = true;
    if (error) error.textContent = "";
    try {
      await apiRequest("/manage/credits/adjust/", {
        method: "POST",
        headers: {
          "Idempotency-Key":
            dialog.dataset.adjustKey ||
            (dialog.dataset.adjustKey = requestIdempotencyKey("credit-adjust")),
        },
        body: JSON.stringify({
          downstream_public_id: form.elements.downstream.value,
          adjustment_type: adjustmentType,
          amount,
          reason: form.elements.reason.value.trim(),
        }),
      });
      dialog.dataset.adjustKey = "";
      dialog.close("success");
      showToast(adjustmentType === "credit" ? "已增加下游额度。" : "已扣回下游额度。");
      await loadAdminCredits();
    } catch (requestError) {
      if (!(requestError instanceof ApiRequestError && requestError.status)) {
        if (error) error.textContent = "可能已经入账，请先看额度流水确认，不要换数字再点。";
      } else if (error) {
        error.textContent = apiErrorMessage(requestError, "额度调整失败，请重试。");
      }
    } finally {
      typeControl.disabled = previousTypeDisabled;
      button.disabled = false;
    }
  });

  document.querySelector("[data-credit-recover-deleted-confirm]")?.addEventListener("click", async (event) => {
    const dialog = document.getElementById("creditRecoverDeletedDialog");
    const form = dialog?.querySelector("form");
    const error = form?.querySelector("[data-form-error]");
    if (!form) return;
    if (isStandaloneStaticPreview) {
      if (error) error.textContent = "静态预览不执行真实扣回。";
      return;
    }
    if (!form.checkValidity()) {
      if (error) error.textContent = "请选择已删除下游并填写数量和原因。";
      form.reportValidity();
      return;
    }
    const recoverButton = event.currentTarget;
    recoverButton.disabled = true;
    if (error) error.textContent = "";
    try {
      await apiRequest("/manage/credits/recover-deleted/", {
        method: "POST",
        headers: {
          "Idempotency-Key":
            dialog.dataset.recoverKey ||
            (dialog.dataset.recoverKey = requestIdempotencyKey("credit-recover-deleted")),
        },
        body: JSON.stringify({
          downstream_public_id: form.elements.downstream_public_id.value,
          amount: Number(form.elements.amount.value),
          reason: form.elements.reason.value.trim(),
        }),
      });
      dialog.dataset.recoverKey = "";
      dialog.close("success");
      showToast("已扣回已删除下游的剩余额度。");
      await loadAdminCredits();
    } catch (requestError) {
      if (error) error.textContent = apiErrorMessage(requestError, "扣回失败，请重试。");
    } finally {
      recoverButton.disabled = false;
    }
  });

  let pendingSoftwareUnlist;
  function prepareSoftwareUnlistDialog(button) {
    const dialog = document.getElementById("softwareUnlistDialog");
    if (!dialog) return;
    pendingSoftwareUnlist = {
      softwareId: button.dataset.softwareUnlistId || "",
      name: button.dataset.softwareUnlistName || "",
      status: button.dataset.softwareStatusTarget || "archived",
      key: requestIdempotencyKey("catalog-software-status"),
    };
    const restoring = pendingSoftwareUnlist.status === "active";
    dialog.querySelector("#softwareUnlistDialogTitle").textContent = restoring ? "重新上架这个软件？" : "下架这个软件？";
    dialog.querySelector("[data-software-status-impact]").textContent = restoring
      ? "恢复软件发行。下架时关闭的下游经营范围不会自动恢复，请在经营范围中重新开放。"
      : "停新发、未激活不能开通、已激活用到过期。不会立刻掐掉在线用户。";
    const confirm = dialog.querySelector("[data-software-unlist-confirm]");
    confirm.textContent = restoring ? "确认上架" : "确认下架";
    confirm.className = restoring ? "button button-primary" : "button button-danger";
    dialog.querySelector("[data-software-unlist-name]").textContent = pendingSoftwareUnlist.name || "当前软件";
    const reason = dialog.querySelector("textarea[name='reason']");
    if (reason) reason.value = "";
    const error = dialog.querySelector("[data-software-unlist-error]");
    if (error) error.textContent = "";
  }

  document.querySelector("[data-software-unlist-confirm]")?.addEventListener("click", async (event) => {
    const dialog = document.getElementById("softwareUnlistDialog");
    if (!dialog || !pendingSoftwareUnlist?.softwareId) return;
    const form = dialog.querySelector("form");
    const error = dialog.querySelector("[data-software-unlist-error]");
    const reason = form?.elements.reason?.value.trim() || "";
    if (!form?.checkValidity() || reason.length < 4) {
      if (error) error.textContent = "请填写至少 4 个字的可追溯原因。";
      form?.reportValidity();
      return;
    }
    const confirm = event.currentTarget;
    confirm.disabled = true;
    if (error) error.textContent = "";
    const request = pendingSoftwareUnlist;
    try {
      if (isStandaloneStaticPreview) {
        if (error) error.textContent = "静态预览不修改真实软件目录。";
        confirm.disabled = false;
        return;
      }
      const body = JSON.stringify({ status: request.status, reason });
      if (request.body && request.body !== body) {
        error.textContent = "上次操作结果还未确认，请先重试原操作原因。";
        form.elements.reason.value = JSON.parse(request.body).reason;
        return;
      }
      request.body = body;
      await apiRequest(`/manage/catalog/software/${encodeURIComponent(request.softwareId)}/status/`, {
        method: "POST",
        headers: { "Idempotency-Key": request.key },
        body: request.body,
      });
    } catch (requestError) {
      if (error) error.textContent = apiErrorMessage(requestError, "操作结果尚未确认，请重试。");
      if (requestError.status >= 400 && requestError.status < 500 && !requestError.retryable) request.body = "";
      confirm.disabled = false;
      return;
    } finally {
      confirm.disabled = false;
    }
    const restored = request.status === "active";
    dialog.close("success");
    pendingSoftwareUnlist = undefined;
    try {
      await loadCatalog();
      showToast(restored ? "软件已重新上架；请按需重新开放下游经营范围。" : "软件已下架：停新发、未激活不能开通、已激活用到过期。");
    } catch {
      showToast(restored ? "软件已重新上架，列表刷新失败，请刷新页面查看并重新开放所需经营范围。" : "软件已下架，列表刷新失败，请刷新页面查看。");
    }
  });

  const pendingPolicySubmissions = new Map();
  function fillPolicySubmission(dialog, body, locked = false) {
    dialog.querySelector("#policyMaxDevices").value = String(body.max_devices);
    dialog.querySelector("#policyVerifyInterval").value = String(body.verify_interval_seconds / 60);
    dialog.querySelector("#policyOfflineGrace").value = String(body.offline_grace_seconds / 3600);
    dialog.querySelector("#policySwitchLimit").value = String(body.device_switch_limit);
    dialog.querySelector("#policyAllowSwitch").checked = body.allow_device_switch;
    dialog.querySelector("#policyProofRequired").checked = body.device_proof_required;
    dialog.querySelectorAll("input").forEach((input) => { input.disabled = locked; });
    dialog.querySelector("[data-policy-save]").textContent = locked ? "重试保存" : "保存授权参数";
  }

  function preparePolicyDialog(button) {
    const dialog = document.getElementById("policyDialog");
    if (!dialog) return;
    const softwareId = button.dataset.policySoftware || "";
    const profileId = button.dataset.policyProfile || "";
    const softwareItem = catalogItems.find((item) => String(item.software_id) === softwareId);
    const profile = softwareItem?.profiles?.find((item) => String(item.profile_id) === profileId) || softwareItem?.profiles?.[0];
    const policy = profile?.policies?.find((item) => item.status === "active") || profile?.policies?.[0];
    dialog.dataset.policySoftware = softwareId;
    dialog.dataset.policyProfile = profile?.profile_id || profileId;
    dialog.querySelector("[data-policy-context]").textContent = `${softwareItem?.name || softwareId} / Profile ${profile?.profile_id || profileId} · 当前 ${policy?.version || "未配置"}`;
    dialog.querySelector("#policyMaxDevices").value = String(policy?.max_devices || 1);
    dialog.querySelector("#policyVerifyInterval").value = String(Math.max(1, Math.ceil(Number(policy?.verify_interval_seconds || 60) / 60)));
    dialog.querySelector("#policyOfflineGrace").value = String(Math.floor(Number(policy?.offline_grace_seconds || 0) / 3600));
    dialog.querySelector("#policySwitchLimit").value = String(policy?.device_switch_limit || 0);
    dialog.querySelector("#policyAllowSwitch").checked = Boolean(policy?.allow_device_switch);
    dialog.querySelector("#policyProofRequired").checked = policy?.device_proof_required !== false;
    const pending = pendingPolicySubmissions.get(`${softwareId}:${dialog.dataset.policyProfile}`);
    dialog.querySelectorAll("input").forEach((input) => { input.disabled = Boolean(pending); });
    dialog.querySelector("[data-policy-save]").textContent = pending ? "重试保存" : "保存授权参数";
    if (pending) fillPolicySubmission(dialog, JSON.parse(pending.body), true);
    dialog.querySelector("[data-policy-error]").textContent = pending ? "上次保存结果还未确认，请重试保存上次参数。" : "";
  }

  document
    .getElementById("policyDialog")
    ?.querySelector("[data-policy-save]")
    ?.addEventListener("click", async (event) => {
      const dialog = document.getElementById("policyDialog");
      const error = dialog.querySelector("[data-policy-error]");
      const maxDevices = Number(dialog.querySelector("#policyMaxDevices").value);
      const verifyIntervalMinutes = Number(dialog.querySelector("#policyVerifyInterval").value);
      const offlineGraceHours = Number(dialog.querySelector("#policyOfflineGrace").value);
      const allowDeviceSwitch = dialog.querySelector("#policyAllowSwitch").checked;
      const deviceSwitchLimit = Number(dialog.querySelector("#policySwitchLimit").value);
      if (!Number.isInteger(maxDevices) || maxDevices < 1 || !Number.isInteger(verifyIntervalMinutes) || verifyIntervalMinutes < 1 || !Number.isInteger(offlineGraceHours) || offlineGraceHours < 0 || !Number.isInteger(deviceSwitchLimit) || deviceSwitchLimit < 0 || (allowDeviceSwitch && deviceSwitchLimit < 1) || (!allowDeviceSwitch && deviceSwitchLimit !== 0)) {
        error.textContent = allowDeviceSwitch ? "请填写有效参数；允许换机时次数至少为 1。" : "请填写有效参数；不允许换机时换机次数必须为 0。";
        return;
      }
      const button = event.currentTarget;
      button.disabled = true;
      error.textContent = "";
      const softwareId = dialog.dataset.policySoftware || "";
      const profileId = dialog.dataset.policyProfile || "";
      const body = {
        max_devices: maxDevices,
        allow_device_switch: allowDeviceSwitch,
        device_switch_limit: deviceSwitchLimit,
        device_proof_required: dialog.querySelector("#policyProofRequired").checked,
        verify_interval_seconds: verifyIntervalMinutes * 60,
        offline_grace_seconds: offlineGraceHours * 3600,
      };
      const target = `${softwareId}:${profileId}`;
      if (isStandaloneStaticPreview) {
        error.textContent = "静态预览不修改真实授权策略。";
        button.disabled = false;
        return;
      }
      let submission = pendingPolicySubmissions.get(target);
      const serialized = JSON.stringify(body);
      if (submission && submission.body !== serialized) {
        fillPolicySubmission(dialog, JSON.parse(submission.body), true);
        error.textContent = "上次保存结果还未确认，请先重试保存上次参数。";
        button.disabled = false;
        return;
      }
      if (!submission) {
        submission = { key: requestIdempotencyKey("policy-revise"), body: serialized };
        pendingPolicySubmissions.set(target, submission);
      }
      fillPolicySubmission(dialog, body, true);
      try {
        await apiRequest(`/manage/catalog/software/${encodeURIComponent(softwareId)}/profiles/${encodeURIComponent(profileId)}/policy/revise/`, {
          method: "POST",
          headers: { "Idempotency-Key": submission.key },
          body: submission.body,
        });
      } catch (requestError) {
        if (requestError.status >= 400 && requestError.status < 500 && !requestError.retryable) {
          pendingPolicySubmissions.delete(target);
          fillPolicySubmission(dialog, body, false);
        }
        error.textContent = apiErrorMessage(requestError, "保存结果尚未确认，请重试保存上次参数。");
        button.disabled = false;
        return;
      }
      pendingPolicySubmissions.delete(target);
      fillPolicySubmission(dialog, body, false);
      button.disabled = false;
      dialog.close("success");
      try {
        await loadCatalog();
        showToast("授权参数已保存，并生成新的策略版本。已售跟着变：满员挤机开关、每日次数、验证间隔。已售不跟：最大设备数、断网宽限、设备证明。");
      } catch {
        showToast("授权参数已保存，列表刷新失败，请刷新页面查看；不必再次保存。");
      }
    });

  function preparePasswordResetDialog(button) {
    const dialog = document.getElementById("passwordResetDialog");
    if (!dialog) return;
    dialog.dataset.publicId = button.dataset.publicId || "";
    dialog.dataset.resetUsername = button.dataset.resetUsername || "";
    const target = dialog.querySelector("[data-password-reset-target]");
    if (target) target.textContent = button.dataset.resetUsername || "待读取账号";
    const form = dialog.querySelector("[data-password-reset-form]");
    form?.reset();
    setFormError(form, "");
  }

  if (software && plan) {
    if (issueDownstream) syncManagementIssueScope();
    else {
      renderPlans(plan.value);
      updateIssuePreview();
    }
  }

  function formatApiDate(value) {
    if (!value) return "—";
    const date = new Date(value);
    if (Number.isNaN(date.getTime())) return "—";
    const parts = new Intl.DateTimeFormat("en-GB", {
      timeZone: "Asia/Shanghai",
      year: "numeric",
      month: "2-digit",
      day: "2-digit",
      hour: "2-digit",
      minute: "2-digit",
      hour12: false,
    }).formatToParts(date);
    const pick = (type) => parts.find((part) => part.type === type)?.value || "";
    const year = pick("year");
    const month = pick("month");
    const day = pick("day");
    const hour = pick("hour");
    const minute = pick("minute");
    if (!year || !month || !day) return "—";
    return `${year}-${month}-${day} ${hour}:${minute}`;
  }

  const AUDIT_ACTION_COPY = {
    "auth.login": "登录",
    "auth.logout": "退出",
    "admin.access": "访问管理端",
    "downstream.register": "下游注册",
    "downstream.archive": "归档下游",
    "authorization.signing_key.export": "导出验签公钥",
    "authorization.activate": "激活授权",
    "authorization.verify": "验证授权",
    "authorization.export": "导出授权摘要",
    "license.activate": "激活授权",
    "license.verify": "验证授权",
    "license_card.search": "精确查找卡密",
    "license_card.reveal": "查看完整卡密",
    "license_card.reclaim": "回收未激活卡",
    "license_card.reclaim_preview": "预览回收",
    "license_card.export": "导出卡密摘要",
    "license_card.issue": "生成授权卡",
    "license_batch.issue": "生成授权卡",
    "license_batch.preview": "预览发卡",
    "license_batch.export": "导出卡密批次",
    "device.reset": "重置设备绑定",
    "quota_card.reveal": "查看完整兑换码",
    "quota_card.issue": "生成额度兑换码",
    "quota_card.redeem": "兑换额度",
    "quota_card.revoke": "作废额度码",
    "quota.settings.update": "保存购卡链接",
    "quota.manual_credit": "调整下游额度",
    "quota.admin_recovery": "扣回已删除下游余额",
    "quota.debit": "扣额度",
    "release.upload": "上传版本",
    "release.publish": "发布版本",
    "release.publish_link": "发布网盘更新",
    "release.update_link": "修改网盘地址",
    "release.withdraw": "撤回版本",
    "release.discard": "丢弃草稿",
    "release.package.delete": "删除安装包",
    "storage.cleanup": "清理可删文件",
    "audit.query": "查看审计",
    "audit.export": "导出审计",
    "backup.download.delete": "删除加密备份",
  };

  const AUDIT_ACTION_HUMAN_COPY = {
    "auth.login": "登录系统",
    "auth.logout": "退出登录",
    "admin.access": "访问管理后台",
    "downstream.register": "下游自主注册账号",
    "downstream.archive": "归档下游账号",
    "authorization.signing_key.export": "导出客户端验签公钥证书",
    "authorization.activate": "客户端激活授权卡密",
    "authorization.verify": "客户端验证授权心跳",
    "authorization.export": "导出授权清单",
    "license.activate": "客户端激活授权卡密",
    "license.verify": "客户端验证授权心跳",
    "license_card.search": "精准查询授权卡密",
    "license_card.reveal": "查看并复制卡密明文",
    "license_card.reclaim": "回收未激活卡密退额度",
    "license_card.reclaim_preview": "预览回收卡密影响",
    "license_card.export": "导出卡密清单",
    "license_card.issue": "生成授权卡密",
    "license_batch.issue": "批量生成授权卡密",
    "license_batch.preview": "预览生成卡密",
    "license_batch.export": "导出卡密批次数据",
    "device.reset": "重置设备绑定（解除硬件绑定）",
    "quota_card.reveal": "查看额度兑换码明文",
    "quota_card.issue": "生成额度兑换码",
    "quota_card.redeem": "使用兑换码充值额度",
    "quota_card.revoke": "作废未消费的额度兑换码",
    "quota.settings.update": "更新下游购卡链接",
    "quota.manual_credit": "划拨/调整下游可用额度",
    "quota.admin_recovery": "扣回已清理账号额度",
    "quota.debit": "下游消费扣除额度",
    "release.upload": "上传新版本客户端安装包",
    "release.publish": "正式发布软件客户端版本",
    "release.publish_link": "发布网盘更新地址",
    "release.update_link": "修改已发布版本的网盘地址",
    "release.withdraw": "撤回已发布的客户端版本",
    "release.discard": "丢弃版本草稿",
    "release.package.delete": "删除版本安装包文件",
    "storage.cleanup": "执行临时文件安全清理",
    "audit.query": "检索审计操作日志",
    "audit.export": "导出审计操作日志",
    "backup.download.delete": "删除本地加密备份",
    "downstream.create_direct": "开通新下游代理商账号",
    "downstream.configuration.update": "调整下游软件经营配置",
    "downstream.software_access.set": "分配下游经营软件范围",
    "policy_version.revise": "修改软件授权策略（换机/设备数）",
    "policy_version.create": "新建软件授权策略",
    "plan.create": "新建授权卡密套餐",
    "software.create": "登记创建新软件",
    "software_profile.create": "登记新接入Profile",
  };

  const AUDIT_REASON_HUMAN = {
    DEVICE_KEY_MISMATCH: "设备密钥不匹配",
    DEVICE_NOT_BOUND: "该卡密未绑定该设备",
    RISK_BLOCKED: "该设备已被系统封禁",
    CARD_FROZEN: "该卡密已被冻结",
    DEVICE_LIMIT_REACHED: "达到最大设备数限制",
    DEVICE_SWITCH_LIMIT_REACHED: "已达每日换机次数上限",
    TIME_ROLLBACK_DETECTED: "服务端可信时间回退",
    INVALID_REQUEST: "请求参数或签名无效",
    CARD_EXPIRED: "卡密已过期",
    SIGNING_KEY_UNAVAILABLE: "验签密钥不可用",
    FORBIDDEN: "权限不足或已被拒绝",
    RATE_LIMITED: "操作过于频繁被限速",
  };

  function auditMetadataMap(item) {
    const map = {};
    if (Array.isArray(item?.metadata)) {
      item.metadata.forEach((entry) => {
        if (entry?.label && entry?.value !== undefined) {
          map[entry.label] = String(entry.value).trim();
        }
      });
    } else if (typeof item?.metadata === "object" && item.metadata !== null) {
      Object.entries(item.metadata).forEach(([k, v]) => {
        map[k] = String(v).trim();
      });
    }
    return map;
  }

  function auditHumanAction(item) {
    const action = item?.action || "";
    const role = item?.actor_role || "";
    const outcome = item?.outcome || "";
    const isFailure = outcome === "failure" || outcome === "失败";
    const meta = auditMetadataMap(item);
    const quantity = meta["数量"] || meta["套餐数量"] || meta["卡密数量"] || meta["quantity"] || "";
    const amount = meta["额度"] || meta["面值"] || meta["amount"] || "";
    const quotaCost = meta["额度成本"] || meta["quota_cost"] || "";
    const rawReason = item?.reason_code || meta["原因"] || meta["reason_code"] || "";
    const friendlyReason = AUDIT_REASON_HUMAN[rawReason] || rawReason;
    const deviceCode = meta["客户端设备码"] || meta["installation_id"] || (item?.actor_label && String(item.actor_label).startsWith("GS-") ? item.actor_label : "");

    // 1. 登录与会话拦截
    if (action === "admin.access" && isFailure) {
      return "越权访问拦截（无权访问管理后台）";
    }
    if (action === "auth.login") {
      if (isFailure) return "账号登录失败（密码或账号错误）";
      if (role.includes("管理") || role === "platform_admin") return "管理员登录管理后台";
      if (role.includes("下游") || role === "downstream") return "下游账号登录工作台";
      return "登录系统控制台";
    }
    if (action === "auth.logout") {
      if (role.includes("管理") || role === "platform_admin") return "退出管理后台登录";
      if (role.includes("下游") || role === "downstream") return "下游账号退出登录";
      return "安全退出登录";
    }

    // 2. 卡密生成（数量与消耗额度）
    if (action === "license_batch.issue" || action === "license_card.issue") {
      if (quantity) {
        const costStr = quotaCost ? `，消耗 ${quotaCost} 额度` : "";
        return `批量生成 ${quantity} 张卡密${costStr}`;
      }
      return "批量生成授权卡密";
    }

    // 3. 额度兑换与充值
    if (action === "quota_card.redeem") {
      if (amount) return `使用兑换码成功充值 ${amount} 额度`;
      return "兑换额度码充值";
    }

    // 4. 额度划拨与调整
    if (action === "quota.manual_credit") {
      if (amount) {
        const dir = meta["方向"] || "";
        const actionWord = dir.includes("扣") ? "扣减" : "划拨增加";
        return `${actionWord}下游 ${amount} 额度`;
      }
      return "划拨/调整下游可用额度";
    }

    // 5. 卡密回收与退额
    if (action === "license_card.reclaim") {
      const qStr = quantity ? `${quantity} 张` : "";
      const refundStr = amount ? `，退回 ${amount} 额度` : "";
      return `回收未激活卡密${qStr}${refundStr}`;
    }

    // 6. 设备激活
    if (action === "authorization.activate" || action === "license.activate") {
      if (isFailure) {
        const devPrefix = deviceCode ? `设备 ${deviceCode} ` : "";
        return `${devPrefix}激活卡密失败（${friendlyReason || "卡密无效"}）`;
      }
      const devPrefix = deviceCode ? `设备 ${deviceCode} ` : "";
      return `${devPrefix}成功激活授权卡密`;
    }

    // 7. 设备心跳验证
    if (action === "authorization.verify" || action === "license.verify") {
      if (isFailure) return "客户端心跳验证失败（授权无效或过期）";
      return "客户端授权心跳验证通过";
    }

    // 8. 重置设备与换绑
    if (action === "device.reset") {
      const devStr = deviceCode ? `（原设备 ${deviceCode}）` : "";
      return `重置设备绑定${devStr}，解除硬件锁定`;
    }

    // 9. 额度码生成与作废
    if (action === "quota_card.issue") {
      if (amount) return `生成面额 ${amount} 额度兑换码`;
      return "生成额度兑换码";
    }
    if (action === "quota_card.revoke") {
      return "作废未消费的额度兑换码";
    }

    // 10. 策略调整与开户
    if (action === "policy_version.revise" || action === "policy_version.create") {
      return "更新软件授权策略（设备上限/离线宽限）";
    }
    if (action === "downstream.create_direct") {
      return "直接开通新下游代理账号";
    }
    if (action === "downstream.software_access.set") {
      return "调整下游可经营的软件授权范围";
    }

    return AUDIT_ACTION_HUMAN_COPY[action] || AUDIT_ACTION_COPY[action] || action || "业务操作";
  }

  function auditHumanObject(item) {
    const rawLabel = String(item?.object_label || "").trim();
    const rawSummary = String(item?.object_summary || "").trim();
    const objType = String(item?.object_type || "").trim();
    const action = item?.action || "";
    const meta = auditMetadataMap(item);
    const quantity = meta["数量"] || meta["套餐数量"] || meta["卡密数量"] || meta["quantity"] || "";
    const softwareId = meta["软件 ID"] || meta["software_id"] || "";
    const deviceCode = meta["客户端设备码"] || meta["installation_id"] || "";

    if (["auth.login", "auth.logout", "admin.access"].includes(action)) {
      return "控制台系统会话";
    }
    if (action === "authorization.signing_key.export" || objType === "AuthorizationSigningKey") {
      return "平台验签公钥证书";
    }
    if (objType === "LicenseCardBatch" || action === "license_batch.issue") {
      const batchParts = [];
      if (softwareId) batchParts.push(softwareId);
      if (quantity) batchParts.push(`${quantity}张`);
      return batchParts.length ? `卡密批次 (${batchParts.join(" · ")})` : "授权卡密批次";
    }
    if (action.startsWith("authorization.") || action.startsWith("license.")) {
      const parts = [];
      if (rawLabel && !["无对象引用", "无关联对象", "—", "未匹配下游"].includes(rawLabel)) {
        parts.push(`下游: ${rawLabel}`);
      }
      if (softwareId) parts.push(softwareId);
      if (deviceCode) parts.push(deviceCode);
      return parts.length ? parts.join(" · ") : (rawLabel || "授权卡密与设备");
    }
    if (objType === "DownstreamProfile" || action.startsWith("downstream.")) {
      return rawLabel && rawLabel !== "—" ? `下游: ${rawLabel}` : (item?.actor_label || "下游账号");
    }
    if (objType === "Device" || objType === "DeviceKey" || action === "device.reset") {
      return deviceCode ? `设备码 ${deviceCode}` : (rawLabel && rawLabel !== "—" ? rawLabel : "客户端硬件设备");
    }
    if (rawLabel && !["无对象引用", "无关联对象", "—", "未匹配下游"].includes(rawLabel)) {
      return rawLabel;
    }
    if (rawSummary && !["无对象引用", "无关联对象", "—", "客户端授权请求"].includes(rawSummary)) {
      return rawSummary;
    }
    return "系统公共业务";
  }

  function auditActionLabel(action) {
    return AUDIT_ACTION_COPY[action] || action || "—";
  }

  function auditObjectLabel(summary) {
    if (!summary || summary === "—") return "—";
    if (summary === "无对象引用") return "无关联对象";
    if (summary === "已保留对象引用") return "仅保留对象引用";
    return summary;
  }

  function auditObjectDetail(item) {
    const label = auditObjectLabel(item?.object_label || item?.object_summary);
    const summary = auditObjectLabel(item?.object_summary);
    const technical = [item?.object_type, item?.object_public_id]
      .filter((value) => value && value !== "—")
      .join(" · ");
    const parts = [label];
    if (summary && summary !== "—" && summary !== label) parts.push(summary);
    if (technical) parts.push(technical);
    return [...new Set(parts.filter(Boolean))].join("\n");
  }

  function auditActorLabel(label, { downstream = false } = {}) {
    if (downstream && label === "当前下游") return "本账号";
    return label || "—";
  }

  function bindDebouncedSearch(input, onSearch) {
    if (!input || input.dataset.fuzzyBound === "true") return;
    input.dataset.fuzzyBound = "true";
    let timer = 0;
    const run = () => onSearch(input.value.trim());
    input.addEventListener("keydown", (event) => {
      if (event.key === "Enter") {
        event.preventDefault();
        window.clearTimeout(timer);
        run();
      }
    });
    input.addEventListener("input", () => {
      window.clearTimeout(timer);
      timer = window.setTimeout(run, 350);
    });
  }

  const downstreamStatusCopy = {
    active: ["正常", "status-green"],
    suspended: ["已暂停", "status-warm"],
    closed: ["已归档", "status-gray"],
  };

  function appendDownstreamAction(actions, label, kind) {
    const btnKind = kind === "delete" ? "danger" : kind === "pause" ? "reset" : kind === "resume" ? "unfreeze" : "detail";
    const button = createTableButton(label, { kind: btnKind });
    button.dataset.managementAction = kind;
    actions.append(button);
  }

  const invitationStatusCopy = {
    issued: ["未使用", "status-green"],
    consumed: ["已使用", "status-gray"],
    revoked: ["已撤销", "status-red"],
    expired: ["已过期", "status-gray"],
    archived: ["已归档", "status-gray"],
  };
  let invitationPage = 1;

  function setInvitationServerPagination(pagination = {}) {
    document.querySelectorAll("[data-invitation-server-pagination]").forEach((controls) => {
      controls.hidden = isStandaloneStaticPreview || !pagination || Number(pagination.total_pages || 0) <= 1;
      controls.querySelector("[data-invitation-server-prev]").disabled = !pagination.has_previous;
      controls.querySelector("[data-invitation-server-next]").disabled = !pagination.has_next;
      controls.querySelector("[data-invitation-server-page]").textContent = formatServerPageLabel(pagination);
    });
  }

  function bindInvitationServerPagination() {
    document.querySelectorAll("[data-invitation-server-prev]").forEach((button) => {
      if (button.dataset.bound) return;
      button.dataset.bound = "true";
      button.addEventListener("click", () => {
        if (hasCredentialSearchOverlay("invitations")) {
          credentialSearchOverlayToast("再翻页");
          return;
        }
        loadInvitations(Math.max(1, invitationPage - 1)).catch((error) => showToast(apiErrorMessage(error, "邀请码分页读取失败，请重试。")));
      });
    });
    document.querySelectorAll("[data-invitation-server-next]").forEach((button) => {
      if (button.dataset.bound) return;
      button.dataset.bound = "true";
      button.addEventListener("click", () => {
        if (hasCredentialSearchOverlay("invitations")) {
          credentialSearchOverlayToast("再翻页");
          return;
        }
        loadInvitations(invitationPage + 1).catch((error) => showToast(apiErrorMessage(error, "邀请码分页读取失败，请重试。")));
      });
    });
  }

  function renderInvitationRows(items, { serverSearch = false } = {}) {
    const body = document.querySelector("[data-invite-item-table]");
    if (!body) return;
    body.replaceChildren();
    items.forEach((item) => {
      const row = document.createElement("tr");
      const code = item.code || "";
      const masked = item.masked_code || (code ? maskCredential(code) : "");
      const suffix = item.code_suffix || (code ? code.slice(-4) : "");
      const [statusLabel, statusClass] = invitationStatusCopy[item.status] || [item.status, "status-gray"];
      row.dataset.publicId = item.public_id || "";
      row.dataset.searchValue = `${masked} ${suffix} ${item.public_id || ""}`.trim();
      row.dataset.credentialType = "邀请码";
      row.dataset.codeSuffix = suffix;
      if (serverSearch) row.dataset.serverSearchMatch = "true";
      row.dataset.codeAvailable = "true";
      row.dataset.codeStatus = statusLabel;
      row.dataset.codeDownstream = item.consumed_username || (item.status === "consumed" ? "已注册" : "尚未注册");
      row.dataset.codeActivity = formatApiDate(item.consumed_at);
      row.dataset.codeExpires = item.expires_at ? formatApiDate(item.expires_at) : item.status === "issued" ? "永久有效" : "已结束";
      const selectCell = document.createElement("td");
      if (document.body.classList.contains("role-admin")) {
        const checkbox = document.createElement("input");
        checkbox.type = "checkbox";
        checkbox.dataset.reclaimSelect = "";
        checkbox.dataset.cardStatus = item.status || "";
        checkbox.dataset.cardId = item.public_id || "";
        checkbox.setAttribute(
          "aria-label",
          `选择邀请码 ${String(item.public_id).slice(-4)}`,
        );
        selectCell.append(checkbox);
      }
      row.append(selectCell);
      appendTextCell(row, masked || (suffix ? `••••-••••-${suffix}` : "—"), "mono");
      appendStatusCell(row, statusLabel, statusClass);
      appendTextCell(row, item.consumed_username || (item.status === "consumed" ? "已注册" : "—"));
      appendTextCell(row, item.consumed_at ? formatApiDate(item.consumed_at) : "尚未使用", "mono");
      const action = appendActionCell(row, "查看完整详情");
      action.dataset.credentialDetail = "";
      body.append(row);
    });
    const panel = body.closest(".table-panel");
    if (panel) panel.dataset.serverDataLoaded = "true";
    setCredentialSearchOverlay("invitations", Boolean(serverSearch));
    syncRecordSelection(body.closest(".table-panel"));
    window.__previewRefreshTables?.();
  }

  function openInvitationRevokeDialog(ids) {
    const dialog = document.getElementById("invitationRevokeDialog");
    if (!dialog || resumeDialogWrite(dialog,"invitations:revoke")) return;
    if (!ids.length) { showToast("请先选择未使用的邀请码。"); return; }
    prepareDialogWrite(dialog,"invitations:revoke",ids); restoreDialogWrite(dialog);
    dialog.querySelector("[data-invitation-revoke-target]").textContent = `已选 ${ids.length} 枚未使用邀请码`;
    const form = dialog.querySelector("form"); if (form?.elements.reason) form.elements.reason.value = "";
    const error = dialog.querySelector("[data-form-error]"); if (error) error.textContent = "";
    dialog.showModal();
  }
  document.querySelector("[data-invitation-revoke-selected]")?.addEventListener("click", () => {
    const panel = document.querySelector('[data-record-view-scope="invitations"] .table-panel');
    openInvitationRevokeDialog(selectedRecordBoxes(panel).filter((box) => box.dataset.cardStatus === "issued").map((box) => box.dataset.cardId));
  });
  document.querySelector("[data-invitation-revoke-confirm]")?.addEventListener("click", async (event) => {
    const dialog = document.getElementById("invitationRevokeDialog"), form = dialog?.querySelector("form");
    const error = form?.querySelector("[data-form-error]"), reason = form?.elements.reason?.value.trim() || "";
    if (isStandaloneStaticPreview && !window.__b1ApiActive) { if (error) error.textContent = "静态预览不执行真实作废。"; return; }
    if (!dialog.__selectedIds?.length || !form?.checkValidity() || reason.length < 2) { if (error) error.textContent = "请填写至少 2 个字的作废原因。"; return; }
    const button = event.currentTarget; button.disabled = true; if (error) error.textContent = "";
    try {
      const result = await submitRecordRevocations(dialog,(publicId) => `/manage/invitations/${encodeURIComponent(publicId)}/revoke/`,reason);
      if (!result.failures.length) { dialog.close("success"); showToast(`已作废 ${result.succeeded.length} 枚邀请码。`); }
      else { if (error) error.textContent = `已作废 ${result.succeeded.length} 枚，${result.failures.length} 枚被拒绝：${result.failures.map((item) => item.error).slice(0,3).join("；")}`; dialog.__selectedIds = result.failures.map((item) => item.id); }
      try { await loadInvitations(invitationPage); } catch (_) { showToast("作废结果已确认，列表刷新失败。请刷新列表，无需重复操作。",8000); }
    } catch (requestError) { if (error) error.textContent = apiErrorMessage(requestError,"邀请码作废未完成，请重试。"); }
    finally { button.disabled = false; }
  });

  const catalogSoftwareStatusCopy = {
    draft: ["草稿", "status-gray"],
    testing: ["测试中", "status-warm"],
    active: ["运行中", "status-green"],
    archived: ["已归档", "status-gray"],
  };
  let downstreamProfiles = [];
  let catalogScopeDialog;
  let pendingCatalogScope;

  function catalogAccessesFor(publicId) {
    return catalogItems.flatMap((softwareItem) =>
      (softwareItem.accesses || [])
        .filter((access) => access.downstream_public_id === publicId)
        .map((access) => ({ ...access, software_id: softwareItem.software_id, software_name: softwareItem.name })),
    );
  }

  function appendCatalogScopeAction(actions) {
    const button = createTableButton("权限", { kind: "detail", tooltip: "设置该下游可经营的软件范围" });
    button.dataset.catalogScope = "";
    actions.append(button);
  }

  function renderCatalogSoftwareOptions(items) {
    const values = [{ value: "all", label: "全部软件" }].concat(
      items.map((item) => ({ value: item.software_id, label: item.name })),
    );
    document.querySelectorAll("[data-plan-catalog-context]").forEach((select) => {
      const previous = select.value;
      select.replaceChildren(
        ...values.map((item) => {
          const option = document.createElement("option");
          option.value = item.value;
          option.textContent = item.label;
          return option;
        }),
      );
      select.value = values.some((item) => item.value === previous) ? previous : "all";
      select.dispatchEvent(new Event("change"));
    });
    [document.getElementById("planSoftware"), document.getElementById("issueSoftware")]
      .filter(Boolean)
      .forEach((select) => {
        const previous = select.value;
        select.replaceChildren(
          ...items.map((item) => {
            const option = document.createElement("option");
            option.value = item.software_id;
            option.textContent = item.name;
            return option;
          }),
        );
        if (items.length) {
          select.value = items.some((item) => item.software_id === previous)
            ? previous
            : items[0].software_id;
        } else {
          select.append(new Option("暂无可用软件", ""));
        }
      });
  }

  function appendPlanSummary(planCell, softwarePlans) {
    if (!softwarePlans.length) {
      planCell.textContent = "尚未创建套餐";
      planCell.className = "table-empty";
      return;
    }
    const summary = document.createElement("div");
    summary.className = "plan-summary";
    const chipList = document.createElement("span");
    chipList.className = "plan-chip-list";
    softwarePlans.slice(0, 4).forEach((item) => {
      const chip = document.createElement("span");
      chip.className = "plan-chip";
      chip.dataset.planStatus = item.status || "active";
      chip.textContent = item.name;
      setTableTooltip(chip, item.name);
      chipList.append(chip);
    });
    if (softwarePlans.length > 4) {
      const more = document.createElement("span");
      more.className = "plan-chip plan-chip-more";
      more.textContent = `+${softwarePlans.length - 4}`;
      chipList.append(more);
    }
    summary.append(chipList);
    planCell.append(summary);
  }

  function renderAdminCatalogRows(items) {
    const table = document.querySelector('[data-screen-panel="software"] table');
    const body = table?.tBodies[0];
    if (!body) return;
    body.replaceChildren();
    if (!items.length) {
      window.__previewRefreshTables?.();
      return;
    }
    items.forEach((softwareItem) => {
      const row = document.createElement("tr");
      row.dataset.catalogSoftwareId = softwareItem.software_id;
      row.dataset.searchValue = [softwareItem.software_id, softwareItem.name].filter(Boolean).join(" ");
      row.dataset.softwareStatus = softwareItem.status || "";
      const profile = softwareItem.profiles?.find((item) => ["testing", "active"].includes(item.status)) || softwareItem.profiles?.[0];
      const policy = profile?.policies?.find((item) => item.status === "active") || profile?.policies?.[0] || {};
      appendSoftwareCell(row, softwareItem.name);
      const profileText = profile?.profile_id || "尚未登记";
      appendTextCell(row, profileText, "mono");
      const [statusLabel, statusClass] = catalogSoftwareStatusCopy[softwareItem.status] || [softwareItem.status, "status-gray"];
      appendStatusCell(row, statusLabel, statusClass);
      const policyCell = document.createElement("td");
      const devices = document.createElement("b");
      devices.textContent = `${policy.max_devices || "—"} 台设备`;
      const policyCopy = document.createElement("small");
      const policyText = `${policy.verify_interval_seconds ? `${Math.round(policy.verify_interval_seconds / 60)} 分钟验证` : "验证间隔待定"} · ${policy.offline_grace_seconds ? `${Math.round(policy.offline_grace_seconds / 3600)} 小时宽限` : "无断网宽限"}`;
      policyCopy.textContent = shortenTableText(policyText, { kind: "compound", maxLength: 18 });
      setTableTooltip(policyCopy, policyText, policyCopy.textContent);
      policyCell.append(devices, policyCopy);
      row.append(policyCell);
      const planCell = document.createElement("td");
      const softwarePlans = (softwareItem.plans || []).filter((item) => item.status !== "deleted");
      appendPlanSummary(planCell, softwarePlans);
      row.append(planCell);
      const connection = softwareItem.client_connection === "connected" ? ["已接通", "status-green"] : ["未接通", "status-gray"];
      appendStatusCell(row, connection[0], connection[1]);
      const actionCell = document.createElement("td");
      const actions = document.createElement("div");
      actions.className = "table-actions";
      const policyButton = createTableButton("参数", { kind: "detail", tooltip: "查看与调整该软件的设备上限与离线宽限参数" });
      policyButton.dataset.dialog = "policyDialog";
      policyButton.dataset.policySoftware = softwareItem.software_id;
      policyButton.dataset.policyProfile = profile?.profile_id || "";
      actions.append(policyButton);
      const managePlansButton = createTableButton("套餐", { kind: "detail", tooltip: "管理日卡/月卡/年卡与单卡额度成本" });
      managePlansButton.dataset.dialog = "planManagerDialog";
      managePlansButton.dataset.planManagerSoftware = softwareItem.software_id;
      actions.append(managePlansButton);
      const configButton = createTableButton("下载接入配置", { kind: "detail", disabled: !profile || softwareItem.status === "archived" || !["active", "testing"].includes(profile.status), disabledReason: "软件及接入配置须启用后才能下载", tooltip: "下载当前软件及 Profile 的 JSON，交给软件项目 AI" });
      configButton.dataset.integrationDownload = "";
      configButton.dataset.integrationSoftware = softwareItem.software_id;
      configButton.dataset.integrationProfile = profile?.profile_id || "";
      actions.append(configButton);
      const isArchived = softwareItem.status === "archived";
      const unlistButton = createTableButton(isArchived ? "重新上架" : "下架", {
        kind: isArchived ? "detail" : "danger",
        tooltip: isArchived ? "恢复软件发行，经营范围需另行开放" : "下架该软件并停止对外发行",
      });
      unlistButton.textContent = "下架";
      if (isArchived) unlistButton.textContent = "重新上架";
      unlistButton.dataset.dialog = "softwareUnlistDialog";
      unlistButton.dataset.softwareUnlistId = softwareItem.software_id;
      unlistButton.dataset.softwareUnlistName = softwareItem.name || softwareItem.software_id;
      unlistButton.dataset.softwareStatusTarget = isArchived ? "active" : "archived";
      actions.append(unlistButton);
      actionCell.append(actions);
      row.append(actionCell);
      body.append(row);
    });
    window.__previewRefreshTables?.();
    bindDialogTriggers(body);
  }

  function renderDownstreamRows(items) {
    downstreamProfiles = Array.isArray(items) ? items : [];
    const table = document.querySelector('[data-screen-panel="downstreams"] table');
    const body = table?.tBodies[0];
    if (!body) return;
    body.replaceChildren();
    applyDownstreamClientFilters(downstreamProfiles).forEach((profile) => {
      const row = document.createElement("tr");
      row.dataset.downstreamRow = "";
      row.dataset.downstream = profile.username;
      row.dataset.downstreamState = profile.status;
      row.dataset.publicId = profile.public_id;
      row.dataset.activeAuthorizationCount = String(profile.active_authorization_count ?? 0);
      row.dataset.unusedCardCount = String(profile.unused_card_count ?? 0);
      row.dataset.availableBalance = String(profile.available_balance ?? 0);
      appendTextCell(row, profile.username, "mono");
      const [statusLabel, statusClass] = downstreamStatusCopy[profile.status] || [profile.status, "status-gray"];
      appendStatusCell(row, statusLabel, statusClass);
      const activeAccesses = catalogAccessesFor(profile.public_id).filter((access) => access.status === "active");
      appendTextCell(row, activeAccesses.map((access) => access.software_name).join(" / ") || (catalogApiReady ? "未开放软件" : "目录加载中"), "", { kind: "compound" });
      appendTextCell(row, profile.available_balance === null || profile.available_balance === undefined ? "—" : Number(profile.available_balance).toLocaleString("zh-CN"), "mono");
      const actionCell = document.createElement("td");
      const actions = document.createElement("div");
      actions.className = "table-actions";
      appendCatalogScopeAction(actions);
      if (profile.status === "active") {
        const resetButton = createTableButton("改密", { kind: "detail", tooltip: `重置 ${profile.username} 的登录密码` });
        resetButton.dataset.dialog = "passwordResetDialog";
        resetButton.dataset.publicId = profile.public_id;
        resetButton.dataset.resetUsername = profile.username;
        actions.append(resetButton);
        appendDownstreamAction(actions, "暂停", "pause");
        appendDownstreamAction(actions, "归档", "archive");
      } else if (profile.status === "suspended") {
        const resetButton = createTableButton("改密", { kind: "detail", tooltip: `重置 ${profile.username} 的登录密码` });
        resetButton.dataset.dialog = "passwordResetDialog";
        resetButton.dataset.publicId = profile.public_id;
        resetButton.dataset.resetUsername = profile.username;
        actions.append(resetButton);
        appendDownstreamAction(actions, "恢复", "resume");
        appendDownstreamAction(actions, "归档", "archive");
      } else if (profile.status === "closed") {
        appendDownstreamAction(actions, "删除", "delete");
      }
      actionCell.append(actions);
      row.append(actionCell);
      body.append(row);
    });
    window.__previewRefreshTables?.();
    bindDialogTriggers(body);
  }

  function ensureCatalogScopeDialog() {
    if (catalogScopeDialog) return catalogScopeDialog;
    catalogScopeDialog = document.createElement("dialog");
    catalogScopeDialog.className = "modal modal-wide";
    catalogScopeDialog.id = "catalogScopeDialog";
    catalogScopeDialog.innerHTML = '<form method="dialog"><button class="modal-close" type="button" value="cancel" aria-label="关闭">×</button><h2>设置下游经营范围</h2><p class="form-hint">关掉某软件后，该下游该软件不能再发、未激活卡不能再开通；已开通验证不受影响；未激活仍可回收退额度。开放后默认允许该软件当前全部可用套餐。</p><div class="form-grid" data-catalog-scope-options></div><p class="form-error" data-catalog-scope-error role="alert"></p><div class="modal-actions"><button class="button button-secondary" type="button" value="cancel">取消</button><button class="button button-primary" type="button" data-catalog-scope-save>保存经营范围</button></div></form>';
    document.body.append(catalogScopeDialog);
    bindDialogChrome(catalogScopeDialog);
    catalogScopeDialog.addEventListener("close", () => {
      if (catalogScopeDialog.returnValue === "cancel") pendingCatalogScope = undefined;
    });
    catalogScopeDialog.querySelector("[data-catalog-scope-save]")?.addEventListener("click", async (event) => {
      if (!pendingCatalogScope) return;
      const saveButton = event.currentTarget;
      const error = catalogScopeDialog.querySelector("[data-catalog-scope-error]");
      const options = [...catalogScopeDialog.querySelectorAll("input[data-scope-software]")];
      const publicId = pendingCatalogScope.publicId;
      const snapshots = options.map((option) => ({
        softwareId: option.dataset.scopeSoftware,
        enabled: option.checked,
      }));
      saveButton.disabled = true;
      if (error) error.textContent = "";
      const failures = [];
      try {
        for (const option of snapshots) {
          try {
            await apiRequest(`/manage/catalog/access/${encodeURIComponent(publicId)}/`, {
          method: "POST",
          headers: { "Idempotency-Key": requestIdempotencyKey("catalog-access") },
          body: JSON.stringify({
            software_id: option.softwareId,
            enabled: option.enabled,
            all_plans_allowed: true,
            allowed_plan_ids: [],
          }),
          });
          } catch (requestError) {
            failures.push(option.softwareId || "未知软件");
            if (error && !error.textContent) {
              error.textContent = apiErrorMessage(requestError, "部分软件未保存。");
        }
          }
        }
        await loadCatalog();
        await loadDownstreams();
        if (failures.length) {
          if (error) error.textContent = `部分软件未保存：${failures.join("、")}。已重新读取当前经营范围。`;
          showToast("经营范围未全部保存，页面已重新读取服务端目录。");
          return;
        }
        catalogScopeDialog.close("success");
        showToast("下游经营范围已保存，页面将重新读取服务端目录。 ");
      } catch (requestError) {
        if (error) error.textContent = apiErrorMessage(requestError, "经营范围保存失败，请重试。");
        try {
          await loadCatalog();
          await loadDownstreams();
        } catch (_reloadError) {
          /* 保存失败后仍尽量重读，避免弹窗里的勾选与库存脱节。 */
        }
      } finally {
        saveButton.disabled = false;
      }
    });
    return catalogScopeDialog;
  }

  function openCatalogScopeDialog(row) {
    if (!row || !catalogApiReady) {
      showToast("目录尚未接通，暂不能修改经营范围。 ");
      return;
    }
    const dialog = ensureCatalogScopeDialog();
    const publicId = row.dataset.publicId;
    const current = new Map(catalogAccessesFor(publicId).map((access) => [access.software_id, access.status === "active"]));
    const options = dialog.querySelector("[data-catalog-scope-options]");
    options.replaceChildren(
      ...catalogItems.map((softwareItem) => {
        const label = document.createElement("label");
        label.className = "checkbox-label";
        const input = document.createElement("input");
        input.type = "checkbox";
        input.dataset.scopeSoftware = softwareItem.software_id;
        input.checked = current.get(softwareItem.software_id) === true;
        const text = document.createElement("span");
        text.textContent = softwareItem.name;
        label.append(input, text);
        return label;
      }),
    );
    pendingCatalogScope = { publicId };
    dialog.querySelector("[data-catalog-scope-error]").textContent = "";
    dialog.showModal();
  }

  document.addEventListener("click", (event) => {
    const trigger = event.target.closest("[data-catalog-scope]");
    if (trigger) openCatalogScopeDialog(trigger.closest("[data-downstream-row]"));
  });

  function renderCatalogUnavailable() {
    catalogApiReady = false;
    setCatalogItems([]);
    renderPlanCatalog([]);
    renderAdminCatalogRows([]);
    if (document.body.classList.contains("role-downstream")) {
      setSupportLoading("渠道支持暂时无法读取");
      document.querySelector("[data-support-context]")?.replaceChildren(new Option("暂时无法读取", ""));
    }
    if (downstreamProfiles.length) renderDownstreamRows(downstreamProfiles);
  }

  async function fetchAllCollectionPages(path, options = {}) {
    const pageSize = Number(options.pageSize || 100);
    const maxPages = Number(options.maxPages || 20);
    const label = options.label || "列表";
    const extraQuery = options.extraQuery || {};
    const items = [];
    let total = 0;
    for (let page = 1; page <= maxPages; page += 1) {
      const query = new URLSearchParams({ page: String(page), page_size: String(pageSize) });
      Object.entries(extraQuery).forEach(([key, value]) => {
        if (value) query.set(key, String(value));
      });
      const payload = await apiRequest(`${path}?${query.toString()}`);
      const batch = Array.isArray(payload.items) ? payload.items : [];
      items.push(...batch);
      total = Number(payload.pagination?.total ?? items.length);
      if (!payload.pagination?.has_next || batch.length === 0) break;
    }
    if (total > items.length) {
      showToast(`${label}只读到前 ${items.length} 条，共 ${total} 条。请用搜索定位其余对象。`);
    }
    return { items, total };
  }

  function beijingDayStamp(value) {
    const date = value instanceof Date ? value : new Date(value);
    if (Number.isNaN(date.getTime())) return "";
    return new Intl.DateTimeFormat("en-CA", {
      timeZone: "Asia/Shanghai",
      year: "numeric",
      month: "2-digit",
      day: "2-digit",
    }).format(date);
  }

  function applyDownstreamClientFilters(items) {
    const filters = document.querySelector("[data-downstream-filters]");
    const software = filters?.querySelector('[name="downstream_software"]')?.value || "";
    const balance = filters?.querySelector('[name="downstream_balance"]')?.value || "";
    const activity = filters?.querySelector('[name="downstream_activity"]')?.value || "";
    const now = Date.now();
    const today = beijingDayStamp(new Date());
    return (items || []).filter((profile) => {
      if (software) {
        const open = catalogAccessesFor(profile.public_id).some(
          (access) => access.status === "active" && access.software_id === software,
        );
        if (!open) return false;
      }
      const available = Number(profile.available_balance || 0);
      if (balance === "positive" && available <= 0) return false;
      if (balance === "zero" && available !== 0) return false;
      const loginAt = profile.last_successful_login_at ? Date.parse(profile.last_successful_login_at) : NaN;
      if (activity === "today") {
        if (!Number.isFinite(loginAt) || beijingDayStamp(loginAt) !== today) return false;
      }
      if (activity === "7d") {
        if (!Number.isFinite(loginAt) || now - loginAt > 7 * 24 * 60 * 60 * 1000) return false;
      }
      if (activity === "stale") {
        if (Number.isFinite(loginAt) && now - loginAt <= 30 * 24 * 60 * 60 * 1000) return false;
      }
      return true;
    });
  }

  function fillDownstreamSoftwareFilter() {
    const select = document.querySelector("[data-downstream-filters] [name='downstream_software']");
    if (!select) return;
    const previous = select.value;
    select.replaceChildren(new Option("全部软件", ""));
    catalogItems.forEach((item) => select.append(new Option(item.name, item.software_id)));
    select.value = [...select.options].some((option) => option.value === previous) ? previous : "";
  }

  async function loadCatalog() {
    const isAdmin = document.body.classList.contains("role-admin");
    const collection = await fetchAllCollectionPages(
      isAdmin ? "/manage/catalog/" : "/downstream/catalog/",
      { label: "软件目录" },
    );
    setCatalogItems(collection.items);
    catalogApiReady = true;
    fillDownstreamSoftwareFilter();
    syncReleaseSoftwareOptions(catalogItems);
    renderCatalogSoftwareOptions(catalogItems);
    if (isAdmin) {
      renderAdminCatalogRows(catalogItems);
      if (downstreamProfiles.length) renderDownstreamRows(downstreamProfiles);
    } else {
      renderPlanCatalog(catalogItems);
    }
    renderPlans(plan?.value);
    updateIssuePreview();
    syncLicenseCredentialFilters();
    syncAuthorizationRiskCatalogFilters();
    return catalogItems;
  }
  window.__previewLoadCatalog = loadCatalog;

  async function loadDownstreams() {
    const status = document.querySelector("[data-downstream-filters] [name='downstream_status']")?.value || "";
    const collection = await fetchAllCollectionPages("/manage/downstreams/", {
      label: "下游账号",
      extraQuery: { status },
    });
    fillDownstreamSoftwareFilter();
    renderDownstreamRows(collection.items);
    syncAuthorizationRiskCatalogFilters();
    return collection.items;
  }

  document.querySelector("[data-downstream-filters]")?.addEventListener("change", (event) => {
    if (isStandaloneStaticPreview) return;
    if (event.target?.name === "downstream_status") {
      loadDownstreams().catch(() => {});
      return;
    }
    if (downstreamProfiles.length) renderDownstreamRows(downstreamProfiles);
  });

  async function loadInvitations(page = invitationPage) {
    const scope = document.querySelector("[data-invitation-scope]")?.value || "current";
    const statusLabels = {
      "未使用": "issued",
      "已使用": "consumed",
      "已撤销": "revoked",
      "已过期": "expired",
      "已归档": "archived",
    };
    const statusLabel = document.querySelector('[data-record-view-scope="invitations"] [data-credential-filter="codeStatus"]')?.value || "";
    const params = new URLSearchParams({ scope, page: String(Math.max(1, Number(page) || 1)), page_size: "5" });
    if (statusLabel && statusLabels[statusLabel]) params.set("status", statusLabels[statusLabel]);
    const invitationSearch = nonSecretTableQuery(
      document.querySelector('[data-record-view-scope="invitations"] [data-sensitive-search]'),
      "invitation",
    );
    if (invitationSearch) params.set("q", invitationSearch);
    bindInvitationServerPagination();
    const payload = await apiRequest(`/manage/invitations/?${params.toString()}`);
    invitationPage = payload.pagination?.page || page;
    renderInvitationRows(payload.items || []);
    snapshotCredentialFilters(document.querySelector('[data-record-view-scope="invitations"] [data-credential-filters]'));
    setInvitationServerPagination(payload.pagination || {});
    return payload.items || [];
  }
  window.__previewLoadInvitations = loadInvitations;

  const invitationScopeSelect = document.querySelector("[data-invitation-scope]");
  invitationScopeSelect?.addEventListener("change", () => {
    if (!isStandaloneStaticPreview) {
      if (hasCredentialSearchOverlay("invitations")) {
        credentialSearchOverlayToast("再改分类");
        return;
      }
      invitationPage = 1;
      loadInvitations(1).catch((error) => showToast(apiErrorMessage(error, "邀请码分类暂时无法读取，请重试。")));
      return;
    }
    const panel = document.querySelector('[data-record-view-scope="invitations"] [data-record-panel="items"]');
    const state = tableStateForContext(panel);
    if (!state) return;
    const scope = invitationScopeSelect.value;
    state.rows.forEach((row) => {
      row.dataset.criteriaMatch = scope === "archived"
        ? String(row.dataset.codeStatus === "已归档")
        : scope === "current"
          ? String(row.dataset.codeStatus !== "已归档" && row.dataset.codeStatus !== "已删除")
          : "true";
    });
    state.page = 1;
    renderTableState(state, false);
  });

  const creditOperationCopy = {
    manual_credit: "人工充值",
    card_redeem: "额度卡兑换",
    license_card_issue: "生成授权卡",
    license_card_reclaim: "回收未激活卡",
    admin_adjustment: "管理员扣回",
  };
  let quotaAccountsCache = [];
  let adminLedgerPage = 1;
  let downstreamLedgerPage = 1;

  function setLedgerPagination(selector, pagination = {}) {
    document.querySelectorAll(selector).forEach((controls) => {
      controls.hidden = isStandaloneStaticPreview || !pagination || Number(pagination.total_pages || 0) <= 1;
      const prev = controls.querySelector("[data-admin-ledger-prev], [data-downstream-ledger-prev]");
      const next = controls.querySelector("[data-admin-ledger-next], [data-downstream-ledger-next]");
      const page = controls.querySelector("[data-admin-ledger-page], [data-downstream-ledger-page]");
      if (prev) prev.disabled = !pagination.has_previous;
      if (next) next.disabled = !pagination.has_next;
      if (page) page.textContent = formatServerPageLabel(pagination);
    });
  }

  function fillCreditAdjustDialog() {
    const dialog = document.getElementById("creditAdjustDialog");
    const select = dialog?.querySelector('select[name="downstream"]');
    if (!select) return;
    const previous = select.value;
    const options = [new Option("请选择下游", "")];
    const sources = quotaAccountsCache.filter((account) => account.username && account.status === "active");
    sources.forEach((item) => {
      const publicId = item.downstream_public_id;
      const username = item.username;
      if (publicId && username) options.push(new Option(username, publicId));
    });
    select.replaceChildren(...options);
    if (options.some((option) => option.value === previous)) select.value = previous;
    const error = dialog.querySelector("[data-form-error]");
    if (error) error.textContent = "";
  }

  function fillCreditRecoverDeletedDialog(accounts) {
    const dialog = document.getElementById("creditRecoverDeletedDialog");
    const select = dialog?.querySelector('select[name="downstream_public_id"]');
    if (!select) return;
    const previous = select.value;
    const options = [new Option("请选择已删除下游", "")];
    (accounts || [])
      .filter((account) => account.status === "deleted" && account.downstream_public_id)
      .forEach((account) => {
        const label = `${account.username || "已删除下游"} · ${Number(account.available_balance || 0).toLocaleString("zh-CN")} 额度`;
        options.push(new Option(label, account.downstream_public_id));
      });
    select.replaceChildren(...options);
    if (options.some((option) => option.value === previous)) select.value = previous;
  }

  function renderAdminCreditLedger(entries, accounts) {
    const body = document.querySelector('[data-screen-panel="credits"] [data-work-panel="ledger"] tbody');
    if (!body) return;
    const accountNames = new Map((accounts || []).map((account) => [account.downstream_public_id, account.username || "已删除下游"]));
    body.replaceChildren();
    (entries || []).forEach((entry) => {
      const row = document.createElement("tr");
      appendTextCell(row, formatApiDate(entry.occurred_at), "mono");
      appendTextCell(row, accountNames.get(entry.downstream_public_id) || entry.downstream_public_id.slice(-8));
      appendTextCell(row, creditOperationCopy[entry.operation_type] || entry.operation_type);
      appendTextCell(row, `${entry.delta > 0 ? "+" : ""}${Number(entry.delta).toLocaleString("zh-CN")}`, `mono ${entry.delta > 0 ? "amount-plus" : "amount-minus"}`);
      appendTextCell(row, Number(entry.balance_after).toLocaleString("zh-CN"), "mono");
      body.append(row);
    });
    const panel = body.closest(".table-panel");
    if (panel) panel.dataset.serverDataLoaded = "true";
    window.__previewRefreshTables?.();
  }

  function renderDownstreamCreditLedger(entries) {
    const body = document.querySelector('[data-screen-panel="ledger"] tbody');
    if (!body) return;
    body.replaceChildren();
    (entries || []).forEach((entry) => {
      const row = document.createElement("tr");
      appendTextCell(row, formatApiDate(entry.occurred_at), "mono");
      appendTextCell(row, creditOperationCopy[entry.operation_type] || entry.operation_type);
      appendTextCell(row, `${entry.delta > 0 ? "+" : ""}${Number(entry.delta).toLocaleString("zh-CN")}`, `mono ${entry.delta > 0 ? "amount-plus" : "amount-minus"}`);
      appendTextCell(row, Number(entry.balance_after).toLocaleString("zh-CN"), "mono");
      body.append(row);
    });
    const countTarget = document.querySelector("[data-downstream-ledger-count]");
    if (countTarget && !document.querySelector("[data-downstream-ledger-pagination]")) {
      countTarget.textContent = String((entries || []).length);
    }
    const panel = body.closest(".table-panel");
    if (panel) panel.dataset.serverDataLoaded = "true";
    window.__previewRefreshTables?.();
  }

  function clearCreditRuntimeData() {
    renderQuotaCardRows([]);
    renderAdminCreditLedger([], []);
    renderDownstreamCreditLedger([]);
    document.querySelectorAll('[data-screen-panel="credits"] .balance-number, [data-screen-panel="ledger"] .balance-number, #downstreamAvailableBalance').forEach((target) => {
      target.textContent = "—";
    });
    syncIssueAvailableBalance(0);
    applyQuotaPurchaseLink("", { keepOnEmpty: true });
  }

  async function loadPublicQuotaPurchaseLink() {
    const payload = await apiRequest("/public/quota-settings/");
    applyQuotaPurchaseLink(payload.purchase_url || "", { fallback: false });
    return payload.purchase_url || "";
  }

  let quotaCardsPage = 1;

  function quotaCardScope() {
    return document.querySelector('[data-record-view-scope="quota-cards"] [data-credential-filter="recordScope"]')?.value || "current";
  }

  function setQuotaCardServerPagination(pagination) {
    const controls = document.querySelector('[data-record-view-scope="quota-cards"] [data-quota-card-server-pagination]');
    if (!controls) return;
    const visible = !isStandaloneStaticPreview && pagination && Number(pagination.total_pages || 0) > 1;
    controls.hidden = !visible;
    controls.querySelector("[data-quota-card-server-prev]").disabled = !pagination?.has_previous;
    controls.querySelector("[data-quota-card-server-next]").disabled = !pagination?.has_next;
    controls.querySelector("[data-quota-card-server-page]").textContent = formatServerPageLabel(pagination);
  }

  function bindQuotaCardServerPagination() {
    const previous = document.querySelector("[data-quota-card-server-prev]");
    const next = document.querySelector("[data-quota-card-server-next]");
    if (previous && !previous.dataset.bound) {
      previous.dataset.bound = "true";
      previous.addEventListener("click", () => {
        if (hasCredentialSearchOverlay("quota-cards")) {
          credentialSearchOverlayToast("再翻页");
          return;
        }
        loadAdminCredits(Math.max(1, quotaCardsPage - 1));
      });
    }
    if (next && !next.dataset.bound) {
      next.dataset.bound = "true";
      next.addEventListener("click", () => {
        if (hasCredentialSearchOverlay("quota-cards")) {
          credentialSearchOverlayToast("再翻页");
          return;
        }
        loadAdminCredits(quotaCardsPage + 1);
      });
    }
  }

  function quotaCardFilterQuery(panel) {
    const query = { scope: quotaCardScope() };
    panel?.querySelectorAll("[data-credential-filter]").forEach((select) => {
      if (!select.value) return;
      const key = select.dataset.credentialFilter;
      if (key === "codeStatus") {
        const status = { "未兑换": "issued", "已兑换": "redeemed", "已作废": "revoked", "已撤销": "revoked", "已归档": "archived" }[select.value];
        if (status) query.status = status;
      } else if (key === "codeAmount") {
        const amount = select.value.match(/\d+/)?.[0];
        if (amount) query.amount = amount;
      } else if (key === "codeDownstream") {
        query.redeemed_by = select.value;
      }
    });
    return query;
  }

  function syncQuotaDownstreamFilterOptions(accounts) {
    if (isStandaloneStaticPreview) return;
    const select = document.querySelector('[data-record-view-scope="quota-cards"] [data-credential-filter="codeDownstream"]');
    if (!select) return;
    const previous = select.value;
    const options = [new Option("全部下游", "")];
    (Array.isArray(accounts) ? accounts : []).forEach((account) => {
      if (!account?.username) return;
      const suffix = account.status && account.status !== "active" ? ` · ${account.status}` : "";
      options.push(new Option(`${account.username}${suffix}`, account.username));
    });
    select.replaceChildren(...options);
    if (options.some((option) => option.value === previous)) select.value = previous;
  }

  async function loadAdminCredits(page = quotaCardsPage) {
    const requestedPage = Math.max(1, Number(page) || 1);
    bindQuotaCardServerPagination();
    const query = new URLSearchParams({
      scope: quotaCardScope(),
      card_page: String(requestedPage),
      ledger_page: String(Math.max(1, adminLedgerPage)),
      ledger_page_size: "5",
    });
    const ledgerSearch = document.querySelector("[data-admin-ledger-search]")?.value.trim() || "";
    if (ledgerSearch) query.set("ledger_q", ledgerSearch);
    Object.entries(quotaCardFilterQuery(document.querySelector('[data-record-view-scope="quota-cards"] [data-record-panel="items"]'))).forEach(([key, value]) => query.set(key, value));
    const quotaSearch = nonSecretTableQuery(
      document.querySelector('[data-record-view-scope="quota-cards"] [data-sensitive-search]'),
      "quota",
    );
    if (quotaSearch) query.set("q", quotaSearch);
    const payload = await apiRequest(`/manage/credits/?${query.toString()}`);
    quotaCardsPage = payload.cards_pagination?.page || requestedPage;
    applyQuotaPurchaseLink(payload.purchase_url || "", { fallback: false });
    quotaAccountsCache = payload.accounts || [];
    syncQuotaDownstreamFilterOptions(payload.accounts || []);
    fillCreditRecoverDeletedDialog(payload.accounts || []);
    renderQuotaCardRows(payload.cards || []);
    syncQuotaAmountFilter(payload.cards || []);
    snapshotCredentialFilters(document.querySelector('[data-record-view-scope="quota-cards"] [data-credential-filters]'));
    setQuotaCardServerPagination(payload.cards_pagination || null);
    document.querySelectorAll('[data-record-view-scope="quota-cards"] [data-record-scope-summary]').forEach((target) => {
      target.textContent = { current: "当前额度兑换码", archived: "归档额度兑换码", all: "全部额度兑换码" }[payload.cards_scope || quotaCardScope()] || "额度兑换码";
    });
    renderAdminCreditLedger(payload.ledger || [], payload.accounts || []);
    adminLedgerPage = payload.ledger_pagination?.page || adminLedgerPage;
    setLedgerPagination("[data-admin-ledger-pagination]", payload.ledger_pagination || {});
    const totalBalance = Number(payload.operating_available_balance);
    document.querySelectorAll('[data-screen-panel="credits"] .balance-number').forEach((target) => {
      target.textContent = Number.isFinite(totalBalance) ? totalBalance.toLocaleString("zh-CN") : "—";
    });
    return payload;
  }

  function syncIssueAvailableBalance(raw) {
    if (!issueDialog) return;
    const value = Number(raw);
    if (!Number.isFinite(value)) return;
    issueDialog.dataset.availableBalance = String(Math.trunc(value));
  }

  function applyDownstreamLedgerBalance(account) {
    const numeric = Number(account?.available_balance);
    const balance = (Number.isFinite(numeric) ? numeric : 0).toLocaleString("zh-CN");
    document.querySelectorAll('[data-screen-panel="ledger"] .balance-number, #downstreamAvailableBalance').forEach((target) => {
      target.textContent = balance;
    });
    syncIssueAvailableBalance(Number.isFinite(numeric) ? numeric : 0);
  }

  async function loadDownstreamCredits(page = downstreamLedgerPage) {
    const requestedPage = Math.max(1, Number(page) || 1);
    const query = new URLSearchParams({
      ledger_page: String(requestedPage),
      ledger_page_size: "5",
    });
    const ledgerSearch = document.querySelector("[data-downstream-ledger-search]")?.value.trim() || "";
    if (ledgerSearch) query.set("ledger_q", ledgerSearch);
    const payload = await apiRequest(`/downstream/credits/?${query.toString()}`);
    applyQuotaPurchaseLink(payload.purchase_url || "", { fallback: false });
    applyDownstreamLedgerBalance(payload.account);
    renderDownstreamCreditLedger(payload.ledger || []);
    downstreamLedgerPage = payload.ledger_pagination?.page || requestedPage;
    setLedgerPagination("[data-downstream-ledger-pagination]", payload.ledger_pagination || {});
    const countTarget = document.querySelector("[data-downstream-ledger-count]");
    if (countTarget) countTarget.textContent = String(payload.ledger_pagination?.total || (payload.ledger || []).length);
    const consumedTarget = document.querySelector("[data-downstream-today-consumed]");
    if (consumedTarget) {
      const consumed = Number(payload.today_consumed);
      consumedTarget.textContent = Number.isFinite(consumed)
        ? consumed.toLocaleString("zh-CN")
        : "—";
    }
    return payload;
  }

  const authorizationRiskRequestState = {
    generation: 0,
    controller: null,
    page: 1,
    hasNext: false,
  };
  let authorizationRiskSearchTimer = 0;

  function beginAuthorizationRiskRequest() {
    authorizationRiskRequestState.controller?.abort();
    const generation = ++authorizationRiskRequestState.generation;
    const controller = new AbortController();
    authorizationRiskRequestState.controller = controller;
    return { controller, generation };
  }

  function isCurrentAuthorizationRiskRequest(request) {
    return request.generation === authorizationRiskRequestState.generation;
  }

  function riskExpiryLabel(value, status) {
    if (status === "expired") return "已到期";
    if (!value) return "其他期限";
    const timestamp = new Date(value).getTime();
    if (Number.isNaN(timestamp)) return "其他期限";
    const days = (timestamp - Date.now()) / 86400000;
    if (days <= 0) return "已到期";
    if (days <= 7) return "7 天内";
    if (days >= 30) return "30 天以上";
    return "其他期限";
  }

  function authorizationRiskUsesServerFilters() {
    return !isStandaloneStaticPreview || Boolean(window.__b1ApiActive);
  }

  function authorizationRiskStatus(item) {
    if (item.time_rollback_blocked === true) return ["时间阻断", "status-warm"];
    if (item.status === "blocked") return ["已阻断", "status-red"];
    if (item.status === "revoked") return ["已撤销", "status-red"];
    if (item.status === "expired" || licenseCardWallClockExpired(item)) return ["已过期", "status-gray"];
    if (item.status === "grace") return ["宽限", "status-warm"];
    return ["可用", "status-green"];
  }

  function authorizationRiskDeviceState(device) {
    if (device.binding_state === "active") return "已绑定";
    if (device.binding_state === "blocked") return "已阻断";
    if (device.binding_state === "unbound") return "已解绑";
    if (device.binding_state === "expired") return "已到期";
    if (device.device_id) return device.binding_state_label || "未绑定";
    return "尚未绑定";
  }

  function appendAuthorizationRiskAction(actions, label, kind, options = {}) {
    const btnKind = kind === "unblock" || kind === "recover" ? "unfreeze" : kind === "reset" ? "reset" : kind === "revoke" || kind === "block" ? "danger" : "detail";
    const shortLabel = label.includes("（") ? label.split("（", 1)[0].trim() : (label === "冻结这张卡" ? "冻结" : label === "解冻这张卡" ? "解冻" : label === "撤销授权" ? "撤销" : label);
    const button = createTableButton(shortLabel, {
      kind: btnKind,
      disabled: Boolean(options.disabled),
      disabledReason: options.disabledReason || "",
      tooltip: label,
    });
    button.dataset.deviceAction = kind;
    button.setAttribute("aria-label", label);
    actions.append(button);
    return button;
  }

  function applyAuthorizationRiskFilters() {
    if (authorizationRiskUsesServerFilters()) {
      const screen = document.querySelector('[data-screen-panel="risk"]');
      const state = tableStateForScreen(screen);
      if (!state) return;
      state.rows.forEach((row) => {
        row.dataset.criteriaMatch = "true";
        row.dataset.filterMatch = "true";
        row.dataset.queryMatch = "true";
      });
      renderServerTableState(state);
      return;
    }
    const screen = document.querySelector('[data-screen-panel="risk"]');
    const state = tableStateForScreen(screen);
    const selects = [...(screen?.querySelectorAll("[data-device-authorization-filters] select") || [])];
    if (!state || selects.length < 6) return;
    const values = selects.map((select) => select.selectedOptions[0]?.textContent.trim() || "");
    state.rows.forEach((row) => {
      const matches = [
        [values[0], row.dataset.riskAuthorization],
        [values[1], row.dataset.riskDevice],
        [values[2], row.dataset.riskState],
        [values[3], row.dataset.riskSoftware],
        [values[4], row.dataset.riskDownstream],
        [values[5], row.dataset.riskExpiry],
      ].every(([selected, actual]) =>
        !selected || selected.startsWith("全部") || selected === actual,
      );
      row.dataset.criteriaMatch = String(matches);
    });
    if (state.serverPaginated) {
      renderServerTableState(state);
      return;
    }
    state.page = 1;
    renderTableState(state, false);
  }

  function bindAuthorizationRiskFilters() {
    document
      .querySelectorAll("[data-device-authorization-filters] select")
      .forEach((select) => {
        if (select.dataset.apiFilterBound) return;
        select.dataset.apiFilterBound = "true";
        select.addEventListener("change", () => {
          if (!authorizationRiskUsesServerFilters()) {
            applyAuthorizationRiskFilters();
            return;
          }
          authorizationRiskRequestState.page = 1;
          loadAuthorizationRisk().catch((error) => showToast(apiErrorMessage(error, "设备与授权筛选失败，请重试。")));
        });
      });
  }

  function fillSelectPreserving(select, allLabel, entries) {
      if (!select) return;
      const previous = select.value;
    const options = [new Option(allLabel, "")];
    (entries || []).forEach(([value, label]) => {
      if (!value) return;
      options.push(new Option(label || value, value));
    });
    select.replaceChildren(...options);
    if ([...select.options].some((option) => option.value === previous)) select.value = previous;
  }

  function syncLicenseCredentialFilters() {
    const softwareSelects = document.querySelectorAll('[data-credential-filter="codeSoftware"]');
    const planSelects = document.querySelectorAll(
      '[data-record-view-scope="management-licenses"] [data-credential-filter="codePlan"], [data-record-view-scope="downstream-licenses"] [data-credential-filter="codePlan"]',
    );
    const softwareEntries = catalogItems.map((item) => [item.name, item.name]);
    softwareSelects.forEach((select) => fillSelectPreserving(select, "全部软件", softwareEntries));
    const selectedSoftware = softwareSelects[0]?.value || "";
    const planNames = new Set();
    catalogItems.forEach((item) => {
      if (selectedSoftware && item.name !== selectedSoftware) return;
      (item.plans || []).forEach((planItem) => {
        if (planItem.name) planNames.add(planItem.name);
      });
    });
    planSelects.forEach((select) => fillSelectPreserving(select, "全部套餐", [...planNames].map((name) => [name, name])));
  }

  function syncQuotaAmountFilter(cards) {
    const select = document.querySelector('[data-record-view-scope="quota-cards"] [data-credential-filter="codeAmount"]');
    if (!select) return;
    const previous = select.value;
    const amounts = new Set();
    select.querySelectorAll("option").forEach((option) => {
      if (option.value) amounts.add(option.value);
    });
    (Array.isArray(cards) ? cards : []).forEach((item) => {
      if (item?.amount != null) amounts.add(String(item.amount));
    });
    const options = [new Option("全部面额", "")];
    [...amounts]
      .sort((left, right) => Number(left) - Number(right))
      .forEach((amount) => options.push(new Option(`${Number(amount).toLocaleString("zh-CN")} 额度`, amount)));
    select.replaceChildren(...options);
    if ([...select.options].some((option) => option.value === previous)) select.value = previous;
  }

  function syncAuthorizationRiskCatalogFilters() {
    const screen = document.querySelector('[data-screen-panel="risk"]');
    if (!screen) return;
    fillSelectPreserving(
      screen.querySelector('[data-risk-filter="software_id"]'),
      "全部软件",
      catalogItems.map((item) => [item.software_id, item.name]),
    );
    fillSelectPreserving(
      screen.querySelector('[data-risk-filter="downstream_public_id"]'),
      "全部下游",
      (downstreamProfiles || []).map((profile) => [profile.public_id, profile.username || "已删除下游"]),
    );
  }

  const riskSignalGuidance = {
    DEVICE_PROOF_INVALID: ["设备证明无效", "核对客户端", "本次请求已拒绝。先检查设备证明、签名输入和客户端版本；单次或多次错误都不能证明某张卡违规。"],
    DEVICE_PROOF_REQUIRED: ["缺少设备证明", "核对接入", "本次请求已拒绝。先检查客户端是否按当前软件配置提交设备证明。"],
    DEVICE_KEY_REUSED: ["设备密钥被复用", "核对设备", "本次请求已拒绝。核对重装、密钥迁移和现有绑定，确认具体授权后再决定是否冻结本卡。"],
    DEVICE_KEY_MISMATCH: ["设备密钥不匹配", "核对设备", "本次请求已拒绝。先核对设备登记、重装和绑定历史，不要据此封禁整台电脑。"],
    PROFILE_MISMATCH: ["软件身份不匹配", "核对配置", "本次请求已拒绝。检查该软件下载的配置与实际软件身份是否一致。"],
    REPLAY_DETECTED: ["请求随机值已使用", "核对重试", "重放请求已拒绝。检查重试是否原样使用同一请求；新的操作须生成新的请求标识与随机值。"],
    TIME_ROLLBACK_DETECTED: ["服务端可信时间回退", "核对服务器", "这是服务端时间异常，不代表客户修改时间作弊。先确认服务器时间恢复，再对具体授权使用时间阻断恢复。"],
  };
  let riskSignals = [];
  let riskSignalsPage = 1;
  let riskSignalsState = "pending";

  function renderRiskSignals(signals, state = "ready") {
    riskSignalsState = state;
    riskSignals = Array.isArray(signals) ? signals.slice(0, 50) : [];
    riskSignalsPage = Math.max(1, Math.min(riskSignalsPage, Math.ceil(riskSignals.length / 10) || 1));
    const dialog = document.getElementById("riskSignalsDialog");
    if (!dialog) return;
    const loading = state === "loading";
    dialog.setAttribute("aria-busy", String(loading));
    document.querySelector("[data-risk-signal-count]").textContent =
      state === "ready" ? String(riskSignals.length) : loading ? "读取中" : state === "error" ? "读取失败" : "待读取";
    const refresh = dialog.querySelector("[data-risk-signals-refresh]");
    refresh.disabled = loading;
    refresh.textContent = loading ? "读取中…" : state === "error" ? "重试读取" : "刷新记录";
    dialog.querySelector("[data-risk-signals-error]").textContent = state === "error"
      ? "异常记录读取失败，请重试。当前未显示旧记录。" : "";
    const empty = dialog.querySelector("[data-risk-signals-empty]");
    empty.hidden = riskSignals.length > 0 || state === "error";
    empty.textContent = loading ? "正在读取异常记录…" : state === "ready"
      ? "最近没有匹配的异常记录。" : "连接后台后读取异常记录。";
    const list = dialog.querySelector("[data-risk-signals-list]");
    list.replaceChildren();
    const start = (riskSignalsPage - 1) * 10;
    riskSignals.slice(start, start + 10).forEach((signal) => {
      const [label, level, guidance] = riskSignalGuidance[signal.reason_code] ||
        ["待核对的异常", "人工核对", "请根据服务端记录核实原因与对象归属，不能仅凭该条记录冻结卡密。"];
      const item = document.createElement("li");
      const details = document.createElement("details");
      const summary = document.createElement("summary");
      const title = document.createElement("strong");
      title.textContent = label;
      const status = document.createElement("span");
      status.className = "status status-warm";
      status.textContent = level;
      const time = document.createElement("time");
      time.dateTime = signal.occurred_at || "";
      time.textContent = formatApiDate(signal.occurred_at);
      summary.append(title, status, time);
      const text = document.createElement("p");
      text.textContent = guidance;
      const evidence = document.createElement("dl");
      const values = [
        ["信号编号", signal.signal_id], ["来源动作", signal.action],
        ["原因码", signal.reason_code], ["请求摘要", signal.request_id],
        ["对象线索", signal.object_id ? `${signal.object_type || "未确认类型"} · ${signal.object_id}（仍须核实归属）` : "无法确认归属，不关联卡密处罚"],
      ];
      values.forEach(([name, value]) => {
        const dt = document.createElement("dt");
        const dd = document.createElement("dd");
        dt.textContent = name;
        dd.textContent = value || "—";
        evidence.append(dt, dd);
      });
      details.append(summary, text, evidence);
      item.append(details);
      list.append(item);
    });
    const pages = Math.ceil(riskSignals.length / 10);
    dialog.querySelector("[data-risk-signals-pagination]").hidden = pages < 2;
    dialog.querySelector("[data-risk-signals-page]").textContent = `第 ${riskSignalsPage} / ${pages || 1} 页 · 共 ${riskSignals.length} 条`;
    dialog.querySelector("[data-risk-signals-prev]").disabled = riskSignalsPage <= 1;
    dialog.querySelector("[data-risk-signals-next]").disabled = riskSignalsPage >= pages;
  }

  document.querySelector("[data-risk-signals-prev]")?.addEventListener("click", () => {
    riskSignalsPage -= 1;
    renderRiskSignals(riskSignals, riskSignalsState);
  });
  document.querySelector("[data-risk-signals-next]")?.addEventListener("click", () => {
    riskSignalsPage += 1;
    renderRiskSignals(riskSignals, riskSignalsState);
  });
  document.querySelector("[data-risk-signals-refresh]")?.addEventListener("click", async () => {
    if (isStandaloneStaticPreview && !window.__b1ApiActive) {
      showToast("静态预览不读取真实异常记录。");
      return;
    }
    try { await loadAuthorizationRisk(); }
    catch { /* The bounded read path renders a visible retry state. */ }
  });

  function renderAuthorizationRiskRows(items, pagination = {}, pendingCount = 0) {
    const panel = document.querySelector('[data-screen-panel="risk"]');
    const body = panel?.querySelector("table tbody");
    if (!body) return;
    body.querySelectorAll(":scope > tr.table-placeholder-row").forEach((row) => row.remove());
    body.querySelectorAll(":scope > tr:not(.table-placeholder-row)").forEach((row) => row.remove());
    const rows = Array.isArray(items) ? items : [];
    syncAuthorizationRiskCatalogFilters();
    rows.forEach((item) => {
      const deviceEntries = Array.isArray(item.devices) && item.devices.length
        ? item.devices
        : [{
          device_id: item.device_id || null,
          device_uuid: item.device_uuid || item.device_id || null,
          installation_id: item.installation_id || null,
          device_code: item.device_code || item.installation_id || item.device_label || item.device_id || null,
          device_label: item.device_label || item.device_code || item.installation_id || null,
          binding_state: item.device_binding_state || "unbound",
          binding_state_label: item.device_binding_state_label || "未绑定",
          risk_state: item.device_risk_state || null,
          risk_state_label: item.device_risk_state_label || "未产生",
          action_ref: item.device_action_ref || null,
          ip: item.device_ip || null,
          bound_at: item.device_bound_at || null,
          last_seen_at: item.device_last_seen_at || null,
        }];
      // 一授权一行：多设备收成摘要，详情里看全量与历史。勾选框=授权级（续期/撤销），
      // 批量封禁=该授权下全部活跃设备，单台精确操作走行内按钮（首个活跃设备）。
      const activeEntries = deviceEntries.filter((entry) => entry.binding_state === "active");
      const device = activeEntries[0] || deviceEntries[0];
      {
        const row = document.createElement("tr");
        const allCodes = deviceEntries
          .map((entry) => entry.device_code || entry.installation_id || entry.device_label || entry.device_id)
          .filter(Boolean);
        const uniqueCodes = Array.from(new Set(allCodes));
        const singleCode = device.device_code || device.installation_id || device.device_label || device.device_id || "尚未绑定";
        const deviceCode = uniqueCodes.length <= 1
          ? singleCode
          : `${uniqueCodes.length}台：${uniqueCodes.slice(0, 3).join("、")}${uniqueCodes.length > 3 ? " 等" : ""}`;
        const deviceLabel = deviceCode;
        const allUuids = deviceEntries
          .map((entry) => entry.device_uuid || entry.device_id)
          .filter(Boolean);
        const uniqueUuids = Array.from(new Set(allUuids));
        const fullCodes = uniqueCodes.join("、") || "尚未绑定";
        const fullUuids = uniqueUuids.join("、") || "—";
        const deviceUuid = uniqueCodes.length <= 1
          ? (device.device_uuid || device.device_id || "—")
          : fullUuids;
        const perDeviceStates = deviceEntries.map((entry) => {
          const code = entry.device_code || entry.installation_id || entry.device_label || entry.device_id || "未知设备";
          return `${code}·${authorizationRiskDeviceState(entry)}`;
        });
        const distinctIps = Array.from(new Set(deviceEntries.map((entry) => entry.ip).filter(Boolean)));
        const fullIps = distinctIps.join("、") || "—";
        const fullBounds = deviceEntries.map((entry) => formatApiDate(entry.bound_at)).join(" ｜ ");
        const fullSeens = deviceEntries.map((entry) => formatApiDate(entry.last_seen_at)).join(" ｜ ");
        const deviceActionRef = device.action_ref || device.device_action_ref || device.device_id || "";
        const deviceState = authorizationRiskDeviceState(device);
        const cardFrozen = item.card_frozen === true;
        const wallClockExpired = licenseCardWallClockExpired(item) || item.status === "expired";
        const [authorizationLabel, authorizationClass] = authorizationRiskStatus(item);
        const shownBinding = uniqueCodes.length > 1
          ? `${uniqueCodes.length}台设备`
          : (wallClockExpired && device.binding_state === "active" ? "已过期" : deviceState);
        const blockedCount = deviceEntries.filter((entry) => entry.risk_state === "blocked").length;
        const riskLabel = cardFrozen
          ? "已冻卡"
          : blockedCount === deviceEntries.length && deviceEntries.length > 0 && deviceEntries.every((entry) => entry.device_id)
            ? "已封禁"
            : blockedCount > 0
              ? `部分封禁${blockedCount}/${deviceEntries.length}`
              : device.device_id ? "未封禁" : "—";
        const riskClass = cardFrozen || blockedCount > 0 ? "status-red" : device.device_id ? "status-green" : "status-gray";

        row.dataset.deviceRow = "";
        row.dataset.authorizationId = item.authorization_id || "";
        row.dataset.deviceId = deviceActionRef;
        row.dataset.deviceUuid = deviceUuid;
        row.dataset.riskActionDeviceUuid = device.device_uuid || device.device_id || "";
        row.dataset.deviceCode = deviceCode;
        row.dataset.deviceLicense = item.masked_code || "授权卡密";
        row.dataset.verifyIntervalSeconds = String(item.verify_interval_seconds || "");
        row.dataset.deviceExpires = formatApiDate(item.expires_at);
        row.dataset.deviceBinding = `${deviceLabel} · ${shownBinding}`;
        row.dataset.riskAuthorization = authorizationLabel;
        row.dataset.riskDevice = deviceState;
        row.dataset.riskState = riskLabel;
        row.dataset.riskSoftware = item.software_name || "—";
        row.dataset.riskDownstream = item.downstream_username || "—";
        row.dataset.riskExpiry = riskExpiryLabel(item.expires_at, item.status);
        row.dataset.filterTags = `${row.dataset.riskAuthorization} ${deviceState} ${riskLabel} ${row.dataset.riskSoftware} ${row.dataset.riskDownstream} ${row.dataset.riskExpiry}`;

        row.dataset.riskCustomer = item.downstream_username || "—";
        row.dataset.riskCard = item.masked_code || "••••-••••-????";
        row.dataset.riskSoftwarePlan = `${item.software_name || "—"} / ${item.plan_name || "—"}`;
        row.dataset.riskPlan = item.plan_name || "—";
        row.dataset.riskDeviceCode = fullCodes;
        row.dataset.riskDeviceUuid = fullUuids;
        row.dataset.riskDeviceLabel = uniqueCodes.length > 1 ? perDeviceStates.join(" ｜ ") : `${deviceLabel} · ${shownBinding}`;
        row.dataset.riskIp = fullIps;
        row.dataset.riskAuthorizationLabel = authorizationLabel;
        row.dataset.riskRiskLabel = riskLabel;
        row.dataset.riskActivated = formatApiDate(item.activated_at);
        row.dataset.riskBound = fullBounds;
        row.dataset.riskVerified = formatApiDate(item.last_verified_at);
        row.dataset.riskSeen = fullSeens;
        row.dataset.riskExpires = formatApiDate(item.expires_at);
        row.dataset.riskRenewal = item.renewal_tag || (item.is_renewed ? "已续期" : "无");
        row.dataset.riskAuthorizationState = item.status || "";
        row.dataset.riskWallClockExpired = String(wallClockExpired);
        row.dataset.riskAudit = item.audit_reference || "—";
        row.dataset.riskHistory = deviceEntries
          .map((entry) => {
            const code = entry.device_code || entry.installation_id || entry.device_label || entry.device_id || "未知设备";
            const history = Array.isArray(entry.binding_history) && entry.binding_history.length
              ? entry.binding_history.map((h) => `${h.binding_state_label || "状态未知"} · ${formatApiDate(h.bound_at)}`).join("；")
              : `${entry.binding_state_label || authorizationRiskDeviceState(entry)} · ${formatApiDate(entry.bound_at)}`;
            return uniqueCodes.length > 1 ? `${code}：${history}` : history;
          })
          .join(" ｜ ") || "暂无绑定历史";

        const canSelect = Boolean(item.authorization_id);
        const selectCell = document.createElement("td");
        const selectBox = document.createElement("input");
        selectBox.type = "checkbox";
        selectBox.dataset.renewSelect = "";
        selectBox.value = item.authorization_id || "";
        selectBox.setAttribute("aria-label", `选择 ${row.dataset.riskCard} 的授权`);
        selectBox.disabled = !canSelect;
        if (canSelect && persistentSelectedIds.has(selectBox.value)) {
          selectBox.checked = true;
          rememberRowLabel(selectBox.value, row);
        }
        if (canSelect) {
          selectBox.addEventListener("change", () => {
            if (selectBox.checked) {
              if (persistentSelectedIds.size >= MAX_BATCH_IDS && !persistentSelectedIds.has(selectBox.value)) {
                selectBox.checked = false;
                showToast(`一次最多选择 ${MAX_BATCH_IDS} 条，请缩小范围。`);
                syncSelectAllHeader();
                return;
              }
              persistentSelectedIds.add(selectBox.value);
              rememberRowLabel(selectBox.value, row);
            } else {
              const stillChecked = Array.from(
                riskPanel()?.querySelectorAll(`[data-renew-select][value="${CSS.escape(selectBox.value)}"]`) || [],
              ).some((box) => box.checked && !box.disabled);
              if (!stillChecked) {
                persistentSelectedIds.delete(selectBox.value);
                persistentSelectedLabels.delete(selectBox.value);
              }
            }
            syncRenewSelection();
            syncSelectAllHeader();
          });
        }
        selectCell.append(selectBox);
        row.append(selectCell);

        appendTextCell(row, row.dataset.riskCustomer);
        appendTextCell(row, row.dataset.riskCard, "mono");
        appendSoftwareCell(row, item.software_name || "—");
        appendPlanCell(row, item.plan_name || "—", item.duration_label || "");
        appendTextCell(row, deviceCode, "mono");
        appendStatusCell(row, authorizationLabel, authorizationClass);
        appendStatusCell(row, riskLabel, riskClass);
        appendTextCell(row, formatApiDate(item.expires_at), "mono");
        appendTextCell(row, formatApiDate(item.last_verified_at), "mono");

        const actionCell = document.createElement("td");
        const actions = document.createElement("div");
        actions.className = "table-actions";

        const detail = createTableButton("详情", {
          kind: "detail",
          tooltip: "查看该条授权的完整排障信息与绑定历史",
        });
        detail.dataset.riskDetail = "";
        actions.append(detail);

        const canReset = Boolean(device.device_id && device.binding_state === "active" && !cardFrozen);
        appendAuthorizationRiskAction(actions, "重置设备（只解绑）", "reset", {
          disabled: !canReset,
          disabledReason: cardFrozen ? "卡密已被冻结，不可重置设备" : "未绑定活跃设备，无需重置",
        });

        if (item.time_rollback_blocked === true) {
          appendAuthorizationRiskAction(actions, "恢复时间阻断", "recover", {
            disabled: !device.device_id,
            disabledReason: "缺少设备引用，请刷新后核对授权记录",
          });
        } else if (cardFrozen) {
          appendAuthorizationRiskAction(actions, "解冻卡密", "unblock");
        } else if (device.risk_state === "blocked") {
          appendAuthorizationRiskAction(actions, "冻结这张卡", "block", {
            disabled: true,
            disabledReason: "设备已被硬件拉黑，请选择该授权后点“解封设备”，单卡冻结不适用",
          });
        } else {
          const canFreeze = Boolean(device.device_id);
          appendAuthorizationRiskAction(actions, "冻结卡密", "block", {
            disabled: !canFreeze,
            disabledReason: "暂无设备或不可封禁",
          });
        }

        actionCell.append(actions);
        row.append(actionCell);
        body.append(row);
      }
    });
    const tablePanel = panel.querySelector(".table-panel");
    if (tablePanel) tablePanel.dataset.serverDataLoaded = "true";
    const summary = panel.querySelector(".table-result");
    if (summary) {
      const total = Number(pagination.total);
      const matchCount = Number.isFinite(total) ? total : rows.length + (pagination.has_next ? "+" : "");
      const pending = Number.isFinite(Number(pendingCount)) ? Number(pendingCount) : 0;
      summary.textContent = pagination.query
        ? `搜索结果 ${matchCount} · 待处理 ${pending}`
        : `待处理 ${pending} · 当前授权 ${matchCount}`;
    }
    const serverPagination = panel.querySelector("[data-risk-server-pagination]");
    if (serverPagination) {
      serverPagination.hidden = isStandaloneStaticPreview;
      serverPagination.querySelector("[data-risk-server-prev]").disabled = !pagination.has_previous;
      serverPagination.querySelector("[data-risk-server-next]").disabled = !pagination.has_next;
      serverPagination.querySelector("[data-risk-server-page]").textContent = formatServerPageLabel(pagination);
    }
    bindAuthorizationRiskFilters();
    bindAuthorizationRiskSearch();
    window.__previewRefreshTables?.();
    applyAuthorizationRiskFilters();
    syncRenewSelection();
    syncSelectAllHeader();
  }

  const renewDialog = document.getElementById("renewAuthorizationDialog");
  let renewPreviewIds = [];
  let renewIdempotencyKey = null;
  let renewPreviewSequence = 0;
  const persistentSelectedIds = new Set();
  const persistentSelectedLabels = new Map();
  let riskSelectionGeneration = 0;
  let riskSelectionBusy = false;

  function riskPanel() {
    return document.querySelector('[data-screen-panel="risk"]');
  }

  function selectedRenewIds() {
    return Array.from(persistentSelectedIds);
  }

  function rememberRowLabel(id, row) {
    if (!id || !row) return;
    persistentSelectedLabels.set(
      id,
      `${row.dataset.riskCard || "授权"} · ${row.dataset.riskSoftware || "—"} · ${row.dataset.deviceExpires || "—"}`,
    );
  }

  function visibleRenewBoxes() {
    return Array.from(riskPanel()?.querySelectorAll("[data-renew-select]") || []).filter((box) => {
      if (box.disabled || !box.value) return false;
      const row = box.closest("tr");
      if (row && (row.hidden || row.style.display === "none")) return false;
      return true;
    });
  }

  function syncSelectAllHeader() {
    const header = document.querySelector("[data-renew-select-all]");
    if (!header) return;
    const boxes = visibleRenewBoxes();
    const checked = boxes.filter((box) => box.checked);
    header.disabled = boxes.length === 0;
    header.checked = boxes.length > 0 && checked.length === boxes.length;
    header.indeterminate = checked.length > 0 && checked.length < boxes.length;
  }

  const MAX_BATCH_IDS = 500;

  function batchIdsWithinLimit(error, actionLabel) {
    const ids = selectedRenewIds();
    if (ids.length > MAX_BATCH_IDS) {
      if (error) error.textContent = `一次最多${actionLabel} ${MAX_BATCH_IDS} 条，请缩小范围。`;
      return false;
    }
    return true;
  }

  function syncRenewSelection() {
    const count = persistentSelectedIds.size;
    let onPage = 0;
    riskPanel()?.querySelectorAll("[data-renew-select]").forEach((box) => {
      box.checked = persistentSelectedIds.has(box.value);
      if (box.checked && !box.closest("tr")?.hidden) onPage += 1;
    });
    const summary = document.querySelector("[data-risk-selection-summary]");
    if (summary) summary.textContent = `已选 ${count} 条${count > onPage ? ` · 本页 ${onPage} 条` : ""}`;
    document.querySelectorAll("[data-renew-open], [data-bulk-revoke-open], [data-bulk-block-open], [data-bulk-unblock-open], [data-clear-selection]")
      .forEach((button) => { button.disabled = count === 0 || riskSelectionBusy; });
  }

  function clearSubmittedSelection(ids) {
    (ids || []).forEach((id) => {
      persistentSelectedIds.delete(id);
      persistentSelectedLabels.delete(id);
    });
    syncRenewSelection();
    syncSelectAllHeader();
  }

  document.querySelector("[data-renew-select-all]")?.addEventListener("change", (event) => {
    const turnOn = event.currentTarget.checked;
    visibleRenewBoxes().forEach((box) => {
      if (box.checked === turnOn) return;
      box.checked = turnOn;
      box.dispatchEvent(new Event("change"));
    });
    syncSelectAllHeader();
  });

  function clearRiskSelection() {
    riskSelectionGeneration += 1;
    riskSelectionBusy = false;
    persistentSelectedIds.clear(); persistentSelectedLabels.clear();
    syncRenewSelection(); syncSelectAllHeader();
  }

  document.querySelector("[data-clear-selection]")?.addEventListener("click", clearRiskSelection);
  document.querySelector("[data-device-authorization-filters]")?.addEventListener("change", clearRiskSelection, true);
  document.querySelector("[data-risk-search]")?.addEventListener("input", clearRiskSelection, true);
  document.querySelector("[data-risk-select-filtered]")?.addEventListener("click", async (event) => {
    if (riskSelectionBusy) return;
    if (isStandaloneStaticPreview && !window.__b1ApiActive) { showToast("静态预览没有业务记录可选。"); return; }
    const button = event.currentTarget;
    const generation = ++riskSelectionGeneration;
    riskSelectionBusy = true; button.disabled = true; button.textContent = "正在读取选择范围…"; syncRenewSelection();
    const picked = new Map();
    try {
      const query = new URLSearchParams({page_size:"100"});
      const rawSearch = document.querySelector("[data-risk-search]")?.value.trim() || "";
      if (rawSearch) query.set("q", await resolveTableSearchQuery(rawSearch,"license"));
      riskPanel()?.querySelectorAll("[data-risk-filter]").forEach((select) => { if (select.value) query.set(select.dataset.riskFilter,select.value); });
      let hasNext = true;
      for (let page = 1; hasNext && page <= 20; page += 1) {
        query.set("page",String(page));
        const payload = await apiRequest(`/manage/authorizations/?${query}`);
        if (generation !== riskSelectionGeneration) return;
        for (const item of payload.items || []) {
          if (item.authorization_id) picked.set(item.authorization_id,`${item.masked_code || "授权"} · ${item.software_name || "—"} · ${formatApiDate(item.expires_at)}`);
        }
        if (picked.size > MAX_BATCH_IDS) throw new Error(`一次最多选择 ${MAX_BATCH_IDS} 条授权，请缩小范围。`);
        hasNext = Boolean(payload.pagination?.has_next);
        if (hasNext && !(payload.items || []).length) throw new Error("选择范围未完整读取，请重试。");
      }
      if (hasNext) throw new Error("选择范围过大，请缩小筛选后重试。");
      persistentSelectedIds.clear(); persistentSelectedLabels.clear();
      picked.forEach((label,id) => { persistentSelectedIds.add(id); persistentSelectedLabels.set(id,label); });
      showToast(`已选择筛选结果中的 ${picked.size} 条授权。新增记录不会自动加入这次选择。`);
    } catch (error) {
      if (generation === riskSelectionGeneration) showToast(apiErrorMessage(error,"选择范围读取失败，请重试。"));
    } finally {
      if (generation === riskSelectionGeneration) riskSelectionBusy = false;
      button.disabled = false; button.textContent = "选择全部筛选结果";
      syncRenewSelection(); syncSelectAllHeader();
    }
  });
  syncRenewSelection(); syncSelectAllHeader();

  function syncGenericSelectAll(table) {
    if (!table) return;
    const header = table.querySelector("thead [data-select-all]:not([data-renew-select-all])");
    if (!header) return;
    const boxes = Array.from(table.querySelectorAll("tbody input[type='checkbox']")).filter((box) => {
      if (box.disabled) return false;
      const row = box.closest("tr");
      if (row && (row.hidden || row.style.display === "none")) return false;
      return true;
    });
    const checked = boxes.filter((box) => box.checked);
    header.disabled = boxes.length === 0;
    header.checked = boxes.length > 0 && checked.length === boxes.length;
    header.indeterminate = checked.length > 0 && checked.length < boxes.length;
  }

  document.addEventListener("change", (event) => {
    const header = event.target.closest?.("[data-select-all]");
    if (header && !header.hasAttribute("data-renew-select-all")) {
      const table = header.closest("table");
      if (!table) return;
      const turnOn = header.checked;
      let touched = 0;
      table.querySelectorAll("tbody input[type='checkbox']").forEach((box) => {
        const row = box.closest("tr");
        if (box.disabled || box.checked === turnOn) return;
        if (row && (row.hidden || row.style.display === "none")) return;
        box.checked = turnOn;
        box.dispatchEvent(new Event("change", { bubbles: true }));
        touched += 1;
      });
      if (turnOn && touched === 0) {
        header.checked = false;
        showToast("当前没有可选行。");
      }
      syncGenericSelectAll(table);
      return;
    }
    const rowBox = event.target.closest?.('tbody input[type="checkbox"]');
    if (rowBox) syncGenericSelectAll(rowBox.closest("table"));
  });

  function renewUnitLabel() {
    return document.getElementById("renewUnit")?.value === "hour" ? "小时" : "天";
  }

  const MAX_RENEW_AMOUNT = { day: 366, hour: 366 * 24 };

  function renewUnitValue() {
    return document.getElementById("renewUnit")?.value === "hour" ? "hour" : "day";
  }

  function renewAmountValue() {
    const raw = Number(document.getElementById("renewAmount")?.value);
    if (!Number.isFinite(raw)) return 0;
    return Math.floor(raw);
  }

  function renewAmountError() {
    const amountInput = document.getElementById("renewAmount");
    const raw = Number(amountInput?.value);
    const unit = renewUnitValue();
    const cap = MAX_RENEW_AMOUNT[unit];
    const unitLabel = unit === "hour" ? "小时" : "天";
    if (!Number.isFinite(raw) || Math.floor(raw) < 1) return "请填写要加的天数或小时数。";
    if (Math.floor(raw) > cap) return `按${unitLabel}单次最多加 ${cap}，请分多次续期。`;
    return "";
  }

  function resetRenewDialog() {
    renewPreviewIds = [];
    const scope = renewDialog?.querySelector("[data-renew-scope]");
    const count = renewDialog?.querySelector("[data-renew-count]");
    const list = renewDialog?.querySelector("[data-renew-preview-list]");
    const error = renewDialog?.querySelector("[data-renew-error]");
    const confirm = renewDialog?.querySelector("[data-renew-confirm]");
    if (scope) scope.textContent = "—";
    if (count) count.textContent = "—";
    if (list) list.textContent = "还没有读取续期范围。";
    if (error) error.textContent = "";
    if (confirm) confirm.disabled = true;
  }

  async function loadRenewPreview() {
    if (!renewDialog) return;
    const scope = renewDialog.querySelector("[data-renew-scope]");
    const count = renewDialog.querySelector("[data-renew-count]");
    const list = renewDialog.querySelector("[data-renew-preview-list]");
    const error = renewDialog.querySelector("[data-renew-error]");
    const confirm = renewDialog.querySelector("[data-renew-confirm]");
    const amount = renewAmountValue();
    const unit = renewUnitValue();
    const unitLabel = renewUnitLabel();
    if (error) error.textContent = "";
    if (confirm) confirm.disabled = true;
    renewPreviewIds = [];
    const amountProblem = renewAmountError();
    if (amountProblem) {
      if (list) list.textContent = amountProblem;
      return;
    }
    const picked = (renewDialog.__selectedIds || []).slice();
    if (picked.length) {
      const sequence = ++renewPreviewSequence;
      const panel = document.querySelector('[data-screen-panel="risk"]');
      const labels = [];
      const renewableIds = [];
      let skippedCount = 0;
      let domRenewableCount = 0;
      const seenRows = new Set();
      panel?.querySelectorAll("[data-device-row]").forEach((row) => {
        const id = row.dataset.authorizationId || "";
        if (!picked.includes(id)) return;
        seenRows.add(id);
        const status = row.dataset.riskAuthorizationState || "";
        const isExpired = row.dataset.riskWallClockExpired === "true" || ["revoked", "expired", "blocked"].includes(status);
        if (isExpired) {
          skippedCount += 1;
          return;
        }
        if (!renewableIds.includes(id)) {
          renewableIds.push(id);
          domRenewableCount += 1;
          labels.push({
            id,
            text: `${row.dataset.riskCard || "授权"} · ${row.dataset.riskSoftware || "—"} · ${row.dataset.deviceExpires || "—"}`,
          });
        }
      });
      picked.forEach((id) => {
        if (seenRows.has(id) || renewableIds.includes(id)) return;
        renewableIds.push(id);
        labels.push({
          id,
          text: persistentSelectedLabels.get(id) || `授权 ${String(id).slice(0, 8)}…（跨页已选，待服务端确认）`,
        });
      });
      if (sequence !== renewPreviewSequence) return;
      renewPreviewIds = renewableIds.slice();
      const pendingIds = picked.filter((id) => !seenRows.has(id));
      if (!renewPreviewIds.length && !pendingIds.length) {
        if (scope) scope.textContent = `已勾选 ${picked.length} 条（全部不可续期）`;
        if (count) count.textContent = "—";
        if (list) list.textContent = "所选授权均不可续期：只有已激活且未过期的授权能补时间。";
        if (confirm) confirm.disabled = true;
        return;
      }
      if (scope) {
        const parts = [`已勾选 ${picked.length} 条（本页可续期 ${domRenewableCount} 条`];
        if (pendingIds.length > 0) parts.push(`跨页 ${pendingIds.length} 条待服务端确认`);
        if (skippedCount > 0) parts.push(`已跳过 ${skippedCount} 条已失效`);
        parts.push("）");
        scope.textContent = parts.join("");
      }
      if (count) count.textContent = `+${amount} ${unitLabel}`;
      if (list) list.textContent = `将续期：${labels.map((entry) => entry.text).join("；")}`;
      if (confirm) confirm.disabled = false;
      return;
    }
    if (scope) scope.textContent = "尚未选择授权";
    if (count) count.textContent = "—";
    if (list) list.textContent = "请先在列表中勾选授权，或明确选择全部筛选结果。";
  }

  document.querySelector("[data-renew-open]")?.addEventListener("click", async () => {
    if (!renewDialog) return;
    if (resumeDialogWrite(renewDialog, "risk:renew")) return;
    const ids = selectedRenewIds();
    if (!ids.length) { showToast("请先选择需要加时间的授权。"); return; }
    prepareDialogWrite(renewDialog, "risk:renew", ids);
    restoreDialogWrite(renewDialog);
    const reason = document.getElementById("renewReason");
    if (reason) reason.value = "";
    const amount = document.getElementById("renewAmount");
    if (amount) amount.value = "1";
    resetRenewDialog();
    renewIdempotencyKey = requestIdempotencyKey("authorization-renew");
    renewDialog.showModal();
    await loadRenewPreview();
  });

  ["[data-renew-amount]", "#renewAmount", "#renewUnit"].forEach((selector) => {
    document.querySelector(selector)?.addEventListener("change", () => {
      if (renewDialog?.open) loadRenewPreview().catch(() => {});
    });
  });
  let renewPreviewTimer = null;
  document.getElementById("renewAmount")?.addEventListener("input", () => {
    if (!renewDialog?.open) return;
    if (renewPreviewTimer) clearTimeout(renewPreviewTimer);
    renewPreviewTimer = setTimeout(() => {
      renewPreviewTimer = null;
      if (renewDialog?.open) loadRenewPreview().catch(() => {});
    }, 400);
  });
  renewDialog?.addEventListener("close", () => {
    if (renewPreviewTimer) {
      clearTimeout(renewPreviewTimer);
      renewPreviewTimer = null;
    }
    renewPreviewSequence += 1;
  });

  renewDialog?.querySelector("[data-renew-confirm]")?.addEventListener("click", async (event) => {
    const dialog = renewDialog;
    const error = dialog.querySelector("[data-renew-error]");
    const reason = document.getElementById("renewReason")?.value.trim() || "";
    const amount = renewAmountValue();
    const unit = renewUnitValue();
    if (error) error.textContent = "";
    if (reason.length < 2) {
      if (error) error.textContent = "请填写至少 2 个字的续期原因。";
      return;
    }
    const amountCheck = renewAmountError();
    if (amountCheck) {
      if (error) error.textContent = amountCheck;
      return;
    }
    if (!renewPreviewIds.length) {
      if (error) error.textContent = "请先勾选授权，或让当前筛选有可续期的授权。";
      return;
    }
    if (renewPreviewIds.length > MAX_BATCH_IDS) {
      if (error) error.textContent = `一次最多续期 ${MAX_BATCH_IDS} 条，请缩小范围。`;
      return;
    }
    if (isStandaloneStaticPreview && !window.__b1ApiActive) {
      if (error) error.textContent = "静态预览不执行真实续期。";
      return;
    }
    event.currentTarget.disabled = true;
    try {
      if (!renewIdempotencyKey) renewIdempotencyKey = requestIdempotencyKey("authorization-renew");
      const payload = await submitDialogWrite(dialog, "/manage/authorizations/renew/", {
        authorization_ids: renewPreviewIds.slice(), unit, amount, reason,
      }, "authorization-renew");
      const renewed = Number(payload.renewed_count || 0);
      const failed = Number(payload.failed_count || 0);
      dialog.close("success");
      renewPreviewIds.forEach((id) => {
        persistentSelectedIds.delete(id);
        persistentSelectedLabels.delete(id);
      });
      resetRenewDialog();
      renewIdempotencyKey = null;
      showToast(
        failed
          ? `已续期 ${renewed} 条，${failed} 条被跳过（已过期、已撤销或已阻断）。每条的跳过原因都记了审计。`
          : `已续期 ${renewed} 条。客户下次握手就会拿到新的到期时间。没有写额度流水，也不计入收入。`,
      );
      try {
        await loadAuthorizationRisk(authorizationRiskRequestState.page);
      } catch (_reloadError) {
        showToast("列表刷新失败，续期已成功，请手动刷新页面。");
      }
    } catch (requestError) {
      if (error) error.textContent = apiErrorMessage(requestError, "续期失败，请重试。");
    } finally {
      const confirm = dialog.querySelector("[data-renew-confirm]");
      if (confirm) confirm.disabled = false;
    }
  });

  const bulkRevokeDialog = document.getElementById("bulkRevokeDialog");
  const bulkBlockDialog = document.getElementById("bulkBlockDialog");

  document.querySelector("[data-bulk-revoke-open]")?.addEventListener("click", () => {
    if (!bulkRevokeDialog) return;
    if (resumeDialogWrite(bulkRevokeDialog, "risk:revoke")) return;
    const ids = selectedRenewIds();
    if (!ids.length) {
      showToast("请先在列表中勾选要撤销的授权。");
      return;
    }
    prepareDialogWrite(bulkRevokeDialog, "risk:revoke", ids);
    restoreDialogWrite(bulkRevokeDialog);
    const countLabel = bulkRevokeDialog.querySelector("[data-bulk-revoke-count]");
    if (countLabel) countLabel.textContent = `${ids.length} 条`;
    const reason = document.getElementById("bulkRevokeReason");
    if (reason) reason.value = "";
    const error = bulkRevokeDialog.querySelector("[data-bulk-revoke-error]");
    if (error) error.textContent = "";
    const confirmBtn = bulkRevokeDialog.querySelector("[data-bulk-revoke-confirm]");
    if (confirmBtn) confirmBtn.disabled = false;
    bulkRevokeDialog.showModal();
  });

  bulkRevokeDialog?.querySelector("[data-bulk-revoke-confirm]")?.addEventListener("click", async (event) => {
    const dialog = bulkRevokeDialog;
    const error = dialog.querySelector("[data-bulk-revoke-error]");
    const reason = document.getElementById("bulkRevokeReason")?.value.trim() || "";
    const ids = (dialog.__selectedIds || []).slice();
    if (error) error.textContent = "";
    if (reason.length < 2) {
      if (error) error.textContent = "请填写至少 2 个字的撤销原因。";
      return;
    }
    if (!ids.length) {
      if (error) error.textContent = "没有勾选授权，请关闭重选。";
      return;
    }
    if (ids.length > MAX_BATCH_IDS) {
      if (error) error.textContent = `一次最多处理 ${MAX_BATCH_IDS} 条，请缩小范围。`;
      return;
    }
    if (isStandaloneStaticPreview && !window.__b1ApiActive) {
      if (error) error.textContent = "静态预览不执行真实撤销。";
      return;
    }
    event.currentTarget.disabled = true;
    try {
      const payload = await submitDialogWrite(dialog, "/manage/authorizations/bulk-revoke/", { authorization_ids: ids, reason }, "authorization-revoke");
      const revoked = Number(payload.revoked_count || 0);
      const failed = Number(payload.failed_count || 0);
      dialog.close("success");
      clearSubmittedSelection(ids);
      showToast(
        failed
          ? `已撤销 ${revoked} 条，${failed} 条失败。`
          : `已撤销 ${revoked} 条授权，对应卡密同步失效。`
      );
      try {
        await loadAuthorizationRisk(authorizationRiskRequestState.page);
      } catch (_reloadError) {
        showToast("列表刷新失败，撤销已成功，请手动刷新页面。");
      }
    } catch (requestError) {
      if (error) error.textContent = apiErrorMessage(requestError, "撤销失败，请重试。");
    } finally {
      const confirm = dialog.querySelector("[data-bulk-revoke-confirm]");
      if (confirm) confirm.disabled = false;
    }
  });

  document.querySelector("[data-bulk-block-open]")?.addEventListener("click", () => {
    if (!bulkBlockDialog) return;
    if (resumeDialogWrite(bulkBlockDialog, "risk:block")) return;
    const ids = selectedRenewIds();
    if (!ids.length) {
      showToast("请先在列表中勾选要封禁设备的授权。");
      return;
    }
    prepareDialogWrite(bulkBlockDialog, "risk:block", ids);
    restoreDialogWrite(bulkBlockDialog);
    const countLabel = bulkBlockDialog.querySelector("[data-bulk-block-count]");
    if (countLabel) countLabel.textContent = `${ids.length} 条`;
    const reason = document.getElementById("bulkBlockReason");
    if (reason) reason.value = "";
    const error = bulkBlockDialog.querySelector("[data-bulk-block-error]");
    if (error) error.textContent = "";
    const confirmBtn = bulkBlockDialog.querySelector("[data-bulk-block-confirm]");
    if (confirmBtn) confirmBtn.disabled = false;
    bulkBlockDialog.showModal();
  });

  bulkBlockDialog?.querySelector("[data-bulk-block-confirm]")?.addEventListener("click", async (event) => {
    const dialog = bulkBlockDialog;
    const error = dialog.querySelector("[data-bulk-block-error]");
    const reason = document.getElementById("bulkBlockReason")?.value.trim() || "";
    const ids = (dialog.__selectedIds || []).slice();
    if (error) error.textContent = "";
    if (reason.length < 2) {
      if (error) error.textContent = "请填写至少 2 个字的封禁原因。";
      return;
    }
    if (reason.length > 255) {
      if (error) error.textContent = "封禁原因不能超过 255 个字。";
      return;
    }
    if (!ids.length) {
      if (error) error.textContent = "没有勾选授权，请关闭重选。";
      return;
    }
    if (ids.length > MAX_BATCH_IDS) {
      if (error) error.textContent = `一次最多处理 ${MAX_BATCH_IDS} 条，请缩小范围。`;
      return;
    }
    if (isStandaloneStaticPreview && !window.__b1ApiActive) {
      if (error) error.textContent = "静态预览不执行真实封禁。";
      return;
    }
    event.currentTarget.disabled = true;
    try {
      const payload = await submitDialogWrite(dialog, "/manage/authorizations/bulk-block/", { authorization_ids: ids, reason }, "authorization-block");
      const blocked = Number(payload.blocked_count || 0);
      const failed = Number(payload.failed_count || 0);
      const skipped = (payload.failures || []).filter((entry) => entry.code === "DEVICE_NOT_BOUND").length;
      const errored = failed - skipped;
      dialog.close("success");
      clearSubmittedSelection(ids);
      showToast(
        errored > 0
          ? `已封禁 ${blocked} 台设备，${skipped} 条跳过（无活跃绑定），${errored} 条失败，请看审计。`
          : failed
            ? `已封禁 ${blocked} 台设备，${failed} 条跳过（无活跃绑定）。`
            : `已封禁 ${blocked} 台物理设备，相关绑定全部立即阻断。`
      );
      try {
        await loadAuthorizationRisk(authorizationRiskRequestState.page);
      } catch (_reloadError) {
        showToast("列表刷新失败，封禁已成功，请手动刷新页面。");
      }
    } catch (requestError) {
      if (error) error.textContent = apiErrorMessage(requestError, "封禁设备失败，请重试。");
    } finally {
      const confirm = dialog.querySelector("[data-bulk-block-confirm]");
      if (confirm) confirm.disabled = false;
    }
  });

  const bulkUnblockDialog = document.getElementById("bulkUnblockDialog");

  document.querySelector("[data-bulk-unblock-open]")?.addEventListener("click", () => {
    if (!bulkUnblockDialog) return;
    if (resumeDialogWrite(bulkUnblockDialog, "risk:unblock")) return;
    const ids = selectedRenewIds();
    if (!ids.length) {
      showToast("请先在列表中勾选要解封设备的授权。");
      return;
    }
    prepareDialogWrite(bulkUnblockDialog, "risk:unblock", ids);
    restoreDialogWrite(bulkUnblockDialog);
    const countLabel = bulkUnblockDialog.querySelector("[data-bulk-unblock-count]");
    if (countLabel) countLabel.textContent = `${ids.length} 条`;
    const reason = document.getElementById("bulkUnblockReason");
    if (reason) reason.value = "";
    const error = bulkUnblockDialog.querySelector("[data-bulk-unblock-error]");
    if (error) error.textContent = "";
    const confirmBtn = bulkUnblockDialog.querySelector("[data-bulk-unblock-confirm]");
    if (confirmBtn) confirmBtn.disabled = false;
    bulkUnblockDialog.showModal();
  });

  bulkUnblockDialog?.querySelector("[data-bulk-unblock-confirm]")?.addEventListener("click", async (event) => {
    const dialog = bulkUnblockDialog;
    const error = dialog.querySelector("[data-bulk-unblock-error]");
    const reason = document.getElementById("bulkUnblockReason")?.value.trim() || "";
    const ids = (dialog.__selectedIds || []).slice();
    if (error) error.textContent = "";
    if (reason.length < 2) {
      if (error) error.textContent = "请填写至少 2 个字的解封原因。";
      return;
    }
    if (reason.length > 255) {
      if (error) error.textContent = "解封原因不能超过 255 个字。";
      return;
    }
    if (!ids.length) {
      if (error) error.textContent = "没有勾选授权，请关闭重选。";
      return;
    }
    if (ids.length > MAX_BATCH_IDS) {
      if (error) error.textContent = `一次最多处理 ${MAX_BATCH_IDS} 条，请缩小范围。`;
      return;
    }
    if (isStandaloneStaticPreview && !window.__b1ApiActive) {
      if (error) error.textContent = "静态预览不执行真实解封。";
      return;
    }
    event.currentTarget.disabled = true;
    try {
      const payload = await submitDialogWrite(dialog, "/manage/authorizations/bulk-unblock/", { authorization_ids: ids, reason }, "authorization-unblock");
      const unblocked = Number(payload.unblocked_count || 0);
      const failed = Number(payload.failed_count || 0);
      const skipped = (payload.failures || []).filter((entry) => entry.code === "DEVICE_NOT_BLOCKED").length;
      const errored = failed - skipped;
      dialog.close("success");
      clearSubmittedSelection(ids);
      showToast(
        errored > 0
          ? `已解封 ${unblocked} 台设备，${skipped} 条跳过（无被封绑定），${errored} 条失败，请看审计。`
          : failed
            ? `已解封 ${unblocked} 台设备，${failed} 条跳过（无被封绑定）。`
            : `已解封 ${unblocked} 台物理设备，被封设备可用新卡重新激活。`
      );
      try {
        await loadAuthorizationRisk(authorizationRiskRequestState.page);
      } catch (_reloadError) {
        showToast("列表刷新失败，解封已成功，请手动刷新页面。");
      }
    } catch (requestError) {
      if (error) error.textContent = apiErrorMessage(requestError, "解封设备失败，请重试。");
    } finally {
      const confirm = dialog.querySelector("[data-bulk-unblock-confirm]");
      if (confirm) confirm.disabled = false;
    }
  });

  let authorizationRiskPendingCache = { key: "", total: 0 };

  async function loadAuthorizationRisk(page = authorizationRiskRequestState.page, options = {}) {
    const { refreshPending = true } = options;
    const request = beginAuthorizationRiskRequest();
    renderRiskSignals([], "loading");
    try {
      const rawSearch = document.querySelector("[data-risk-search]")?.value.trim() || "";
      const search = rawSearch ? await resolveTableSearchQuery(rawSearch, "license") : "";
      const query = new URLSearchParams({ page_size: "10", page: String(Math.max(1, page)) });
      if (search) query.set("q", search);
      const screen = document.querySelector('[data-screen-panel="risk"]');
      screen?.querySelectorAll("[data-device-authorization-filters] select").forEach((select) => {
        const key = select.dataset.riskFilter;
        if (key && select.value) query.set(key, select.value);
      });
      const payload = await apiRequest(`/manage/authorizations/?${query.toString()}`, {
        signal: request.controller.signal,
      });
      if (!isCurrentAuthorizationRiskRequest(request)) return null;
      renderRiskSignals(payload.risk_signals || []);
      // 待处理数变化极少，翻页沿用缓存，只在筛选/搜索/批量动作后刷新，省一次跨站往返。
      const pendingKey = (() => {
        const keyParams = new URLSearchParams(query);
        keyParams.delete("page");
        keyParams.delete("page_size");
        return keyParams.toString();
      })();
      let pendingTotal = 0;
      if (query.get("risk_state") === "blocked") {
        pendingTotal = Number(payload.pagination?.total) || 0;
        authorizationRiskPendingCache = { key: pendingKey, total: pendingTotal };
      } else if (!refreshPending && authorizationRiskPendingCache.key === pendingKey) {
        pendingTotal = authorizationRiskPendingCache.total;
      } else {
        const pendingQuery = new URLSearchParams(query);
        pendingQuery.set("risk_state", "blocked");
        pendingQuery.set("page", "1");
        pendingQuery.set("page_size", "1");
        const pendingPayload = await apiRequest(`/manage/authorizations/?${pendingQuery.toString()}`, {
          signal: request.controller.signal,
        });
        if (!isCurrentAuthorizationRiskRequest(request)) return null;
        pendingTotal = Number(pendingPayload.pagination?.total) || 0;
        authorizationRiskPendingCache = { key: pendingKey, total: pendingTotal };
      }
      authorizationRiskRequestState.page = payload.pagination?.page || page;
      authorizationRiskRequestState.hasNext = Boolean(payload.pagination?.has_next);
      renderAuthorizationRiskRows(payload.items || [], payload.pagination || {}, pendingTotal);
      return payload;
    } catch (error) {
      if (error?.name === "AbortError" || !isCurrentAuthorizationRiskRequest(request)) return null;
      renderRiskSignals([], "error");
      throw error;
    } finally {
      if (isCurrentAuthorizationRiskRequest(request)) authorizationRiskRequestState.controller = null;
    }
  }

  function bindAuthorizationRiskSearch() {
    const input = document.querySelector("[data-risk-search]");
    const submit = document.querySelector("[data-risk-search-submit]");
    if (!input || input.dataset.searchBound) return;
    input.dataset.searchBound = "true";
    const runSearch = () => {
      window.clearTimeout(authorizationRiskSearchTimer);
      authorizationRiskRequestState.page = 1;
      if (!authorizationRiskUsesServerFilters()) {
        const query = input.value.trim().toLowerCase();
        const screen = document.querySelector('[data-screen-panel="risk"]');
        const state = tableStateForScreen(screen);
        if (state) {
          state.rows.forEach((row) => {
            const haystack = `${row.dataset.filterTags || ""} ${row.dataset.deviceLicense || ""} ${row.dataset.deviceId || ""} ${row.dataset.deviceCode || ""}`.toLowerCase();
            row.dataset.criteriaMatch = String(!query || haystack.includes(query));
          });
          state.page = 1;
          renderTableState(state, false);
        }
        return;
      }
      if (submit) {
        submit.disabled = true;
        submit.textContent = "搜索中…";
      }
      loadAuthorizationRisk()
        .catch((error) => showToast(apiErrorMessage(error, "设备与授权搜索失败，请重试。")))
        .finally(() => {
          if (submit) {
            submit.disabled = false;
            submit.textContent = "搜索";
          }
        });
    };
    input.addEventListener("keydown", (event) => {
      if (event.key === "Enter") {
        event.preventDefault();
        runSearch();
      }
    });
    input.addEventListener("input", () => {
      window.clearTimeout(authorizationRiskSearchTimer);
      authorizationRiskSearchTimer = window.setTimeout(runSearch, 350);
    });
    submit?.addEventListener("click", runSearch);
    const previous = document.querySelector("[data-risk-server-prev]");
    const next = document.querySelector("[data-risk-server-next]");
    previous?.addEventListener("click", () => {
      if (authorizationRiskRequestState.controller) return;
      loadAuthorizationRisk(Math.max(1, authorizationRiskRequestState.page - 1), { refreshPending: false });
    });
    next?.addEventListener("click", () => {
      if (authorizationRiskRequestState.controller) return;
      loadAuthorizationRisk(authorizationRiskRequestState.page + 1, { refreshPending: false });
    });
  }

  bindAuthorizationRiskFilters();
  bindAuthorizationRiskSearch();

  const licenseStatusCopy = {
    unused: ["未激活", "status-green"],
    activated: ["已激活", "status-gray"],
    expired: ["已过期", "status-gray"],
    reclaimed: ["已回收", "status-gray"],
    revoked: ["已撤销", "status-red"],
    disabled: ["已禁用", "status-red"],
    archived: ["已归档", "status-gray"],
  };

  function licenseCardWallClockExpired(item) {
    const raw = item?.expires_at || "";
    if (!raw) return false;
    const expiry = Date.parse(raw);
    return Number.isFinite(expiry) && expiry <= Date.now();
  }

  function licenseCardDisplayStatus(item) {
    const inventory = item?.status || "";
    if (inventory === "activated" && licenseCardWallClockExpired(item)) {
      return licenseStatusCopy.expired;
    }
    return licenseStatusCopy[inventory] || [item?.status_label || "未知", "status-gray"];
  }

  function licenseActivationRuleLabel(item) {
    if (item?.expires_at) return `${formatApiDate(item.expires_at)} 到期`;
    return item?.activation_rule || (item?.duration_label ? `激活后 ${item.duration_label}` : "激活后计时");
  }

  function licenseCardsPrefix() {
    return document.body.classList.contains("role-admin")
      ? "/manage/licenses/cards"
      : "/downstream/licenses/cards";
  }

  function renderDownstreamRecentCards(items, pagination) {
    if (isStandaloneStaticPreview && !window.__b1ApiActive) return;
    const list = document.querySelector("[data-downstream-recent-cards]");
    if (!list) return;
    list.replaceChildren();
    list.dataset.liveDataLoaded = "true";
    delete list.dataset.recentLoadFailed;
    const recentItems = Array.isArray(items) ? items.slice(0, 3) : [];
    if (!recentItems.length) {
      const empty = document.createElement("p");
      empty.className = "table-empty";
      empty.textContent =
        Number(pagination?.total) === 0
          ? "还没有授权卡密。完整库存在「全部卡密」。"
          : "这里只显示最近 3 张。完整库存在「全部卡密」。";
      list.append(empty);
      return;
    }
    recentItems.forEach((item) => {
      const row = document.createElement("button");
      row.className = "batch-row";
      row.type = "button";
      row.dataset.screenTarget = "licenses";
      row.dataset.targetRecordScope = "downstream-licenses";
      row.dataset.targetRecordView = "items";
      const status = licenseCardDisplayStatus(item);
      const code = document.createElement("span");
      code.className = "batch-id mono";
      code.textContent = item.masked_code || "••••-••••-????";
      const name = document.createElement("span");
      name.className = "batch-name";
      const plan = document.createElement("b");
      plan.textContent = `${item.software_name || "—"} / ${item.plan_name || "—"}`;
      const detail = document.createElement("small");
      detail.textContent = status[0];
      name.append(plan, detail);
      const statusBadge = document.createElement("span");
      statusBadge.className = `status ${status[1]}`;
      statusBadge.textContent = status[0];
      const arrow = document.createElement("span");
      arrow.className = "row-arrow";
      arrow.textContent = "→";
      row.append(code, name, statusBadge, arrow);
      list.append(row);
    });
  }

  function renderDownstreamRecentCardsError(message) {
    const list = document.querySelector("[data-downstream-recent-cards]");
    if (!list) return;
    list.replaceChildren();
    list.dataset.liveDataLoaded = "true";
    list.dataset.recentLoadFailed = "true";
    const empty = document.createElement("p");
    empty.className = "table-empty";
    empty.textContent = message || "最近卡密暂时无法读取。";
    const retry = document.createElement("button");
    retry.type = "button";
    retry.className = "button button-secondary";
    retry.textContent = "重试";
    retry.addEventListener("click", () => {
      loadDownstreamRecentCards();
    });
    list.append(empty, retry);
  }

  async function loadDownstreamRecentCards() {
    if (isStandaloneStaticPreview && !window.__b1ApiActive) return null;
    if (!document.body.classList.contains("role-downstream")) return null;
    const list = document.querySelector("[data-downstream-recent-cards]");
    if (!list) return null;
    try {
      const payload = await apiRequest(`${licenseCardsPrefix()}/?page=1&page_size=3`);
      renderDownstreamRecentCards(payload.items || [], payload.pagination || {});
      return payload;
    } catch (error) {
      renderDownstreamRecentCardsError(apiErrorMessage(error, "最近卡密暂时无法读取。"));
      throw error;
    }
  }

  function renderLicenseCardRows(items, { serverSearch = false } = {}) {
    const isAdmin = document.body.classList.contains("role-admin");
    const scopeName = isAdmin ? "management-licenses" : "downstream-licenses";
    const panel = document.querySelector(
      `[data-record-view-scope="${scopeName}"] [data-record-panel="items"]`,
    );
    const body = panel?.querySelector("tbody");
    if (!body) return;
    const selectedIds = new Set(
      [...body.querySelectorAll("[data-reclaim-select]:checked")]
        .map((checkbox) => checkbox.closest("tr")?.dataset.publicId)
        .filter(Boolean),
    );
    body.replaceChildren();
    (Array.isArray(items) ? items : []).forEach((item) => {
      const row = document.createElement("tr");
      const status = licenseCardDisplayStatus(item);
      row.dataset.publicId = item.public_id || "";
      row.dataset.searchValue = [
        item.masked_code,
        item.code_suffix,
        item.device_code,
        item.installation_id,
        item.device_label,
        item.device,
      ].filter(Boolean).join(" ");
      row.dataset.credentialType = "授权卡密";
      row.dataset.fullCode = "";
      row.dataset.codeSuffix = item.code_suffix || "";
      row.dataset.codeAvailable = String(item.code_available !== false);
      row.dataset.cardStatus = item.status || "";
      row.dataset.codeStatus = status[0];
      row.dataset.codeSoftware = item.software_name || "—";
      row.dataset.codePlan = `${item.plan_name || "—"} · ${item.duration_label || "有效期待定"} · ${Number(item.quota_cost || 0)} 额度`;
      row.dataset.codeDownstream = item.downstream_username || "当前下游";
      row.dataset.codeDeviceCode = item.device_code || item.installation_id || item.device_label || item.device || "尚未绑定";
      row.dataset.codeDeviceUuid = item.device_uuid || item.device_id || "尚未产生";
      row.dataset.codeDevice = item.device_state || "未绑定";
      row.dataset.codeDeviceState = item.device_state || "未绑定";
      row.dataset.codeIp = item.ip || "尚未产生";
      row.dataset.codeActivity = item.activated_at ? formatApiDate(item.activated_at) : "尚未激活";
      row.dataset.codeExpires = licenseActivationRuleLabel(item);
      row.dataset.codeExpiryState = item.status === "unused" ? "未开始" : status[0];
      row.dataset.expiresAt = item.expires_at || "";

      const selectCell = document.createElement("td");
      const canSelect = isAdmin || item.status === "unused";
      if (canSelect) {
        const checkbox = document.createElement("input");
        checkbox.type = "checkbox";
        checkbox.dataset.reclaimSelect = "";
        checkbox.dataset.cardStatus = item.status || "";
        checkbox.dataset.expiresAt = item.expires_at || "";
        checkbox.dataset.reclaimCredit = String(item.quota_cost || 0);
        checkbox.dataset.cardId = item.public_id || "";
        checkbox.checked = selectedIds.has(item.public_id);
        checkbox.setAttribute("aria-label", `选择 ${item.masked_code || "授权卡密"}`);
        selectCell.append(checkbox);
      }
      row.append(selectCell);
      appendTextCell(row, item.masked_code || "••••-••••-????", "mono");
      appendStatusCell(row, status[0], status[1]);
      appendSoftwareCell(row, item.software_name || "—");
      appendPlanCell(row, item.plan_name || "—", `${item.duration_label || "有效期待定"} · ${Number(item.quota_cost || 0)} 额度`);
      if (isAdmin) appendTextCell(row, item.downstream_username || "已删除下游");
      appendTextCell(row, licenseActivationRuleLabel(item));
      const actionCell = document.createElement("td");
      const actions = document.createElement("div");
      actions.className = "table-actions";
      const detailBtn = createTableButton("详情", {
        kind: "detail",
        tooltip: item.status === "reclaimed" ? "查看回收详情" : "查看完整卡密与交付信息",
      });
      detailBtn.dataset.credentialDetail = "";
      actions.append(detailBtn);
      actionCell.append(actions);
      row.append(actionCell);
      body.append(row);
    });
    panel.dataset.serverDataLoaded = "true";
    setCredentialSearchOverlay(scopeName, Boolean(serverSearch));
    window.__previewRefreshTables?.();
    syncLicenseReclaimSelection(panel);
    if (serverSearch) {
      body.querySelectorAll("tr[data-public-id]").forEach((row) => {
        row.dataset.serverSearchMatch = "true";
        row.hidden = false;
        row.dataset.queryMatch = "true";
        row.dataset.filterMatch = "true";
        row.dataset.criteriaMatch = "true";
      });
    }
  }

  let licenseRequestGeneration = 0;
  let licenseRequestController = null;
  let licenseCardsPage = 1;

  function formatServerPageLabel(pagination = {}) {
    const page = Number(pagination.page) || 1;
    const totalPages = Number(pagination.total_pages) || 0;
    const total = Number(pagination.total);
    if (totalPages > 0 && Number.isFinite(total)) return `第 ${page} / ${totalPages} 页 · 共 ${total} 条`;
    if (totalPages > 0) return `第 ${page} / ${totalPages} 页`;
    return `第 ${page} 页`;
  }

  function setLicenseServerPagination(pagination) {
    document.querySelectorAll('[data-record-view-scope="management-licenses"] [data-license-server-pagination], [data-record-view-scope="downstream-licenses"] [data-license-server-pagination]').forEach((controls) => {
      const visible = !isStandaloneStaticPreview && pagination && Number(pagination.total_pages || 0) > 1;
      controls.hidden = !visible;
      controls.querySelector("[data-license-server-prev]").disabled = !pagination?.has_previous;
      controls.querySelector("[data-license-server-next]").disabled = !pagination?.has_next;
      controls.querySelector("[data-license-server-page]").textContent = formatServerPageLabel(pagination);
    });
  }

  function bindLicenseServerPagination() {
    document.querySelectorAll("[data-license-server-prev]").forEach((button) => {
      if (button.dataset.bound) return;
      button.dataset.bound = "true";
      button.addEventListener("click", () => {
        if (hasCredentialSearchOverlay(licenseSearchOverlayScope())) {
          credentialSearchOverlayToast("再翻页");
          return;
        }
        loadLicenseCards(Math.max(1, licenseCardsPage - 1));
      });
    });
    document.querySelectorAll("[data-license-server-next]").forEach((button) => {
      if (button.dataset.bound) return;
      button.dataset.bound = "true";
      button.addEventListener("click", () => {
        if (hasCredentialSearchOverlay(licenseSearchOverlayScope())) {
          credentialSearchOverlayToast("再翻页");
          return;
        }
        loadLicenseCards(licenseCardsPage + 1);
      });
    });
  }

  function beginLicenseRequest() {
    licenseRequestController?.abort();
    const generation = ++licenseRequestGeneration;
    const controller = new AbortController();
    licenseRequestController = controller;
    return { controller, generation };
  }

  function isCurrentLicenseRequest(request) {
    return request.generation === licenseRequestGeneration;
  }

  function isAbortedLicenseRequest(error, request) {
    return error?.name === "AbortError" || !isCurrentLicenseRequest(request);
  }

  async function loadLicenseCards(page = licenseCardsPage) {
    const request = beginLicenseRequest();
    try {
      bindLicenseServerPagination();
      const requestedPage = Math.max(1, Number(page) || 1);
      const panel = document.querySelector(
        `[data-record-view-scope="${document.body.classList.contains("role-admin") ? "management-licenses" : "downstream-licenses"}"] [data-record-panel="items"]`,
      );
      const queryParams = new URLSearchParams({ page_size: "10", page: String(requestedPage) });
      Object.entries(licenseCardFilterQuery(panel)).forEach(([key, value]) => queryParams.set(key, value));
      const fuzzy = nonSecretTableQuery(panel?.querySelector("[data-sensitive-search]"), "license");
      if (fuzzy) queryParams.set("q", fuzzy);
      const payload = await apiRequest(`${licenseCardsPrefix()}/?${queryParams.toString()}`, {
        signal: request.controller.signal,
      });
      if (!isCurrentLicenseRequest(request)) return null;
      licenseCardsPage = payload.pagination?.page || requestedPage;
      renderLicenseCardRows(payload.items || []);
      setLicenseServerPagination(payload.pagination || null);
      syncLicenseScopeSummary(panel, payload.scope || "current");
      snapshotCredentialFilters(panel?.querySelector("[data-credential-filters]") || panel);
      if (!document.body.classList.contains("role-admin") && payload.account) {
        const numeric = Number(payload.account.available_balance);
        const balance = (Number.isFinite(numeric) ? numeric : 0).toLocaleString("zh-CN");
        document.querySelectorAll("#downstreamAvailableBalance").forEach((target) => {
          target.textContent = balance;
        });
        syncIssueAvailableBalance(Number.isFinite(numeric) ? numeric : 0);
      }
      return payload;
    } catch (error) {
      if (isAbortedLicenseRequest(error, request)) return null;
      throw error;
    } finally {
      if (isCurrentLicenseRequest(request)) licenseRequestController = null;
    }
  }

  async function searchLicenseCard(input) {
    if (input.dataset.searchPending === "true") return;
    const query = input.value.trim();
    if (!query) {
      input.dataset.searchPending = "true";
      try {
        await loadLicenseCards(1);
      } finally {
        delete input.dataset.searchPending;
      }
      return;
    }
    if (!shouldExactCredentialSearch(query, "license")) {
      loadLicenseCards(1).catch((error) => showToast(apiErrorMessage(error, "授权卡密搜索失败，请重试。")));
      return;
    }
    input.dataset.searchPending = "true";
    input.disabled = true;
    const request = beginLicenseRequest();
    try {
      const payload = await apiRequest(`${licenseCardsPrefix()}/search/`, {
        method: "POST",
        body: JSON.stringify({ code: query }),
        signal: request.controller.signal,
      });
      if (!isCurrentLicenseRequest(request)) return;
      renderLicenseCardRows(payload.item ? [payload.item] : [], { serverSearch: true });
      setLicenseServerPagination(null);
      showToast("已定位到这张授权卡密。");
    } catch (error) {
      if (isAbortedLicenseRequest(error, request)) return;
      if (looksLikePrefixedCredential(query, "license")) {
        showToast("没有找到匹配的授权卡密。请粘客户发来的完整卡密。屏幕尾号搜不到。表里已有的行点「查看 / 交付」再「显示完整码」。当前列表未改动。");
        return;
      }
      try {
        await loadLicenseCards(1);
      } catch (fuzzyError) {
        showToast(apiErrorMessage(fuzzyError, "没有找到匹配的授权卡密。当前列表未改动。"));
      }
    } finally {
      if (isCurrentLicenseRequest(request)) {
        input.disabled = false;
        delete input.dataset.searchPending;
        licenseRequestController = null;
      }
    }
  }

  document
    .querySelectorAll(
      '[data-record-view-scope="management-licenses"] [data-sensitive-search], [data-record-view-scope="downstream-licenses"] [data-sensitive-search]',
    )
    .forEach((input) => {
      bindDebouncedSearch(input, () => {
      if (isStandaloneStaticPreview) return;
      searchLicenseCard(input);
    });
    });

  async function searchAdminCredential(input, { endpoint, kind, reload, render, successMessage, emptyMessage }) {
    if (input.dataset.searchPending === "true") return;
    const query = input.value.trim();
    if (!query) {
      input.dataset.searchPending = "true";
      try {
        await reload();
      } finally {
        delete input.dataset.searchPending;
      }
      return;
    }
    if (!shouldExactCredentialSearch(query, kind)) {
      reload(1).catch((error) => showToast(apiErrorMessage(error, emptyMessage)));
      return;
    }
    input.dataset.searchPending = "true";
    input.disabled = true;
    const request = beginLicenseRequest();
    try {
      const payload = await apiRequest(endpoint, {
        method: "POST",
        body: JSON.stringify({ code: query }),
        signal: request.controller.signal,
      });
      if (!isCurrentLicenseRequest(request)) return;
      render(payload.item ? [payload.item] : []);
      if (endpoint.includes("/invitations/")) setInvitationServerPagination(null);
      if (endpoint.includes("/credits/cards/search/")) setQuotaCardServerPagination(null);
      showToast(payload.item ? successMessage : emptyMessage);
    } catch (error) {
      if (isAbortedLicenseRequest(error, request)) return;
      if (looksLikePrefixedCredential(query, kind)) {
        showToast(`没有找到匹配的完整码。请粘客户发来的完整码。屏幕尾号搜不到。表里已有的行点查看后再点「显示完整码」。当前列表未改动。`);
        return;
      }
      try {
        await reload(1);
      } catch (fuzzyError) {
        showToast(apiErrorMessage(fuzzyError, emptyMessage));
      }
    } finally {
      input.disabled = false;
      delete input.dataset.searchPending;
      if (isCurrentLicenseRequest(request)) licenseRequestController = null;
    }
  }

  bindDebouncedSearch(
    document.querySelector('[data-record-view-scope="invitations"] [data-sensitive-search]'),
    () => {
        if (isStandaloneStaticPreview) return;
      searchAdminCredential(document.querySelector('[data-record-view-scope="invitations"] [data-sensitive-search]'), {
      endpoint: "/manage/invitations/search/",
        kind: "invitation",
      reload: loadInvitations,
      render: (items) => renderInvitationRows(items, { serverSearch: true }),
        successMessage: "已定位到这个邀请码。",
      emptyMessage: "没有找到匹配的邀请码。",
      });
    },
  );
  bindDebouncedSearch(
    document.querySelector('[data-record-view-scope="quota-cards"] [data-sensitive-search]'),
    () => {
      if (isStandaloneStaticPreview) return;
      searchAdminCredential(document.querySelector('[data-record-view-scope="quota-cards"] [data-sensitive-search]'), {
      endpoint: "/manage/credits/cards/search/",
        kind: "quota",
      reload: loadAdminCredits,
      render: (items) => renderQuotaCardRows(items, { serverSearch: true }),
        successMessage: "已定位到这个额度兑换码。",
      emptyMessage: "没有找到匹配的额度兑换码。",
      });
    },
  );

  const redeemDialog = document.getElementById("redeemDialog");
  redeemDialog
    ?.querySelector('[data-success-screen="ledger"]')
    ?.addEventListener("click", async (event) => {
      if (!window.__b1ApiActive) {
        showToast("静态预览不执行真实兑换。");
        return;
      }
      const button = event.currentTarget;
      const form = button.closest("form");
      const input = form?.elements.quota_code;
      const error = form?.querySelector("[data-form-error]");
      if (!form?.checkValidity()) {
        if (error) error.textContent = "请输入完整额度兑换码。";
        form?.reportValidity();
        return;
      }
      button.disabled = true;
      if (error) error.textContent = "";
      let payload;
      try {
        payload = await apiRequest("/downstream/credits/", {
          method: "POST",
          headers: {
            "Idempotency-Key":
              redeemDialog.dataset.redeemKey ||
              (redeemDialog.dataset.redeemKey = requestIdempotencyKey("quota-card-redeem")),
          },
          body: JSON.stringify({ card_code: input.value.trim() }),
        });
      } catch (requestError) {
        if (error) error.textContent = apiErrorMessage(requestError, "额度卡兑换失败，请重试。");
        button.disabled = false;
        return;
      }
      applyDownstreamLedgerBalance(payload.account);
      redeemDialog.dataset.redeemKey = "";
      redeemDialog.close("success");
      activateScreen("ledger", { history: "push" });
      const repeated = Boolean(payload.repeated);
      try {
        await loadDownstreamCredits(1);
        showToast(repeated ? "这张额度卡已经兑换过，本次没有重复入账。" : "额度卡兑换成功，余额和流水已更新。");
      } catch {
        showToast(
          repeated
            ? "这张额度卡已经兑换过，本次没有重复入账。账本列表请稍后重试。"
            : "额度已兑换，账本列表请稍后重试。",
        );
      } finally {
        button.disabled = false;
      }
    });

  function updateSessionIdentity(session) {
    const username = session.user?.username || (session.role === "platform_admin" ? "平台管理员" : "下游账号");
    document.querySelectorAll(".header-user").forEach((target) => {
      const marker = target.querySelector("i");
      target.replaceChildren(marker || document.createElement("i"), document.createTextNode(username));
    });
    document.querySelectorAll(".preview-chip").forEach((chip) => {
      chip.textContent = "已连接";
    });
    const railIdentity = document.querySelector(".rail-bottom strong");
    if (railIdentity) {
      railIdentity.textContent = session.role === "platform_admin"
        ? "平台管理员"
        : `${username} · ${session.user?.status || "active"}`;
    }
  }

  async function refreshScreenData(screen) {
    const registered = workspaceReloaders[screen];
    if (typeof registered === "function") {
      await registered();
      return;
    }
    const isAdmin = document.body.classList.contains("role-admin");
    const isDownstream = document.body.classList.contains("role-downstream");
    switch (screen) {
      case "overview":
        await loadOverviewSnapshot();
        return;
      case "analytics":
        await applyAnalyticsRange();
        return;
      case "software":
        await loadCatalog();
        return;
      case "downstreams":
        await Promise.all([loadDownstreams(), loadInvitations()]);
        return;
      case "credits":
        await loadAdminCredits();
        return;
      case "licenses":
        await loadLicenseCards();
        return;
      case "risk":
        await loadAuthorizationRisk();
        return;
      case "releases":
        await loadReleasesForSoftware(releaseContext?.value || "all");
        return;
      case "backup":
        await loadAdminBackup();
        return;
      case "workspace":
        await Promise.all([
          loadDownstreamRecentCards(),
          applyDownstreamMetrics(),
        ]);
        return;
      case "devices":
        await loadDownstreamDevices();
        return;
      case "ledger":
        await loadDownstreamCredits();
        return;
      case "support": {
        const softwareId =
          document.querySelector("[data-support-context]")?.value || "";
        if (softwareId) await loadDownstreamSupport(softwareId);
        return;
      }
      default:
        if (isAdmin) await loadOverviewSnapshot();
        else if (isDownstream) {
          await Promise.all([
            loadDownstreamRecentCards(),
            applyDownstreamMetrics(),
          ]);
        }
    }
  }

  async function refreshVisibleWorkspace(options) {
    options = options || {};
    const silent = Boolean(options.silent);
    const button = document.querySelector("[data-workspace-refresh]");
    if (workspaceRefreshBusy) {
      if (!silent) showToast("正在刷新，请稍候。");
      return;
    }
    if (isStandaloneStaticPreview && !window.__b1ApiActive) {
      if (!silent) showToast("静态预览没有真实数据可刷新。");
      return;
    }
    if (!window.__b1ApiActive) {
      if (!silent) showToast("当前还没有接通工作台。");
      return;
    }
    if (silent && document.querySelector("dialog[open]")) return;
    const now = Date.now();
    if (now - lastWorkspaceRefreshAt < 8000) {
      if (!silent) showToast("刷新太频繁，请稍候再试。");
      return;
    }
    const screen =
      currentVisibleScreen ||
      document.querySelector(".screen.is-visible")?.dataset.screenPanel ||
      "";
    workspaceRefreshBusy = true;
    if (button) {
      button.disabled = true;
      button.textContent = "刷新中…";
    }
    try {
      await refreshScreenData(screen);
      lastWorkspaceRefreshAt = Date.now();
      if (!silent) showToast("已刷新当前页数据。");
    } catch (error) {
      if (!silent) showToast(apiErrorMessage(error, "刷新失败，请稍后重试。"));
    } finally {
      workspaceRefreshBusy = false;
      if (button) {
        button.disabled = false;
        button.textContent = "刷新";
      }
    }
  }

  function installWorkspaceRefresh() {
    const buttons = document.querySelectorAll("[data-workspace-refresh]");
    buttons.forEach((button) => {
      if (button.dataset.workspaceRefreshBound) return;
      button.dataset.workspaceRefreshBound = "true";
      button.addEventListener("click", () => {
        refreshVisibleWorkspace({ silent: false });
      });
    });
    if (!buttons.length || document.documentElement.dataset.workspaceVisibilityRefreshBound) {
      return;
    }
    document.documentElement.dataset.workspaceVisibilityRefreshBound = "true";
    document.addEventListener("visibilitychange", () => {
      if (document.visibilityState !== "visible") return;
      refreshVisibleWorkspace({ silent: true });
    });
  }

  function installStandaloneCardSearch() {
    document.querySelectorAll("[data-global-search]").forEach((button) => {
      if (button.dataset.cardSearchBound) return;
      button.dataset.cardSearchBound = "true";
      button.addEventListener("click", () => {
        activateScreen("licenses");
        const input = document.querySelector(
          '[data-record-view-scope="management-licenses"] [data-sensitive-search]',
        );
        input?.focus();
        showToast("只找完整卡密。屏幕尾号搜不到。");
      });
    });
  }

  function installLogout(session) {
    document.querySelectorAll(".header-actions .text-button").forEach((button) => {
      if (!button.textContent.includes("退出") || button.dataset.apiLogoutBound) return;
      button.dataset.apiLogoutBound = "true";
      button.addEventListener("click", async () => {
        button.disabled = true;
        try {
          const payload = await apiRequest("/auth/logout/", { method: "POST", body: "{}" });
          const fallback = session.role === "platform_admin" ? "manage-login.html" : "downstream-login.html";
          const allowedRedirects = new Set(["manage-login.html", "downstream-login.html"]);
          const redirect = allowedRedirects.has(payload.redirect) ? payload.redirect : fallback;
          window.location.href = redirect;
        } catch (error) {
          button.disabled = false;
          showToast(apiErrorMessage(error, "退出失败，请稍后重试。"));
        }
      });
    });
  }

  function installPasswordLifecycle(reloadDownstreams) {
    const changeDialog = document.getElementById("passwordChangeDialog");
    const changeForm = changeDialog?.querySelector("[data-password-change-form]");
    const changeButton = changeDialog?.querySelector("[data-password-change-submit]");
    if (changeDialog && changeForm && changeButton && !changeDialog.dataset.apiPasswordBound) {
      changeDialog.dataset.apiPasswordBound = "true";
      changeButton.addEventListener("click", async () => {
        const error = changeForm.querySelector("[data-form-error]");
        const newPassword = changeForm.elements.new_password;
        const confirmation = changeForm.elements.new_password_confirm;
        if (!changeForm.checkValidity()) {
          if (error) error.textContent = "请填写完整且符合要求的密码。";
          changeForm.reportValidity();
          return;
        }
        if (newPassword.value !== confirmation.value) {
          if (error) error.textContent = "两次输入的新密码不一致，请重新确认。";
          confirmation.setCustomValidity("两次输入的新密码不一致");
          confirmation.reportValidity();
          return;
        }
        confirmation.setCustomValidity("");
        changeButton.disabled = true;
        if (error) error.textContent = "";
        try {
          if (isStandaloneStaticPreview) {
            changeDialog.close("success");
            showToast("静态预览：已表达修改密码成功状态，未写入真实账号。");
            return;
          }
          const payload = Object.fromEntries(new FormData(changeForm).entries());
          const result = await apiRequest("/auth/password/change/", {
            method: "POST",
            headers: {
              "Idempotency-Key":
                changeDialog.dataset.passwordChangeKey ||
                (changeDialog.dataset.passwordChangeKey = requestIdempotencyKey("password-change")),
            },
            body: JSON.stringify(payload),
          });
          changeDialog.dataset.passwordChangeKey = "";
          changeDialog.close("success");
          showToast(result.replayed ? "这次密码修改请求已处理过，当前会话保持有效。" : "密码已修改，当前会话保持有效，其他旧会话已失效。 ");
        } catch (requestError) {
          if (error) error.textContent = apiErrorMessage(requestError, "请求没有完成，请稍后重试。");
        } finally {
          changeButton.disabled = false;
        }
      });
      changeForm.addEventListener("input", () => {
        changeForm.elements.new_password_confirm?.setCustomValidity("");
        setFormError(changeForm, "");
      });
      changeDialog.addEventListener("close", () => {
        changeForm.reset();
        setFormError(changeForm, "");
        changeButton.disabled = false;
      });
    }

    const resetDialog = document.getElementById("passwordResetDialog");
    const resetForm = resetDialog?.querySelector("[data-password-reset-form]");
    const resetButton = resetDialog?.querySelector("[data-password-reset-submit]");
    if (resetDialog && resetForm && resetButton && !resetDialog.dataset.apiPasswordBound) {
      resetDialog.dataset.apiPasswordBound = "true";
      resetButton.addEventListener("click", async () => {
        const error = resetForm.querySelector("[data-form-error]");
        const newPassword = resetForm.elements.new_password;
        const confirmation = resetForm.elements.new_password_confirm;
        if (!resetForm.checkValidity()) {
          if (error) error.textContent = "请填写完整且符合要求的密码和重置原因。";
          resetForm.reportValidity();
          return;
        }
        if (newPassword.value !== confirmation.value) {
          if (error) error.textContent = "两次输入的新密码不一致，请重新确认。";
          confirmation.setCustomValidity("两次输入的新密码不一致");
          confirmation.reportValidity();
          return;
        }
        confirmation.setCustomValidity("");
        const publicId = resetDialog.dataset.publicId || "";
        if (!publicId) {
          if (error) error.textContent = "下游账号标识缺失，请刷新列表后重试。";
          return;
        }
        resetButton.disabled = true;
        if (error) error.textContent = "";
        try {
          if (isStandaloneStaticPreview) {
            resetDialog.close("success");
            showToast("静态预览：已表达重置下游密码成功状态，未写入真实账号。");
            return;
          }
          const payload = Object.fromEntries(new FormData(resetForm).entries());
          const result = await apiRequest(`/manage/downstreams/${encodeURIComponent(publicId)}/password/reset/`, {
            method: "POST",
            headers: {
              "Idempotency-Key":
                resetDialog.dataset.passwordResetKey ||
                (resetDialog.dataset.passwordResetKey = requestIdempotencyKey("password-reset")),
            },
            body: JSON.stringify(payload),
          });
          resetDialog.dataset.passwordResetKey = "";
          resetDialog.close("success");
          showToast(result.replayed ? "这次密码重置请求已处理过，未重复修改。" : "下游密码已重置，该账号的旧会话已全部失效。 ");
          await reloadDownstreams?.();
        } catch (requestError) {
          if (error) error.textContent = apiErrorMessage(requestError, "请求没有完成，请稍后重试。");
        } finally {
          resetButton.disabled = false;
        }
      });
      resetForm.addEventListener("input", () => {
        resetForm.elements.new_password_confirm?.setCustomValidity("");
        setFormError(resetForm, "");
      });
      resetDialog.addEventListener("close", () => {
        resetForm.reset();
        setFormError(resetForm, "");
        resetButton.disabled = false;
      });
    }
  }

  function installDirectDownstreamCreation(loadData) {
    const dialog = document.getElementById("downstreamCreateDialog");
    const button = dialog?.querySelector("[data-downstream-create]");
    if (!dialog || !button || button.dataset.apiCreateBound) return;
    button.dataset.apiCreateBound = "true";
    button.addEventListener("click", async () => {
      const form = button.closest("form");
      const username = form?.elements.username;
      const password = form?.elements.password;
      const error = form?.querySelector("[data-form-error]");
      if (!username?.value.trim() || !password?.value) {
        if (error) error.textContent = "请填写用户名和初始密码。";
        return;
      }
      button.disabled = true;
      if (error) error.textContent = "";
      try {
        await apiRequest("/manage/downstreams/", {
          method: "POST",
          body: JSON.stringify({ username: username.value.trim(), password: password.value }),
        });
        dialog.close("success");
        showToast("下游账号已创建。入账请用「调整下游额度」，开通软件请用经营范围。");
        await loadData();
      } catch (requestError) {
        if (error) error.textContent = apiErrorMessage(requestError, "下游账号创建失败。");
      } finally {
        button.disabled = false;
      }
    });
  }

  function installDownstreamManagement(loadData) {
    if (!managementActionDialog || managementActionDialog.dataset.apiActionsBound) return;
    managementActionDialog.dataset.apiActionsBound = "true";
    const button = managementActionDialog.querySelector("[data-management-action-confirm]");
    button?.addEventListener("click", async () => {
      if (!pendingManagementAction || pendingManagementAction.scope !== "downstream") return;
      const form = managementActionDialog.querySelector("form");
      const error = form?.querySelector("[data-form-error]");
      if (!form?.checkValidity()) {
        if (error) error.textContent = "请填写至少 4 个字的可追溯原因。";
        form?.reportValidity();
        return;
      }
      const { row, kind } = pendingManagementAction;
      const publicId = row.dataset.publicId;
      const reason = form.elements.reason?.value.trim() || "";
      const route = kind === "archive" ? `/manage/downstreams/${publicId}/archive/` : kind === "delete" ? `/manage/downstreams/${publicId}/delete/` : `/manage/downstreams/${publicId}/status/`;
      const body = kind === "delete" ? { confirmation: true, reason } : kind === "archive" ? { reason } : { status: kind === "pause" ? "suspended" : "active", reason };
      button.disabled = true;
      if (error) error.textContent = "";
      try {
        await apiRequest(route, { method: "POST", body: JSON.stringify(body) });
        managementActionDialog.close("success");
        pendingManagementAction = undefined;
        showToast(`${managementActionCopy[kind][0]}已完成，服务端审计记录已保留。`);
        await loadData();
      } catch (requestError) {
        if (error) error.textContent = apiErrorMessage(requestError, "管理操作失败。");
      } finally {
        button.disabled = false;
      }
    });
  }

  function installAuthorizationRiskManagement(loadData) {
    if (!managementActionDialog || managementActionDialog.dataset.apiRiskActionsBound) return;
    managementActionDialog.dataset.apiRiskActionsBound = "true";
    const button = managementActionDialog.querySelector("[data-management-action-confirm]");
    button?.addEventListener("click", async () => {
      if (!pendingManagementAction || pendingManagementAction.scope !== "device") return;
      const form = managementActionDialog.querySelector("form");
      const error = form?.querySelector("[data-form-error]");
      if (!form?.checkValidity()) {
        if (error) error.textContent = "请填写至少 4 个字的可追溯原因。";
        form?.reportValidity();
        return;
      }
      const { row, kind } = pendingManagementAction;
      const authorizationId = row.dataset.authorizationId;
      const deviceId = row.dataset.deviceId;
      const route = riskManagementRoute(row, kind);
      if (
        !authorizationId
        || (["reset", "block", "unblock", "recover"].includes(kind) && !deviceId)
      ) {
        if (error) error.textContent = "服务端对象标识缺失，请刷新页面后重试。";
        return;
      }
      const reason = form.elements.reason?.value.trim() || "";
      const operationKey = riskManagementOperationKey(row, kind);
      const snapshot = riskManagementAttempts.get(operationKey) || {
        route,
        reason,
        body: JSON.stringify({ reason }),
        key: requestIdempotencyKey(`authorization-${kind}`),
        label: managementActionDialog.querySelector("[data-management-action-title]").textContent,
      };
      riskManagementAttempts.set(operationKey, snapshot);
      form.elements.reason.readOnly = true;
      button.disabled = true;
      button.textContent = "正在确认…";
      managementActionDialog.dataset.operationPending = "true";
      if (error) error.textContent = "";
      let completed = false;
      try {
        const payload = await apiRequest(snapshot.route, {
          method: "POST",
          headers: { "Idempotency-Key": snapshot.key },
          body: snapshot.body,
        });
        riskManagementAttempts.delete(operationKey);
        managementActionDialog.close("success");
        pendingManagementAction = undefined;
        completed = true;
        showToast(payload.repeated ? `${snapshot.label}已处理过，状态没有重复改变。` : `${snapshot.label}已完成，服务端状态和审计已更新。`);
      } catch (requestError) {
        const unknown = !requestError.status || requestError.status >= 500 || requestError.status === 408 || requestError.retryable;
        if (unknown) {
          if (error) error.textContent = "操作结果尚未确认。请按原请求重试，或关闭后刷新列表核对；不要另建相同操作。";
        } else {
          riskManagementAttempts.delete(operationKey);
          form.elements.reason.readOnly = false;
          if (error) error.textContent = apiErrorMessage(requestError, "操作未完成，请核对提示后重试。");
        }
      } finally {
        delete managementActionDialog.dataset.operationPending;
        button.disabled = false;
        button.textContent = riskManagementAttempts.has(operationKey) ? "按原请求重试" : snapshot.label;
      }
      if (completed) {
        try { await loadData(); }
        catch { showToast(`${snapshot.label}已完成，列表刷新失败。请刷新列表查看，不必再次提交。`, 8000); }
      }
    });
  }

  function installInvitationIssue(loadData) {
    if (!inviteDialog || inviteDialog.dataset.apiIssueBound) return;
    inviteDialog.dataset.apiIssueBound = "true";
    const button = inviteDialog.querySelector("[data-invite-generate]");
    button?.addEventListener("click", async () => {
      const quantityValue = Number(inviteQuantity?.value);
      const error = inviteDialog.querySelector("[data-invite-error]");
      if (!Number.isInteger(quantityValue) || quantityValue < 1 || quantityValue > 100) {
        if (error) error.textContent = "生成数量必须是 1 至 100 之间的整数。";
        inviteQuantity?.reportValidity();
        return;
      }
      button.disabled = true;
      if (error) error.textContent = "";
      try {
        const payload = await apiRequest("/manage/invitations/", {
          method: "POST",
          headers: { "Idempotency-Key": inviteDialog.dataset.inviteKey || (inviteDialog.dataset.inviteKey = requestIdempotencyKey("invitation-issue")) },
          body: JSON.stringify({ quantity: quantityValue }),
        });
        const items = payload.items || [];
        inviteDialog.dataset.generatedCodes = JSON.stringify(items.map((item) => item.code).filter(Boolean));
        inviteDialog.dataset.downloadFilename = "invitation-codes.txt";
        inviteDialog.querySelector("[data-invite-result-count]").textContent = `${items.length} 枚`;
        const codeList = inviteDialog.querySelector("[data-invite-codes]");
        codeList?.replaceChildren(...items.map((item) => {
          const output = document.createElement("code");
          output.className = "mono";
          output.textContent = item.code;
          return output;
        }));
        inviteFormStage.hidden = true;
        inviteResultStage.hidden = false;
        inviteResultStage.querySelector("h3")?.focus({ preventScroll: true });
        inviteDialog.dataset.inviteKey = "";
        await loadData();
        showToast("邀请码已生成；之后可在单码详情中按需重复查看。");
      } catch (requestError) {
        if (error) error.textContent = apiErrorMessage(requestError, "邀请码生成失败。");
      } finally {
        button.disabled = false;
      }
    });
  }

  function bootstrapStaticPreviewRuntime() {
    if (!document.body.classList.contains("role-admin") && !document.body.classList.contains("role-downstream")) return;
    setCatalogItems(standaloneCatalogItems);
    catalogApiReady = true;
    renderCatalogSoftwareOptions(catalogItems);
    if (document.body.classList.contains("role-admin")) renderAdminCatalogRows(catalogItems);
    renderPlanCatalog(catalogItems);
    renderPlans(plan?.value);
    updateIssuePreview();
    bindAuthorizationRiskSearch();
    installPasswordLifecycle();
  }

  async function bootstrapB1Runtime() {
    if (isStandaloneStaticPreview) {
      bootstrapStaticPreviewRuntime();
      return;
    }
    const isAdmin = document.body.classList.contains("role-admin");
    const isDownstream = document.body.classList.contains("role-downstream");
    const isAccessPage = document.body.classList.contains("access-preview");
    if (!isAdmin && !isDownstream && !isAccessPage) return;
    window.__b1ApiActive = true;
    try {
      try {
        await loadPublicQuotaPurchaseLink();
      } catch (purchaseError) {
        applyQuotaPurchaseLink("", { keepOnEmpty: true });
        showToast(apiErrorMessage(purchaseError, "额度卡购买链接暂时无法读取。"));
      }
      const session = await apiRequest("/session/");
        if (isAccessPage) {
          const destination =
            document.querySelector("form[data-preview-destination]")?.dataset.previewDestination ||
            "";
          const loginForm = document.querySelector("form[data-preview-destination]");
          const isLoginForm = Boolean(loginForm) && !loginForm.querySelector('[name="password_confirm"]');
          if (isLoginForm && session.authenticated && session.user?.username) {
            const hint = loginForm.querySelector("[data-session-switch-hint]");
            if (hint) {
              hint.hidden = false;
              hint.textContent = `当前登录账号：${session.user.username}（提交将切换新身份）`;
            }
            return;
          }
          if (session.authenticated) {
            if (destination.includes("manage.html") && session.role === "platform_admin") {
              window.location.href = workspaceLandingUrl("manage.html");
              return;
            }
            if (destination.includes("downstream.html") && session.role === "downstream") {
              window.location.href = workspaceLandingUrl("downstream.html");
              return;
            }
          }
          return;
        }
      const expectedRole = isAdmin ? "platform_admin" : "downstream";
      if (!session.authenticated || session.role !== expectedRole) {
        window.location.href = isAdmin ? "manage-login.html" : "downstream-login.html";
        return;
      }
      updateSessionIdentity(session);
      installLogout(session);
      installStandaloneCardSearch();
      installWorkspaceRefresh();
      if (isAdmin) {
        const loadAdminData = async () => {
          await Promise.all([
            loadDownstreams().catch((downstreamError) => {
              renderDownstreamRows([]);
              showRuntimeReadError(
                '[data-screen-panel="downstreams"]',
                apiErrorMessage(downstreamError, "下游账号暂时无法读取，当前没有可用数据。"),
                loadDownstreams,
              );
            }),
            loadInvitations().catch((invitationError) => {
              renderInvitationRows([]);
              showRuntimeReadError(
                '[data-work-panel="invitations"]',
                apiErrorMessage(invitationError, "邀请码暂时无法读取，当前没有可用数据。"),
                loadInvitations,
              );
            }),
          ]);
        };
        installDirectDownstreamCreation(loadDownstreams);
        installPasswordLifecycle(loadDownstreams);
        installDownstreamManagement(loadDownstreams);
        installAuthorizationRiskManagement(loadAuthorizationRisk);
        installInvitationIssue(loadInvitations);
        await loadAdminData();
        try {
          await loadAdminCredits();
        } catch (creditError) {
          clearCreditRuntimeData();
          showRuntimeReadError(
            '[data-screen-panel="credits"]',
            apiErrorMessage(creditError, "额度数据暂时无法读取，当前没有可用数据。"),
            loadAdminCredits,
          );
        }
        try {
          await loadCatalog();
        } catch (catalogError) {
          renderCatalogUnavailable();
          showRuntimeReadError(
            '[data-screen-panel="software"]',
            apiErrorMessage(catalogError, "软件目录暂时无法连接，当前没有可用数据。"),
            loadCatalog,
          );
        }
        try {
          await loadLicenseCards();
        } catch (licenseError) {
          renderLicenseCardRows([]);
          showRuntimeReadError(
            '[data-screen-panel="licenses"]',
            apiErrorMessage(licenseError, "授权卡密列表暂时无法读取，当前没有可用数据。"),
            loadLicenseCards,
          );
        }
        try {
          await loadAuthorizationRisk();
        } catch (riskError) {
          showRuntimeReadError(
            '[data-screen-panel="risk"]',
            apiErrorMessage(riskError, "设备与授权风险列表暂时无法读取，当前没有可用数据。"),
            loadAuthorizationRisk,
          );
        }
        try {
          await loadOverviewSnapshot();
        } catch (overviewError) {
          showRuntimeReadError(
            '[data-screen-panel="overview"]',
            apiErrorMessage(overviewError, "总览数据暂时无法读取。"),
            loadOverviewSnapshot,
          );
        }
        await applyAnalyticsRange();
        try {
          await loadReleasesForSoftware(releaseContext?.value || "all");
        } catch (_releaseError) {
          /* loadReleasesForSoftware 已在版本页展示读取错误，不再把表格画成空成功态。 */
        }
        try {
          await loadAdminBackup();
        } catch (backupError) {
          showRuntimeReadError(
            '[data-screen-panel="backup"]',
            apiErrorMessage(backupError, "备份中心暂时无法读取，当前没有可用数据。"),
            loadAdminBackup,
          );
        }
        revealLiveApp();
      } else if (isDownstream) {
        installPasswordLifecycle();
        try {
          await loadDownstreamDevices();
        } catch (deviceError) {
          renderDownstreamDeviceRows([]);
          showRuntimeReadError(
            '[data-screen-panel="devices"]',
            apiErrorMessage(deviceError, "已激活设备暂时无法读取，当前没有可用数据。"),
            () => loadDownstreamDevices(downstreamDevicePage),
          );
        }
        try {
          await loadDownstreamCredits();
        } catch (creditError) {
          clearCreditRuntimeData();
          showRuntimeReadError(
            '[data-screen-panel="ledger"]',
            apiErrorMessage(creditError, "额度数据暂时无法读取，当前没有可用数据。"),
            loadDownstreamCredits,
          );
        }
        try {
          await loadCatalog();
        } catch (catalogError) {
          renderCatalogUnavailable();
          showRuntimeReadError(
            '[data-screen-panel="software"]',
            apiErrorMessage(catalogError, "软件目录暂时无法连接，当前没有可用数据。"),
            loadCatalog,
          );
        }
        try {
          await loadLicenseCards();
        } catch (licenseError) {
          renderLicenseCardRows([]);
          showRuntimeReadError(
            '[data-screen-panel="licenses"]',
            apiErrorMessage(licenseError, "授权卡密列表暂时无法读取，当前没有可用数据。"),
            loadLicenseCards,
          );
        }
        await loadDownstreamRecentCards();
        await applyDownstreamMetrics();
        revealLiveApp();
      }
    } catch (error) {
      // The standalone 8124 artifact server has no /api/ endpoint. Keep its
      // visual-only navigation usable; the real 8123 same-origin gateway
      // returns JSON (401/403) and still follows the normal login redirect.
      if (error instanceof ApiRequestError && error.status === 404) return;
      if (!isAccessPage) {
        window.location.replace(isAdmin ? "manage-login.html" : "downstream-login.html");
        return;
      }
      showToast(apiErrorMessage(error, "授权平台暂时无法连接。"));
    }
  }

  window.__b1RuntimeReady = bootstrapB1Runtime();

  // 通用 CSV 导出：真实模式下载，静态预览只提示
  document.querySelectorAll("[data-export]").forEach((button) => {
    button.addEventListener("click", async () => {
      if (
        (button.dataset.exportQuery === "licenses" && hasCredentialSearchOverlay(licenseSearchOverlayScope()))
        || (button.dataset.exportQuery === "quota-cards" && hasCredentialSearchOverlay("quota-cards"))
      ) {
        credentialSearchOverlayToast("再导出");
        return;
      }
      if (isStandaloneStaticPreview) {
        showToast("静态预览不执行真实导出。");
        return;
      }
      const endpoint = button.dataset.export;
      button.disabled = true;
      try {
        let url = `${API_ROOT}${endpoint}`;
        if (button.dataset.exportQuery === "analytics") {
          const filters = document.querySelector("[data-analytics-filters]");
          const params = new URLSearchParams();
          const software = filters?.querySelector('[name="analytics_software"]')?.value;
          const downstream = filters?.querySelector('[name="analytics_downstream"]')?.value;
          const windowValue = filters?.querySelector('[name="analytics_window"]')?.value;
          if (software && software !== "all") params.set("software_id", software);
          if (downstream && downstream !== "all") params.set("downstream_id", downstream);
          if (windowValue) params.set("window", windowValue);
          const query = params.toString();
          if (query) url += `?${query}`;
        } else if (button.dataset.exportQuery === "quota-cards") {
          const panel = document.querySelector(
            '[data-record-view-scope="quota-cards"] [data-record-panel="items"]',
          );
          const params = new URLSearchParams(quotaCardFilterQuery(panel));
          const quotaSearch = nonSecretTableQuery(panel?.querySelector("[data-sensitive-search]"), "quota");
          if (quotaSearch) params.set("q", quotaSearch);
          const query = params.toString();
          if (query) url += `?${query}`;
        } else if (button.dataset.exportQuery === "licenses") {
          const panel = document.querySelector(
            `[data-record-view-scope="${document.body.classList.contains("role-admin") ? "management-licenses" : "downstream-licenses"}"] [data-record-panel="items"]`,
          );
          const params = new URLSearchParams(licenseCardFilterQuery(panel));
          const fuzzy = nonSecretTableQuery(panel?.querySelector("[data-sensitive-search]"), "license");
          if (fuzzy) params.set("q", fuzzy);
          const query = params.toString();
          if (query) url += `?${query}`;
        } else if (button.dataset.exportQuery === "risk") {
          const screen = document.querySelector('[data-screen-panel="risk"]');
          const params = new URLSearchParams();
          const search = document.querySelector("[data-risk-search]")?.value.trim();
          if (search) params.set("q", await resolveTableSearchQuery(search, "license"));
          screen?.querySelectorAll("[data-device-authorization-filters] select").forEach((select) => {
            const key = select.dataset.riskFilter;
            if (key && select.value) params.set(key, select.value);
          });
          const query = params.toString();
          if (query) url += `?${query}`;
        }
        const response = await window.fetch(url, {
          credentials: "same-origin",
          headers: { "X-Request-Id": requestIdempotencyKey("web-export") },
        });
        if (!response.ok) throw new Error(`export failed: ${response.status}`);
        const blob = await response.blob();
        const downloadUrl = URL.createObjectURL(blob);
        const link = document.createElement("a");
        link.href = downloadUrl;
        link.download = button.dataset.exportFilename || "export.csv";
        document.body.append(link);
        link.click();
        link.remove();
        setTimeout(() => URL.revokeObjectURL(downloadUrl), 0);
        showToast(
          response.headers.get("X-Export-Truncated") === "1"
            ? `导出已下载脱敏摘要，已截断为最多 1000 条（服务端共 ${response.headers.get("X-Export-Total") || "多"} 条）。`
            : "导出已下载，仅包含脱敏摘要。",
        );
      } catch (exportError) {
        showToast(apiErrorMessage(exportError, "导出失败，请稍后重试。"));
      } finally {
        button.disabled = false;
      }
    });
  });

  issueDialog?.addEventListener("close", () => {
    stopIssuePreviewCountdown();
    if (issueForm && issueResult) {
      issueForm.hidden = false;
      issueResult.hidden = true;
      quantity?.setCustomValidity("");
      if (issueError) issueError.textContent = "";
    }
    const leftover = JSON.parse(issueDialog.dataset.generatedCodes || "[]");
    if (Array.isArray(leftover) && leftover.length && issueDialog.dataset.codesCopied !== "true") {
      showToast("请先复制完整码。完整码已从窗口清除，可到单卡列表按需显示。");
    }
    issueDialog.dataset.generatedCodes = "[]";
    issueDialog.dataset.codesCopied = "false";
    issueResult?.querySelector("[data-issue-codes]")?.replaceChildren();
  });

  inviteDialog?.addEventListener("close", () => {
    inviteDialog.dataset.generatedCodes = "[]";
    inviteDialog.querySelector("[data-invite-codes]")?.replaceChildren();
  });

  quotaCardDialog?.addEventListener("close", () => {
    quotaCardDialog.dataset.generatedCodes = "[]";
    quotaCardDialog.querySelector("[data-quota-card-codes]")?.replaceChildren();
  });

  const requestedScreen = window.location.hash.slice(1);
  const initialScreen = requestedScreen || defaultScreen;
  if (
    !document.body.classList.contains("access-preview") &&
    !requestedScreen &&
    defaultScreen
  ) {
    window.history.replaceState(
      window.history.state,
      "",
      `${window.location.pathname}${window.location.search}#${defaultScreen}`,
    );
  }
  if (!activateScreen(initialScreen, { smooth: false, focus: false })) {
    window.history.replaceState(
      null,
      "",
      `${window.location.pathname}${window.location.search}`,
    );
    activateScreen(defaultScreen, { smooth: false, focus: false });
  }
  function syncScreenFromLocation() {
    const screen = window.location.hash.slice(1) || defaultScreen;
    if (!activateScreen(screen, { smooth: false })) {
      window.history.replaceState(
        null,
        "",
        `${window.location.pathname}${window.location.search}`,
      );
      activateScreen(defaultScreen, { smooth: false });
    }
  }

  window.addEventListener("popstate", syncScreenFromLocation);
  window.addEventListener("hashchange", syncScreenFromLocation);
  installWorkspaceRefresh();
})();
