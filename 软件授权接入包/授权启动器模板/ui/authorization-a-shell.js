/*
 * Dependency-free visual prototype for authorization-a-ui.v1.
 * The page has no network, IPC, storage, or launch authority. A production
 * renderer receives a validated snapshot and emits intents to the runtime.
 */

(() => {
  "use strict";

  const bootstrap = window.AUTHORIZATION_A_UI_BOOTSTRAP || {};
  let profile = bootstrap.profile || window.AUTHORIZATION_A_UI_PROFILE || {
    locale: "zh-CN",
    theme: {
      accent: "#D4B45A",
      surface: "#0C0B09",
      text: "#F3EEE4",
      danger: "#E85A6F"
    },
    copy: {},
    enabled_modules: []
  };

  const copyDefaults = {
    app_kicker: "本软件",
    credential_label: "卡密",
    credential_placeholder: "请输入卡密",
    activate: "立即激活",
    request_launch: "正在打开本软件",
    reactivate: "重新激活",
    loading: "正在检查",
    entering: "正在打开本软件",
    retry: "重新检查",
    online: "在线",
    offline: "离线",
    authorized: "授权有效",
    grace: "离线宽限",
    expired: "授权已过期",
    revoked: "授权已撤销",
    blocked: "当前访问已阻断",
    device_mismatch: "设备不匹配",
    unavailable: "服务暂时不可用",
    invalid_response: "无法验证授权响应",
    unauthenticated: "等待验证",
    scope_current_device: "当前设备",
    source_live: "实时检查",
    source_recovery: "本机恢复",
    source_cache: "离线租约",
    source_none: "等待检查",
    device_confirmed: "已确认",
    device_pending: "正在确认",
    device_unconfirmed: "未确认",
    support: "联系客服",
    purchase: "购买授权"
  };

  const stateConfig = {
    login: {
      labelKey: "unauthenticated",
      source: "none",
      connectivity: "online",
      message: "输入卡密开始检查。",
      device: "device_unconfirmed",
      deviceDetail: "等待授权服务确认",
      deviceCode: "待确认",
      feedback: false,
      buttonKey: "activate",
      buttonDisabled: false
    },
    loading: {
      labelKey: "loading",
      source: "recovery",
      connectivity: "loading",
      message: "正在检查卡密和当前设备，请稍候。",
      device: "device_pending",
      deviceDetail: "等待服务端确认设备范围",
      deviceCode: "生成中",
      feedback: true,
      buttonKey: "loading",
      buttonDisabled: true
    },
    active: {
      labelKey: "authorized",
      source: "live",
      connectivity: "online",
      message: "验证通过，正在打开本软件。",
      device: "device_confirmed",
      deviceDetail: "当前授权实例已绑定本机范围",
      deviceCode: "DEMO-DEVICE",
      feedback: true,
      buttonKey: "entering",
      buttonDisabled: true,
      autoLaunch: true,
      bridgeIntent: "request_launch"
    },
    grace: {
      labelKey: "grace",
      source: "cache",
      connectivity: "offline",
      message: "离线授权仍有效，正在打开本软件。",
      device: "device_confirmed",
      deviceDetail: "使用最近一次服务端确认的设备范围",
      deviceCode: "DEMO-DEVICE",
      feedback: true,
      buttonKey: "entering",
      buttonDisabled: true,
      autoLaunch: true,
      bridgeIntent: "request_launch"
    },
    expired: {
      labelKey: "expired",
      source: "live",
      connectivity: "online",
      message: "卡密已过期，请更换卡密后重新激活。",
      device: "device_unconfirmed",
      deviceDetail: "需要新的服务端检查",
      deviceCode: "待确认",
      feedback: true,
      buttonKey: "reactivate",
      buttonDisabled: false
    },
    revoked: {
      labelKey: "revoked",
      source: "live",
      connectivity: "online",
      message: "卡密已撤销，请联系客服或更换卡密。",
      device: "device_unconfirmed",
      deviceDetail: "当前绑定不会在本机自动转移",
      deviceCode: "待确认",
      feedback: true,
      buttonKey: "reactivate",
      buttonDisabled: false
    },
    blocked: {
      labelKey: "blocked",
      source: "live",
      connectivity: "online",
      message: "当前设备未通过授权，请联系客服处理绑定。",
      device: "device_unconfirmed",
      deviceDetail: "绑定转移需要授权端策略",
      deviceCode: "待确认",
      feedback: true,
      buttonKey: "reactivate",
      buttonDisabled: false
    },
    device_mismatch: {
      labelKey: "device_mismatch",
      source: "live",
      connectivity: "online",
      message: "这张卡密已绑定其他设备，本机不会自动改绑。",
      device: "device_unconfirmed",
      deviceDetail: "请在授权端执行解绑或转移",
      deviceCode: "待确认",
      feedback: true,
      buttonKey: "reactivate",
      buttonDisabled: false
    },
    unavailable: {
      labelKey: "unavailable",
      source: "none",
      connectivity: "unavailable",
      message: "暂时无法连接授权服务，请稍后重试。",
      device: "device_unconfirmed",
      deviceDetail: "等待重新检查",
      deviceCode: "待确认",
      feedback: true,
      buttonKey: "retry",
      buttonDisabled: false,
      bridgeIntent: "retry"
    },
    invalid: {
      labelKey: "invalid_response",
      source: "none",
      connectivity: "unavailable",
      message: "授权响应无效，已停止继续。请重新激活。",
      device: "device_unconfirmed",
      deviceDetail: "服务端响应需要重新获取",
      deviceCode: "待确认",
      feedback: true,
      buttonKey: "reactivate",
      buttonDisabled: false
    }
  };

  const shell = document.querySelector(".shell");
  const picker = document.getElementById("statePicker");
  const prototypeRibbon = document.querySelector(".prototype-ribbon");
  const prototypeTools = document.querySelector(".prototype-tools");
  const liveRegion = document.getElementById("liveRegion");
  const credential = document.getElementById("credential");
  const activateButton = document.getElementById("activateButton");
  const feedbackPanel = document.getElementById("feedbackPanel");
  const feedbackTitle = document.getElementById("feedbackTitle");
  const feedbackMessage = document.getElementById("feedbackMessage");
  const connectivityLabel = document.getElementById("connectivityLabel");
  const headerConnection = document.getElementById("headerConnection");
  const deviceCode = document.getElementById("deviceCode");
  let renderSnapshot = bootstrap.snapshot || null;
  const supportLinks = document.getElementById("supportLinks");
  const supportActions = [
    { type: "purchase", element: document.getElementById("purchaseLink") },
    { type: "contact", element: document.getElementById("contactLink") }
  ];
  let demoTimer = 0;
  let currentState = "login";
  let launchSent = false;
  let displayedDeviceCode = "待确认";
  let copyResetTimer = 0;
  const hasDesktopBridge = Boolean(window.ipc && typeof window.ipc.postMessage === "function");
  // Remove the retired prototype's plaintext recovery value. Credentials now
  // live only for the immediate host request and never return to the page.
  try { window.localStorage.removeItem("a.saved_card"); } catch (error) { /* opaque origin */ }

  const isPrototypePreview = new URLSearchParams(window.location.search).get("prototype") === "1";
  if (isPrototypePreview) {
    prototypeRibbon.hidden = false;
    prototypeTools.hidden = false;
    document.body.dataset.prototype = "true";
  }

  function text(key) {
    return (profile.copy && profile.copy[key]) || copyDefaults[key] || key;
  }

  function fallbackCopy(value) {
    const area = document.createElement("textarea");
    area.value = value;
    area.setAttribute("readonly", "");
    area.style.position = "fixed";
    area.style.left = "-9999px";
    document.body.appendChild(area);
    area.select();
    let ok = false;
    try {
      ok = document.execCommand("copy");
    } catch (error) {
      ok = false;
    }
    document.body.removeChild(area);
    return ok;
  }

  function copyDeviceCode() {
    const value = (displayedDeviceCode || "").trim();
    if (!value || !deviceCode) return;
    const afterCopy = function () {
      liveRegion.textContent = "设备码已复制";
      deviceCode.textContent = "已复制";
      if (copyResetTimer) window.clearTimeout(copyResetTimer);
      copyResetTimer = window.setTimeout(function () {
        copyResetTimer = 0;
        deviceCode.textContent = displayedDeviceCode;
      }, 900);
    };
    if (navigator.clipboard && typeof navigator.clipboard.writeText === "function") {
      navigator.clipboard.writeText(value).then(afterCopy).catch(function () {
        if (fallbackCopy(value)) afterCopy();
      });
      return;
    }
    if (fallbackCopy(value)) afterCopy();
  }

  function applyProfile() {
    const theme = profile.theme || {};
    const root = document.documentElement;
    ["accent", "surface", "text", "danger"].forEach((key) => {
      if (typeof theme[key] === "string" && /^#[0-9a-f]{6,8}$/i.test(theme[key])) {
        root.style.setProperty("--a-" + key, theme[key]);
      }
    });
    document.querySelectorAll("[data-copy]").forEach((node) => {
      node.textContent = text(node.dataset.copy);
    });
    document.querySelectorAll("[data-copy-placeholder]").forEach((node) => {
      node.placeholder = text(node.dataset.copyPlaceholder);
    });
    document.documentElement.lang = profile.locale || "zh-CN";
    const displayName =
      (renderSnapshot && renderSnapshot.display_name) || text("app_kicker") || "本软件";
    document.title = displayName + " 授权";
  }

  // Downstream contact/notice text, verbatim: show exactly what the server
  // sent, no labels, no prefixes, no additions. Empty stays hidden.
  function renderContactBanner() {
    const banner = document.getElementById("contactBanner");
    if (!banner) return;
    while (banner.firstChild) banner.removeChild(banner.firstChild);
    const modules = (renderSnapshot && renderSnapshot.modules) || [];
    let shown = 0;
    modules.forEach((card) => {
      if (!card || typeof card !== "object") return;
      if (card.kind !== "contact" && card.kind !== "announcement" && card.kind !== "notice") return;
      const fields = (card.fields && typeof card.fields === "object") ? card.fields : {};
      Object.keys(fields).forEach((key) => {
        const value = fields[key];
        if (typeof value !== "string" || value.trim() === "") return;
        const line = document.createElement("div");
        line.className = "contact-line";
        line.textContent = value;
        banner.appendChild(line);
        shown += 1;
      });
    });
    banner.hidden = shown === 0;
  }

  function renderSupportLinks() {
    const enabled = new Set(Array.isArray(profile.enabled_modules) ? profile.enabled_modules : []);
    let visible = 0;
    supportActions.forEach(({ type, element }) => {
      const cards = (renderSnapshot && renderSnapshot.modules) || [];
      const isEnabled = enabled.has(type) && cards.some(card => card.kind === type && card.fields && Object.values(card.fields).some(value => typeof value === "string" && value.trim()));
      element.hidden = !isEnabled;
      if (isEnabled) visible += 1;
    });
    supportLinks.hidden = visible === 0;
  }

  function sourceText(source) {
    if (source === "cache") return text("source_cache");
    if (source === "recovery") return text("source_recovery");
    if (source === "live") return text("source_live");
    return text("source_none");
  }

  function connectivityText(connectivity) {
    if (connectivity === "offline") return text("offline");
    if (connectivity === "loading") return text("loading");
    if (connectivity === "online") return text("online");
    return text("unavailable");
  }

  function clearDemoTimer() {
    if (demoTimer) {
      window.clearTimeout(demoTimer);
      demoTimer = 0;
    }
  }

  function postBridge(message) {
    if (!hasDesktopBridge) return false;
    window.ipc.postMessage(JSON.stringify(message));
    return true;
  }

  function stateFromSnapshot() {
    const authorization = renderSnapshot && renderSnapshot.state && renderSnapshot.state.authorization;
    return ({
      unauthenticated: "login",
      pending: "loading",
      active: "active",
      grace: "grace",
      expired: "expired",
      revoked: "revoked",
      blocked: "blocked",
      unavailable: "unavailable",
      contract_invalid: "invalid"
    })[authorization] || "login";
  }

  function emitIntent(name) {
    if (postBridge({ type: "intent", name })) return;
    liveRegion.textContent = "已发送" + name + "意图，仍由运行时进行授权检查。";
  }

  function buttonIntentFor(state) {
    const config = stateConfig[state] || stateConfig.invalid;
    const allowed = renderSnapshot && renderSnapshot.state && renderSnapshot.state.intents;
    if (state === "unavailable" && Array.isArray(allowed) && allowed.includes("activate") && !allowed.includes("retry")) return "activate";
    return config.bridgeIntent || "activate";
  }

  function setState(state, announce = true) {
    const config = stateConfig[state] || stateConfig.invalid;
    const buttonIntent = buttonIntentFor(state);
    const label = state === "unavailable" && buttonIntent === "activate" ? "授权检查未通过" : text(config.labelKey);
    const hostConnectivity = renderSnapshot && renderSnapshot.state && renderSnapshot.state.connectivity;
    const connectionState = hostConnectivity || config.connectivity;
    const connectivity = connectivityText(connectionState);
    currentState = state;
    if (!config.autoLaunch) launchSent = false;
    shell.dataset.state = state;
    shell.dataset.connectivity = connectionState;
    shell.setAttribute("aria-busy", connectionState === "loading");
    picker.value = state;
    feedbackPanel.hidden = !config.feedback;
    feedbackTitle.textContent = label;
    feedbackMessage.textContent = config.message;
    connectivityLabel.textContent = connectivity;
    headerConnection.textContent = connectivity;
    if (deviceCode) {
      displayedDeviceCode = (renderSnapshot && renderSnapshot.device_code) || config.deviceCode;
      deviceCode.textContent = displayedDeviceCode;
    }
    const allowedIntents = renderSnapshot && renderSnapshot.state && renderSnapshot.state.intents;
    const intentAllowed = !Array.isArray(allowedIntents) || allowedIntents.includes(buttonIntent);
    activateButton.disabled = config.buttonDisabled || (!isPrototypePreview && (!hasDesktopBridge || !intentAllowed));
    activateButton.textContent = text(state === "unavailable" && buttonIntent === "activate" ? "reactivate" : config.buttonKey);
    if (state === "unavailable" && renderSnapshot && renderSnapshot.error) {
      const code = String(renderSnapshot.error);
      feedbackMessage.textContent = buttonIntent === "activate"
        ? (code === "LICENSE_NOT_FOUND" ? "未找到这张卡密，请核对后重新激活。" : "授权检查未通过，请核对卡密或联系支持。") + "（" + code + "）"
        : "上次请求结果尚未确认，请重新检查原请求。（" + code + "）";
    }
    if (announce) liveRegion.textContent = label + "。" + feedbackMessage.textContent;
    if (!hasDesktopBridge && !isPrototypePreview) {
      feedbackPanel.hidden = false;
      feedbackMessage.textContent = "授权连接不可用，请从本软件的授权启动器打开。";
    }
    if (renderSnapshot && Number.isSafeInteger(renderSnapshot.expires_at)) {
      const date = new Date(renderSnapshot.expires_at * 1000);
      if (!Number.isNaN(date.getTime())) feedbackMessage.textContent += " 到期时间：" + date.toLocaleString("zh-CN");
    }
    maybeAutoLaunch(state);
  }

  function maybeAutoLaunch(state) {
    const config = stateConfig[state];
    if (!config || !config.autoLaunch || launchSent) return;
    launchSent = true;
    if (hasDesktopBridge) {
      emitIntent("request_launch");
    }
  }

  function beginDemoVerification() {
    if (!isPrototypePreview) return;
    clearDemoTimer();
    setState("loading");
    demoTimer = window.setTimeout(() => {
      demoTimer = 0;
      if (picker.value === "loading") setState("active");
    }, 650);
  }

  document.getElementById("activationForm").addEventListener("submit", (event) => {
    event.preventDefault();
    if (activateButton.disabled) return;
    const typed = (credential.value || "").trim();
    if (hasDesktopBridge) {
      const intent = buttonIntentFor(currentState);
      if (intent === "retry") {
        emitIntent(intent);
      } else {
        postBridge({ type: "activate", credential: typed });
      }
      credential.value = "";
      return;
    }
    credential.value = "";
    if (isPrototypePreview) beginDemoVerification();
    else setState("unavailable");
  });

  picker.addEventListener("change", () => {
    if (!isPrototypePreview) return;
    clearDemoTimer();
    setState(picker.value);
  });

  applyProfile();
  supportActions.forEach(({type, element}) => element.addEventListener("click", () => {
    if (!element.hidden) postBridge({type: "open_module", module: type});
  }));
  window.authorizationAApplySnapshot = function (next) {
    if (!hasDesktopBridge || !next || !next.snapshot || !next.profile) return;
    profile = next.profile;
    renderSnapshot = next.snapshot;
    applyProfile();
    renderSupportLinks();
    renderContactBanner();
    setState(stateFromSnapshot());
  };
  renderSupportLinks();
  renderContactBanner();
  if (deviceCode) {
    deviceCode.addEventListener("click", copyDeviceCode);
  }
  setState(stateFromSnapshot(), false);
  credential.focus();
})();
