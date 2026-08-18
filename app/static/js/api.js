/* API 客户端（本地模式：无鉴权）与通用工具。 */
const Api = (() => {
  async function request(method, path, body, isForm) {
    const headers = {};
    let payload;
    if (body !== undefined && !isForm) {
      headers["Content-Type"] = "application/json";
      payload = JSON.stringify(body);
    } else if (isForm) {
      payload = body;
    }
    let res;
    try {
      res = await fetch("/api/v1" + path, { method, headers, body: payload });
    } catch (e) {
      throw new Error("网络错误：" + e.message);
    }
    const ct = res.headers.get("content-type") || "";
    const data = ct.includes("application/json") ? await res.json() : await res.text();
    if (!res.ok) {
      const msg = (data && data.message) || (typeof data === "string" ? data : "请求失败");
      const err = new Error(msg);
      err.detail = data && data.detail;
      err.status = res.status;
      throw err;
    }
    return data;
  }

  return {
    get: (p) => request("GET", p),
    post: (p, b) => request("POST", p, b),
    put: (p, b) => request("PUT", p, b),
    del: (p) => request("DELETE", p),
    upload: (p, formData) => request("POST", p, formData, true),
  };
})();

/* 通用工具 */
const U = {
  esc(s) { return String(s ?? "").replace(/[&<>"']/g, c => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c])); },
  icon(name, size) {
    let svg = TE_ICONS[name] || TE_ICONS.file;
    if (size) svg = svg.replace(/width="\d+"/, `width="${size}"`).replace(/height="\d+"/, `height="${size}"`);
    return svg;
  },
  fmtSize(b) { if (b == null) return "-"; if (b >= 1 << 30) return (b / (1 << 30)).toFixed(2) + " GB"; if (b >= 1 << 20) return (b / (1 << 20)).toFixed(2) + " MB"; if (b >= 1024) return (b / 1024).toFixed(1) + " KB"; return b + " B"; },
  fmtTs(ts) { if (!ts) return "-"; const d = new Date(ts * 1000); return d.toLocaleString("zh-CN", { hour12: false }); },
  fmtDt(s) { if (!s) return "-"; const d = new Date(s); return d.toLocaleString("zh-CN", { hour12: false }); },
  /* 人体工学：相对时间（hover 显示完整时间） */
  relTime(ts) {
    if (!ts) return "-";
    const full = U.fmtTs(ts);
    const diff = Date.now() / 1000 - ts;
    if (diff < 60) return `<span class="small" title="${full}">刚刚</span>`;
    if (diff < 3600) return `<span class="small" title="${full}">${Math.floor(diff / 60)} 分钟前</span>`;
    if (diff < 86400) return `<span class="small" title="${full}">${Math.floor(diff / 3600)} 小时前</span>`;
    if (diff < 86400 * 7) return `<span class="small" title="${full}">${Math.floor(diff / 86400)} 天前</span>`;
    return `<span class="small" title="${full}">${full}</span>`;
  },
  /* 人体工学：一键复制（clipboard API + textarea 降级） */
  copy(text) {
    const done = () => U.toast("已复制");
    if (navigator.clipboard && navigator.clipboard.writeText) {
      navigator.clipboard.writeText(text).then(done).catch(() => U._copyFallback(text, done));
    } else {
      U._copyFallback(text, done);
    }
  },
  _copyFallback(text, done) {
    const ta = document.createElement("textarea");
    ta.value = text; ta.style.position = "fixed"; ta.style.opacity = "0";
    document.body.appendChild(ta); ta.select();
    try { document.execCommand("copy"); done(); } catch (e) { U.toast("复制失败", true); }
    ta.remove();
  },
  copyBtn(text) {
    return `<button class="btn small" onclick="U.copy(${JSON.stringify(String(text).slice(0, 400))})">${U.icon("copy")}复制</button>`;
  },
  sevBadge(sev) {
    const cn = { info: "信息", low: "低", medium: "中", high: "高", critical: "严重" };
    return `<span class="badge ${U.esc(sev)}">${cn[sev] || U.esc(sev)}</span>`;
  },
  statusHtml(st) {
    const cn = { queued: "排队中", running: "分析中", succeeded: "成功", failed: "失败", cancelled: "已取消" };
    return `<span class="status"><span class="dot ${st}"></span>${cn[st] || st}</span>`;
  },
  levelOf(score) { if (score >= 90) return "critical"; if (score >= 70) return "high"; if (score >= 40) return "medium"; if (score >= 20) return "low"; return "info"; },
  levelCn(l) { return { info: "信息", low: "低风险", medium: "中风险", high: "高风险", critical: "严重" }[l] || l; },
  toast(msg, isErr) {
    const t = document.getElementById("toast");
    t.textContent = msg;
    t.className = "toast show" + (isErr ? " err" : "");
    clearTimeout(U._toastTimer);
    U._toastTimer = setTimeout(() => { t.className = "toast"; }, 3200);
  },
  params() {
    const h = location.hash.replace(/^#\//, "");
    const [path, qs] = h.split("?");
    const q = {};
    if (qs) new URLSearchParams(qs).forEach((v, k) => q[k] = v);
    return { path: path || "dashboard", q };
  },
  pager(page, total, pageSize, onChange) {
    const pages = Math.max(1, Math.ceil(total / pageSize));
    return `<div class="pager"><span>共 ${total} 条 · 第 ${page}/${pages} 页</span>` +
      `<button class="btn small" ${page <= 1 ? "disabled" : ""} onclick="(${onChange})(${page - 1})">上一页</button>` +
      `<button class="btn small" ${page >= pages ? "disabled" : ""} onclick="(${onChange})(${page + 1})">下一页</button></div>`;
  },
  empty(icon, text, actionHtml) {
    return `<div class="empty"><span class="empty-ic">${U.icon(icon || "file", 30)}</span><div>${U.esc(text)}</div>${actionHtml ? `<div class="empty-act">${actionHtml}</div>` : ""}</div>`;
  },
};
