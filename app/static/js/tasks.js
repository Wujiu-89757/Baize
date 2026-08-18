/* 分析任务页：任务列表 + 结果页（KPI/时间线/告警/会话/包/报告导出）。 */
const TasksView = {
  cache: false,
  state: { page: 1, pageSize: 15, status: "", taskId: null, refreshTimer: null },

  async render(main, path) {
    const segs = path.split("/");
    if (segs.length >= 2 && segs[1]) {
      this.state.taskId = segs[1];
      await this.renderResult(main, segs[1]);
    } else {
      this.state.taskId = null;
      this.renderList(main);
    }
  },

  /* ---------------- 任务列表 ---------------- */
  async renderList(main) {
    main.innerHTML = `
      <div class="page-head"><h2>分析任务</h2>
        <div class="actions"><button class="btn" id="t-refresh">${U.icon("refresh", 14)}刷新</button></div>
      </div>
      <div class="card">
        <div class="filters">
          <select id="t-status"><option value="">全部状态</option>
            ${["queued","running","succeeded","failed","cancelled"].map(s => `<option ${this.state.status === s ? "selected" : ""}>${s}</option>`).join("")}
          </select>
          <button class="btn" id="t-search">${U.icon("search", 14)}查询</button>
        </div>
        <div class="table-wrap"><table class="data"><thead><tr>
          <th>文件</th><th>任务 ID</th><th>状态</th><th>进度</th><th>风险</th><th>告警</th><th>创建时间</th><th>操作</th>
        </tr></thead><tbody id="t-body"></tbody></table></div>
        <div id="t-pager"></div>
      </div>`;
    document.getElementById("t-search").onclick = () => {
      this.state.status = document.getElementById("t-status").value;
      this.state.page = 1; this.loadList(main);
    };
    document.getElementById("t-refresh").onclick = () => this.loadList(main);
    this.loadList(main);
    // 复用全局唯一轮询器（App.route 离开页面时统一清理）
    Poller.set(() => {
      if (location.hash.startsWith("#/tasks") && !this.state.taskId) this.loadList(main, true);
    }, 5000);
  },

  async loadList(main, silent) {
    try {
      const qs = new URLSearchParams({ page: this.state.page, page_size: this.state.pageSize, status: this.state.status });
      const r = await Api.get("/analysis?" + qs);
      const body = document.getElementById("t-body");
      if (!body) return;
      body.innerHTML = r.items.length ? r.items.map(t => `
        <tr style="cursor:pointer" onclick="location.hash='#/tasks/${t.id}'">
          <td class="truncate" title="${U.esc(t.file_name || t.file_id)}">${U.esc(t.file_name || t.file_id.slice(0, 8) + "…")}</td>
          <td class="mono"><a href="#/tasks/${t.id}" onclick="event.stopPropagation()">${t.id.slice(0, 10)}…</a></td>
          <td>${U.statusHtml(t.status)}</td>
          <td><span class="mono" style="margin-right:8px">${t.progress}%</span><div class="progress"><div class="${t.status === "succeeded" ? "done" : ""}" style="width:${t.progress}%"></div></div></td>
          <td>${t.risk_score > 0 ? `<span class="badge ${U.levelOf(t.risk_score)}">${t.risk_score.toFixed(1)} ${U.levelCn(t.risk_level)}</span>` : '<span class="muted">-</span>'}</td>
          <td>${t.alert_count}</td>
          <td>${U.relTime(new Date(t.created_at).getTime() / 1000)}</td>
          <td>
            <a class="btn small primary" href="#/tasks/${t.id}">查看</a>
            ${t.status === "failed" ? `<button class="btn small" onclick="event.stopPropagation();TasksView.retry('${t.id}')">重试</button>` : ""}
            ${t.status === "running" || t.status === "queued" ? `<button class="btn small" onclick="event.stopPropagation();TasksView.cancel('${t.id}')">取消</button>` : ""}
            <button class="btn small danger-solid" onclick="event.stopPropagation();TasksView.trash('${t.id}')">${U.icon("trash", 13)}删除</button>
          </td>
        </tr>`).join("") : `<tr><td colspan="8">${U.empty("play", "暂无分析任务", `<a class="btn small primary" href="#/files">上传流量包开始分析</a>`)}</td></tr>`;
      document.getElementById("t-pager").innerHTML = U.pager(this.state.page, r.total, this.state.pageSize, p => { this.state.page = p; this.loadList(main); });
    } catch (e) { if (!silent) U.toast(e.message, true); }
  },

  async cancel(id) {
    try { await Api.post(`/analysis/${id}/cancel`); U.toast("已请求取消"); this.loadList(document.getElementById("main")); }
    catch (e) { U.toast(e.message, true); }
  },
  async retry(id) {
    try { await Api.post(`/analysis/${id}/retry`); U.toast("已重新入队"); location.hash = "#/tasks"; }
    catch (e) { U.toast(e.message, true); }
  },
  async trash(id) {
    if (!confirm("删除该分析任务？将移入回收站，可随时还原。")) return;
    try { await Api.del(`/analysis/${id}`); U.toast("已移入回收站"); this.loadList(document.getElementById("main")); }
    catch (e) { U.toast(e.message, true); }
  },

  /* ---------------- 结果页 ---------------- */
  async renderResult(main, taskId) {
    const task = await Api.get(`/analysis/${taskId}`);
    if (task.status !== "succeeded") {
      main.innerHTML = `
        <div class="page-head"><h2><a href="#/tasks">← 任务</a> / ${task.id.slice(0, 10)}…</h2></div>
        <div class="card">
          <h3>任务状态：${U.statusHtml(task.status)}</h3>
          <p class="muted">进度：${task.progress}% · ${U.esc(task.stage)}</p>
          ${task.error_message ? `<p class="err" style="color:var(--te-danger)">${U.esc(task.error_message)}</p>` : ""}
          ${task.status === "failed" ? `<button class="btn primary" onclick="TasksView.retry('${task.id}')">重试</button>` : ""}
          ${task.status === "cancelled" ? `<p class="muted small" style="margin-top:10px">已取消，可返回列表点击重试</p>` : `<p class="muted small" style="margin-top:10px">页面将自动刷新…</p>`}
        </div>`;
      if (task.status === "queued" || task.status === "running") {
        // 只对活动任务轮询；终态（failed/cancelled）立即停止，不再持续刷新
        Poller.set(() => { if (location.hash === "#/tasks/" + taskId) this.renderResult(main, taskId); }, 3000);
      } else {
        Poller.clear();
      }
      return;
    }
    Poller.clear();

    const s = await Api.get(`/analysis/${taskId}/summary`);
    const risk = s.risk;
    const sc = risk.score || 0;
    const sevCounts = Object.entries(risk.severity_counts || {});
    main.innerHTML = `
      <div class="page-head"><h2><a href="#/tasks">← 任务</a> / ${task.id.slice(0, 10)}…</h2>
        <div class="actions">
          <button class="btn" onclick="TasksView.exportR('${taskId}','json')">${U.icon("download", 14)}JSON</button>
          <button class="btn" onclick="TasksView.exportR('${taskId}','csv')">${U.icon("download", 14)}告警 CSV</button>
          <button class="btn" onclick="TasksView.exportR('${taskId}','packets_csv')">${U.icon("download", 14)}包 CSV</button>
          <button class="btn primary" onclick="TasksView.exportR('${taskId}','html')">${U.icon("download", 14)}HTML 报告</button>
        </div>
      </div>
      <div class="stat-cards">
        <div class="stat-card"><span class="label">风险总分</span>
          <span class="value ${sc >= 70 ? "danger" : sc >= 40 ? "warning" : "primary"}">${sc.toFixed(1)}</span>
          <span class="sub">${U.levelCn(risk.level)}</span></div>
        <div class="stat-card"><span class="label">告警</span><span class="value ${sevCounts.length ? "warning" : ""}">${task.alert_count}</span>
          <span class="sub">${sevCounts.map(([k, v]) => `<span class="badge ${k}" style="margin:1px">${v}</span>`).join(" ") || "无"}</span></div>
        <div class="stat-card"><span class="label">数据包</span><span class="value">${task.parse_summary.packets || 0}</span><span class="sub">${task.parse_summary.duration ? U.fmtTs(task.parse_summary.first_ts) + " ~ " + U.fmtTs(task.parse_summary.last_ts) : ""}</span></div>
        <div class="stat-card"><span class="label">会话</span><span class="value">${task.parse_summary.sessions || 0}</span><span class="sub">双向五元组聚合</span></div>
        <div class="stat-card"><span class="label">涉及主机</span><span class="value primary">${s.hosts.length}</span><span class="sub">告警关联主机</span></div>
      </div>
      <div class="grid2">
        <div class="card"><h3>告警时间线</h3><div class="timeline" id="tl"></div></div>
        <div class="card"><h3>协议分布</h3><div id="proto"></div></div>
      </div>
      <div class="card"><h3>涉及主机</h3><div class="host-list" id="hosts"></div></div>
      <div class="card"><h3>策略命中统计</h3>
        <div class="table-wrap"><table class="data"><thead><tr><th>策略</th><th>名称</th><th>版本</th><th>命中</th><th>累计分</th></tr></thead>
        <tbody>${(s.strategy_hits || []).map(h => `<tr><td class="mono">${U.esc(h.strategy_id)}</td><td>${U.esc(h.name)}</td><td class="mono">v${U.esc(h.version)}</td><td>${h.count}</td><td>${h.score.toFixed(2)}</td></tr>`).join("") || `<tr><td colspan="5">${U.empty("shield", "无策略命中")}</td></tr>`}</tbody></table></div>
      </div>
      <div class="card">
        <div class="tabs">
          <button data-tab="alerts" class="active">告警明细</button>
          <button data-tab="sessions">会话</button>
          <button data-tab="packets">数据包</button>
        </div>
        <div id="tab-body"><div class="empty">加载中…</div></div>
      </div>`;

    const tl = s.timeline || [];
    const max = Math.max(...tl.map(b => b.count), 1);
    document.getElementById("tl").innerHTML = tl.map(b =>
      `<div class="tl-col" style="height:${Math.max(4, b.count / max * 76)}px" data-tip="${b.count} 条告警 @ ${U.fmtTs(b.ts)}"></div>`).join("")
      || '<span class="muted small">无告警</span>';
    const proto = s.protocol_stats || {};
    const entries = Object.entries(proto).sort((a, b) => b[1] - a[1]).slice(0, 8);
    const pmax = Math.max(...entries.map(e => e[1]), 1);
    document.getElementById("proto").innerHTML = entries.map(([k, v]) =>
      `<div style="display:flex;align-items:center;gap:8px;margin-bottom:6px"><span class="muted small" style="width:56px">${U.esc(k)}</span>
       <div class="progress" style="flex:1"><div style="width:${v / pmax * 100}%"></div></div><span class="small">${v}</span></div>`).join("")
      || '<span class="muted small">无</span>';
    document.getElementById("hosts").innerHTML = (s.hosts || []).map(h =>
      `<span class="host-chip"><span class="h-ip">${U.esc(h.ip)}</span>${U.sevBadge(h.max_severity)}<span class="h-cnt">${h.alert_count} 条告警 · ${h.score.toFixed(1)} 分</span></span>`).join("")
      || '<span class="muted small">无</span>';

    document.querySelectorAll(".tabs button").forEach(b => b.onclick = () => {
      document.querySelectorAll(".tabs button").forEach(x => x.classList.remove("active"));
      b.classList.add("active");
      this.loadTab(taskId, b.dataset.tab, document.getElementById("tab-body"));
    });
    this.loadTab(taskId, "alerts", document.getElementById("tab-body"));
  },

  async exportR(taskId, fmt) {
    try {
      const res = await fetch(`/api/v1/analysis/${taskId}/report?format=${fmt}`);
      if (!res.ok) throw new Error("导出失败");
      const blob = await res.blob();
      const ext = { json: "json", csv: "csv", packets_csv: "csv", html: "html" }[fmt];
      const a = document.createElement("a");
      a.href = URL.createObjectURL(blob);
      a.download = `baize-report-${taskId.slice(0, 8)}.${ext}`;
      a.click();
      URL.revokeObjectURL(a.href);
    } catch (e) { U.toast(e.message, true); }
  },

  /* ---------------- Tab：告警 ---------------- */
  alertState: { page: 1, pageSize: 20, severity: "", strategyId: "", status: "", srcIp: "", dstIp: "", q: "" },

  async loadTab(taskId, tab, el) {
    this.alertState.page = 1;
    if (tab === "alerts") this.loadAlerts(taskId, el);
    else if (tab === "sessions") this.loadSessions(taskId, el);
    else this.loadPackets(taskId, el);
  },

  async loadAlerts(taskId, el) {
    const st = this.alertState;
    el.innerHTML = `
      <div class="filters">
        <select id="a-sev"><option value="">全部级别</option>${["info","low","medium","high","critical"].map(s => `<option ${st.severity === s ? "selected" : ""}>${s}</option>`).join("")}</select>
        <input id="a-src" placeholder="源 IP" value="${U.esc(st.srcIp)}" style="min-width:110px">
        <input id="a-dst" placeholder="目的 IP" value="${U.esc(st.dstIp)}" style="min-width:110px">
        <select id="a-status"><option value="">全部标记</option>${["pending","confirmed","suspected","false_positive","ignored"].map(s => `<option ${st.status === s ? "selected" : ""}>${s}</option>`).join("")}</select>
        <button class="btn" id="a-go">${U.icon("search", 14)}筛选</button>
      </div>
      <div class="table-wrap"><table class="data"><thead><tr>
        <th>#</th><th>级别</th><th>策略</th><th>源 → 目的</th><th>命中字段</th><th>原始分</th><th>归一化</th><th>代表帧</th><th>标记</th>
      </tr></thead><tbody id="a-body"></tbody></table></div>
      <div id="a-pager"></div>`;
    const load = async (page) => {
      const qs = new URLSearchParams({ page, page_size: st.pageSize, severity: st.severity, status: st.status, src_ip: st.srcIp, dst_ip: st.dstIp });
      const r = await Api.get(`/analysis/${taskId}/alerts?${qs}`);
      const body = document.getElementById("a-body");
      if (!body) return;
      body.innerHTML = r.items.length ? r.items.map(a => `
        <tr style="cursor:pointer" onclick="TasksView.showAlert('${taskId}', ${a.id})">
          <td class="muted">${a.id}</td>
          <td>${U.sevBadge(a.severity)}</td>
          <td>${U.esc(a.strategy_name)}<div class="small muted">${U.esc(a.strategy_id)} v${U.esc(a.strategy_version)}</div></td>
          <td class="mono">${U.esc(a.src_ip || "-")} → ${U.esc(a.dst_ip || "-")}<div class="small muted">${U.esc(a.protocol)}${a.dst_port ? ":" + a.dst_port : ""}${a.domain ? " · " + U.esc(a.domain) : ""}</div></td>
          <td class="small truncate" title="${(a.hit_fields || []).map(h => h.field + "=" + h.actual).join(", ")}">${(a.hit_fields || []).slice(0, 3).map(h => U.esc(h.field)).join(", ")}${(a.hit_fields || []).length > 3 ? "…" : ""}</td>
          <td>${a.raw_score.toFixed(1)}</td>
          <td>${a.normalized_score.toFixed(1)}</td>
          <td class="mono small" title="${(a.evidence_packets || []).join(", ")}">${(a.evidence_packets || []).slice(0, 3).join(", ")}${(a.evidence_packets || []).length > 3 ? "…" : ""}</td>
          <td>${this.statusBadge(a.status)}</td>
        </tr>`).join("") : `<tr><td colspan="9">${U.empty("alert", "无匹配告警")}</td></tr>`;
      document.getElementById("a-pager").innerHTML = U.pager(page, r.total, st.pageSize, p => load(p));
    };
    document.getElementById("a-go").onclick = () => {
      st.severity = document.getElementById("a-sev").value;
      st.srcIp = document.getElementById("a-src").value.trim();
      st.dstIp = document.getElementById("a-dst").value.trim();
      st.status = document.getElementById("a-status").value;
      load(1);
    };
    await load(1);
  },

  statusBadge(st) {
    const m = { pending: ["待处理", "gray"], confirmed: ["确认恶意", "critical"], suspected: ["疑似", "high"], false_positive: ["误报", "success"], ignored: ["忽略", "gray"] };
    const [label, cls] = m[st] || [st, "gray"];
    return `<span class="badge ${cls}">${label}</span>`;
  },

  async showAlert(taskId, alertId) {
    const a = await Api.get(`/analysis/${taskId}/alerts/${alertId}`);
    const drawer = document.createElement("div");
    drawer.className = "drawer";
    drawer.innerHTML = `
      <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:14px">
        <h3>告警 #${a.id} ${U.sevBadge(a.severity)}</h3>
        <button class="btn ghost" onclick="this.closest('.drawer').remove()">${U.icon("x", 14)}</button>
      </div>
      <div class="te-detail-section">
        <h4>策略</h4>
        <p style="margin:0"><b>${U.esc(a.strategy_name)}</b> ${U.copyBtn(a.strategy_id + "@" + a.strategy_version)}
        <div class="small muted mono">${U.esc(a.strategy_id)} v${U.esc(a.strategy_version)}</div></p>
        <p class="muted small" style="margin:8px 0">${U.esc(a.description || "")}</p>
        ${a.false_positive_hint ? `<p class="muted small" style="border-left:3px solid var(--te-warning);padding-left:8px;margin:8px 0">⚠ 误报提示：${U.esc(a.false_positive_hint)}</p>` : ""}
      </div>
      <div class="te-detail-section">
        <h4>基本信息</h4>
        <div class="kv-row"><span class="k">时间范围</span><span class="v">${U.fmtTs(a.time_start)} ~ ${U.fmtTs(a.time_end)}</span></div>
        <div class="kv-row"><span class="k">源 → 目的</span><span class="v mono">${U.esc(a.src_ip || "-")}:${a.src_port || "-"} → ${U.esc(a.dst_ip || "-")}:${a.dst_port || "-"} (${U.esc(a.protocol)})</span></div>
        <div class="kv-row"><span class="k">分组键</span><span class="v mono small">${U.esc(a.group_key_text || "-")}</span></div>
        <div class="kv-row"><span class="k">域名</span><span class="v">${U.esc(a.domain || "-")}${a.domain ? U.copyBtn(a.domain) : ""}</span></div>
        <div class="kv-row"><span class="k">包 / 字节</span><span class="v">${a.packet_count} / ${U.fmtSize(a.byte_count)}</span></div>
        <div class="kv-row"><span class="k">分数</span><span class="v">原始 ${a.raw_score.toFixed(2)} × 置信度 ${a.confidence} → 归一化 ${a.normalized_score.toFixed(2)}</span></div>
        <div class="kv-row"><span class="k">MITRE</span><span class="v mono small">${(a.mitre_tags || []).map(U.esc).join(", ") || "-"}</span></div>
      </div>
      <div class="te-detail-section">
        <h4>命中条件（字段 / 算子 / 期望 → 实际值）</h4>
        ${(a.hit_fields || []).map(h => `<span class="hit-tag">${U.esc(h.field)} ${U.esc(h.op)} ${U.esc(h.expected)} → <b>${U.esc(h.actual)}</b>${U.copyBtn(h.field + "=" + h.actual)}</span>`).join("") || '<span class="muted small">-</span>'}
      </div>
      <div class="te-detail-section">
        <h4>结构化证据（alert_evidence）</h4>
        ${(a.evidence || []).map(e => `<div class="hit-tag">${U.esc(e.field)} ${U.esc(e.op)} 期望 ${U.esc(e.expected)} → <b>${U.esc(e.actual_value)}</b>${e.frame_number ? ` · frame ${e.frame_number}` : ""}${U.copyBtn(e.field + "=" + e.actual_value)}</div>`).join("") || '<span class="muted small">无独立证据行</span>'}
      </div>
      <div class="te-detail-section">
        <h4>证据统计</h4>
        <pre class="mono small" style="background:var(--te-bg);padding:10px;border-radius:8px;overflow:auto;border:1px solid var(--te-border)">${U.esc(JSON.stringify(a.stats || {}, null, 2))}</pre>
      </div>
      <div class="te-detail-section">
        <h4>代表数据包（Wireshark 对照 frame number）</h4>
        <div>${(a.evidence_packets || []).map(f => `<button class="btn small" style="margin:2px" onclick="TasksView.jumpFrame(${f})">frame ${f}</button>`).join("") || '-'}</div>
      </div>
      <div class="te-detail-section">
        <h4>人工标记（不覆盖原始规则结果）</h4>
        ${["confirmed","suspected","false_positive","ignored"].map(s => `<button class="btn small" style="margin:2px" onclick="TasksView.markAlert('${taskId}', ${a.id}, '${s}', this)">${({confirmed:"确认恶意",suspected:"疑似",false_positive:"误报",ignored:"忽略"})[s]}</button>`).join("")}
        <span class="muted small" style="margin-left:6px">当前：${this.statusBadge(a.status)}</span>
      </div>`;
    document.body.appendChild(drawer);
  },

  async markAlert(taskId, alertId, status, btn) {
    try {
      await Api.post(`/analysis/${taskId}/alerts/${alertId}/mark`, { status, note: "" });
      U.toast("已标记为" + { confirmed: "确认恶意", suspected: "疑似", false_positive: "误报", ignored: "忽略" }[status]);
      const d = document.querySelector(".drawer");
      if (d) d.remove();
      const el = document.getElementById("tab-body");
      if (el) this.loadAlerts(taskId, el);
    } catch (e) { U.toast(e.message, true); }
  },

  async jumpFrame(f) {
    const el = document.getElementById("tab-body");
    document.querySelectorAll(".tabs button").forEach(b => b.classList.toggle("active", b.dataset.tab === "packets"));
    const segs = U.params().path.split("/");
    this.loadPackets(segs[1], el, { frame: f, page: 1 });
  },

  /* ---------------- Tab：会话 ---------------- */
  async loadSessions(taskId, el) {
    el.innerHTML = `
      <div class="filters">
        <input id="s-src" placeholder="源 IP"><input id="s-dst" placeholder="目的 IP">
        <button class="btn" id="s-go">${U.icon("search", 14)}筛选</button>
        <span class="muted small" style="margin-left:auto">按字节数排序</span>
      </div>
      <div class="table-wrap"><table class="data"><thead><tr>
        <th>会话</th><th>方向</th><th>协议</th><th>包</th><th>字节</th><th>载荷占比</th><th>SYN/SYNACK/RST</th><th>握手</th><th>DNS/HTTP/TLS</th><th>周期分</th>
      </tr></thead><tbody id="s-body"></tbody></table></div>
      <div id="s-pager"></div>`;
    const load = async (page) => {
      const qs = new URLSearchParams({ page, page_size: 20 });
      const src = document.getElementById("s-src").value.trim();
      const dst = document.getElementById("s-dst").value.trim();
      if (src) qs.set("src_ip", src);
      if (dst) qs.set("dst_ip", dst);
      const r = await Api.get(`/analysis/${taskId}/sessions?${qs}`);
      const body = document.getElementById("s-body");
      if (!body) return;
      body.innerHTML = r.items.length ? r.items.map(x => `
        <tr>
          <td class="mono small" title="${U.esc(x.session_key)}">${U.esc(x.session_key)}</td>
          <td class="mono">${U.esc(x.src_ip)}:${x.src_port || "-"} → ${U.esc(x.dst_ip)}:${x.dst_port || "-"}</td>
          <td><span class="badge blue">${U.esc(x.protocol)}</span></td>
          <td>${x.packet_count}</td>
          <td>${U.fmtSize(x.byte_count)}</td>
          <td>${(x.payload_ratio * 100).toFixed(1)}%</td>
          <td>${x.syn_count}/${x.synack_count}/${x.rst_count}</td>
          <td>${x.completed_handshake ? '<span class="badge success">完成</span>' : '<span class="badge gray">未完成</span>'}</td>
          <td class="muted">${x.dns_query_count}/${x.http_request_count}/${x.tls_handshake_count}</td>
          <td>${x.periodicity_score || "-"}</td>
        </tr>`).join("") : `<tr><td colspan="10">${U.empty("traffic", "无会话")}</td></tr>`;
      document.getElementById("s-pager").innerHTML = U.pager(page, r.total, 20, p => load(p));
    };
    document.getElementById("s-go").onclick = () => load(1);
    await load(1);
  },

  /* ---------------- Tab：数据包 ---------------- */
  packetState: { page: 1, pageSize: 50, srcIp: "", dstIp: "", protocol: "", dstPort: "", srcPort: "", frame: "" },

  async loadPackets(taskId, el, init) {
    if (init) Object.assign(this.packetState, init);
    el.innerHTML = `
      <div class="filters">
        <input id="p-frame" placeholder="帧号" value="${U.esc(this.packetState.frame)}" style="min-width:80px">
        <input id="p-src" placeholder="源 IP" value="${U.esc(this.packetState.srcIp)}">
        <input id="p-dst" placeholder="目的 IP" value="${U.esc(this.packetState.dstIp)}">
        <select id="p-proto"><option value="">全部协议</option>${["tcp","udp","dns","http","tls","icmp","arp","other"].map(x => `<option ${this.packetState.protocol === x ? "selected" : ""}>${x}</option>`).join("")}</select>
        <input id="p-port" placeholder="端口" value="${U.esc(this.packetState.dstPort || this.packetState.srcPort || "")}" style="min-width:70px">
        <button class="btn" id="p-go">${U.icon("search", 14)}筛选</button>
      </div>
      <div class="table-wrap"><table class="data"><thead><tr>
        <th>帧号</th><th>时间</th><th>源 → 目的</th><th>协议</th><th>长度</th><th>标志</th><th>DNS</th><th>HTTP</th><th>TLS</th>
      </tr></thead><tbody id="p-body"></tbody></table></div>
      <div id="p-pager"></div>`;
    const load = async (page) => {
      const qs = new URLSearchParams({ page, page_size: this.packetState.pageSize });
      if (this.packetState.frame) qs.set("frame_number", this.packetState.frame);
      if (this.packetState.srcIp) qs.set("src_ip", this.packetState.srcIp);
      if (this.packetState.dstIp) qs.set("dst_ip", this.packetState.dstIp);
      if (this.packetState.protocol) qs.set("protocol", this.packetState.protocol);
      const port = this.packetState.dstPort || this.packetState.srcPort;
      if (port) qs.set("dst_port", port);
      const r = await Api.get(`/analysis/${taskId}/packets?${qs}`);
      const body = document.getElementById("p-body");
      if (!body) return;
      body.innerHTML = r.items.length ? r.items.map(p => `
        <tr>
          <td class="mono">${p.frame_number}</td>
          <td class="muted small" title="${U.fmtTs(p.timestamp)}">${U.relTime(p.timestamp)}</td>
          <td class="mono small">${U.esc(p.src_ip || "-")}:${p.src_port || ""} → ${U.esc(p.dst_ip || "-")}:${p.dst_port || ""}</td>
          <td><span class="badge blue">${U.esc(p.protocol)}</span></td>
          <td>${p.length}${p.payload_length ? `<span class="muted small">/${p.payload_length}</span>` : ""}</td>
          <td class="mono">${U.esc(p.tcp_flags)}</td>
          <td class="small truncate" title="${U.esc(p.dns_query)}">${U.esc(p.dns_query || "")}</td>
          <td class="small">${U.esc(p.http_method || "")} ${U.esc((p.http_uri || "").slice(0, 24))}</td>
          <td class="small">${U.esc(p.tls_version || "")} ${U.esc(p.tls_sni || "")}</td>
        </tr>`).join("") : `<tr><td colspan="9">${U.empty("traffic", "无数据包")}</td></tr>`;
      document.getElementById("p-pager").innerHTML = U.pager(page, r.total, this.packetState.pageSize, p => load(p));
    };
    document.getElementById("p-go").onclick = () => {
      this.packetState.frame = document.getElementById("p-frame").value.trim();
      this.packetState.srcIp = document.getElementById("p-src").value.trim();
      this.packetState.dstIp = document.getElementById("p-dst").value.trim();
      this.packetState.protocol = document.getElementById("p-proto").value;
      this.packetState.dstPort = document.getElementById("p-port").value.trim();
      this.packetState.srcPort = "";
      load(1);
    };
    await load(1);
  },
};
