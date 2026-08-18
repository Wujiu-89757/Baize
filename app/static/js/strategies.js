/* 策略库页：卡片网格、筛选、YAML 编辑器（服务端 PyYAML 往返）、校验、发布、启停、导入导出。 */
const StrategiesView = {
  cache: false,
  state: { page: 1, pageSize: 30, category: "", scope: "", enabled: "", q: "" },

  async render(main) {
    main.innerHTML = `
      <div class="page-head"><h2>策略库</h2>
        <div class="actions">
          <button class="btn" id="s-import">${U.icon("upload", 14)}导入 YAML</button>
          <button class="btn" id="s-export">${U.icon("download", 14)}导出已发布</button>
          <button class="btn primary" id="s-new">${U.icon("plus", 14)}新建策略</button>
        </div>
      </div>
      <div class="card">
        <div class="filters">
          <input id="s-q" placeholder="名称 / ID 搜索" value="${U.esc(this.state.q)}">
          <select id="s-cat"><option value="">全部分类</option>${["scanning","dns","http","tls","outbound","credential","tunneling","malicious_download"].map(c => `<option>${c}</option>`).join("")}</select>
          <select id="s-scope"><option value="">全部范围</option>${["packet","session","host","file","correlation"].map(s => `<option>${s}</option>`).join("")}</select>
          <select id="s-enabled"><option value="">全部状态</option><option value="true">已启用</option><option value="false">已停用</option></select>
          <button class="btn" id="s-search">${U.icon("search", 14)}查询</button>
        </div>
        <div class="strat-grid" id="s-grid"></div>
        <div id="s-pager"></div>
      </div>`;
    document.getElementById("s-search").onclick = () => {
      this.state.q = document.getElementById("s-q").value.trim();
      this.state.category = document.getElementById("s-cat").value;
      this.state.scope = document.getElementById("s-scope").value;
      this.state.enabled = document.getElementById("s-enabled").value;
      this.state.page = 1; this.load(main);
    };
    document.getElementById("s-new").onclick = () => this.openEditor(null);
    document.getElementById("s-import").onclick = () => this.openImport();
    document.getElementById("s-export").onclick = async () => {
      try {
        const res = await fetch("/api/v1/strategies/export");
        const text = await res.text();
        const a = document.createElement("a");
        a.href = URL.createObjectURL(new Blob([text], { type: "text/yaml" }));
        a.download = "baize-strategies.yaml"; a.click();
      } catch (e) { U.toast(e.message, true); }
    };
    this.load(main);
  },

  async load(main) {
    try {
      const qs = new URLSearchParams({ page: this.state.page, page_size: this.state.pageSize,
        category: this.state.category, scope: this.state.scope, q: this.state.q });
      if (this.state.enabled) qs.set("enabled", this.state.enabled);
      const r = await Api.get("/strategies?" + qs);
      const grid = document.getElementById("s-grid");
      if (!grid) return;
      grid.innerHTML = r.items.length ? r.items.map(s => `
        <div class="strat-card">
          <div class="sc-top">
            <div>
              <div class="sc-name">${U.esc(s.name)}</div>
              <div class="sc-id">${U.esc(s.id)}</div>
            </div>
            <span class="badge ${s.enabled ? "success" : "gray"}">${s.enabled ? "已启用" : "已停用"}</span>
          </div>
          <div class="sc-meta">
            <span class="badge blue">${U.esc(s.category)}</span>
            <span class="badge gray">scope: ${U.esc(s.scope)}</span>
            <span class="badge gray">${s.current_version ? "v" + U.esc(s.current_version) : "未发布"}</span>
          </div>
          <div class="sc-desc">${U.esc(s.description || "")}</div>
          <div class="sc-actions">
            <button class="btn small" onclick="StrategiesView.openEditor('${U.esc(s.id)}')">编辑</button>
            ${s.enabled ? `<button class="btn small" onclick="StrategiesView.toggle('${U.esc(s.id)}',false)">停用</button>`
                        : `<button class="btn small primary" onclick="StrategiesView.toggle('${U.esc(s.id)}',true)">启用</button>`}
            <button class="btn small success" onclick="StrategiesView.publish('${U.esc(s.id)}')">发布</button>
          </div>
        </div>`).join("")
        : U.empty("shield", "暂无策略", `<button class="btn small primary" id="s-empty-new">新建策略</button>`);
      const emptyNew = document.getElementById("s-empty-new");
      if (emptyNew) emptyNew.onclick = () => this.openEditor(null);
      document.getElementById("s-pager").innerHTML = U.pager(this.state.page, r.total, this.state.pageSize, p => { this.state.page = p; this.load(main); });
    } catch (e) { U.toast(e.message, true); }
  },

  async toggle(id, on) {
    try { await Api.post(`/strategies/${id}/${on ? "enable" : "disable"}`); U.toast(on ? "已启用" : "已停用"); this.load(document.getElementById("main")); }
    catch (e) { U.toast(e.message, true); }
  },

  async publish(id) {
    if (!confirm("发布策略？历史任务继续引用执行时版本。")) return;
    try { await Api.post(`/strategies/${id}/publish`); U.toast("已发布"); this.load(document.getElementById("main")); }
    catch (e) { U.toast(e.message, true); }
  },

  async openEditor(id) {
    try {
      const m = await Api.get("/strategies/meta");
      const isNew = !id;
      let yamlText;
      if (id) {
        const d = await Api.get(`/strategies/${id}`);
        const y = await Api.post("/strategies/to-yaml", { content: d.content });
        yamlText = y.text;
      } else {
        yamlText = this.template(m);
      }
      const mask = document.createElement("div");
      mask.className = "modal-mask";
      mask.innerHTML = `
        <div class="modal wide">
          <div class="modal-head"><b>${isNew ? "新建策略" : "编辑策略：" + U.esc(id)}</b>
            <button class="btn ghost" onclick="this.closest('.modal-mask').remove()">${U.icon("x", 14)}</button></div>
          <div class="modal-body">
            <div class="filters" style="margin-bottom:8px">
              <button class="btn small" id="se-validate">${U.icon("check", 13)}校验</button>
              <span id="se-result" class="small"></span>
              <span class="muted small" style="margin-left:auto">字段帮助：<a href="javascript:void(0)" id="se-help">查看可用字段</a></span>
            </div>
            <textarea class="yaml-editor" id="se-yaml" spellcheck="false">${U.esc(yamlText)}</textarea>
          </div>
          <div class="modal-foot">
            <button class="btn" onclick="this.closest('.modal-mask').remove()">取消</button>
            <button class="btn" id="se-save">保存草稿</button>
            <button class="btn primary" id="se-publish">保存并发布</button>
          </div>
        </div>`;
      document.body.appendChild(mask);
      document.getElementById("se-help").onclick = () => this.showFieldHelp(m);
      const validate = async () => {
        try {
          const r = await Api.post("/strategies/parse-yaml", { text: document.getElementById("se-yaml").value });
          const vr = await Api.post(`/strategies/${id || "x"}/validate`, { content: r.content });
          document.getElementById("se-result").innerHTML =
            vr.valid ? '<span class="validation-ok">✔ 校验通过</span>'
                     : `<span class="validation-err">✘ ${vr.errors.map(U.esc).join("；")}</span>` +
                       (vr.warnings.length ? `<span class="muted small">（警告：${vr.warnings.map(U.esc).join("；")}）</span>` : "");
          return r.content;
        } catch (e) {
          document.getElementById("se-result").innerHTML = `<span class="validation-err">${U.esc(e.message)}</span>`;
          return null;
        }
      };
      document.getElementById("se-validate").onclick = validate;
      const submit = async (publish) => {
        // 一次请求：text + publish，服务端单事务完成解析、校验、保存、可选发布
        const text = document.getElementById("se-yaml").value;
        try {
          const body = { text, publish };
          if (isNew) await Api.post("/strategies", body);
          else await Api.put(`/strategies/${id}`, body);
          mask.remove();
          U.toast(publish ? "已保存并发布" : "已保存草稿");
          this.state.page = 1;
          this.load(document.getElementById("main"));
        } catch (e) {
          document.getElementById("se-result").innerHTML = `<span class="validation-err">${U.esc(e.message)}${e.detail && e.detail.errors ? "：" + e.detail.errors.map(U.esc).join("；") : ""}</span>`;
        }
      };
      document.getElementById("se-save").onclick = () => submit(false);
      document.getElementById("se-publish").onclick = () => submit(true);
    } catch (e) { U.toast(e.message, true); }
  },

  template(m) {
    return `id: custom.strategy.example
name: 示例策略
version: 1.0.0
category: scanning
scope: session
enabled: false
severity: medium
weight: 30
confidence: 0.7
description: 示例：描述观察什么特征、满足什么条件、贡献多少风险。
false_positive_hint: 示例误报提示。
window:
  seconds: 60
  group_by: [src_ip, dst_ip]
conditions:
  all:
    - field: session.syn_count
      op: gte
      value: 100
evidence: [frame.number, frame.time, ip.src, ip.dst]
mitre_tags: [T1046]
`;
  },

  showFieldHelp(m) {
    const mask = document.createElement("div");
    mask.className = "modal-mask";
    mask.innerHTML = `<div class="modal">
      <div class="modal-head"><b>可用字段与算子</b><button class="btn ghost" onclick="this.closest('.modal-mask').remove()">${U.icon("x", 14)}</button></div>
      <div class="modal-body">
        <h4 class="muted" style="margin:6px 0">算子：${m.operators.map(U.esc).join(", ")}</h4>
        <h4 class="muted" style="margin:14px 0 6px">分组键（window.group_by）：${m.group_key_fields.map(U.esc).join(", ")}</h4>
        <h4 class="muted" style="margin:14px 0 6px">统一字段：</h4>
        <p class="mono small" style="line-height:1.9">${m.fields.map(U.esc).join("<br>")}</p>
      </div></div>`;
    document.body.appendChild(mask);
  },

  openImport() {
    const mask = document.createElement("div");
    mask.className = "modal-mask";
    mask.innerHTML = `<div class="modal">
      <div class="modal-head"><b>导入策略（YAML 多文档或 JSON 数组）</b><button class="btn ghost" onclick="this.closest('.modal-mask').remove()">${U.icon("x", 14)}</button></div>
      <div class="modal-body">
        <select id="im-mode" style="width:100%;margin-bottom:10px">
          <option value="create">create：仅新建（ID 冲突则跳过）</option>
          <option value="update">update：冲突则生成新草稿版本</option>
          <option value="skip">skip：全部跳过已存在</option>
        </select>
        <textarea class="yaml-editor" id="im-yaml" spellcheck="false" placeholder="粘贴 YAML 策略内容（可用 --- 分隔多个文档）"></textarea>
      </div>
      <div class="modal-foot"><button class="btn" onclick="this.closest('.modal-mask').remove()">取消</button>
        <button class="btn primary" id="im-go">导入</button></div></div>`;
    document.body.appendChild(mask);
    document.getElementById("im-go").onclick = async () => {
      try {
        const text = document.getElementById("im-yaml").value;
        const mode = document.getElementById("im-mode").value;
        // 服务端一次解析 + 导入
        const ir = await Api.post("/strategies/import", { text, mode });
        mask.remove();
        U.toast(`导入完成：新建 ${ir.created.length}，更新 ${ir.updated.length}，跳过 ${ir.skipped.length}，失败 ${ir.errors.length}`);
        this.load(document.getElementById("main"));
      } catch (e) { U.toast(e.message, true); }
    };
  },
};
