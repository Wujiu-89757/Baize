/* 审计日志页。 */
const AuditView = {
  cache: false,
  state: { page: 1, pageSize: 20, action: "", username: "" },

  async render(main) {
    main.innerHTML = `
      <div class="page-head"><h2>审计日志</h2></div>
      <div class="card">
        <div class="filters">
          <input id="au-action" placeholder="动作（如 strategy.publish）">
          <input id="au-user" placeholder="用户名">
          <button class="btn" id="au-go">${U.icon("search", 14)}查询</button>
        </div>
        <div class="table-wrap"><table class="data"><thead><tr>
          <th>时间</th><th>用户</th><th>动作</th><th>对象</th><th>详情</th><th>IP</th>
        </tr></thead><tbody id="au-body"></tbody></table></div>
        <div id="au-pager"></div>
      </div>`;
    document.getElementById("au-go").onclick = () => {
      this.state.action = document.getElementById("au-action").value.trim();
      this.state.username = document.getElementById("au-user").value.trim();
      this.state.page = 1; this.load(main);
    };
    this.load(main);
  },

  async load(main) {
    try {
      const qs = new URLSearchParams({ page: this.state.page, page_size: this.state.pageSize,
        action: this.state.action, username: this.state.username });
      const r = await Api.get("/audit?" + qs);
      document.getElementById("au-body").innerHTML = r.items.length ? r.items.map(x => `
        <tr>
          <td class="muted small" title="${U.fmtDt(x.ts)}">${U.relTime(new Date(x.ts).getTime() / 1000)}</td>
          <td>${U.esc(x.username)}</td>
          <td><span class="badge blue">${U.esc(x.action)}</span></td>
          <td class="mono small">${U.esc(x.target_type)}:${U.esc(x.target_id)}</td>
          <td class="small muted truncate" title="${U.esc(JSON.stringify(x.detail || {}))}">${U.esc(JSON.stringify(x.detail || {}).slice(0, 80))}</td>
          <td class="muted small">${U.esc(x.ip)}</td>
        </tr>`).join("") : `<tr><td colspan="6">${U.empty("log", "暂无审计记录")}</td></tr>`;
      document.getElementById("au-pager").innerHTML = U.pager(this.state.page, r.total, this.state.pageSize, p => { this.state.page = p; this.load(main); });
    } catch (e) { U.toast(e.message, true); }
  },
};
