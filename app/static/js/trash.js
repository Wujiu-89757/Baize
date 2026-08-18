/* 回收站：已删除的分析任务（可还原 / 彻底删除）。 */
const TrashView = {
  cache: false,
  state: { page: 1, pageSize: 15 },

  async render(main) {
    main.innerHTML = `
      <div class="page-head"><h2>回收站</h2>
        <div class="actions">
          <button class="btn" id="tr-refresh">${U.icon("refresh", 14)}刷新</button>
          <span class="muted small">删除的任务暂存于此，可还原或彻底删除</span>
        </div>
      </div>
      <div class="card">
        <div class="table-wrap"><table class="data"><thead><tr>
          <th>文件</th><th>任务 ID</th><th>原状态</th><th>风险</th><th>告警</th><th>删除时间</th><th>操作</th>
        </tr></thead><tbody id="tr-body"></tbody></table></div>
        <div id="tr-pager"></div>
      </div>`;
    document.getElementById("tr-refresh").onclick = () => this.load(main);
    this.load(main);
  },

  async load(main) {
    try {
      const qs = new URLSearchParams({ page: this.state.page, page_size: this.state.pageSize, status: "deleted" });
      const r = await Api.get("/analysis?" + qs);
      const body = document.getElementById("tr-body");
      if (!body) return;
      body.innerHTML = r.items.length ? r.items.map(t => {
        const orig = (t.config_snapshot && t.config_snapshot.restore_status) || "succeeded";
        return `
        <tr>
          <td class="truncate" title="${U.esc(t.file_name || t.file_id)}">${U.esc(t.file_name || t.file_id.slice(0, 8) + "…")}</td>
          <td class="mono">${t.id.slice(0, 10)}…</td>
          <td><span class="badge gray">已删除</span> <span class="muted small">原状态：${U.esc(orig)}</span></td>
          <td>${t.risk_score > 0 ? `<span class="badge ${U.levelOf(t.risk_score)}">${t.risk_score.toFixed(1)} ${U.levelCn(t.risk_level)}</span>` : '<span class="muted">-</span>'}</td>
          <td>${t.alert_count}</td>
          <td>${(t.deleted_at || t.finished_at) ? U.relTime(new Date((t.deleted_at || t.finished_at)).getTime() / 1000) : "-"}</td>
          <td>
            <button class="btn small primary" onclick="TrashView.restore('${t.id}')">${U.icon("undo", 13)}还原</button>
            <button class="btn small danger-solid" onclick="TrashView.purge('${t.id}')">${U.icon("trash", 13)}彻底删除</button>
          </td>
        </tr>`;
      }).join("") : `<tr><td colspan="7">${U.empty("trash", "回收站是空的", `<a class="btn small primary" href="#/tasks">返回分析任务</a>`)}</td></tr>`;
      document.getElementById("tr-pager").innerHTML = U.pager(this.state.page, r.total, this.state.pageSize, p => { this.state.page = p; this.load(main); });
    } catch (e) { U.toast(e.message, true); }
  },

  async restore(id) {
    try {
      await Api.post(`/analysis/${id}/restore`);
      U.toast("已还原任务，可到「分析任务」查看");
      this.load(document.getElementById("main"));  // 留在回收站页，刷新列表
    } catch (e) { U.toast(e.message, true); }
  },

  async purge(id) {
    if (!confirm("彻底删除该任务及其全部分析结果（包/会话/告警/证据）？此操作不可恢复！")) return;
    try {
      await Api.del(`/analysis/${id}/purge`);
      U.toast("已彻底删除");
      this.load(document.getElementById("main"));
    } catch (e) { U.toast(e.message, true); }
  },
};
