/* 仪表盘：系统概览 + 统计卡片 + 最近任务 + 快速入口。 */
const DashboardView = {
  cache: false,

  async render(main) {
    // 仪表盘统计来自全库聚合接口（不再是"最近 6 条任务"的近似值）
    const [meta, stats] = await Promise.all([
      Api.get("/meta").catch(() => ({ app: "白泽流量分析平台", version: "-", engine_version: "-" })),
      Api.get("/analysis/stats"),
    ]);
    const tasks = stats.recent_tasks || [];
    const alertTotal = stats.alerts || 0;
    const topTask = stats.max_risk_task || null;
    const st = { queued: "排队中", running: "分析中", succeeded: "成功", failed: "失败", cancelled: "已取消" };

    main.innerHTML = `
      <div class="page-head"><h2>仪表盘</h2>
        <div class="actions">
          <a class="btn primary" href="#/files">${U.icon("upload", 15)} 上传流量包</a>
        </div>
      </div>
      <div class="stat-cards">
        <div class="stat-card"><span class="label">${U.icon("file", 14)} 流量文件</span><span class="value primary">${stats.files}</span><span class="sub">pcap / pcapng</span></div>
        <div class="stat-card"><span class="label">${U.icon("play", 14)} 分析任务</span><span class="value">${stats.tasks}</span><span class="sub">异步执行 · 进度可见</span></div>
        <div class="stat-card"><span class="label">${U.icon("alert", 14)} 告警总数</span><span class="value ${alertTotal ? "warning" : ""}">${alertTotal}</span><span class="sub">全部任务累计</span></div>
        <div class="stat-card"><span class="label">${U.icon("shield", 14)} 当前最高风险</span>
          <span class="value ${topTask ? (topTask.risk_level === "critical" || topTask.risk_level === "high" ? "danger" : topTask.risk_level === "medium" ? "warning" : "primary") : ""}">
            ${topTask ? topTask.risk_score.toFixed(1) : "-"}</span>
          <span class="sub">${topTask ? U.levelCn(topTask.risk_level) + (topTask.file_name ? " · " + U.esc(topTask.file_name) : "") : "暂无分析任务"}</span>
        </div>
      </div>

      <div class="grid2">
        <div class="card">
          <h3>最近任务</h3>
          ${tasks.length ? `
          <div class="table-wrap"><table class="data"><thead><tr>
            <th>任务</th><th>状态</th><th>进度</th><th>风险</th><th>告警</th><th>创建时间</th>
          </tr></thead><tbody>
          ${tasks.map(t => `
            <tr style="cursor:pointer" onclick="location.hash='#/tasks/${t.id}'">
              <td class="mono">${t.id.slice(0, 10)}…</td>
              <td>${U.statusHtml(t.status)}</td>
              <td><span class="mono" style="margin-right:8px">${t.progress}%</span><div class="progress"><div class="${t.status === "succeeded" ? "done" : ""}" style="width:${t.progress}%"></div></div></td>
              <td>${t.risk_score > 0 ? `<span class="badge ${U.levelOf(t.risk_score)}">${t.risk_score.toFixed(1)} ${U.levelCn(t.risk_level)}</span>` : '<span class="muted">-</span>'}</td>
              <td>${t.alert_count}</td>
              <td>${U.relTime(new Date(t.created_at).getTime() / 1000)}</td>
            </tr>`).join("")}
          </tbody></table></div>
          <div style="margin-top:10px"><a class="btn small" href="#/tasks">查看全部任务</a></div>`
          : U.empty("play", "还没有分析任务", `<a class="btn small primary" href="#/files">上传流量包开始分析</a>`)}
        </div>

        <div>
          <div class="card">
            <h3>快速开始</h3>
            <div class="quick-actions">
              <a class="btn primary" href="#/files">${U.icon("upload", 15)} 上传并分析流量包</a>
              <a class="btn" href="#/strategies">${U.icon("shield", 15)} 管理识别策略</a>
              <a class="btn" href="#/tasks">${U.icon("play", 15)} 查看分析任务</a>
            </div>
            <p class="muted small" style="margin-top:12px;line-height:1.8">
              支持 .pcap / .pcapng；上传后自动校验格式与哈希去重，可立即创建异步分析任务，
              结果以可解释告警 + 证据帧（frame number）呈现，可导出 JSON / CSV / HTML 报告。
            </p>
          </div>
          <div class="card">
            <h3>系统信息</h3>
            <div class="kv-row"><span class="k">产品</span><span class="v">${U.esc(meta.app)}</span></div>
            <div class="kv-row"><span class="k">版本</span><span class="v">v${U.esc(meta.version)}</span></div>
            <div class="kv-row"><span class="k">分析引擎</span><span class="v mono">${U.esc(meta.engine_version)}</span></div>
            <div class="kv-row"><span class="k">运行模式</span><span class="v">本地模式</span></div>
          </div>
        </div>
      </div>`;
  },
};
