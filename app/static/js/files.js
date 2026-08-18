/* 文件管理页：拖拽上传（空态引导）、文件列表、一键分析。 */
const FilesView = {
  cache: false,
  state: { page: 1, pageSize: 15, status: "", q: "", strategies: [] },

  async render(main, path) {
    main.innerHTML = `
      <div class="page-head"><h2>文件管理</h2>
        <div class="actions"><span class="muted small">支持 .pcap / .pcapng · 默认最大 512 MB（可配置）· 自动哈希去重</span></div>
      </div>
      <div class="card">
        <div class="dropzone" id="dz">
          <span class="dz-ic">${U.icon("upload", 34)}</span>
          <b>拖拽流量包到此处，或点击选择文件</b>
          <div class="dz-tip">上传后自动校验格式（magic number）与 SHA-256，可立即创建分析任务</div>
        </div>
        <input type="file" id="dz-input" accept=".pcap,.pcapng" style="display:none">
      </div>
      <div class="card">
        <div class="filters">
          <input id="f-q" placeholder="文件名 / SHA256 前缀" value="${U.esc(this.state.q)}">
          <select id="f-status"><option value="">全部状态</option>
            ${["uploaded", "queued", "analyzing", "completed", "invalid", "failed", "deleted"].map(s => `<option ${this.state.status === s ? "selected" : ""}>${s}</option>`).join("")}
          </select>
          <button class="btn" id="f-search">${U.icon("search", 14)}查询</button>
        </div>
        <div class="table-wrap"><table class="data"><thead><tr>
          <th>文件名</th><th>格式</th><th>大小</th><th>SHA-256</th><th>状态</th><th>上传时间</th><th>操作</th>
        </tr></thead><tbody id="f-body"></tbody></table></div>
        <div id="f-pager"></div>
      </div>`;

    const dz = document.getElementById("dz");
    const input = document.getElementById("dz-input");
    dz.onclick = () => input.click();
    dz.ondragover = e => { e.preventDefault(); dz.classList.add("over"); };
    dz.ondragleave = () => dz.classList.remove("over");
    dz.ondrop = e => { e.preventDefault(); dz.classList.remove("over"); if (e.dataTransfer.files.length) this.upload(e.dataTransfer.files[0]); };
    input.onchange = () => { if (input.files.length) this.upload(input.files[0]); input.value = ""; };
    document.getElementById("f-search").onclick = () => {
      this.state.q = document.getElementById("f-q").value.trim();
      this.state.status = document.getElementById("f-status").value;
      this.state.page = 1; this.load(main);
    };
    this.load(main);
  },

  async upload(file) {
    const dz = document.getElementById("dz");
    const orig = dz.innerHTML;
    dz.innerHTML = `<span class="dz-ic">${U.icon("refresh", 30)}</span><b>上传中：${U.esc(file.name)} …</b>`;
    try {
      const fd = new FormData();
      fd.append("file", file);
      const f = await Api.upload("/files", fd);
      U.toast(f.deduplicated ? "重复文件：已去重，指向已有记录" : `上传成功：${f.original_name}`);
      this.state.page = 1;
      await this.load(document.getElementById("main"));
    } catch (e) {
      U.toast("上传失败：" + e.message, true);
    } finally {
      dz.innerHTML = orig;
    }
  },

  async load(main) {
    try {
      const qs = new URLSearchParams({ page: this.state.page, page_size: this.state.pageSize, status: this.state.status, q: this.state.q });
      const r = await Api.get("/files?" + qs);
      const st = { uploaded: "已上传", queued: "排队中", analyzing: "分析中", completed: "已完成", invalid: "无效", failed: "失败", deleted: "已删除" };
      const body = document.getElementById("f-body");
      if (!body) return;
      body.innerHTML = r.items.length ? r.items.map(f => `
        <tr>
          <td class="truncate" title="${U.esc(f.original_name)}">${U.esc(f.original_name)}${f.duplicate_of ? ' <span class="badge gray">重复</span>' : ""}</td>
          <td><span class="badge blue">${U.esc(f.format)}</span></td>
          <td>${U.fmtSize(f.size_bytes)}</td>
          <td class="mono" title="${f.sha256}">${f.sha256.slice(0, 12)}…</td>
          <td>${st[f.status] || f.status}${f.error_message ? ` <span class="badge critical" title="${U.esc(f.error_message)}">!</span>` : ""}</td>
          <td>${U.relTime(new Date(f.created_at).getTime() / 1000)}</td>
          <td>
            <button class="btn small" onclick="FilesView.download('${f.id}')">${U.icon("download", 13)}下载</button>
            ${f.status === "uploaded" || f.status === "completed" || f.status === "failed" ? `<button class="btn small primary" onclick="FilesView.analyze('${f.id}','${U.esc(f.original_name)}')">${U.icon("play", 13)}分析</button>` : ""}
            <button class="btn small danger" onclick="FilesView.del('${f.id}')">删除</button>
          </td>
        </tr>`).join("")
        : `<tr><td colspan="7">${U.empty("upload", "暂无流量文件", `<button class="btn small primary" onclick="document.getElementById('dz-input').click()">上传第一个文件</button>`)}</td></tr>`;
      document.getElementById("f-pager").innerHTML = U.pager(this.state.page, r.total, this.state.pageSize, p => { this.state.page = p; this.load(main); });
    } catch (e) { U.toast(e.message, true); }
  },

  async download(id) {
    try {
      const res = await fetch(`/api/v1/files/${id}/download`);
      if (!res.ok) throw new Error("下载失败");
      const blob = await res.blob();
      const cd = res.headers.get("content-disposition") || "";
      const name = decodeURIComponent((cd.match(/filename\*=UTF-8''(.+)/) || [])[1] || "download.pcap");
      const a = document.createElement("a");
      a.href = URL.createObjectURL(blob); a.download = name; a.click();
      URL.revokeObjectURL(a.href);
    } catch (e) { U.toast(e.message, true); }
  },

  async del(id) {
    if (!confirm("确认删除该文件？(软删除)")) return;
    try { await Api.del(`/files/${id}`); U.toast("已删除"); this.load(document.getElementById("main")); }
    catch (e) { U.toast(e.message, true); }
  },

  async analyze(fileId, fileName) {
    try {
      if (!this.state.strategies.length) {
        const r = await Api.get("/strategies?page_size=100&enabled=true");
        this.state.strategies = r.items;
      }
      const sts = this.state.strategies;
      const mask = document.createElement("div");
      mask.className = "modal-mask";
      mask.innerHTML = `
        <div class="modal">
          <div class="modal-head"><b>创建分析任务</b><button class="btn ghost" onclick="this.closest('.modal-mask').remove()">${U.icon("x", 14)}</button></div>
          <div class="modal-body">
            <div class="kv-row"><span class="k">文件</span><span class="v truncate" title="${U.esc(fileName)}">${U.esc(fileName)}</span></div>
            <div class="kv-row"><span class="k">文件 ID</span><span class="v mono">${fileId}</span></div>
            <div style="margin:14px 0 6px"><label class="muted small">选择策略（默认全部已启用策略，共 ${sts.length} 条）</label></div>
            <select id="an-strategies" style="width:100%">
              <option value="">全部已启用策略</option>
              ${sts.map(s => `<option value="${s.id}">${U.esc(s.id)} · ${U.esc(s.name)}</option>`).join("")}
            </select>
            <div style="margin:14px 0 6px"><label class="muted small">最低告警级别（低于该级别的告警不保存）</label></div>
            <select id="an-sev" style="width:100%">
              <option value="">不限制</option><option>info</option><option>low</option><option>medium</option><option>high</option>
            </select>
            <p class="muted small" style="margin-top:12px">分析为异步任务，创建后可在「分析任务」页查看进度。</p>
          </div>
          <div class="modal-foot">
            <button class="btn" onclick="this.closest('.modal-mask').remove()">取消</button>
            <button class="btn primary" id="an-go">${U.icon("play", 14)}创建任务</button>
          </div>
        </div>`;
      document.body.appendChild(mask);
      document.getElementById("an-go").onclick = async () => {
        const sel = document.getElementById("an-strategies").value;
        const body = { file_id: fileId };
        if (sel) body.strategy_ids = [sel];
        const sev = document.getElementById("an-sev").value;
        if (sev) body.severity_threshold = sev;
        try {
          const t = await Api.post("/analysis", body);
          mask.remove();
          U.toast("分析任务已创建：" + t.id);
          location.hash = "#/tasks/" + t.id;
        } catch (e) { U.toast(e.message, true); }
      };
    } catch (e) { U.toast(e.message, true); }
  },
};
