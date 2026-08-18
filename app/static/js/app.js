/* 应用核心：本地模式（无登录）、路由、主题切换、动态标题。 */

/* 全局唯一轮询器：任何页面最多持有一个定时器，路由离开即清理，
   避免任务列表/结果页各自新建 interval 造成重复轮询。 */
const Poller = {
  _timer: null,
  _fn: null,
  _interval: 0,
  set(fn, interval) {
    this.clear();
    this._fn = fn;
    this._interval = interval;
    this._timer = setInterval(() => { try { this._fn(); } catch (e) { /* 静默，下次再试 */ } }, interval);
  },
  clear() {
    if (this._timer) { clearInterval(this._timer); this._timer = null; }
    this._fn = null;
  },
};

const App = (() => {
  const views = { dashboard: DashboardView, files: FilesView, strategies: StrategiesView, tasks: TasksView, trash: TrashView, audit: AuditView };
  const TITLES = { dashboard: "仪表盘", files: "文件管理", strategies: "策略库", tasks: "分析任务", trash: "回收站", audit: "审计日志" };
  let current = "";

  function boot() {
    // 图标注入
    document.getElementById("logo-mark").innerHTML = U.icon("shield", 20);
    document.querySelectorAll("[data-ic]").forEach(el => { el.innerHTML = U.icon(el.dataset.ic, 15); });
    document.getElementById("theme-btn").innerHTML = isDark() ? U.icon("sun", 14) + "亮色" : U.icon("moon", 14) + "暗色";
    document.getElementById("theme-btn").addEventListener("click", toggleTheme);
    fetch("/api/v1/meta").then(r => r.json()).then(m => {
      const el = document.getElementById("sys-version");
      if (el) el.innerHTML = `${U.esc(m.app)} v${U.esc(m.version)}`;
    }).catch(() => {});
    window.addEventListener("hashchange", route);
    route();
  }

  function isDark() { return document.documentElement.classList.contains("dark"); }

  function toggleTheme() {
    const dark = !isDark();
    document.documentElement.classList.toggle("dark", dark);
    try { localStorage.setItem("te-theme", dark ? "dark" : "light"); } catch (e) {}
    const btn = document.getElementById("theme-btn");
    btn.innerHTML = dark ? U.icon("sun", 14) + "亮色" : U.icon("moon", 14) + "暗色";
  }

  async function route() {
    const { path } = U.params();
    const seg = path.split("/")[0];
    // 路由切换时停止上一页的轮询器（列表页/结果页都可能启动轮询）
    Poller.clear();
    document.querySelectorAll(".nav-item").forEach(a =>
      a.classList.toggle("active", a.dataset.nav === seg));
    const main = document.getElementById("main");
    const view = views[seg];
    if (!view) { main.innerHTML = U.empty("file", "未知页面"); return; }
    document.title = "白泽流量分析" + (TITLES[seg] ? " · " + TITLES[seg] : "");
    if (current === path && view.cache !== false) return;
    current = path;
    try {
      main.innerHTML = `<div class="empty">加载中…</div>`;
      await view.render(main, path);
    } catch (e) {
      main.innerHTML = `<div class="card"><h3>加载失败</h3><p class="err" style="color:var(--te-danger)">${U.esc(e.message)}</p></div>`;
    }
  }

  return { boot, route };
})();
