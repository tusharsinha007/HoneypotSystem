/**
 * LLMPot Dashboard — Main App Logic
 * Handles UI interactions, navigation, and DOM updates
 */

"use strict";

document.addEventListener("DOMContentLoaded", () => {
  const dom = {
    app: document.getElementById("app"),
    sidebar: document.getElementById("sidebar"),
    sidebarToggle: document.getElementById("sidebarToggle"),
    mobileMenuBtn: document.getElementById("mobileMenuBtn"),
    overlay: document.getElementById("overlay"),
    themeToggles: [document.getElementById("themeToggle"), document.getElementById("themeToggleLg")].filter(Boolean),
    navItems: document.querySelectorAll(".nav-item"),
    pages: document.querySelectorAll(".page"),
    notifBtn: document.getElementById("notifBtn"),
    notifPanel: document.getElementById("notifPanel"),
    clearNotifs: document.getElementById("clearNotifs"),
    liveCount: document.getElementById("liveCount"),
  };

  const data = window.LLMPOT_DATA;

  // ─── INIT ──────────────────────────────────────────
  initTheme();
  lucide.createIcons();
  
  if (window.ChartManager) window.ChartManager.init();
  if (window.MapManager) window.MapManager.initMain();

  injectAlerts();
  injectNotifications();
  injectLogsTable();
  injectThreatInfo();
  injectSuspiciousList();
  injectClustersInfo();
  updateKPIs();

  // ─── THEME HANDLING ────────────────────────────────
  function initTheme() {
    const saved = localStorage.getItem("llmpot_theme");
    const prefersDark = window.matchMedia && window.matchMedia("(prefers-color-scheme: dark)").matches;
    const theme = saved || (prefersDark ? "dark" : "light");
    setTheme(theme);
  }

  function setTheme(theme) {
    document.documentElement.setAttribute("data-theme", theme);
    localStorage.setItem("llmpot_theme", theme);
    
    // Update large toggle button if exists
    const toggleLg = document.getElementById("themeToggleLg");
    if (toggleLg) {
      toggleLg.innerHTML = theme === "dark" 
        ? '<i data-lucide="sun"></i> Light Mode' 
        : '<i data-lucide="moon"></i> Dark Mode';
      lucide.createIcons();
    }
    
    if (window.ChartManager) {
      setTimeout(() => window.ChartManager.refreshAllCharts(), 50);
    }
  }

  dom.themeToggles.forEach(btn => {
    btn.addEventListener("click", () => {
      const current = document.documentElement.getAttribute("data-theme");
      setTheme(current === "dark" ? "light" : "dark");
    });
  });

  // ─── NAVIGATION ────────────────────────────────────
  function switchPage(pageId) {
    dom.navItems.forEach(n => n.classList.remove("active"));
    dom.pages.forEach(p => p.classList.remove("active"));

    const targetNav = document.getElementById(`nav-${pageId}`);
    const targetPage = document.getElementById(`page-${pageId}`);
    
    if (targetNav) targetNav.classList.add("active");
    if (targetPage) {
      targetPage.classList.add("active");
      
      // Page specific logic
      if (pageId === "map") {
        setTimeout(() => { if (window.MapManager) window.MapManager.initFull(); }, 50);
      } else if (pageId === "dashboard") {
        setTimeout(() => { if (window.MapManager) window.MapManager.invalidate(); }, 50);
      } else if (pageId === "threats") {
         setTimeout(() => { if (window.ChartManager) window.ChartManager.renderVectorChart(); }, 50);
      } else if (pageId === "ml") {
        setTimeout(() => { if (window.ChartManager) window.ChartManager.renderClusterChart("mlScatterFull"); }, 50);
      }
    }
    
    if (window.innerWidth <= 640) closeMobileMenu();
  }

  dom.navItems.forEach(item => {
    item.addEventListener("click", (e) => {
      e.preventDefault();
      switchPage(item.dataset.page);
    });
  });

  // ─── SIDEBAR & MOBILE MENU ─────────────────────────
  dom.sidebarToggle?.addEventListener("click", () => {
    dom.sidebar.classList.toggle("collapsed");
    setTimeout(() => {
      if (window.ChartManager) window.ChartManager.refreshAllCharts();
      if (window.MapManager) window.MapManager.invalidate();
    }, 450);
  });

  function openMobileMenu() {
    dom.sidebar.classList.add("mobile-open");
    dom.overlay.classList.add("active");
  }
  
  function closeMobileMenu() {
    dom.sidebar.classList.remove("mobile-open");
    dom.overlay.classList.remove("active");
  }

  dom.mobileMenuBtn?.addEventListener("click", openMobileMenu);
  dom.overlay?.addEventListener("click", () => {
    closeMobileMenu();
    closeNotifications();
  });

  // ─── NOTIFICATIONS ─────────────────────────────────
  function toggleNotifications() {
    dom.notifPanel.classList.toggle("open");
    if (dom.notifPanel.classList.contains("open")) {
      if (window.innerWidth <= 640) dom.overlay.classList.add("active");
    } else {
      closeNotifications();
    }
  }

  function closeNotifications() {
    dom.notifPanel.classList.remove("open");
    dom.overlay.classList.remove("active");
  }

  dom.notifBtn?.addEventListener("click", toggleNotifications);
  
  dom.clearNotifs?.addEventListener("click", () => {
    const list = document.getElementById("notifList");
    if (list) {
      list.innerHTML = `<div style="padding:20px;text-align:center;color:var(--text-muted);font-size:0.8rem;">No new notifications</div>`;
      document.getElementById("notifBadge").style.display = 'none';
    }
    setTimeout(closeNotifications, 800);
  });

  function injectNotifications() {
    const list = document.getElementById("notifList");
    if (!list || !data) return;
    
    list.innerHTML = data.notifications.map(n => `
      <div class="notif-item">
        <div class="notif-icon ${n.type}"><i data-lucide="${n.icon}"></i></div>
        <div class="notif-body">
          <div class="notif-title">${n.title}</div>
          <div class="notif-text">${n.text}</div>
          <div class="notif-time">${n.time}</div>
        </div>
      </div>
    `).join("");
    lucide.createIcons();
  }

  // ─── DATA INJECTION ────────────────────────────────
  function updateKPIs() {
    if (!data) return;
    
    // Animate numbers
    const animateValue = (id, target) => {
      const el = document.getElementById(id);
      if (!el) return;
      const duration = 1500;
      const start = performance.now();
      
      const step = (now) => {
        const progress = Math.min((now - start) / duration, 1);
        const easeOutQuart = 1 - Math.pow(1 - progress, 4);
        const current = Math.floor(target * easeOutQuart);
        el.innerText = current.toLocaleString();
        if (progress < 1) requestAnimationFrame(step);
        else el.innerText = target.toLocaleString();
      };
      requestAnimationFrame(step);
    };

    animateValue("metric-attacks", 24871);
    animateValue("metric-sessions", data.randomInt(5, 12));
    animateValue("metric-risk", 87);
    animateValue("metric-ips", 1432);

    const riskFill = document.getElementById("riskFill");
    if (riskFill) {
      setTimeout(() => riskFill.style.width = "87%", 300);
    }
  }

  function injectAlerts() {
    if (!data) return;
    
    const renderAlert = (a) => `
      <div class="alert-item">
        <div class="alert-sev ${a.sev}"></div>
        <div class="alert-body">
          <div class="alert-title">${a.title}</div>
          <div class="alert-description">${a.desc}</div>
          <div class="alert-time">${a.time}</div>
        </div>
      </div>
    `;

    const feed = document.getElementById("alertsFeed");
    const full = document.getElementById("alertsFullList");
    
    if (feed) feed.innerHTML = data.alerts.slice(0, 5).map(renderAlert).join("");
    if (full) full.innerHTML = data.alerts.map((a, i) => `
      <div class="alert-item" style="animation-delay: ${i*0.05}s">
        <div class="alert-sev ${a.sev}" style="width: 8px"></div>
        <div class="notif-icon ${a.sev === 'critical' ? 'red' : a.sev === 'warning' ? 'yellow' : 'blue'}" style="margin: 4px 6px">
          <i data-lucide="${a.icon}"></i>
        </div>
        <div class="alert-body">
          <div class="alert-title" style="font-size: 0.9rem">${a.title}</div>
          <div class="alert-description" style="font-size: 0.8rem">${a.desc}</div>
          <div class="alert-time">${a.time}</div>
        </div>
        <button class="btn btn-secondary btn-sm" style="align-self: center; margin-right: 10px;">Investigate</button>
      </div>
    `).join("");
    
    lucide.createIcons();
  }

  function injectLogsTable() {
    if (!data) return;
    
    const tbodyBody = document.getElementById("logsTableBody");
    const fullBody = document.getElementById("fullLogsBody");
    if (!tbodyBody) return;

    const renderRow = (s) => `
      <tr>
        <td class="ip-cell">${s.ip}</td>
        <td>
          <div class="flag-cell">
            <span>${s.flag}</span>
            <span>${s.country}</span>
          </div>
        </td>
        <td>${s.username}</td>
        <td class="cmd-cell" title="${s.command}">${s.command}</td>
        <td><span class="status-badge ${s.status}">${s.status}</span></td>
        <td>${data.formatDateTime(s.timestamp)}</td>
        <td>
          <button class="icon-btn" title="View details"><i data-lucide="eye"></i></button>
        </td>
      </tr>
    `;

    tbodyBody.innerHTML = data.sessions.slice(0, 15).map(renderRow).join("");
    if (fullBody) fullBody.innerHTML = data.sessions.slice(0, 100).map(renderRow).join("");
    lucide.createIcons();
  }

  function injectThreatInfo() {
    if (!data) return;
    
    const cList = document.getElementById("countryList");
    if (!cList) return;

    cList.innerHTML = data.topCountries.slice(0, 8).map((c, i) => `
      <div class="country-item">
        <div class="country-rank">${i + 1}</div>
        <div style="font-size: 1.2rem">${c.flag}</div>
        <div class="country-name">${c.name}</div>
        <div class="country-count">${c.count}</div>
        <div class="country-bar-outer">
          <div class="country-bar-inner" style="width: ${c.pct}%"></div>
        </div>
      </div>
    `).join("");
  }

  function injectClustersInfo() {
    if (!data) return;
    
    const cItems = document.getElementById("clusterItems");
    if (!cItems) return;

    cItems.innerHTML = data.clusterTypes.map((type, i) => `
      <div class="cluster-item">
        <div class="cluster-color-bar" style="background: ${data.clusterColors[i]}"></div>
        <div class="cluster-info">
          <div class="cluster-name">${type.replace("_", " ").toUpperCase()}</div>
          <div class="cluster-desc">${data.clusterDescs[i]}</div>
        </div>
        <div class="cluster-count">${data.clusters.counts[i]}</div>
      </div>
    `).join("");
  }

  function injectSuspiciousList() {
    if (!data) return;
    
    const sList = document.getElementById("suspiciousList");
    if (!sList) return;

    sList.innerHTML = data.suspicious.map((s, i) => `
      <div class="suspicious-item" style="animation: fadeIn 0.4s ease ${i*0.05}s both">
        <div class="suspicious-item-icon"><i data-lucide="target"></i></div>
        <div class="suspicious-body">
          <div class="suspicious-ip">${s.ip}</div>
          <div class="suspicious-desc">${s.desc}</div>
        </div>
        <div class="suspicious-score">${s.score}</div>
      </div>
    `).join("");
    lucide.createIcons();
  }

  // ─── UTILS ───────────────────────────────────────
  
  // Fake log filter
  document.getElementById("logsFilter")?.addEventListener("input", (e) => {
    const val = e.target.value.toLowerCase();
    const rows = document.querySelectorAll("#logsTableBody tr");
    rows.forEach(tr => {
      const text = tr.innerText.toLowerCase();
      tr.style.display = text.includes(val) ? "" : "none";
    });
  });

  // Export btn animation
  document.getElementById("exportBtn")?.addEventListener("click", function() {
    const orig = this.innerHTML;
    this.innerHTML = `<i data-lucide="loader-2" class="spin"></i> Exporting...`;
    lucide.createIcons();
    setTimeout(() => {
      this.innerHTML = `<i data-lucide="check"></i> Downloaded`;
      lucide.createIcons();
      setTimeout(() => { this.innerHTML = orig; lucide.createIcons(); }, 2000);
    }, 1500);
  });

  // Map fullscreen logic inside dashboard
  document.getElementById("mapFullscreen")?.addEventListener("click", () => {
    switchPage("map");
  });

  // Live session update simulation
  setInterval(() => {
    if (dom.liveCount) {
      dom.liveCount.innerText = `${data.randomInt(4, 15)} sessions`;
    }
  }, 5000);

  // Tab switching in charts
  document.querySelectorAll(".tab-btn").forEach(btn => {
    btn.addEventListener("click", function() {
      const parent = this.closest(".tab-group");
      parent.querySelectorAll(".tab-btn").forEach(b => b.classList.remove("active"));
      this.classList.add("active");
      
      const range = this.dataset.range;
      if (window.ChartManager) {
        window.ChartManager.renderAttackTrend(range);
      }
    });
  });

  // Add simple spin CSS dynamically
  const style = document.createElement('style');
  style.innerHTML = `
    .spin { animation: spin 1s linear infinite; }
    @keyframes spin { 100% { transform: rotate(360deg); } }
  `;
  document.head.appendChild(style);

});
