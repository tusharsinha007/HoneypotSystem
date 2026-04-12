/**
 * LLMPot Dashboard — Chart Manager
 * Renders all Chart.js charts with theme-aware styling
 */

"use strict";

const ChartManager = (() => {
  const chartInstances = {};

  // ─── Theme-aware color helper ───────────────────
  function getThemeColors() {
    const isDark = document.documentElement.getAttribute("data-theme") === "dark";
    return {
      gridColor: isDark ? "rgba(255,255,255,0.05)" : "rgba(15,23,42,0.06)",
      textColor: isDark ? "#64748B" : "#94A3B8",
      tickColor: isDark ? "#475569" : "#94A3B8",
      tooltipBg: isDark ? "#1E293B" : "#FFFFFF",
      tooltipBorder: isDark ? "rgba(255,255,255,0.08)" : "rgba(15,23,42,0.08)",
      tooltipText: isDark ? "#F1F5F9" : "#0F172A",
    };
  }

  // ─── Shared plugin defaults ─────────────────────
  function tooltipPlugin() {
    const t = getThemeColors();
    return {
      backgroundColor: t.tooltipBg,
      borderColor: t.tooltipBorder,
      borderWidth: 1,
      titleColor: t.tooltipText,
      bodyColor: t.tickColor,
      padding: 10,
      cornerRadius: 8,
      displayColors: true,
      boxWidth: 10,
      boxHeight: 10,
    };
  }

  function scaleDefaults(showGrid = true) {
    const t = getThemeColors();
    return {
      x: {
        grid: { color: showGrid ? t.gridColor : "transparent", drawBorder: false },
        ticks: { color: t.textColor, font: { family: "'Inter', sans-serif", size: 11 } },
        border: { display: false },
      },
      y: {
        grid: { color: showGrid ? t.gridColor : "transparent", drawBorder: false },
        ticks: { color: t.textColor, font: { family: "'Inter', sans-serif", size: 11 } },
        border: { display: false },
      },
    };
  }

  // ─── Sparkline helper ───────────────────────────
  function createSparkline(canvasId, data, color) {
    const ctx = document.getElementById(canvasId);
    if (!ctx) return;
    if (chartInstances[canvasId]) chartInstances[canvasId].destroy();
    chartInstances[canvasId] = new Chart(ctx, {
      type: "line",
      data: {
        labels: data.map((_, i) => i),
        datasets: [{ data, borderColor: color, borderWidth: 1.5, pointRadius: 0, fill: true, backgroundColor: `${color}20`, tension: 0.4 }],
      },
      options: {
        responsive: true,
        maintainAspectRatio: false,
        plugins: { legend: { display: false }, tooltip: { enabled: false } },
        scales: { x: { display: false }, y: { display: false } },
        animation: { duration: 1000 },
      },
    });
  }

  // ─── Attack Trend Line Chart ────────────────────
  function renderAttackTrend(days = "7d") {
    const ctx = document.getElementById("attackTrendChart");
    if (!ctx) return;
    if (chartInstances.attackTrend) chartInstances.attackTrend.destroy();

    const { labels, data } = window.LLMPOT_DATA.trendData[days];
    const t = getThemeColors();

    const gradient = ctx.getContext("2d").createLinearGradient(0, 0, 0, 240);
    gradient.addColorStop(0, "rgba(59, 130, 246, 0.3)");
    gradient.addColorStop(1, "rgba(59, 130, 246, 0.01)");

    chartInstances.attackTrend = new Chart(ctx, {
      type: "line",
      data: {
        labels,
        datasets: [{
          label: "Attacks",
          data,
          borderColor: "#3B82F6",
          borderWidth: 2,
          pointRadius: 3,
          pointBackgroundColor: "#3B82F6",
          pointBorderColor: "#3B82F6",
          pointHoverRadius: 5,
          fill: true,
          backgroundColor: gradient,
          tension: 0.4,
        }],
      },
      options: {
        responsive: true,
        maintainAspectRatio: false,
        interaction: { mode: "index", intersect: false },
        plugins: {
          legend: { display: false },
          tooltip: {
            ...tooltipPlugin(),
            callbacks: {
              label: ctx => ` ${ctx.parsed.y.toLocaleString()} attacks`,
            },
          },
        },
        scales: {
          ...scaleDefaults(),
          y: {
            ...scaleDefaults().y,
            beginAtZero: true,
            ticks: { ...scaleDefaults().y.ticks, callback: v => v >= 1000 ? `${(v/1000).toFixed(1)}k` : v },
          },
        },
        animation: { duration: 800, easing: "easeOutQuart" },
      },
    });
  }

  // ─── Attack Category Bar Chart ──────────────────
  function renderAttackCategory() {
    const ctx = document.getElementById("attackCategoryChart");
    if (!ctx) return;
    if (chartInstances.attackCategory) chartInstances.attackCategory.destroy();

    const { labels, data } = window.LLMPOT_DATA.topVectors;
    const colors = ["#3B82F6", "#8B5CF6", "#06B6D4", "#EF4444", "#F59E0B", "#10B981"];

    chartInstances.attackCategory = new Chart(ctx, {
      type: "bar",
      data: {
        labels,
        datasets: [{
          label: "Sessions",
          data,
          backgroundColor: colors.map(c => `${c}CC`),
          borderColor: colors,
          borderWidth: 1,
          borderRadius: 5,
          borderSkipped: false,
        }],
      },
      options: {
        responsive: true,
        maintainAspectRatio: false,
        plugins: {
          legend: { display: false },
          tooltip: { ...tooltipPlugin() },
        },
        scales: {
          ...scaleDefaults(),
          y: { ...scaleDefaults().y, beginAtZero: true, ticks: { ...scaleDefaults().y.ticks, callback: v => v >= 1000 ? `${(v/1000).toFixed(0)}k` : v } },
        },
        animation: { duration: 800, easing: "easeOutQuart" },
      },
    });
  }

  // ─── Severity Donut Chart ───────────────────────
  function renderSeverityDonut() {
    const ctx = document.getElementById("severityChart");
    if (!ctx) return;
    if (chartInstances.severity) chartInstances.severity.destroy();

    const t = getThemeColors();

    chartInstances.severity = new Chart(ctx, {
      type: "doughnut",
      data: {
        labels: ["Critical", "High", "Medium", "Low"],
        datasets: [{
          data: [3241, 7892, 9102, 4635],
          backgroundColor: ["#EF4444", "#F97316", "#F59E0B", "#10B981"],
          borderColor: "transparent",
          borderWidth: 3,
          hoverOffset: 8,
        }],
      },
      options: {
        responsive: true,
        maintainAspectRatio: false,
        cutout: "72%",
        plugins: {
          legend: {
            position: "right",
            labels: {
              color: t.textColor,
              padding: 14,
              usePointStyle: true,
              pointStyleWidth: 10,
              font: { family: "'Inter', sans-serif", size: 11 },
            },
          },
          tooltip: {
            ...tooltipPlugin(),
            callbacks: {
              label: ctx => ` ${ctx.label}: ${ctx.parsed.toLocaleString()}`,
            },
          },
        },
        animation: { duration: 900, easing: "easeInOutCirc" },
      },
    });
  }

  // ─── Attack Vector Chart (Threats page) ──────────
  function renderVectorChart() {
    const ctx = document.getElementById("vectorChart");
    if (!ctx) return;
    if (chartInstances.vector) chartInstances.vector.destroy();

    const { labels, data } = window.LLMPOT_DATA.topVectors;
    const maxVal = Math.max(...data);

    chartInstances.vector = new Chart(ctx, {
      type: "bar",
      data: {
        labels,
        datasets: [{
          label: "Count",
          data,
          backgroundColor: data.map((v, i) => {
            const ratio = v / maxVal;
            return `rgba(${Math.round(59 + (139-59)*i/labels.length)}, ${Math.round(130 + (92-130)*i/labels.length)}, ${Math.round(246)}, ${0.6 + 0.4*ratio})`;
          }),
          borderRadius: 6,
          borderSkipped: false,
        }],
      },
      options: {
        indexAxis: "y",
        responsive: true,
        maintainAspectRatio: false,
        plugins: {
          legend: { display: false },
          tooltip: { ...tooltipPlugin() },
        },
        scales: {
          ...scaleDefaults(),
          x: { ...scaleDefaults().x, beginAtZero: true, ticks: { ...scaleDefaults().x.ticks, callback: v => v >= 1000 ? `${(v/1000).toFixed(0)}k` : v } },
        },
        animation: { duration: 700 },
      },
    });
  }

  // ─── K-Means Scatter Chart ──────────────────────
  function renderClusterChart(canvasId) {
    const ctx = document.getElementById(canvasId);
    if (!ctx) return;
    if (chartInstances[canvasId]) chartInstances[canvasId].destroy();

    const { scatter } = window.LLMPOT_DATA.clusters;
    const clusterColors = window.LLMPOT_DATA.clusterColors;
    const clusterTypes = window.LLMPOT_DATA.clusterTypes;
    const t = getThemeColors();

    // Group by cluster
    const datasets = clusterTypes.map((name, ci) => ({
      label: name.replace("_", " ").replace(/\b\w/g, c => c.toUpperCase()),
      data: scatter.filter(p => p.cluster === ci).map(p => ({ x: p.x, y: p.y })),
      backgroundColor: `${clusterColors[ci]}AA`,
      borderColor: clusterColors[ci],
      borderWidth: 1.5,
      pointRadius: 7,
      pointHoverRadius: 9,
    }));

    chartInstances[canvasId] = new Chart(ctx, {
      type: "scatter",
      data: { datasets },
      options: {
        responsive: true,
        maintainAspectRatio: false,
        plugins: {
          legend: {
            position: "bottom",
            labels: {
              color: t.textColor,
              padding: 14,
              usePointStyle: true,
              font: { family: "'Inter', sans-serif", size: 11 },
            },
          },
          tooltip: {
            ...tooltipPlugin(),
            callbacks: {
              label: ctx => `${ctx.dataset.label}: (${ctx.parsed.x.toFixed(2)}, ${ctx.parsed.y.toFixed(2)})`,
            },
          },
        },
        scales: {
          ...scaleDefaults(),
          x: { ...scaleDefaults().x, title: { display: true, text: "Session Duration (norm)", color: t.textColor, font: { size: 11 } } },
          y: { ...scaleDefaults().y, title: { display: true, text: "Command Count (norm)", color: t.textColor, font: { size: 11 } } },
        },
        animation: { duration: 1000 },
      },
    });
  }

  // ─── Sparklines ─────────────────────────────────
  function renderSparklines() {
    createSparkline("sparkline-attacks", [1200, 1480, 1900, 1650, 2100, 1800, 2400, 2871], "#3B82F6");
    createSparkline("sparkline-sessions", [3, 5, 4, 7, 6, 8, 9, 8], "#8B5CF6");
    createSparkline("sparkline-ips", [120, 145, 132, 189, 201, 178, 220, 243], "#06B6D4");
  }

  // ─── Update charts on theme change ──────────────
  function refreshAllCharts() {
    Object.values(chartInstances).forEach(chart => {
      if (!chart || typeof chart.update !== "function") return;
      const t = getThemeColors();
      if (chart.options.scales?.x) {
        chart.options.scales.x.grid.color = t.gridColor;
        chart.options.scales.x.ticks.color = t.textColor;
      }
      if (chart.options.scales?.y) {
        chart.options.scales.y.grid.color = t.gridColor;
        chart.options.scales.y.ticks.color = t.textColor;
      }
      if (chart.options.plugins?.tooltip) {
        const tip = tooltipPlugin();
        Object.assign(chart.options.plugins.tooltip, tip);
      }
      chart.update("none");
    });
  }

  // ─── Public API ──────────────────────────────────
  return {
    init() {
      renderSparklines();
      renderAttackTrend("7d");
      renderAttackCategory();
      renderSeverityDonut();
      renderClusterChart("clusterChart");
    },
    renderAttackTrend,
    renderVectorChart,
    renderClusterChart,
    refreshAllCharts,
    destroy(id) {
      if (chartInstances[id]) {
        chartInstances[id].destroy();
        delete chartInstances[id];
      }
    },
    destroyAll() {
      Object.keys(chartInstances).forEach(id => {
        chartInstances[id].destroy();
        delete chartInstances[id];
      });
    },
  };
})();

window.ChartManager = ChartManager;
