document.addEventListener("DOMContentLoaded", () => {
  const autoRefreshMs = Number(document.body?.getAttribute("data-auto-refresh") || 0);
  const autoRefreshToggle = document.querySelector("[data-auto-refresh-toggle]");
  if (Number.isFinite(autoRefreshMs) && autoRefreshMs >= 5000) {
    const autoRefreshKey = "scan_jobs_auto_refresh";
    let enabled = localStorage.getItem(autoRefreshKey) !== "off";

    const syncAutoRefreshLabel = () => {
      if (!autoRefreshToggle) return;
      autoRefreshToggle.textContent = `Auto-refresh: ${enabled ? "On" : "Off"}`;
      autoRefreshToggle.setAttribute("aria-pressed", enabled ? "true" : "false");
    };

    syncAutoRefreshLabel();

    autoRefreshToggle?.addEventListener("click", () => {
      enabled = !enabled;
      localStorage.setItem(autoRefreshKey, enabled ? "on" : "off");
      syncAutoRefreshLabel();
    });

    setInterval(() => {
      if (enabled) {
        window.location.reload();
      }
    }, autoRefreshMs);
  }

  document.querySelectorAll("[data-copy]").forEach((button) => {
    button.addEventListener("click", async () => {
      const target = document.querySelector(button.getAttribute("data-copy"));
      if (!target) return;
      await navigator.clipboard.writeText(target.textContent.trim());
      button.textContent = "Copied";
      setTimeout(() => {
        button.textContent = "Copy";
      }, 1200);
    });
  });

  const table = document.querySelector("#auditTable");
  if (table) {
    const rows = Array.from(table.querySelectorAll("tbody tr"));
    const search = document.querySelector("#auditSearch");
    const severityButtons = Array.from(document.querySelectorAll("[data-filter]"));
    const typeButtons = Array.from(document.querySelectorAll("[data-type]"));
    const detail = {
      type: document.querySelector("#auditDetailType"),
      title: document.querySelector("#auditDetailTitle"),
      location: document.querySelector("#auditDetailLocation"),
      priority: document.querySelector("#auditDetailPriority"),
      status: document.querySelector("#auditDetailStatus"),
      claim: document.querySelector("#auditDetailClaim"),
      claimedBy: document.querySelector("#auditDetailClaimedBy"),
      claimedAt: document.querySelector("#auditDetailClaimedAt"),
      description: document.querySelector("#auditDetailDescription"),
      recommendation: document.querySelector("#auditDetailRecommendation"),
      aiIssue: document.querySelector("#auditDetailAiIssue"),
      aiRemediation: document.querySelector("#auditDetailAiRemediation"),
      validation: document.querySelector("#auditDetailValidation"),
      tagged: document.querySelector("#auditDetailTagged"),
      analysis: document.querySelector("#auditDetailAnalysis"),
      source: document.querySelector("#auditDetailSource"),
    };
    let severity = "all";
    let type = "all";

    const applyFilters = () => {
      const query = (search?.value || "").trim().toLowerCase();
      rows.forEach((row) => {
        const rowSeverity = row.getAttribute("data-severity") || "";
        const rowType = row.getAttribute("data-type") || "";
        const rowSearch = row.getAttribute("data-search") || "";
        const matchesSeverity = severity === "all" || rowSeverity === severity;
        const matchesType = type === "all" || rowType === type;
        const matchesQuery = !query || rowSearch.includes(query);
        row.style.display = matchesSeverity && matchesType && matchesQuery ? "" : "none";
      });
    };

    severityButtons.forEach((button) => {
      if (!button.hasAttribute("data-filter")) return;
      button.addEventListener("click", () => {
        severity = button.getAttribute("data-filter") || "all";
        severityButtons.forEach((btn) => btn.classList.toggle("active", btn === button && btn.hasAttribute("data-filter")));
        applyFilters();
      });
    });

    typeButtons.forEach((button) => {
      if (!button.hasAttribute("data-type")) return;
      button.addEventListener("click", () => {
        type = button.getAttribute("data-type") || "all";
        typeButtons.forEach((btn) => btn.classList.toggle("active", btn === button && btn.hasAttribute("data-type")));
        applyFilters();
      });
    });

    search?.addEventListener("input", applyFilters);
    applyFilters();

    const setDetail = (row) => {
      if (!row || !detail.title) return;
      const text = (key) => row.getAttribute(key) || "";
      if (detail.type) detail.type.textContent = text("data-type");
      if (detail.title) detail.title.textContent = text("data-title");
      if (detail.location) detail.location.textContent = text("data-location");
      if (detail.priority) detail.priority.textContent = text("data-priority").toUpperCase();
      if (detail.status) detail.status.textContent = (text("data-status") || "").replaceAll("_", " ").toUpperCase();
      if (detail.claim) detail.claim.textContent = text("data-claim-state");
      if (detail.claimedBy) detail.claimedBy.textContent = text("data-claimed-by");
      if (detail.claimedAt) detail.claimedAt.textContent = text("data-claimed-at");
      if (detail.description) detail.description.textContent = text("data-description");
      if (detail.recommendation) detail.recommendation.textContent = text("data-recommendation");
      if (detail.aiIssue) detail.aiIssue.textContent = text("data-ai-issue-summary");
      if (detail.aiRemediation) detail.aiRemediation.textContent = text("data-ai-remediation");
      if (detail.validation) detail.validation.textContent = text("data-validation-notes");
      if (detail.tagged) detail.tagged.textContent = text("data-tagged");
      if (detail.analysis) detail.analysis.textContent = text("data-analysis");
      if (detail.source) detail.source.textContent = text("data-file-path");
    };

    rows.forEach((row) => {
      row.addEventListener("click", (event) => {
        if (event.target.closest("button") || event.target.closest("form") || event.target.closest("a")) return;
        setDetail(row);
      });
      row.addEventListener("keydown", (event) => {
        if (event.key === "Enter" || event.key === " ") {
          event.preventDefault();
          setDetail(row);
        }
      });
    });

    if (rows[0]) setDetail(rows[0]);
  }
});
