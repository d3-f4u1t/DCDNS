/* Minimal progressive-enhancement helpers.
 *
 * The portal is fully usable without JavaScript: every action is a normal form
 * POST followed by a redirect. This file only adds live status polling and
 * confirmation prompts, which keeps the demo resilient (no CDN, no build step).
 */
(function () {
  "use strict";

  // --- live cluster/DNS status -------------------------------------------
  var target = document.getElementById("live-status");
  var badge = document.getElementById("live-badge");

  async function refreshStatus() {
    if (!target) return;
    try {
      var resp = await fetch("/partials/status", { cache: "no-store" });
      if (!resp.ok) throw new Error("HTTP " + resp.status);
      target.innerHTML = await resp.text();
      if (badge) {
        badge.className = "badge accent";
        badge.textContent = "live";
      }
    } catch (err) {
      if (badge) {
        badge.className = "badge danger";
        badge.textContent = "polling failed";
      }
    }
  }

  if (target) {
    refreshStatus();
    setInterval(refreshStatus, 2000);
  }

  // --- destructive action confirmation -----------------------------------
  document.addEventListener("submit", function (event) {
    var form = event.target;
    var message = form.getAttribute("data-confirm");
    if (message && !window.confirm(message)) {
      event.preventDefault();
    }
  });
})();
