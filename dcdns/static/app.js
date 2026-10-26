/* Progressive enhancement for the DCDNS console.
 *
 * The portal is usable without JavaScript: the query form is a normal GET and
 * every fault control is a normal POST followed by a redirect. This file only
 * makes the query result and status board update without a full page reload.
 */
(function () {
  "use strict";

  var statusTarget = document.getElementById("live-status");
  var liveDot = document.getElementById("live-dot");
  var liveLabel = document.getElementById("live-label");
  var probeTarget = document.getElementById("probe-live");
  var queryInput = document.getElementById("q");
  var queryForm = document.getElementById("dns-query-form");
  var probeEmbed =
    queryForm && queryForm.getAttribute("data-probe-embed") === "1";
  var currentQuery =
    new URLSearchParams(window.location.search).get("q") ||
    (queryInput && queryInput.value) ||
    "techfest.cs.test";

  function syncQueryInputs(name) {
    currentQuery = name;
    document.querySelectorAll("[data-query-name]").forEach(function (input) {
      input.value = name;
    });
  }

  async function refreshStatus() {
    if (!statusTarget) return;
    // Do not replace the board out from under a keyboard user or while the
    // tab is in the background. The next poll resumes when focus leaves.
    if (document.hidden) return;
    if (statusTarget.contains(document.activeElement)) return;
    try {
      var resp = await fetch(
        "/partials/status?q=" + encodeURIComponent(currentQuery),
        { cache: "no-store" }
      );
      if (!resp.ok) throw new Error("HTTP " + resp.status);
      var html = await resp.text();
      // A request may already have been in flight when focus moved into the
      // board. Check again before swapping the DOM.
      if (document.hidden) return;
      if (statusTarget.contains(document.activeElement)) return;
      statusTarget.innerHTML = html;
      if (liveDot) liveDot.className = "dot-live up";
      if (liveLabel) liveLabel.textContent = "live";
    } catch (err) {
      // Leave the last good board in place. A transient poll failure should not
      // replace real state with a fabricated error state, but the header must
      // stop claiming the board is live.
      if (liveDot) liveDot.className = "dot-live down";
      if (liveLabel) liveLabel.textContent = "polling failed";
    }
  }

  if (statusTarget) {
    refreshStatus();
    setInterval(refreshStatus, 2000);
  }

  if (queryForm && probeTarget) {
    queryForm.addEventListener("submit", async function (event) {
      event.preventDefault();
      var name = (queryInput && queryInput.value.trim()) || currentQuery;
      if (!name) return;
      syncQueryInputs(name);
      var button = queryForm.querySelector("button[type=submit]");
      if (button) {
        button.disabled = true;
        button.textContent = "Querying…";
      }
      try {
        var probeUrl = "/partials/probe?name=" + encodeURIComponent(name);
        if (probeEmbed) probeUrl += "&embed=1";
        var resp = await fetch(
          probeUrl,
          { cache: "no-store" }
        );
        if (!resp.ok) throw new Error("HTTP " + resp.status);
        probeTarget.innerHTML = await resp.text();
        var url = new URL(window.location.href);
        url.searchParams.set("q", name);
        window.history.replaceState({}, "", url);
      } catch (err) {
        // Fall back to the server-rendered page if the partial request fails.
        var url = new URL(queryForm.action, window.location.origin);
        url.searchParams.set("q", name);
        window.location.href = url.toString();
      } finally {
        if (button) {
          button.disabled = false;
          button.textContent = "Query DNS";
        }
      }
    });
  }

  document.addEventListener("submit", function (event) {
    var form = event.target;
    var message = form.getAttribute("data-confirm");
    if (message && !window.confirm(message)) {
      event.preventDefault();
    }
  });
})();
