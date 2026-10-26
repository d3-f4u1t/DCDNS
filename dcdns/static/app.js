/* Progressive enhancement for the DCDNS console.
 *
 * The portal is usable without JavaScript: the query form is a normal GET and
 * every fault control is a normal POST followed by a redirect. This file only
 * makes the query result and status board update without a full page reload.
 */
(function () {
  "use strict";

  document.documentElement.classList.add("has-js");

  var statusTarget = document.getElementById("live-status");
  var activityTarget = document.getElementById("live-activity");
  var liveDot = document.getElementById("live-dot");
  var liveLabel = document.getElementById("live-label");
  var livePill = document.getElementById("live-pill");
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

  function setLiveState(ok) {
    if (liveDot) liveDot.className = "dot-live " + (ok ? "up" : "down");
    if (liveLabel) liveLabel.textContent = ok ? "live" : "polling failed";
    if (livePill) livePill.className = "live-pill" + (ok ? "" : " is-down");
  }

  function captureActivityScroll(target) {
    return Array.prototype.map.call(
      target.querySelectorAll(".activity-log"),
      function (log) {
        return {
          top: log.scrollTop,
          atBottom:
            log.scrollHeight - log.scrollTop - log.clientHeight < 12,
        };
      }
    );
  }

  function restoreActivityScroll(target, states) {
    if (!target || !states.length) return;
    var logs = target.querySelectorAll(".activity-log");
    states.forEach(function (state, index) {
      var log = logs[index];
      if (!log) return;
      log.scrollTop = state.atBottom ? log.scrollHeight : state.top;
    });
  }

  async function refreshLive() {
    if (!statusTarget && !activityTarget) return;
    // Do not replace the board out from under a keyboard user or while the
    // tab is in the background. The next poll resumes when focus leaves.
    if (document.hidden) return;
    if (statusTarget && statusTarget.contains(document.activeElement)) return;
    if (activityTarget && activityTarget.contains(document.activeElement)) {
      return;
    }
    try {
      var resp = await fetch(
        "/partials/live?q=" + encodeURIComponent(currentQuery),
        { cache: "no-store" }
      );
      if (!resp.ok) throw new Error("HTTP " + resp.status);
      var payload = await resp.json();
      if (!payload || typeof payload.status !== "string") {
        throw new Error("bad live payload");
      }
      // A request may already have been in flight when focus moved into the
      // board. Check again before swapping the DOM.
      if (document.hidden) return;
      if (statusTarget && statusTarget.contains(document.activeElement)) return;
      if (activityTarget && activityTarget.contains(document.activeElement)) {
        return;
      }
      var scrollStates = activityTarget
        ? captureActivityScroll(activityTarget)
        : [];
      if (statusTarget) statusTarget.innerHTML = payload.status;
      if (activityTarget && typeof payload.activity === "string") {
        activityTarget.innerHTML = payload.activity;
        restoreActivityScroll(activityTarget, scrollStates);
      }
      setLiveState(true);
    } catch (err) {
      // Leave the last good board in place. A transient poll failure should not
      // replace real state with a fabricated error state, but the header must
      // stop claiming the board is live.
      setLiveState(false);
    }
  }

  if (statusTarget || activityTarget) {
    refreshLive();
    setInterval(refreshLive, 2000);
  }

  function syncTopbarHeight() {
    var topbar = document.querySelector(".topbar");
    if (!topbar) return;
    var height = Math.ceil(topbar.getBoundingClientRect().height);
    document.documentElement.style.setProperty("--topbar-h", height + "px");
  }

  function initSectionNav() {
    var nav = document.querySelector("[data-section-nav]");
    if (!nav) return;
    var links = Array.prototype.slice.call(
      nav.querySelectorAll("[data-section-link]")
    );
    if (!links.length) return;
    var sections = links
      .map(function (link) {
        return document.getElementById(link.getAttribute("data-section-link"));
      })
      .filter(Boolean);
    if (!sections.length) return;

    function setActive(id) {
      links.forEach(function (link) {
        var active = link.getAttribute("data-section-link") === id;
        link.classList.toggle("active", active);
        if (active) {
          link.setAttribute("aria-current", "location");
        } else {
          link.removeAttribute("aria-current");
        }
      });
    }

    setActive(sections[0].id);
    links.forEach(function (link) {
      link.addEventListener("click", function () {
        setActive(link.getAttribute("data-section-link"));
      });
    });

    if (!("IntersectionObserver" in window)) return;
    var observer = new IntersectionObserver(
      function (entries) {
        var visible = entries.filter(function (entry) {
          return entry.isIntersecting;
        });
        if (!visible.length) return;
        visible.sort(function (a, b) {
          return b.intersectionRatio - a.intersectionRatio;
        });
        setActive(visible[0].target.id);
      },
      { rootMargin: "-30% 0px -55% 0px", threshold: [0, 0.25, 0.5, 1] }
    );
    sections.forEach(function (section) {
      observer.observe(section);
    });
  }

  syncTopbarHeight();
  window.addEventListener("resize", syncTopbarHeight);
  if (document.fonts && document.fonts.ready) {
    document.fonts.ready.then(syncTopbarHeight);
  }
  initSectionNav();

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
