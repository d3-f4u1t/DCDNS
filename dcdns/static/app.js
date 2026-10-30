/* Progressive enhancement for the DCDNS console.
 *
 * The portal is usable without JavaScript: the query form is a normal GET and
 * every fault control is a normal POST followed by a redirect. This file only
 * makes the query result and status board update without a full page reload.
 */
(function () {
  "use strict";

  document.documentElement.classList.add("has-js");

  // A hash URL names an explicit target. Do not let reload scroll restoration
  // move the reader away from it after the section nav has aligned the page.
  if (window.location.hash && "scrollRestoration" in history) {
    history.scrollRestoration = "manual";
  }

  var statusTarget = document.getElementById("live-status");
  var activityTarget = document.getElementById("live-activity");
  var liveLabel = document.getElementById("live-label");
  var probeTarget = document.getElementById("probe-live");
  var sectionNav = null;
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
    if (!liveLabel) return;
    liveLabel.textContent = ok ? "live" : "polling failed";
    liveLabel.classList.toggle("is-down", !ok);
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
      var anchor = sectionNav ? sectionNav.captureAnchor() : null;
      if (statusTarget) statusTarget.innerHTML = payload.status;
      if (activityTarget && typeof payload.activity === "string") {
        activityTarget.innerHTML = payload.activity;
        restoreActivityScroll(activityTarget, scrollStates);
      }
      if (sectionNav) {
        // A live update can change the height of sections above the reader.
        // Keep the section they are looking at in the same viewport position.
        sectionNav.restoreAnchor(anchor);
        sectionNav.update();
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
    if (!nav) return null;
    var links = Array.prototype.slice.call(
      nav.querySelectorAll("[data-section-link]")
    );
    if (!links.length) return null;
    var sections = links
      .map(function (link) {
        return document.getElementById(link.getAttribute("data-section-link"));
      })
      .filter(Boolean);
    if (!sections.length) return null;

    var activeId = null;

    function setActive(id) {
      if (id === activeId) return;
      activeId = id;
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

    // The active section is the one with the most pixels inside the reading
    // area below the sticky topbar and section index.
    function update() {
      var topbar = document.querySelector(".topbar");
      var jump = document.querySelector(".term-jump");
      var viewTop = 0;
      if (topbar) {
        viewTop = Math.max(viewTop, topbar.getBoundingClientRect().bottom);
      }
      if (jump) {
        viewTop = Math.max(viewTop, jump.getBoundingClientRect().bottom);
      }
      var viewBottom =
        window.innerHeight || document.documentElement.clientHeight;
      var best = null;
      var bestVisible = 0;
      sections.forEach(function (section) {
        var rect = section.getBoundingClientRect();
        var visible =
          Math.min(rect.bottom, viewBottom) - Math.max(rect.top, viewTop);
        if (visible < 0) visible = 0;
        if (visible > bestVisible + 1) {
          best = section;
          bestVisible = visible;
        } else if (
          best &&
          visible > 0 &&
          Math.abs(visible - bestVisible) <= 1
        ) {
          var bestDistance = Math.abs(
            best.getBoundingClientRect().top - viewTop
          );
          var distance = Math.abs(rect.top - viewTop);
          if (distance < bestDistance) best = section;
        }
      });
      if (best) setActive(best.id);
    }

    function scrollToHash() {
      var id = (window.location.hash || "").replace(/^#/, "");
      if (!id) return;
      var target = document.getElementById(id);
      if (!target) return;
      var topbar = document.querySelector(".topbar");
      var jump = document.querySelector(".term-jump");
      var offset = 0;
      if (topbar) {
        offset = Math.max(offset, topbar.getBoundingClientRect().bottom);
      }
      if (jump) {
        offset = Math.max(offset, jump.getBoundingClientRect().bottom);
      }
      if (Math.abs(target.getBoundingClientRect().top - offset) <= 2) return;
      target.scrollIntoView();
    }

    function captureAnchor() {
      var section = activeId ? document.getElementById(activeId) : null;
      return section
        ? { id: activeId, top: section.getBoundingClientRect().top }
        : null;
    }

    function restoreAnchor(anchor) {
      if (!anchor) return;
      var section = document.getElementById(anchor.id);
      if (!section) return;
      var delta = section.getBoundingClientRect().top - anchor.top;
      if (Math.abs(delta) > 1) window.scrollBy(0, delta);
    }

    var hashId = (window.location.hash || "").replace(/^#/, "");
    var initial = sections.filter(function (section) {
      return section.id === hashId;
    })[0] || sections[0];
    setActive(initial.id);

    links.forEach(function (link) {
      link.addEventListener("click", function () {
        setActive(link.getAttribute("data-section-link"));
      });
    });

    var ticking = false;
    function requestUpdate() {
      if (ticking) return;
      ticking = true;
      window.requestAnimationFrame(function () {
        ticking = false;
        update();
      });
    }

    window.addEventListener("scroll", requestUpdate, { passive: true });
    window.addEventListener("resize", requestUpdate);
    window.addEventListener("hashchange", function () {
      var id = (window.location.hash || "").replace(/^#/, "");
      if (
        sections.some(function (section) {
          return section.id === id;
        })
      ) {
        setActive(id);
      }
      scrollToHash();
      requestUpdate();
    });

    function settle() {
      scrollToHash();
      update();
    }
    if (document.readyState === "complete") {
      settle();
    } else {
      window.addEventListener("load", settle);
    }
    if (document.fonts && document.fonts.ready) {
      document.fonts.ready.then(update);
    }

    return {
      update: update,
      captureAnchor: captureAnchor,
      restoreAnchor: restoreAnchor,
    };
  }

  syncTopbarHeight();
  window.addEventListener("resize", syncTopbarHeight);
  if (document.fonts && document.fonts.ready) {
    document.fonts.ready.then(syncTopbarHeight);
  }
  sectionNav = initSectionNav();

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
