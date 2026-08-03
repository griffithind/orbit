// Orbit operator UI — the whole of the JavaScript.
//
// EVERY SCREEN WORKS WITHOUT THIS FILE. If it 404s, is blocked by an extension,
// or is turned off entirely, every page still renders, every link still
// navigates, and every action still fires — the forms are real forms posting to
// real URLs. What this adds is two conveniences and nothing else:
//
//   1. live refresh, so a page being watched during an incident updates itself
//   2. a confirmation dialog on destructive controls, as a guard against a
//      misclick — never as the thing that makes an action safe. The block
//      confirmation is a server-rendered PAGE for that reason.
//
// No framework, no bundler, no dependencies. It is small enough to read in one
// sitting, which is the only property that matters for code nobody will look at
// again until it misbehaves.

(function () {
  "use strict";

  // --- destructive-action confirmation ------------------------------------

  // Any control carrying data-confirm asks first. Attached at the document
  // level so markup rendered by a live refresh is covered without re-binding.
  document.addEventListener(
    "click",
    function (ev) {
      // Guarded: a click can originate on a node without closest (a text node
      // in some engines, the document itself). A throw here would be harmless —
      // it cannot cancel the default action, so the form would still submit —
      // but it would fill the console during an incident.
      var el = ev.target && ev.target.closest && ev.target.closest("[data-confirm]");
      if (!el) return;
      if (!window.confirm(el.getAttribute("data-confirm"))) {
        ev.preventDefault();
        ev.stopPropagation();
      }
    },
    true
  );

  // --- live refresh --------------------------------------------------------

  var body = document.body;
  var network = body.getAttribute("data-live-network");
  if (!network) return;

  var status = document.querySelector("[data-live-status]");
  var main = document.getElementById("main");
  if (!main) return;

  var refreshing = false;

  function note(text, stale) {
    if (!status) return;
    status.textContent = text;
    status.classList.toggle("stale", !!stale);
  }

  // Refetch this exact URL and swap <main>. The server is the only thing that
  // knows how to render this page, so the client never builds markup — it asks
  // for the same page again and replaces the part that changes. That is why
  // there is no JSON API behind these screens and nothing to keep in step.
  function refresh() {
    if (refreshing || document.hidden) return;
    refreshing = true;

    fetch(window.location.href, {
      credentials: "same-origin",
      headers: { Accept: "text/html" },
      redirect: "manual",
    })
      .then(function (res) {
        // A redirect means the session ended and the server is sending us to
        // the login form. Follow it rather than silently rendering nothing.
        if (res.type === "opaqueredirect" || res.status === 401 || res.status === 403) {
          window.location.reload();
          return null;
        }
        if (!res.ok) throw new Error("HTTP " + res.status);
        return res.text();
      })
      .then(function (html) {
        if (html === null) return;
        var doc = new DOMParser().parseFromString(html, "text/html");
        var fresh = doc.getElementById("main");
        if (!fresh) throw new Error("no main element");

        // Do not clobber a form the operator is in the middle of. A live view
        // that eats a half-typed filter is a live view people turn off.
        var active = document.activeElement;
        if (active && main.contains(active) && active.tagName !== "BODY") return;

        main.replaceWith(fresh);
        main = fresh;
        note("Updated " + new Date().toLocaleTimeString() + ".", false);
      })
      .catch(function (err) {
        // Say so. A live page that quietly stops updating during an incident is
        // worse than one that never claimed to be live, because it keeps being
        // believed.
        note("Not updating: " + err.message + ". Reload to be sure.", true);
      })
      .finally(function () {
        refreshing = false;
      });
  }

  // The timer. It exists even when the event stream is up, and that is the
  // whole subtlety: last_seen_at and the applied epochs move when an AGENT
  // REPORTS, and a report issues no notification — so convergence drifts with
  // no event behind it. Ten seconds covers that; the stream covers the rest,
  // instantly.
  var timer = null;
  function startTimer() {
    if (timer === null) timer = window.setInterval(refresh, 10000);
  }
  function stopTimer() {
    if (timer !== null) {
      window.clearInterval(timer);
      timer = null;
    }
  }

  // A tab on a second monitor costs nothing while it is hidden, and refreshes
  // once the moment it is looked at again.
  document.addEventListener("visibilitychange", function () {
    if (document.hidden) {
      stopTimer();
    } else {
      refresh();
      startTimer();
    }
  });
  startTimer();

  // The event stream. Failing to open it is not an error worth showing: the
  // timer already keeps the page correct, so push is a latency improvement and
  // its absence is invisible except in how fast a revocation appears to land.
  if (!window.EventSource) return;

  var es = new EventSource("/ui/events?network=" + encodeURIComponent(network));

  es.addEventListener("epoch", function () {
    refresh();
  });

  // The server sends this when it re-validates the session and finds it gone.
  // Stop reconnecting and go to the login page — an EventSource retrying
  // forever against a revoked session is a background loop nobody can see.
  es.addEventListener("expired", function () {
    es.close();
    window.location.reload();
  });

  es.addEventListener("error", function () {
    // EventSource reconnects on its own; nothing to do but stay on the timer.
    // Deliberately silent, because a control plane restart would otherwise put
    // a scary message on every open tab for the two seconds it takes to come
    // back.
  });

  window.addEventListener("pagehide", function () {
    es.close();
  });
})();
