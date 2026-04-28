/**
 * PostureIQ — Teams Tab Integration
 *
 * Detects whether the app is running inside Microsoft Teams and initialises
 * the Teams JavaScript SDK so that the iframe is trusted.  When running
 * outside Teams (standalone browser) this script is a harmless no-op.
 *
 * Load order in every HTML page:
 *   1. <script src="https://res.cdn.office.net/teams-js/2.31.1/js/MicrosoftTeams.min.js"></script>
 *   2. <script src="/teams-init.js"></script>
 *   3. <script src="/msal-browser.min.js"></script>
 *   ... rest of page scripts
 */
(function () {
  "use strict";

  /* ── Detect Teams context ─────────────────────────────────── */
  var inTeams = (
    window.parent !== window ||                       // In an iframe (Tab)
    window.name === "embedded-page-container" ||      // Teams iframe name
    navigator.userAgent.indexOf("Teams") !== -1 ||    // Teams desktop UA
    window.location.search.indexOf("inTeams") !== -1  // Explicit query param
  );

  window.__esiqInTeams = inTeams;
  window.__esiqTeamsLoginHint = null;

  if (!inTeams) {
    /* Standalone browser — resolved promise so initMsal can await safely */
    window.__esiqTeamsReady = Promise.resolve(null);
    return;
  }

  /* ── Initialise Teams SDK ─────────────────────────────────── */
  if (typeof microsoftTeams === "undefined") {
    console.warn("[PostureIQ] Teams SDK not loaded — cannot initialise.");
    window.__esiqTeamsReady = Promise.resolve(null);
    return;
  }

  /* Export promise so MSAL init can await Teams SDK readiness */
  window.__esiqTeamsReady = microsoftTeams.app
    .initialize(["https://teams.cloud.microsoft"])
    .then(function () {
      console.log("[PostureIQ] Teams SDK initialised.");

      /* Tell Teams the app content is loaded (hides loading spinner) */
      microsoftTeams.app.notifyAppLoaded();

      /* Tell Teams this tab is ready for interaction */
      microsoftTeams.app.notifySuccess();

      /* Get Teams context (theme, loginHint for NAA) */
      return microsoftTeams.app.getContext();
    })
    .then(function (ctx) {
      if (!ctx) return ctx;

      /* Store loginHint — critical for MSAL NAA token acquisition */
      if (ctx.user && ctx.user.loginHint) {
        window.__esiqTeamsLoginHint = ctx.user.loginHint;
        console.log("[PostureIQ] loginHint stored:", ctx.user.loginHint);
      }

      /* Sync Teams theme with PostureIQ theme toggle */
      var teamsTheme = ctx.app && ctx.app.theme;
      if (teamsTheme === "dark" || teamsTheme === "contrast") {
        document.documentElement.setAttribute("data-theme", "dark");
        localStorage.setItem("esiq-theme", "dark");
      } else {
        document.documentElement.removeAttribute("data-theme");
        localStorage.setItem("esiq-theme", "light");
      }

      /* Listen for live theme changes while open */
      microsoftTeams.app.registerOnThemeChangeHandler(function (theme) {
        if (theme === "dark" || theme === "contrast") {
          document.documentElement.setAttribute("data-theme", "dark");
          localStorage.setItem("esiq-theme", "dark");
        } else {
          document.documentElement.removeAttribute("data-theme");
          localStorage.setItem("esiq-theme", "light");
        }
      });

      console.log("[PostureIQ] Teams context:", teamsTheme, ctx.user && ctx.user.loginHint);
      return ctx;
    })
    .catch(function (err) {
      /* Non-fatal — app still works, just without Teams integration */
      console.warn("[PostureIQ] Teams init failed (may be standalone):", err);
      return null;
    });
})();
