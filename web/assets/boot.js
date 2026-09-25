// Runs before first paint: apply the saved theme and language so the page
// never flashes the wrong palette. Everything else lives in app.js.
(function () {
  try {
    var root = document.documentElement;
    var theme = localStorage.getItem("mb_theme");
    if (theme === "light" || theme === "dark") root.setAttribute("data-theme", theme);
    var lang = localStorage.getItem("mb_lang");
    if (lang) root.setAttribute("lang", lang);
  } catch (e) { /* storage unavailable: fall back to system theme */ }
})();
