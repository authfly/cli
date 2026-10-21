// Authfly theme: light/dark on <html class="dark">, remembered in localStorage, OS preference by default.
// Wires every [data-ui8kit="theme-toggle"] button (aria-pressed), as documented by the ThemeToggle brick.
(function () {
  var root = document.documentElement;
  var saved = localStorage.getItem("authfly-theme");
  var dark = saved ? saved === "dark" : window.matchMedia("(prefers-color-scheme: dark)").matches;
  var q = new URLSearchParams(location.search).get("theme");
  if (q === "dark" || q === "light") dark = q === "dark";
  root.classList.toggle("dark", dark);
  document.addEventListener("DOMContentLoaded", function () {
    document.querySelectorAll('[data-ui8kit="theme-toggle"]').forEach(function (b) {
      b.setAttribute("aria-pressed", String(root.classList.contains("dark")));
      b.addEventListener("click", function () {
        var d = !root.classList.contains("dark");
        root.classList.toggle("dark", d);
        localStorage.setItem("authfly-theme", d ? "dark" : "light");
        b.setAttribute("aria-pressed", String(d));
      });
    });
  });
})();
