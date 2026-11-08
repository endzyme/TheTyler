// Admin page behaviour. Served from /static/admin.js so the CSP can forbid
// inline scripts. Uses event delegation because the copy button arrives via
// an htmx swap after this script has run.
(function () {
  async function copyAPIKey(button) {
    const key = button.dataset.copyKey;
    if (!key) return;

    try {
      await navigator.clipboard.writeText(key);
    } catch (_) {
      const el = document.createElement("textarea");
      el.value = key;
      el.setAttribute("readonly", "");
      el.style.position = "absolute";
      el.style.left = "-9999px";
      document.body.appendChild(el);
      el.select();
      document.execCommand("copy");
      document.body.removeChild(el);
    }

    const original = button.textContent;
    button.textContent = "Copied!";
    button.disabled = true;
    setTimeout(() => {
      button.textContent = original;
      button.disabled = false;
    }, 1200);
  }

  document.addEventListener("click", (event) => {
    const button = event.target.closest("button[data-copy-key]");
    if (button) copyAPIKey(button);
  });
})();
