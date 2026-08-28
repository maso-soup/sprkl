// TODO(dev): before launch, remove /debug and /backup.zip, and take the
// legacy /api/v1 endpoints offline. See /robots.txt for the current disallow list.
// SPRKL storefront front-end.
// VULN(secrets-in-js): a live promo API key is embedded client-side. Used by the
// promo validator widget below, so it is naturally discoverable by reading this file.
const SPRKL_PROMO_KEY = "SPRKL-CANARY-JSKEY-9c1f2a";

// Add-to-cart buttons (progressive enhancement).
document.addEventListener("click", async (e) => {
  const b = e.target.closest("[data-add-cart]");
  if (!b) return;
  e.preventDefault();
  const pid = b.getAttribute("data-add-cart");
  await fetch("/cart/add", {
    method: "POST", headers: {"Content-Type": "application/x-www-form-urlencoded"},
    body: "pid=" + encodeURIComponent(pid) + "&qty=1",
  });
  const badge = document.querySelector(".badge");
  if (badge) badge.textContent = (parseInt(badge.textContent || "0", 10) + 1);
  b.textContent = "Added ✓";
  setTimeout(() => (b.textContent = "Add to cart"), 1200);
});

// Promo validator widget: sends the embedded key to the promo service.
window.sprklValidatePromo = async function (code) {
  const r = await fetch("/api/v2/keycheck?key=" + encodeURIComponent(SPRKL_PROMO_KEY));
  return r.json();
};

console.log("SPRKL storefront loaded");

// Generic handler: forms with class "ajax" POST/GET and show the JSON result inline.
document.addEventListener("submit", async (e) => {
  const f = e.target;
  if (!f.classList.contains("ajax")) return;
  e.preventDefault();
  const method = (f.getAttribute("method") || "post").toUpperCase();
  const out = f.parentElement.querySelector(".result") ||
              (() => { const d = document.createElement("pre"); d.className = "result"; f.after(d); return d; })();
  try {
    let url = f.getAttribute("action"), opts = { method };
    if (method === "GET") {
      url += "?" + new URLSearchParams(new FormData(f));
    } else {
      opts.headers = { "Content-Type": "application/x-www-form-urlencoded" };
      opts.body = new URLSearchParams(new FormData(f));
    }
    const r = await fetch(url, opts);
    const t = await r.text();
    try { out.textContent = JSON.stringify(JSON.parse(t), null, 2); }
    catch { out.textContent = t.slice(0, 2000); }
  } catch (err) { out.textContent = String(err); }
});
