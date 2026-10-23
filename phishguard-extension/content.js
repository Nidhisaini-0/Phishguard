browser.runtime.onMessage.addListener((msg) => {
  if (!msg || msg.type !== "phishguard-banner") return;
  if (document.getElementById("phishguard-banner")) return;

  const bg = msg.verdict === "red" ? "#ef4444" : "#eab308";
  const fg = msg.verdict === "red" ? "#ffffff" : "#1c1917";

  const bar = document.createElement("div");
  bar.id = "phishguard-banner";
  bar.style.cssText =
    "position:fixed;top:0;left:0;right:0;z-index:2147483647;display:flex;gap:12px;" +
    "align-items:flex-start;padding:10px 16px;box-shadow:0 2px 10px rgba(0,0,0,.35);" +
    "font:14px/1.4 system-ui,sans-serif;background:" + bg + ";color:" + fg + ";";

  const box = document.createElement("div");
  box.style.cssText = "flex:1;";
  const title = document.createElement("strong");
  title.textContent = msg.verdict === "red"
    ? "PhishGuard: this page is likely a scam. Don't enter any information. (Risk " + msg.score + "/100)"
    : "PhishGuard: be careful with this page. (Risk " + msg.score + "/100)";
  const why = document.createElement("div");
  why.style.cssText = "font-size:12.5px;margin-top:3px;opacity:.95;";
  why.textContent = msg.reasons.join("  \u2022  ");
  box.appendChild(title);
  box.appendChild(why);

  const close = document.createElement("button");
  close.textContent = "Dismiss";
  close.style.cssText =
    "border:0;border-radius:6px;padding:6px 12px;cursor:pointer;font-weight:600;" +
    "background:rgba(0,0,0,.25);color:" + fg + ";";
  close.addEventListener("click", () => bar.remove());

  bar.appendChild(box);
  bar.appendChild(close);
  document.documentElement.appendChild(bar);
});