const API = "http://127.0.0.1:5000/api/check";
const COLORS = { green: "#22c55e", yellow: "#eab308", red: "#ef4444" };
const TITLES = { green: "Looks safe", yellow: "Be careful", red: "Likely a scam" };

const out = document.getElementById("out");

function el(tag, text, cls) {
  const e = document.createElement(tag);
  if (text !== undefined) e.textContent = text;   // textContent prevents HTML injection
  if (cls) e.className = cls;
  return e;
}

function render(d) {
  out.textContent = "";
  out.className = "";
  const color = COLORS[d.verdict];

  const top = el("div", undefined, "top");
  const dot = el("div", undefined, "dot");
  dot.style.background = color;
  dot.style.boxShadow = "0 0 14px " + color;
  const info = el("div");
  const v = el("div", TITLES[d.verdict], "verdict");
  v.style.color = color;
  info.appendChild(v);
  info.appendChild(el("div", d.url, "url"));
  top.appendChild(dot);
  top.appendChild(info);
  out.appendChild(top);

  const meter = el("div", undefined, "meter");
  const bar = el("div", undefined, "bar");
  bar.style.background = color;
  meter.appendChild(bar);
  out.appendChild(meter);
  out.appendChild(el("div", "Risk score: " + d.score + "/100", "score"));
  requestAnimationFrame(() => requestAnimationFrame(() => (bar.style.width = d.score + "%")));

  const ul = el("ul");
  d.reasons.forEach(r => {
    const li = el("li", r);
    li.style.borderLeftColor = color;
    ul.appendChild(li);
  });
  out.appendChild(ul);
}

async function init() {
  const [tab] = await browser.tabs.query({ active: true, currentWindow: true });
  const url = tab && tab.url ? tab.url : "";
  if (!/^https?:\/\//i.test(url)) {
    out.textContent = "Open a website (http or https) to check it.";
    return;
  }
  try {
    const res = await fetch(API, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ url })
    });
    if (!res.ok) throw new Error();
    render(await res.json());
  } catch {
    out.textContent = "Can't reach PhishGuard. Start the server with: python app.py";
  }
}

init();