const API = "http://127.0.0.1:5000/api/check";

const COLORS = { green: "#22c55e", yellow: "#eab308", red: "#ef4444" };
const BADGE = { green: "OK", yellow: "!", red: "X" };
// Which verdicts show the warning banner on the page. Use ["red"] for a quieter demo.
const BANNER_LEVELS = ["red", "yellow"];

function isCheckable(url) {
  let u;
  try { u = new URL(url); } catch (e) { return false; }
  if (!["http:", "https:"].includes(u.protocol)) return false;
  if (["127.0.0.1", "localhost"].includes(u.hostname)) return false;  // don't check our own server
  return true;
}

async function scan(tabId, url) {
  if (!isCheckable(url)) {
    browser.browserAction.setBadgeText({ tabId, text: "" });
    return;
  }
  try {
    const res = await fetch(API, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ url })
    });
    if (!res.ok) throw new Error("API error");
    const data = await res.json();

    browser.browserAction.setBadgeText({ tabId, text: BADGE[data.verdict] });
    browser.browserAction.setBadgeBackgroundColor({ tabId, color: COLORS[data.verdict] });

    if (BANNER_LEVELS.includes(data.verdict)) {
      // Make sure the tab hasn't navigated away while we were checking
      const tab = await browser.tabs.get(tabId);
      if (tab.url === url) {
        await browser.tabs.sendMessage(tabId, {
          type: "phishguard-banner",
          verdict: data.verdict,
          score: data.score,
          reasons: data.reasons.slice(0, 3)
        });
      }
    }
  } catch (e) {
    // Server not running or page can't receive the banner: grey "?" badge
    browser.browserAction.setBadgeText({ tabId, text: "?" });
    browser.browserAction.setBadgeBackgroundColor({ tabId, color: "#64748b" });
  }
}

browser.tabs.onUpdated.addListener((tabId, changeInfo, tab) => {
  if (changeInfo.status === "complete" && tab.url) scan(tabId, tab.url);
});