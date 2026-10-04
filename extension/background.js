// ScamShield context-menu companion (Manifest V3).
// Right-click selected text on any page -> "Check with ScamShield" ->
// opens the ScamShield web app with the text pre-filled in the analyzer.
//
// 1) Deploy the web app (see ../render.yaml), then set your URL below.
// 2) Load this folder as an unpacked extension (see README.md).
const SCAMSHIELD_URL = 'https://scamshield.onrender.com'; // <-- change to your deployed URL

chrome.runtime.onInstalled.addListener(() => {
  chrome.contextMenus.create({
    id: 'scamshield-check',
    title: 'Check with ScamShield',
    contexts: ['selection'],
  });
});

chrome.contextMenus.onClicked.addListener((info) => {
  if (info.menuItemId === 'scamshield-check' && info.selectionText) {
    const q = encodeURIComponent(info.selectionText.slice(0, 2000));
    chrome.tabs.create({ url: `${SCAMSHIELD_URL}/?q=${q}` });
  }
});
