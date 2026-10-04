# ScamShield Browser Extension (MVP)

A minimal Manifest V3 Chrome extension: select any suspicious text on a
webpage, right-click → **Check with ScamShield** → the ScamShield web app
opens with the text pre-filled in the analyzer.

Permissions used: `contextMenus` only. No data is collected by the extension;
the selected text is passed to *your own* ScamShield deployment via the URL.

## Setup

1. Deploy the ScamShield web app (see `../render.yaml`), note its public URL.
2. Open `background.js` and set `SCAMSHIELD_URL` to your deployed URL.
3. In Chrome, go to `chrome://extensions`.
4. Enable **Developer mode** (top right).
5. Click **Load unpacked** and select this `extension/` folder.
6. Select any text on a page → right-click → **Check with ScamShield**.

## Files

- `manifest.json` — MV3 manifest (contextMenus permission only)
- `background.js` — creates the context-menu item, opens the app with `?q=<text>`
- `icons/` — extension icons
