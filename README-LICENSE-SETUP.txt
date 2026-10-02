RADILUX LICENSE SYSTEM - NETLIFY SETUP
======================================

FILES TO COMMIT TO GITHUB
--------------------------
index.html
radilux-engine.js
package.json
netlify.toml
netlify/functions/license.mjs

NETLIFY ENVIRONMENT VARIABLES
-----------------------------
In Netlify -> Project configuration -> Environment variables, add:

RADILUX_LICENSE_KEYS
  Put all valid license keys here, separated by commas or new lines.
  Example:
  RDLX-DEMO-001
  RDLX-DEMO-002
  RDLX-DEMO-003

RADILUX_AUTH_SECRET
  Long random secret. Example format only:
  64+ random characters
  Do NOT put the example itself into production.

RADILUX_ADMIN_SECRET
  Another long random secret used only for administrator reset requests.
  Keep this secret out of GitHub and out of index.html.

Mark these environment variables as secret in Netlify.

DEPLOY
------
Push the files to the same GitHub repository connected to the Netlify site.
Netlify will install @netlify/blobs and deploy the license function automatically.

USER FLOW
---------
1. User sees the Radilux license activation screen.
2. User enters license key + phone number.
3. The server checks the license key against RADILUX_LICENSE_KEYS.
4. On first successful activation, the server binds a hash of the phone number to that license.
5. The raw phone number is not stored in the Radilux license record; only a keyed hash and last 4 digits are stored.
6. Later activation with a different phone number increments the server-side failed-attempt counter.
7. After 3 mismatches, the server permanently sets the license status to locked.
8. The UI displays an ILLEGAL / UNAUTHORIZED USE WARNING and does not initialize the generator engine.
9. A valid existing binding receives a signed 30-day browser session token.

ADMIN RESET
-----------
To reset a locked/bound license, send a POST request to:

/.netlify/functions/license

JSON body:
{"action":"adminReset","licenseKey":"RDLX-..."}

Header:
x-radilux-admin-secret: YOUR_RADILUX_ADMIN_SECRET

The reset deletes the license binding record. The next successful activation binds a new phone number.

IMPORTANT SECURITY NOTE
-----------------------
This system makes license validation and phone binding server-side, and the generation engine is loaded only after successful verification.
However, the generation engine itself is still a browser-delivered JavaScript file. A determined user can still inspect or copy a static client-side engine from the browser.
True source/code protection requires moving the generation engine to a server-side API/Function so the browser receives only results, not the engine source.

PHONE VERIFICATION NOTE
-----------------------
This version verifies the phone number as the bound identifier, but it does not send an SMS OTP. Therefore it cannot independently prove that the person typing the number controls that SIM/phone. An OTP layer can be added later if ownership verification is required.
