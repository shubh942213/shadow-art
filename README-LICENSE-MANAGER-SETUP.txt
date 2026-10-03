RADILUX LICENSE MANAGER v1.0 - SETUP
====================================

WHAT CHANGED
------------
The customer application no longer depends on a long comma/newline-separated
RADILUX_LICENSE_KEYS list for normal operation.

Licenses are now stored individually in Netlify Blobs. The same server-side
store already used for phone binding is now also the license database.

FILES
-----
index.html
radilux-engine.js
radilux-license-admin.html
package.json
netlify.toml
netlify/functions/license.mjs

NETLIFY ENVIRONMENT VARIABLES
-----------------------------
Keep:
RADILUX_AUTH_SECRET
RADILUX_ADMIN_SECRET

RADILUX_LICENSE_KEYS is now ONLY a temporary migration/legacy variable.
You may remove it after importing the old keys into the license database.

HOW TO DEPLOY
-------------
1. Replace the old license.mjs in your GitHub repository with the new:
   netlify/functions/license.mjs
2. Keep your current index.html, radilux-engine.js, package.json and netlify.toml.
   This package contains the working v14 files with the licensing backend updated.
3. Add radilux-license-admin.html to the site repository if you want the admin
   page hosted with the site. You can also open the HTML file locally.
4. Deploy the site on Netlify.

ADMIN TOOL
----------
Open radilux-license-admin.html.

License API URL:
- When admin HTML is hosted inside the same Netlify site:
  /.netlify/functions/license
- When the admin HTML is opened as a local file, enter the full URL, for example:
  https://YOUR-SITE.netlify.app/.netlify/functions/license

Enter RADILUX_ADMIN_SECRET, then click CONNECT / REFRESH.

FIRST-TIME MIGRATION OF YOUR EXISTING KEYS
------------------------------------------
1. Keep RADILUX_LICENSE_KEYS in Netlify for now.
2. Deploy the new code.
3. Open the Admin Tool.
4. Enter your Admin Secret.
5. Click CONNECT / REFRESH.
6. Click IMPORT EXISTING NETLIFY KEYS.
7. Refresh the database and confirm that your old keys are listed.
8. You can then delete RADILUX_LICENSE_KEYS from Netlify.
9. Deploy again.

The old test key RDLX-SHUBHAM94-TEST-001 can also be registered manually from
REGISTER EXISTING KEY if needed.

GENERATING NEW LICENSES
-----------------------
In the Admin Tool:
1. Enter Customer / User ID, for example CUSTOMER021.
2. Choose quantity.
3. Choose validity.
4. Add an optional note.
5. Click GENERATE & REGISTER.

Keys are generated server-side and immediately saved to the license database.
The new keys are also copied to the clipboard.
No Netlify environment-variable edit is required for each new customer.

CUSTOMER ACTIVATION
-------------------
The customer still enters:
- License Key
- Phone Number

The first successful activation binds that license to the phone number.
A different phone number consumes one failed attempt. After 3 mismatches the
license is locked.

LICENSE MANAGEMENT
------------------
Available: generated but not phone-bound.
Active: phone-bound and usable.
Locked: 3 wrong-phone attempts; customer blocked.
Revoked: administrator blocked the license.
Expired: validity date has passed.

ADMIN ACTIONS
-------------
COPY - copies the exact license key.
RESET - clears phone binding and failed-attempt lock while preserving the license.
REVOKE - blocks the license.
RESTORE - restores a revoked license when not expired.
DELETE - permanently removes the license record.

SECURITY NOTES
--------------
- RADILUX_ADMIN_SECRET must never be placed in index.html, radilux-engine.js,
  or any public source file.
- The admin page keeps the secret only in memory and does not store it in
  localStorage.
- The admin API returns only the last four digits of the bound phone number.
- Phone ownership is not independently verified by SMS OTP in this version.
- The generation engine is still browser-delivered. A determined user can
  inspect/copy client-side JavaScript. Full source protection requires a
  server-side generation engine.
