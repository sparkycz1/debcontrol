/* WebAuthn/passkey registration and login-time authentication.
 *
 * Two ceremonies, both the same shape: fetch options (JSON, base64url-
 * encoded per the WebAuthn JSON serialization — see app.auth.webauthn's
 * module docstring for why they're generated server-side), decode the
 * binary fields, hand them to the native `navigator.credentials` API, then
 * re-encode the browser's result and submit it as a normal form POST — the
 * server-side route verifies it exactly like any other login/account
 * mutation, no fetch/JSON round trip needed once the ceremony itself is
 * done. Progressive, not a SPA: a browser/site without WebAuthn support
 * (or a user who declines) just never sees the button do anything, and can
 * still use TOTP/recovery codes normally.
 *
 * `PublicKeyCredential.prototype.toJSON()` (Credential Management Level 3)
 * already produces exactly the base64url JSON shape py_webauthn's
 * `parse_*_credential_json` expects, so that's used when available; a
 * manual fallback covers browsers without it yet.
 */
(function () {
  "use strict";

  function base64urlToBytes(value) {
    const padded = value.replace(/-/g, "+").replace(/_/g, "/");
    const withPadding = padded + "=".repeat((4 - (padded.length % 4)) % 4);
    const binary = atob(withPadding);
    const bytes = new Uint8Array(binary.length);
    for (let i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i);
    return bytes.buffer;
  }

  function bytesToBase64url(buffer) {
    const bytes = new Uint8Array(buffer);
    let binary = "";
    for (let i = 0; i < bytes.length; i++) binary += String.fromCharCode(bytes[i]);
    return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
  }

  function decodeCreationOptions(options) {
    options.challenge = base64urlToBytes(options.challenge);
    options.user.id = base64urlToBytes(options.user.id);
    if (options.excludeCredentials) {
      options.excludeCredentials = options.excludeCredentials.map((cred) => ({
        ...cred,
        id: base64urlToBytes(cred.id),
      }));
    }
    return options;
  }

  function decodeRequestOptions(options) {
    options.challenge = base64urlToBytes(options.challenge);
    if (options.allowCredentials) {
      options.allowCredentials = options.allowCredentials.map((cred) => ({
        ...cred,
        id: base64urlToBytes(cred.id),
      }));
    }
    return options;
  }

  // Manual fallback for browsers without PublicKeyCredential.toJSON() yet.
  function credentialToJson(credential, kind) {
    if (typeof credential.toJSON === "function") return credential.toJSON();
    const response = credential.response;
    const base = {
      id: credential.id,
      rawId: bytesToBase64url(credential.rawId),
      type: credential.type,
      clientExtensionResults: credential.getClientExtensionResults
        ? credential.getClientExtensionResults()
        : {},
    };
    if (kind === "registration") {
      base.response = {
        clientDataJSON: bytesToBase64url(response.clientDataJSON),
        attestationObject: bytesToBase64url(response.attestationObject),
        transports:
          typeof response.getTransports === "function" ? response.getTransports() : [],
      };
    } else {
      base.response = {
        clientDataJSON: bytesToBase64url(response.clientDataJSON),
        authenticatorData: bytesToBase64url(response.authenticatorData),
        signature: bytesToBase64url(response.signature),
        userHandle: response.userHandle ? bytesToBase64url(response.userHandle) : null,
      };
    }
    return base;
  }

  function submitCredential(actionUrl, form, credentialJson) {
    const submitForm = document.createElement("form");
    submitForm.method = "post";
    submitForm.action = actionUrl;
    submitForm.style.display = "none";
    for (const el of form.elements) {
      if (el.name === "csrf_token" || el.name === "next" || el.name === "name") {
        const hidden = document.createElement("input");
        hidden.type = "hidden";
        hidden.name = el.name;
        hidden.value = el.value;
        submitForm.appendChild(hidden);
      }
    }
    const credentialInput = document.createElement("input");
    credentialInput.type = "hidden";
    credentialInput.name = "credential";
    credentialInput.value = JSON.stringify(credentialJson);
    submitForm.appendChild(credentialInput);
    document.body.appendChild(submitForm);
    submitForm.submit();
  }

  function setStatus(el, message) {
    if (el) el.textContent = message;
  }

  async function registerPasskey(trigger) {
    const form = trigger.closest("form");
    const statusEl = form ? form.querySelector("[data-webauthn-status]") : null;
    if (!window.PublicKeyCredential) {
      setStatus(statusEl, "This browser doesn't support passkeys.");
      return;
    }
    setStatus(statusEl, "Follow your browser/device's prompt…");
    try {
      const optionsResponse = await fetch("/account/webauthn/register/options");
      if (!optionsResponse.ok) {
        setStatus(statusEl, "Couldn't start passkey registration — reload and try again.");
        return;
      }
      const options = decodeCreationOptions(await optionsResponse.json());
      const credential = await navigator.credentials.create({ publicKey: options });
      const credentialJson = credentialToJson(credential, "registration");
      submitCredential("/account/webauthn/register/verify", form, credentialJson);
    } catch (err) {
      setStatus(statusEl, "Passkey registration was cancelled or failed: " + err.message);
    }
  }

  async function signInWithPasskey(trigger) {
    const form = trigger.closest("form") || document.querySelector("form[data-webauthn-login]");
    const statusEl = document.querySelector("[data-webauthn-status]");
    if (!window.PublicKeyCredential) {
      setStatus(statusEl, "This browser doesn't support passkeys.");
      return;
    }
    setStatus(statusEl, "Follow your browser/device's prompt…");
    try {
      const optionsResponse = await fetch("/login/webauthn/options");
      if (!optionsResponse.ok) {
        setStatus(statusEl, "Couldn't start passkey sign-in — reload and try again.");
        return;
      }
      const options = decodeRequestOptions(await optionsResponse.json());
      const credential = await navigator.credentials.get({ publicKey: options });
      const credentialJson = credentialToJson(credential, "authentication");
      submitCredential("/login/webauthn/verify", form, credentialJson);
    } catch (err) {
      setStatus(statusEl, "Passkey sign-in was cancelled or failed: " + err.message);
    }
  }

  document.addEventListener("click", (event) => {
    const registerButton = event.target.closest("[data-webauthn-register]");
    if (registerButton) {
      event.preventDefault();
      registerPasskey(registerButton);
      return;
    }
    const loginButton = event.target.closest("[data-webauthn-login-button]");
    if (loginButton) {
      event.preventDefault();
      signInWithPasskey(loginButton);
    }
  });
})();
