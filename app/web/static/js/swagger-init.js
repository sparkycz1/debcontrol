// Boots Swagger UI against this app's own OpenAPI schema. Kept as its own
// file (not inlined in api_docs.html) because this app's CSP forbids
// inline scripts — see app/web/routes/api_docs.py.
window.addEventListener("DOMContentLoaded", function () {
  var mount = document.getElementById("swagger-ui");
  window.ui = SwaggerUIBundle({
    url: mount.dataset.openapiUrl,
    dom_id: "#swagger-ui",
    // SwaggerUIStandalonePreset comes from the separate
    // swagger-ui-standalone-preset.js bundle (its own global, not a
    // property of SwaggerUIBundle, despite what some older examples show).
    presets: [SwaggerUIBundle.presets.apis, SwaggerUIStandalonePreset],
    layout: "StandaloneLayout",
    // No third-party spec validator call (validator.swagger.io) — this is
    // an internal admin tool's API shape, not something to hand to an
    // outside service, and it would be silently blocked by connect-src
    // 'self' anyway.
    validatorUrl: null,
    docExpansion: "list",
    persistAuthorization: true,
  });
});
