Docker: packages inside images (SBOM) and moving or cloning a stack to another machine (0.133.0)

New features
- Packages inside images (SBOM): every image scan also keeps the
  image's package list from Trivy (--list-all-pkgs): system packages and
  language libraries with version, type and package URL, at most 10,000
  per image. Images scanned before 0.133.0 get theirs with their next
  scan.
  - An image's page shows how many packages of which type and offers
    "Download CycloneDX" (CycloneDX 1.6 JSON).
  - Security -> Package search also searches inside the machines'
    scanned Docker images ("In Docker images": machine, image, package,
    version, type; source filter "Docker images" for only those). Images
    are matched by the start of the package name (at least 2
    characters, case-insensitive, up to 500 rows) through an index, and
    scoped to the machines the account can see.
- Move or clone a stack to another machine: a stack's page ->
  "Move or clone to another machine" (action.terminal + action.updates).
  The stack is added to the target (compose file or Git source, .env,
  deploy key, settings; no webhook, no history) and a "Stack move /
  clone" job copies its data and then deploys it there.
  - Copied: the named volumes Compose created for the project (local
    driver, no options) and the files it bind-mounts from the stack's
    own directory; a Git stack's repo/ comes from the repository. Other
    host paths and volumes with driver options are listed, not copied.
  - The data streams through debcontrol (tar in a busybox container on
    each side, over the two SSH connections): no shared storage and no
    SSH key between the machines. Ownership and permissions are kept.
  - The source is stopped while its data is copied. Clone: started
    again afterwards. Move: its containers are taken down (docker
    compose down); its stack, volumes and files stay until deleted by
    hand. A failed copy always starts the source again.
  - Refused before anything changes when the target already has a
    volume of the same name, a stack of the same name, or the stack's
    directory there holds other files; debcontrol's own stack is never
    moved. The job can be cancelled while it copies; a copy interrupted
    by a debcontrol restart is not repeated on its own.

REST API
- GET /api/v1/machines/{id}/docker/images/{image_id}/sbom: CycloneDX 1.6
  JSON (404 before the first scan).
- GET /api/v1/machines/{id}/docker/images/{image_id} adds "packages"
  (count per type).
- GET /api/v1/machines/package-search adds "images" and
  "images_truncated"; pkg_source=docker returns only image packages.
- POST /api/v1/machines/{id}/docker/stacks/{stack_id}/transfer
  {target_machine_id, mode: copy|move, data} -> 202 with the job (on the
  target), stack_id and machine_id; 404 for a target the token can't
  use, 409 for a name the target already has or a busy stack.

Audit log
- machine.docker.stack.transfer (started, or refused for debcontrol's
  own stack), recorded on the source machine.

Upgrade notes
- Migration 5c9e3a7b2d4f: new table docker_image_packages (empty; filled
  by scans from now on). Nothing else changes until you use the new
  features.

