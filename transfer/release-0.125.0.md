## Changes

### Docker upgrade #3: update policy, container events, CVEs across the fleet (0.125.0) (#131)

Image update checks
- How often the Docker tab checks images for newer versions is a setting
  now: Settings -> Background checks -> "Docker image check" (1-168 hours,
  default 24). The sweep runs hourly and checks only the machines that are
  due; "Check now" on the Docker tab is unchanged.
- Each image that could not be checked says why: pinned by digest, local
  image, Docker Hub rate limit, registry login needed, not found, no
  buildx, network, other error. Digest-pinned and local images no longer
  send a registry request at all.
- The Docker tab shows when the last check hit the Docker Hub rate limit
  or failed, and how many Docker Hub requests it made.

Container events in notification rules
- Four new notification-rule events: a container crashed (exited with an
  error code), is in a restart loop (3+ crashes since the last sample),
  was killed for running out of memory, or became unhealthy. They come
  from `docker events` collected with each monitoring sample, so they
  need no new agent or socket access. Templates in English and Czech.

Update policy (semver)
- Each container has an update policy: any newer image (default), only a
  newer minor version, or only a newer patch version. It applies to
  scheduled updates of containers set to update automatically; an update
  started by hand is not limited.
- Every container: after the pull, the image's declared version
  (org.opencontainers.image.version) must stay within the policy, or the
  update is skipped and the old image keeps its tag.
- Containers not created by Compose and running a version tag
  (nginx:1.27.3) move to the newest allowed tag (1.27.4 / 1.29.0) and are
  recreated on it; rollback returns to the previous tag. Compose
  containers keep their tag and the Docker tab shows the newer allowed
  tag as a hint.

Container vulnerabilities across the fleet
- New Security -> Containers tab: every critical and high vulnerability
  found in the visible machines' Docker images, with how many machines
  and images carry it, and a page per vulnerability listing them.
- A vulnerability can be accepted (for every image or one image
  repository) with a reason and an expiry (1-365 days, default 90). An
  accepted vulnerability no longer counts in the image's and machine's
  counts nor stops an update at the vulnerability gate; it counts again
  when the acceptance expires (checked hourly) or is revoked. Needs
  `action.updates` and an account not limited to some groups. New audit
  codes `docker.vulnerability.accept` and `docker.vulnerability.revoke`.
- The per-machine Vulnerabilities page marks accepted findings, shows the
  count before acceptances and links to the fleet view.

REST API
- `GET /api/v1/docker/vulnerabilities`, `GET /api/v1/docker/vulnerabilities/{id}`.
- `GET|POST /api/v1/docker/vulnerability-acceptances`,
  `DELETE /api/v1/docker/vulnerability-acceptances/{id}`.
- Container settings take and return `update_policy`; the containers
  listing adds `update_policy`, `image_check_reason` and `image_check`;
  machine hardware adds `docker_image_check`; check-images returns `check`.
- Background checks settings take `docker_image_check_interval_hours`.

Upgrade notes
- Migration c8e0f2a4b6d7: new columns (all with defaults or nullable) and
  two new tables; existing scan results are copied into the new findings
  table during the migration.
- The image-check Beat task keeps its name but runs hourly (each machine
  still only checked once per interval).
- Container events start with the second monitoring sample after the
  upgrade (the first one only records where to start).


**Full diff:** https://github.com/sparkycz1/debcontrol/compare/v0.124.0...v0.125.0
