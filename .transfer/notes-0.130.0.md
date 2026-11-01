## Changes

### Docker across the fleet, image actions and container limits (0.130.0) (#140)

Docker -> Containers (new page in the header)
- /docker/containers lists every container of every machine the account
  can see, from each machine's last monitoring sample (no SSH, opens at
  once). The header shows "Docker" once some machine reported Docker;
  /docker redirects here. Its second tab links to Security -> Container
  vulnerabilities.
- Columns: machine (with its group), container (stack, auto-update
  badge), ports / links, image (newer image badge), vulnerability counts,
  status. Sortable by machine, name, image, state, vulnerabilities and
  newer image; a machine repeated in a row is muted.
- Filters (a GET form, so views can be bookmarked): text, machine group,
  critical / critical-or-high vulnerabilities, newer image available,
  state tiles, and a click on a stack name. 100 rows per page; the list
  stops at 20,000 containers and says so.
- Tick containers on any machines and Start / Restart / Stop
  (action.power), Update selected or Scan images (action.updates). Runs
  machine by machine through the same code as a machine's own bulk
  buttons: same checks, debcontrol's own containers left out, one audit
  entry per container. Remove stays on the machine's page.

One image (Docker tab -> Images)
- A click on an image opens its page: tags, digests, created, size,
  platform, entrypoint, command, user, working directory, exposed ports,
  the containers using it, labels and its layers (docker history, oldest
  first, with sizes). Environment variables are never read (secrets).
- Pull any image reference from the Images page, or "Pull <tag> again"
  on an image's page. A pull is a new cancellable job kind "Pull image"
  whose result has the pulled image id; the container list and image
  checks refresh afterwards.
- Tag an image under a new name (docker tag).
- Remove a tag or an image (docker image rm, never forced: Docker
  refuses an image a container uses and its answer is shown). The list
  offers Remove only for images no container uses.
- All need action.updates. New audit codes machine.docker.image.pull,
  machine.docker.image.tag, machine.docker.image.remove (a failed tag or
  remove is recorded as a failure).

Container limits (Docker tab -> a container -> Resources)
- Shows the memory limit and CPU limit with what the container used at
  the last sample. "Change limits" (action.updates) changes memory
  (512m, 2g; at least 6 MiB; memory+swap set to twice the memory), CPUs
  (0 removes the limit) and the restart policy (with retries for
  on-failure) on the running container with docker update, no restart.
  Empty fields keep their value. A Compose service gets its compose
  values back on the next recreate (the page says so). debcontrol's own
  containers are refused. New audit code machine.container.resources.

Docker tab polish
- The containers table is no longer cut off at a fixed height.
- The bulk buttons under the containers table show only once something
  is ticked, with the count; Remove sits apart at the end.
- Panels that ask the machine show a small spinner while loading (none
  with reduced motion).
- State tiles show which one is active.

REST API
- GET /api/v1/docker/containers (the page's filters, rows carry a key
  "<machine id>/<container>") and POST /api/v1/docker/containers/bulk
  {action: start|stop|restart|update|scan, containers: [key, ...]}.
- GET /api/v1/machines/{id}/docker/images/{image_id} (details, layers,
  scan counts); POST .../docker/images/pull {ref} (202, a job);
  POST .../docker/images/tag {image, tag}; POST .../docker/images/remove
  {image}.
- POST /api/v1/machines/{id}/docker/containers/{name}/resources
  {memory, cpus, restart_policy, max_retries}.

Dependencies
- anyio 4.16.0, openai 3.42.0, openrouter 1.3.106, python-dateutil 4.0.0,
  python-multipart 0.0.33, types-pyyaml 6.0.12.20261030, websockets 17.4
  (six is no longer needed).
- Vendored Swagger UI 5.34.1 (bundle checked against the npm integrity
  hash). Docker base images, PostgreSQL, TimescaleDB, Redis, Caddy, uv,
  htmx and xterm.js were already current.

Upgrade notes
- No migration. The new job kind is stored in the existing column.
- New Celery tasks app.tasks.docker_jobs.docker_image_op and
  app.tasks.docker_jobs.docker_container_resources: the worker container
  is rebuilt by the usual upgrade.

**Full diff:** https://github.com/sparkycz1/debcontrol/compare/v0.129.1...v0.130.0
