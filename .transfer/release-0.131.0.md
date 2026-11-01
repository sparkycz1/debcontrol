## Changes

### Docker: private registries, shared variables, taking over what already runs, drift (0.131.0) (#141)

Private registries (Docker -> Registries)
- Logins to private registries (GHCR, GitLab, Harbor, your own) for all
  machines, one machine group or one machine; for a machine the most
  specific login per server applies.
- Saving one logs every machine in scope in (one background task per
  machine) with docker login --password-stdin: the password goes over SSH
  standard input only and is stored encrypted, never shown again.
- Each machine's image update check logs in first where a login is
  missing, failed or older than the last change, so a machine added to a
  group later picks its logins up; servers no entry applies to any more
  are logged out.
- The page shows per registry which machines are logged in and which
  failed (with docker's message), "Log in again", edit and remove.

Shared variables and secrets (Docker -> Variables)
- Variables such as TZ or SMTP_PASSWORD defined once for all machines, a
  group or a machine (the most specific wins). Values are stored
  encrypted; a secret one is never shown again.
- A stack picks variables by name ("Shared variables" on the stack form).
  On deploy and check the values for its machine are appended to the .env
  debcontrol writes; the stack's own .env wins. A picked name defined
  nowhere for the machine is shown on the stack page.
- Changing a value marks the stacks using it as changed since deploy.

Taking over what already runs
- "Adopt" on a Compose project found on the machine: its compose file(s)
  and .env become a stack written in debcontrol with the same name and
  directory. Nothing restarts; only the .debcontrol-stack mark is written.
  Several compose files are merged with docker compose config
  --no-interpolate (no secrets from the environment end up in the file).
- "Make a stack from it" on a docker run container: the new-stack form is
  filled in from docker inspect (ports, volumes as external, networks,
  limits, labels, health check ...; environment into the encrypted .env;
  $ escaped). The first deploy stops the container, sets it aside as
  <name>-pre-debcontrol and removes it once the stack runs; if the stack
  doesn't come up, the old container is started again.

Drift
- "Check drift" on a stack compares the machine with what debcontrol
  deployed: compose.yaml and .env hashes, the checked-out Git commit, and
  each container's Compose config hash (containers recreated by hand,
  missing or extra).
- Optional hourly check per stack ("Check for drift every hour", off by
  default); turning to drift sends the new notification event
  docker.stack.drift (templates in English and Czech).
- The stack page and the stacks list show drift; "Take the machine's
  files over" stores the files changed on the machine into a stack
  written in debcontrol (shared variables stay shared).

Permissions and audit
- Registries, variables, adopt, container to stack and taking files over
  need action.terminal; Check drift needs action.updates. An account
  limited to some machine groups manages only its groups' and machines'
  registries and variables and sees the fleet-wide ones read-only; it sees
  registry login results and "used by" counts for its own machines only.
- A secret variable stays secret until it gets a new value; changing a
  registry's server needs its password again (a password is never sent to
  another server than it was given for).
- New audit codes: docker.registry.create/edit/login/delete,
  docker.variable.create/edit/delete, machine.docker.project.adopt,
  machine.docker.stack.import.

REST API
- GET|POST /api/v1/docker/registries, GET|PUT|DELETE
  /api/v1/docker/registries/{id}, POST /api/v1/docker/registries/{id}/login.
- GET|POST /api/v1/docker/variables, GET|PUT|DELETE
  /api/v1/docker/variables/{id}.
- POST /api/v1/machines/{id}/docker/projects/{project}/adopt,
  GET .../docker/containers/{name}/compose,
  POST .../docker/stacks/{stack_id}/drift,
  POST .../docker/stacks/{stack_id}/import.
- Stacks take shared_variables, drift_check and (on create)
  replace_container; reads add shared_variables_missing, drift_status,
  drift_details, drift_summary and drift_checked_at.

Upgrade notes
- Migration 380462813240: three new tables (docker_registries,
  docker_registry_logins, docker_variables) and nullable/defaulted columns
  on docker_stacks. Existing stacks are unchanged (no shared variables,
  drift check off, same content hash).
- New Beat entry check-stack-drift (hourly, only stacks with the check on).

**Full diff:** https://github.com/sparkycz1/debcontrol/compare/v0.130.0...v0.131.0
