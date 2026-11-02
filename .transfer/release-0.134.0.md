## Changes

### Docker: fleet-wide Docker settings, a row actions menu, pause/resume and updating everything at once (0.134.0) (#145)

New features
- Docker -> Settings (/docker/settings, settings.view): the daemon.json
  keys that should be the same on every machine, or only on the ticked
  machine groups. A field left on "Keep as it is" is not managed;
  debcontrol changes only the keys set there and keeps the rest of
  /etc/docker/daemon.json as it is.
  - Log driver (json-file, local, journald) with max-size / max-file
    rotation, live restore, no-new-privileges, build cache kept
    (builder.gc), default address pools for new networks (private IPv4
    only), DNS servers for containers (up to 4), Docker Hub mirrors
    (up to 5, no credentials in the URL).
  - Save only stores the settings (settings.manage; not for an account
    limited to some machine groups). "Where the machines stand" shows
    for each machine in scope whether it matches (from its last host
    check), what differs and whether a restart is waiting.
  - "Write to machines" (settings.manage + action.terminal) queues a
    "Write daemon.json" job per machine: the current file is read (an
    unreadable or invalid one is never written over), the managed keys
    merged in, the new file checked with dockerd --validate (Docker
    23+), the old one kept as daemon.json.debcontrol.bak, the new one
    installed as root through sudo -n. The file goes over stdin, never
    into a command line. Docker is not restarted.
  - "Restart Docker where waiting" (action.power) queues a "Docker
    restart" job per machine: systemctl (or service) restart, then up to
    90 s waiting for docker info; if Docker doesn't come back, the
    backup is put back and Docker restarted again. Without root nothing
    is restarted and the job says so. Never on the machine debcontrol
    runs on (restart Docker there by hand).
  - Defaults for new containers: automatic updates (off / patch /
    minor / any), vulnerability gate, and autoheal for containers with a
    health check. A container gets them the first time a monitoring
    sample sees it (never one that existed before, never debcontrol's
    own); its own settings always win. A new stack starts with the
    default gate.
- Docker -> Host: a "Docker -> Settings on this machine" panel with the
  differences (on the machine / wanted), a waiting restart, and "Write
  daemon.json" (action.terminal) / "Restart Docker" (action.power) for
  this machine alone.
- Every container row has an actions menu (the "..." button) in the
  fleet table and on a machine's Containers page: start, stop, restart,
  pause, resume, update, remove - whatever fits the container's state -
  plus links to its page, logs and shell. It replaces the buttons under
  each container's name.
- Pause and resume a container (action.power): in the row menu, on the
  container's page, and for the selected containers under "More".
  debcontrol's own containers can't be paused.
- Docker -> Containers (fleet): remove the selected stopped containers
  (action.updates), pause / resume and autoheal on / off for the
  selected (action.power), and "Update all with a newer image (N)"
  (action.updates) for every visible container with a newer image,
  machine by machine. The same "More" actions on a machine's own
  Containers page.
- A CPU and memory column (last monitoring sample) in the fleet table
  and on a machine's Containers page; hidden on half a screen.

Changed
- A container's page puts Update, Automatic updates and Autoheal side
  by side, with the long explanations folded under "More about this".
- The paused state shows as a warning badge.

REST API
- GET|PUT /api/v1/docker/settings, GET /api/v1/docker/settings/machines,
  POST /api/v1/docker/settings/apply and /restart.
- POST /api/v1/machines/{id}/docker/daemon/apply and /restart (409 when
  not in scope, already queued, or on debcontrol's own machine).
- GET /api/v1/machines/{id}/docker/host also answers daemon_settings.
- POST /api/v1/docker/containers/update-all answers {ok, queued, errors}.
- Bulk actions (fleet and per machine) also take pause, unpause,
  autoheal_on, autoheal_off; the fleet one also remove.
- POST /api/v1/machines/{id}/containers/{name}/pause|unpause.

Audit log
- docker.settings.update, docker.settings.apply,
  machine.docker.daemon.apply, machine.docker.daemon.restart,
  machine.container.pause, machine.container.unpause.

Upgrade notes
- Migration 6d1f4b8c2e5a adds nullable columns (app_settings:
  docker_daemon_config, docker_daemon_group_ids,
  docker_default_update_policy, docker_default_vulnerability_gate;
  machines.docker_daemon_state) and docker_default_autoheal (default
  false). Nothing changes on a machine until "Write to machines" is
  pressed; no defaults apply until they are set.


**Full diff:** https://github.com/sparkycz1/debcontrol/compare/v0.133.0...v0.134.0
