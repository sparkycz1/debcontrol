## Changes

### Docker upgrade #4: cancel jobs, backup hooks and test restores, better logs, a safer file editor (0.126.0) (#132)

Cancelling Docker jobs
- A job page has a "Cancel job" button. A waiting job is cancelled at
  once and the machine's next waiting job starts. A running job is
  stopped when that is safe: image scans, prune, stack checks, every
  backup job (run, check, prune, restore, test restore) and a container
  update while it is still pulling. Deploys, stack actions and the
  recreate step of an update are never interrupted.
- Stopping sends SIGTERM to the job's own process group on the machine
  (jobs now run under setsid); every job script turns that into a normal
  exit, so its cleanup still runs (stopped containers are started again,
  temporary volumes removed). A job that hasn't reached its next step
  when asked doesn't start it.
- New job status "cancelled" (with who cancelled it). Cancelling needs
  the permission that starts that kind of job (stack actions:
  action.power; stack deploy/check and backup restore: action.terminal;
  the rest: action.updates). New audit code machine.docker.job.cancel.
- Live job output was already there (the page follows the job every few
  seconds); it is unchanged.

Consistent backups
- A backup can run a command in one container before it (for example a
  database dump; if it fails nothing is backed up) and one after it,
  once the containers run again, whether the backup worked or not. Both
  run with docker exec; a failing "after" command is shown on the job.
- "Test restore": restores the newest snapshot into a temporary volume
  with restic --verify (every restored file read back and compared),
  then removes the volume. The result (files and bytes restored) is
  shown on the backup; a failed test restore sends the "Docker backup
  failed" notification. Also available as the scheduled action
  "Docker backup: test restore".

Logs tab
- Level filter for log files and Docker logs: errors, or warnings and
  errors (a fixed word list, also when following live).
- Merged logs of a whole Compose stack: pick the stack under
  "Stacks" in the container list; each line is prefixed with its
  container and lines are sorted by time. The Docker -> Stacks list
  links each project to its logs.
- "Download" saves the current view (same filters, up to the last 20000
  lines) as a .log file; audited like viewing logs.
- Saved log views remember the level.

File editor (containers and volumes)
- "Show changes" compares the edited text with the file as it is on the
  machine now, before anything is saved.
- Saving refuses to overwrite a file that changed on the machine since
  it was opened: the editor comes back with your text kept and the
  differences shown; saving again overwrites.
- Upload several files at once, or a whole folder with its subfolders
  (up to 1000 files, 25 MB in all). Several files are written owned by
  root (644, folders 755); a single file replacing an existing one still
  keeps its owner and mode.
- Download a folder as .tar.gz (owners and modes kept, up to 50 MB before
  compression).

REST API
- POST /api/v1/machines/{id}/docker/jobs/{job_id}/cancel (409 when the
  job can't be cancelled); jobs include cancel_requested_by,
  cancel_requested_at and cancellable.
- POST .../docker/backups/{id}/verify (test restore); backups take
  hook_container, pre_command, post_command and return hook_container,
  hooks_set and last_verify_at/status/details. The commands themselves
  are returned only to action.terminal (they may carry a password), like
  the web page and the export.
- GET /api/v1/machines/{id}/logs takes level, and lines up to 20000.
- GET .../files/content returns sha256; PUT .../files/content takes
  expect_sha256 (409 when the file changed meanwhile).
- POST .../docker/{containers|volumes}/{name}/files/upload (several
  files with relative paths) and GET .../files/archive (folder as
  .tar.gz).

Upgrade notes
- Migration d9f1a3b5c7e9 adds nullable columns only (docker_jobs:
  cancel_requested_by/at; docker_backups: hook_container, pre_command,
  post_command, last_verify_at/status/details).
- Jobs started before this version can still be cancelled; the signal
  then goes to the job's main process.

**Full diff:** https://github.com/sparkycz1/debcontrol/compare/v0.125.0...v0.126.0
