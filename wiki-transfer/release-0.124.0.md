Git stacks
- SSH repositories (git@host:owner/repo.git, ssh://git@host[:port]/...)
  with a deploy key: "Generate a new key" makes an Ed25519 key and shows
  its public half on the stack page, or paste a private key (OpenSSH or
  PEM, no passphrase; Ed25519, ECDSA, RSA >= 2048). Stored encrypted,
  never shown again; it reaches git only in a mode-700 temporary
  directory.
- The repository host's key is pinned: paste known_hosts lines, or the
  key seen on the first connection is recorded and required from then
  on. Moving the stack to another server forgets it.
- More compose files (overrides): up to 5 extra paths, applied in order
  like `docker compose -f a -f b`.
- Services with a `build:` section are built from the repository on
  every deploy (`up --build`), so a stack can live in a subdirectory of
  a monorepo.

Deploy safety (per stack, all off by default)
- Check changes / Save and check: shows what a deploy would change (the
  compose diff and the .env variables changed, by name only; for Git the
  new commits and compose diff since the deployed commit) and runs
  `docker compose config` on the new files. Changes nothing; its output
  is shown only to action.terminal.
- Keep a history of deployed versions (the last 20): a History panel on
  the stack page with Show (compose file and diff) and Roll back, which
  restores that version's settings and deploys it. Rolling a Git stack
  back deploys that commit and turns auto-sync off.
- Roll back automatically: after `up`, wait up to 3 minutes for every
  container to run and be healthy; otherwise deploy the previous version
  again. Needs a previous deploy made with 0.124.0 or later.
- Vulnerability gate for new images (off / critical / high / worse):
  pull, scan the images that would newly run with Trivy and Grype, and
  only then `up`. A blocked deploy starts nothing, points the tags back
  at the running images, puts the previous files back and ends "blocked"
  (notified as docker.stack.failed).
- Auto-sync no longer redeploys, every few minutes, a commit whose last
  deploy failed, was rolled back or blocked.

REST API
- Stack fields: git_compose_overrides, git_ssh_key ("generate" / key /
  "" / omitted), git_ssh_public_key (read), git_known_hosts,
  keep_history, auto_rollback, vulnerability_gate.
- POST /api/v1/machines/{id}/docker/stacks/{stack_id}/check
- GET  .../stacks/{stack_id}/versions
- GET  .../stacks/{stack_id}/versions/{version_id}
- POST .../stacks/{stack_id}/versions/{version_id}/rollback
- A stack check job's output is returned only to action.terminal.

Audit and permissions
- New audit codes machine.docker.stack.check and
  machine.docker.stack.rollback. Check and viewing a version need
  action.terminal; rolling back needs action.terminal and
  action.updates.

Fixes
- The container update job page showed no vulnerability counts for a
  gate verdict (wrong field names).

Upgrade notes
- Migration b7d9e1f3a5c6: new nullable/defaulted columns on
  docker_stacks and a new docker_stack_versions table. Existing stacks
  keep working unchanged (every new switch is off, their content hash is
  unchanged).

