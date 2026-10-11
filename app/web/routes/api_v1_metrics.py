"""`GET /api/v1/metrics` — the fleet's current state for Prometheus (see
`app.services.prometheus_metrics`).

Authenticated like the rest of the REST API, with a bearer API token whose
account has `machine.view`; a read-only token is enough and is what a
scraper should carry. In Prometheus:

    scrape_configs:
      - job_name: debcontrol
        metrics_path: /api/v1/metrics
        scheme: https
        authorization:
          credentials: <API token>
        static_configs:
          - targets: ["debcontrol.example.com"]

The machines are the ones the token's account can see. Endpoint checks
belong to the whole instance, so an account limited to some machine groups
gets none of them — the same rule the Dashboard's fleet-wide trends follow.
"""

from __future__ import annotations

from fastapi import APIRouter, Depends, Response
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from app.auth.dependencies import get_api_token_user, require_api_permission
from app.db.models.endpoint_check import EndpointCheck
from app.db.models.machine import Machine
from app.db.models.role import Permission
from app.db.models.user import User
from app.db.session import get_db
from app.services import prometheus_metrics
from app.services.access_scope import is_restricted, machines_visible_to
from app.services.fleet_overview import build_fleet_overview

router = APIRouter(prefix="/api/v1")


@router.get(
    "/metrics",
    dependencies=[Depends(require_api_permission(Permission.MACHINE_VIEW))],
    response_class=Response,
    responses={200: {"content": {"text/plain": {}}}},
)
async def metrics_api(
    db: AsyncSession = Depends(get_db), user: User = Depends(get_api_token_user)
) -> Response:
    """Prometheus text format: per machine reachability, pending updates,
    reboot needed, failed units and the newest CPU/RAM/disk/load/temperature
    reading; per endpoint check its last result, latency and certificate
    expiry. Nothing is measured at scrape time."""
    machines = list(
        (
            await db.execute(
                (await machines_visible_to(db, user))
                .where(Machine.is_active)
                .options(selectinload(Machine.group))
                .order_by(Machine.name)
            )
        )
        .scalars()
        .all()
    )
    rows = await build_fleet_overview(db, machines)
    checks: list[EndpointCheck] = []
    if not await is_restricted(db, user):
        checks = list(
            (await db.execute(select(EndpointCheck).order_by(EndpointCheck.name))).scalars().all()
        )
    return Response(
        content=prometheus_metrics.render(machines, rows, checks),
        media_type=prometheus_metrics.CONTENT_TYPE,
    )
