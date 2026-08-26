"""Sdílená instance Jinja2 šablon (odděleno od `app.main`, aby ji šlo importovat
z routerů bez cyklické závislosti)."""

from __future__ import annotations

from pathlib import Path

from fastapi.templating import Jinja2Templates

TEMPLATES_DIR = Path(__file__).resolve().parent / "templates"

templates = Jinja2Templates(directory=str(TEMPLATES_DIR))
templates.env.autoescape = True
