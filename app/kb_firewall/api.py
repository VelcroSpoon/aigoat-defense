"""Admin endpoints for the KB Firewall: status, on/off switch, events, quarantine."""
from __future__ import annotations

import asyncio
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.database import get_db
from app.core.dependencies import get_current_admin
from app.kb_firewall.firewall import QUARANTINE_TIER, get_kb_firewall
from app.models import KnowledgeBaseEntry, User
from app.rag.service import get_rag_service

router = APIRouter(prefix="/api/kb-firewall", tags=["kb-firewall"])


class ToggleIn(BaseModel):
    enabled: bool
    mode: str | None = None


class ScanIn(BaseModel):
    text: str


@router.get("/status")
async def status(admin: Annotated[User, Depends(get_current_admin)]) -> dict:
    return get_kb_firewall().status()


@router.post("/toggle")
async def toggle(body: ToggleIn, admin: Annotated[User, Depends(get_current_admin)]) -> dict:
    fw = get_kb_firewall()
    if body.mode is not None:
        if body.mode not in ("block", "monitor"):
            raise HTTPException(status_code=422, detail="mode must be 'block' or 'monitor'")
        fw.mode = body.mode
    fw.enabled = body.enabled
    if fw.enabled:
        # Load the embedding model now, so the first customer question is not the slow one.
        await asyncio.to_thread(fw.scan, "warm-up")
    return fw.status()


@router.get("/events")
async def events(
    admin: Annotated[User, Depends(get_current_admin)],
    limit: int = Query(50, ge=1, le=200),
) -> dict:
    return {"events": list(get_kb_firewall().events)[:limit]}


@router.delete("/events")
async def clear_events(admin: Annotated[User, Depends(get_current_admin)]) -> dict:
    get_kb_firewall().events.clear()
    return {"cleared": True}


# Admin only: an open scan endpoint would let attackers tune payloads until they pass.
@router.post("/scan")
async def scan(body: ScanIn, admin: Annotated[User, Depends(get_current_admin)]) -> dict:
    verdict = await asyncio.to_thread(get_kb_firewall().scan, body.text)
    return verdict.to_dict()


@router.get("/quarantine")
async def quarantine(
    admin: Annotated[User, Depends(get_current_admin)],
    db: Annotated[AsyncSession, Depends(get_db)],
) -> dict:
    result = await db.execute(
        select(KnowledgeBaseEntry).where(KnowledgeBaseEntry.trust_tier == QUARANTINE_TIER)
    )
    fw = get_kb_firewall()
    entries = []
    for e in result.scalars().all():
        verdict = await asyncio.to_thread(fw.scan, f"{e.title or ''}\n{e.content or ''}")
        entries.append({
            "id": e.id,
            "title": e.title,
            "content": e.content,
            "owner_id": e.owner_id,
            "risk": round(verdict.risk, 3),
            "reasons": verdict.reasons,
        })
    return {"entries": entries}


@router.post("/quarantine/{entry_id:int}/release")
async def release(
    entry_id: int,
    admin: Annotated[User, Depends(get_current_admin)],
    db: Annotated[AsyncSession, Depends(get_db)],
) -> dict:
    """A reviewer decided the entry is a false positive: publish it as user content."""
    entry = (
        await db.execute(select(KnowledgeBaseEntry).where(KnowledgeBaseEntry.id == entry_id))
    ).scalar_one_or_none()
    if entry is None or entry.trust_tier != QUARANTINE_TIER:
        raise HTTPException(status_code=404, detail="No quarantined entry with that id")
    entry.trust_tier = "user"
    # The index only re-embeds entries whose hash changed; clear it so the new tier is stored.
    entry.content_hash = None
    await db.commit()
    entries = list((await db.execute(select(KnowledgeBaseEntry))).scalars().all())
    await get_rag_service()._retrieval.sync_async(entries)
    await db.commit()
    return {"released": True, "id": entry_id}
