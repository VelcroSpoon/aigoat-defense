from __future__ import annotations

import asyncio
import json
import logging
import re
from collections.abc import AsyncIterator
from typing import Annotated

from fastapi import APIRouter, Depends, Query, Request
from fastapi.responses import StreamingResponse
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.database import get_db
from app.core.dependencies import get_current_user
from app.defense.nemo_guardrails import get_guardrails_service
from app.defense.pipeline import defense_pipeline
from app.models import User
from app.schemas.chat import (
    ChatRequest,
    ChatResponse,
    DefenseLevelOut,
    SetDefenseLevelRequest,
)
from app.services.ollama_client import get_ollama_client
from app.surfaces import ensure_registered
from app.surfaces.base import SurfaceRequest
from app.surfaces.chat_cracky import output_context, prepare_chat
from app.surfaces.registry import get_surface

logger = logging.getLogger(__name__)

router = APIRouter(prefix="", tags=["chat"])

DEFENSE_LEVELS = {
    0: {
        "level": 0,
        "name": "Vulnerable",
        "color": "#ef4444",
        "description": "No protection - all attacks succeed",
    },
    1: {
        "level": 1,
        "name": "Hardened",
        "color": "#fbbf24",
        "description": "Basic prompt hardening active",
    },
    2: {
        "level": 2,
        "name": "Guardrailed",
        "color": "#4ade80",
        "description": "Input/output guardrails active",
    },
}


def _get_defense_level(user: User) -> int:
    return user.defense_level


def _client_left(task: asyncio.Task) -> bool:
    return task.done() and not task.cancelled() and task.exception() is None


async def _stream_model_tokens(
    client,
    request: Request,
    prompt: str,
    options: dict | None,
    gone: dict | None = None,
) -> AsyncIterator[str]:
    """Yield model tokens, and close the model stream when the browser disconnects.

    Ollama serves one generation at a time. Leaving the upstream stream open
    queues the next turn until the abandoned reply finishes.
    """
    queue: asyncio.Queue[str | None] = asyncio.Queue()
    client_gone = False
    stop = asyncio.Event()
    if gone is None:
        gone = {}

    async def pump() -> None:
        try:
            async for token in client.generate_stream(
                prompt=prompt,
                system="",
                options=options,
                stop=stop,
            ):
                await queue.put(token)
        except asyncio.CancelledError:
            raise
        except Exception as e:
            logger.error("Stream generation error: %s", e)
        finally:
            queue.put_nowait(None)

    async def watch_disconnect() -> None:
        # StreamingResponse does not listen for disconnect on ASGI 2.4.
        # Starlette's is_disconnected() poll cancels the read immediately and
        # can miss the message, so block on the ASGI receive channel instead.
        receive = getattr(request, "_receive", None)
        if receive is None:
            while not await request.is_disconnected():
                await asyncio.sleep(0.05)
            return
        while True:
            message = await receive()
            if message.get("type") == "http.disconnect":
                return

    pump_task = asyncio.create_task(pump())
    watch_task: asyncio.Task | None = asyncio.create_task(watch_disconnect())
    try:
        while True:
            get_task = asyncio.create_task(queue.get())
            waiting = {get_task}
            if watch_task is not None:
                waiting.add(watch_task)
            done, _pending = await asyncio.wait(
                waiting,
                return_when=asyncio.FIRST_COMPLETED,
            )
            if watch_task is not None and watch_task in done and get_task not in done:
                if _client_left(watch_task):
                    client_gone = True
                    get_task.cancel()
                    await asyncio.gather(get_task, return_exceptions=True)
                    break
                logger.error("Disconnect watch failed: %s", watch_task.exception())
                watch_task = None
                token = await get_task
            else:
                token = get_task.result()
            if token is None:
                break
            if watch_task is not None and _client_left(watch_task):
                client_gone = True
                break
            yield token
    finally:
        if not pump_task.done():
            # Starlette may cancel this generator on disconnect without our
            # watcher seeing the message. Closing the socket is what frees
            # Ollama; cancelling the read task does not.
            stop.set()
            pump_task.cancel()
        pending = [pump_task]
        if watch_task is not None:
            if not watch_task.done():
                watch_task.cancel()
            pending.append(watch_task)
        try:
            await asyncio.shield(asyncio.gather(*pending, return_exceptions=True))
        except asyncio.CancelledError:
            raise

    if client_gone:
        gone["client"] = True
        return


async def _prepare_chat(
    body: ChatRequest,
    user: User,
    db: AsyncSession,
) -> dict | ChatResponse:
    """Shared pre-processing for streaming chat and T006 level-precedence tests.

    Non-streaming ``POST /api/chat/`` goes through ``chat.cracky`` execute so
    the reply matches ``POST /api/surfaces/chat.cracky/execute``.
    """
    prepared = await prepare_chat(body, user, db)
    if prepared.blocked is not None:
        return prepared.blocked
    assert prepared.payload is not None
    return prepared.payload


@router.post("/api/chat/", response_model=ChatResponse)
async def chat(
    body: ChatRequest,
    user: Annotated[User, Depends(get_current_user)],
    db: Annotated[AsyncSession, Depends(get_db)],
) -> ChatResponse:
    """Send a message to the AI shopping assistant and receive a complete response.

    The message passes through the defense pipeline based on the user's current defense level.
    Optionally include a lab_id to activate a lab-specific system prompt.
    """
    ensure_registered()
    result = await get_surface("chat.cracky").execute(
        SurfaceRequest(
            user=user,
            db=db,
            lab_id=body.lab_id,
            input={
                "message": body.message,
                "use_kb": body.use_kb,
                "defense_level": body.defense_level,
            },
        )
    )
    return ChatResponse(
        reply=result.result["reply"],
        kb_used=result.result["kb_used"],
        kb_context_count=result.result["kb_context_count"],
        citations=result.result.get("citations") or [],
    )


@router.post("/api/chat/stream")
async def chat_stream(
    body: ChatRequest,
    request: Request,
    user: Annotated[User, Depends(get_current_user)],
    db: Annotated[AsyncSession, Depends(get_db)],
) -> StreamingResponse:
    """SSE streaming endpoint. Each event is a JSON chunk with a `token` field."""
    prepared = await _prepare_chat(body, user, db)

    if isinstance(prepared, ChatResponse):
        async def blocked_gen():
            data = json.dumps({"token": prepared.reply, "done": True})
            yield f"data: {data}\n\n"
        return StreamingResponse(blocked_gen(), media_type="text/event-stream")

    client = get_ollama_client()
    level = prepared["level"]

    async def token_gen():
        collected: list[str] = []
        gone: dict = {}
        # At Level 1 and 2 the reply is released a sentence at a time, and only
        # after the output controls have checked everything up to it, so a
        # refund claim or a leaked secret never reaches the screen. Level 0
        # streams raw tokens.
        shown = ""
        checked = 0
        stream = _stream_model_tokens(
            client,
            request,
            prepared["prompt"],
            prepared["options"],
            gone,
        )
        try:
            async for token in stream:
                collected.append(token)
                if level == 0:
                    yield _sse({"token": token, "done": False})
                    continue
                text = "".join(collected)
                cut = _release_point(text, checked)
                if cut <= checked:
                    continue
                checked = cut
                review = await defense_pipeline.review_output(
                    text[:cut],
                    level,
                    user_id=prepared.get("user_id"),
                    context=output_context(prepared, preview=True),
                )
                if not review.allowed:
                    yield _sse({"replace": review.message, "done": True})
                    return
                for event in _update_events(shown, review.message):
                    yield event
                shown = review.message
        finally:
            # Stops the model as soon as a partial reply is refused.
            await stream.aclose()

        if gone.get("client"):
            return

        full_reply = "".join(collected)
        if not full_reply:
            full_reply = "I'm sorry, I couldn't process that request."
            data = json.dumps({"token": full_reply, "done": True})
            yield f"data: {data}\n\n"
            return

        if level == 0:
            yield _sse({"done": True})
            return

        moderated = await defense_pipeline.moderate_output(
            full_reply,
            level,
            user_id=prepared.get("user_id"),
            context=output_context(prepared),
        )
        if level >= 2:
            nemo = get_guardrails_service()
            if nemo.available:
                nemo_out = await nemo.check_output(moderated)
                if not nemo_out.allowed:
                    moderated = nemo_out.message

        if moderated == shown:
            yield _sse({"done": True})
        elif moderated.startswith(shown):
            yield _sse({"token": moderated[len(shown):], "done": False})
            yield _sse({"done": True})
        else:
            yield _sse({"replace": moderated, "done": True})

    return StreamingResponse(token_gen(), media_type="text/event-stream")


_SENTENCE_END = re.compile(r"[.!?…](?=\s)|\n")
# Without a sentence end for this long, release up to the last space.
_MAX_HELD = 400


def _release_point(text: str, checked: int) -> int:
    """End of the last complete sentence in ``text`` (0 if none yet)."""
    ends = [m.end() for m in _SENTENCE_END.finditer(text, checked)]
    if ends:
        return ends[-1]
    if len(text) - checked > _MAX_HELD and " " in text[checked:]:
        return text.rindex(" ")
    return checked


def _update_events(shown: str, moderated: str) -> list[str]:
    """Events that turn what the browser shows into ``moderated``."""
    if moderated == shown:
        return []
    if moderated.startswith(shown):
        return [_sse({"token": moderated[len(shown):], "done": False})]
    return [_sse({"replace": moderated, "done": False})]


def _sse(payload: dict) -> str:
    return f"data: {json.dumps(payload)}\n\n"


@router.get("/api/chat/defense-levels", response_model=DefenseLevelOut)
async def get_defense_levels(
    user: Annotated[User, Depends(get_current_user)],
    surface: str | None = Query(default=None),
) -> DefenseLevelOut:
    """Return all available defense levels and the user's current selection."""
    current = _get_defense_level(user)
    levels = [dict(DEFENSE_LEVELS[i]) for i in sorted(DEFENSE_LEVELS)]
    if surface:
        from app.defense.control import get_control
        from app.defense.profiles import resolve_profile

        try:
            for item in levels:
                profile = resolve_profile(surface, int(item["level"]))
                item["intent"] = profile.intent
                item["controls"] = [
                    {
                        "id": cid,
                        "name": get_control(cid).name,
                        "stage": (
                            get_control(cid).applies_to[0].value
                            if get_control(cid).applies_to
                            else ""
                        ),
                        "description": get_control(cid).verifies,
                        "verifies": get_control(cid).verifies,
                    }
                    for cid in profile.controls
                ]
        except ValueError as exc:
            from app.core.exceptions import ValidationError

            raise ValidationError(str(exc)) from exc
    return DefenseLevelOut(current_level=current, levels=levels)


@router.post("/api/chat/defense-level")
async def set_defense_level(
    body: SetDefenseLevelRequest,
    user: Annotated[User, Depends(get_current_user)],
    db: Annotated[AsyncSession, Depends(get_db)],
) -> dict:
    """Set the user's defense level (0=Vulnerable, 1=Hardened, 2=Guardrailed)."""
    if body.level not in DEFENSE_LEVELS:
        return {"success": False, "detail": "Invalid level"}
    result = await db.execute(select(User).where(User.id == user.id))
    db_user = result.scalar_one()
    db_user.defense_level = body.level
    await db.commit()
    return {"success": True, "level": body.level}


@router.get("/api/chat/defense-level", response_model=DefenseLevelOut)
async def get_defense_level(
    user: Annotated[User, Depends(get_current_user)],
    surface: str | None = Query(default=None),
) -> DefenseLevelOut:
    """Return the user's current defense level. Alias for /api/chat/defense-levels."""
    return await get_defense_levels(user, surface=surface)
