"""action.firewall — permissions for sensitive chat actions, enforced in code.

The chat model can be talked into *saying* it refunded someone else's order or
applied a staff-only coupon. This control never asks the model whether an
action is allowed. It finds the action in the user's request (input stage) or
in the model's reply (output stage) and checks it against facts the prompt
cannot change: the user row behind the JWT, the orders that user owns in the
database, and the coupon table.

Detection reads every sentence twice: as written, and after the KB firewall's
normalizer has undone hiding tricks (look-alike letters, invisible characters,
s p a c e d letters, base64). Request and claim words are recognised in
English, Spanish, French, Portuguese and German, the same five languages the
KB firewall covers.

Each action gets one of three decisions:
  allow    the action is within the caller's own rights
  confirm  a person must approve it first; nothing has happened yet
  block    the caller may not do this; the text is replaced with a refusal

Every decision on a detected action is appended to a JSON-lines audit log and
shown in the shared firewall log on the admin page.
"""
from __future__ import annotations

import json
import re
import unicodedata
from collections.abc import Iterable, Mapping
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from enum import Enum
from functools import lru_cache
from pathlib import Path
from typing import Any

from app.core.config import get_settings
from app.core.logging import get_logger
from app.defense import firewall_log
from app.defense.control import (
    ControlAction,
    ControlOutcome,
    DefenseControl,
    DefenseDecision,
    DefenseStage,
)
from app.defense.rejection import get_rejection_response
from app.kb_firewall.normalize import normalize

logger = get_logger(__name__)

BLOCK_MESSAGE = get_rejection_response("action_blocked")
CONFIRM_MESSAGE = get_rejection_response("action_needs_confirmation")

# ── Policy limits ────────────────────────────────────────────────────
CUSTOMER_REFUND_LIMIT = 250.00
REFUNDABLE_STATUSES = frozenset({"delivered", "shipped"})


class Decision(str, Enum):
    ALLOW = "allow"
    CONFIRM = "confirm"
    BLOCK = "block"


_SEVERITY = {Decision.ALLOW: 0, Decision.CONFIRM: 1, Decision.BLOCK: 2}


# ── Who is asking (built from the database, never from the prompt) ───


@dataclass(frozen=True)
class OrderFacts:
    order_id: int
    paid: float
    status: str


@dataclass(frozen=True)
class ActorContext:
    user_id: int
    username: str
    email: str
    is_staff: bool
    orders: Mapping[str, OrderFacts]  # every id a user might type for an order they own
    coupons: Mapping[str, str]  # upper-case code -> target_audience
    # Lower-case usernames of every account. When known, "orders for X" only
    # counts as someone else's data if X is a real account.
    usernames: frozenset[str] = field(default_factory=frozenset)


def build_actor(
    user: Any,
    orders: Iterable[Any],
    coupons: Iterable[Any],
    usernames: Iterable[str] = (),
) -> ActorContext:
    """Snapshot the caller's identity, own orders and the coupon table.

    ``orders`` may contain other users' rows; only the caller's are kept.
    """
    own: dict[str, OrderFacts] = {}
    for order in orders:
        if order.user_id != user.id:
            continue
        paid = order.final_amount if order.final_amount is not None else order.total_amount
        facts = OrderFacts(order.id, float(paid), (order.status or "").lower())
        own[str(order.id)] = facts
        custom = re.search(r"(\d+)$", order.custom_order_id or "")
        if custom:
            own[custom.group(1)] = facts
    return ActorContext(
        user_id=user.id,
        username=user.username,
        email=(user.email or "").lower(),
        is_staff=bool(user.is_staff),
        orders=own,
        coupons={c.code.upper(): c.target_audience for c in coupons},
        usernames=frozenset(name.lower() for name in usernames if name),
    )


def coupon_allowed(actor: ActorContext, code: str) -> bool:
    """May this actor use (and see) the coupon? Unknown codes are never allowed."""
    audience = actor.coupons.get(code.upper())
    return audience == "all" or (audience == "staff" and actor.is_staff)


# ── Detection: what action does this text request or claim? ──────────


@dataclass(frozen=True)
class DetectedAction:
    kind: str  # refund | coupon | export | status_change | data_access
    order_ids: tuple[str, ...] = ()
    amount: float | None = None
    codes: tuple[str, ...] = ()
    scope: str = ""  # export: "self" or "all"
    new_status: str = ""
    subject: str = ""  # data_access: whose data ("*" = everyone)
    emails: tuple[str, ...] = ()  # data_access: personal email addresses mentioned
    disclosed: bool = False  # coupon: a reply names the code without claiming to apply it


# Words below cover English, Spanish, French, Portuguese and German. Accented
# letters have a plain twin ("[eé]") so the normalized pass, which strips
# accents, matches as well.

_SENTENCE_SPLIT = re.compile(r"(?<=[.!?])\s+|\n+")
_ORDER_WORD = r"(?:order|pedido|commande|encomenda|bestellung)"
_ORDER_ID = re.compile(
    r"\bORD-(\d+)"
    rf"|\b{_ORDER_WORD}\s+(?:#\s?|(?:id|no\.?|number|n[uú]mero|num[eé]ro|nr\.?|n[º°]\.?)\s*#?\s*)(\d+)"
    rf"|\b{_ORDER_WORD}\s+(\d{{3,}})\b"
    r"|#(\d{3,})\b",
    re.I,
)
_CURRENCY = r"(?:\$|usd|us\$|€|eur(?:os?)?|d[oó]lares|dollars?)"
# In a refund or status sentence, a bare number like "refund 1003" is an order
# id too, unless it is an amount ("900 €").
_BARE_NUMBER = re.compile(rf"(?<![$.,\d])\b\d{{3,}}\b(?!\s?{_CURRENCY})", re.I)
_AMOUNT = re.compile(
    r"(?:\$|usd|us\$|€|eur)\s?(\d[\d,.]*\d|\d)"
    rf"|(\d[\d,.]*\d|\d)\s?{_CURRENCY}",
    re.I,
)
_REFUND = re.compile(r"\b(?:refund|reembols|rembours|(?:r[uü]ck)?erstatt)", re.I)
_COUPON_WORD = re.compile(
    r"\b(?:coupon|promo|discount|voucher|code|cup[oó]n|cupom|c[oó]digo|descuento|desconto"
    r"|r[eé]duction|remise|gutschein|rabatt\w*)\b"
    r"|\b(?:appl|aplic|appliqu|anwend|angewend|einl[oö]s|eingel[oö]s)",
    re.I,
)
_CODE = re.compile(r"\b[a-z]{3,}\d{1,4}\b", re.I)
_EXPORT = re.compile(r"\bexport", re.I)
_EXPORT_TARGET = re.compile(
    r"\b(?:customer|user|account|order|personal|profile|data|record|e-?mail|database)s?\b"
    r"|\b(?:clientes?|usuarios?|usu[aá]rios?|cuentas?|contas?|datos|dados|correos?|pedidos?|perfil(?:es)?"
    r"|registros?|clients?|utilisateurs?|comptes?|donn[eé]es|courriels?|commandes?|profils?"
    r"|kunden|nutzer|benutzer|konten|daten|bestellungen|datenbank)\b",
    re.I,
)
_EXPORT_ALL = re.compile(
    r"\b(?:all|every|entire|bulk|customers|users|database"
    r"|tod[oa]s|clientes|usuarios|usu[aá]rios|base de datos|banco de dados"
    r"|tous|toutes|clients|utilisateurs|base de donn[eé]es"
    r"|alle[nrs]?|kunden|nutzer|benutzer|datenbank)\b",
    re.I,
)
_EXPORT_SELF = re.compile(
    r"\b(?:my|mine|own|your|mis?|tus?|mes|mon|ma|tes|ton|ta|votre|vos|meus?|minhas?|teus?|tuas?"
    r"|meine?[nrs]?|deine?[nrs]?|propi[oa]s?|propres?|eigenen?)\b",
    re.I,
)
_STATUS_CHANGE = re.compile(
    r"\b(?:update|change|set|mark|modif)\w*\b.{0,40}?\bstatus\b"
    r"|\bstatus\b.{0,40}?\b(?:updated|changed|set|marked)\b"
    r"|\b(?:cambia|cambiar|cambie|cambi[eé]|actualiza|actualizar|actualice|actualic[eé]|modifica|modificar"
    r"|modifique|modifiqu[eé]|marca|marcar|marque|marqu[eé]|pon|poner|ponga|muda|mudar|mude|mudei|altera"
    r"|alterar|altere|alterei|atualiza|atualizar|atualize|atualizei)\b.{0,40}?\b(?:estado|status)\b"
    r"|\b(?:estado|status)\b.{0,40}?\b(?:cambiad|actualizad|modificad|marcad|alterad|atualizad|mudad)[oa]s?\b"
    r"|\b(?:change|changer|changez|modifie|modifier|modifiez|mets|mettez|mettre|marque|marquer|marquez"
    r"|passe|passer|passez)\b.{0,40}?\bstatut\b"
    r"|\bstatut\b.{0,40}?\b(?:chang|modifi|mis|marqu|pass)[eé]e?s?\b"
    r"|\b(?:ändere|ändern|aendere|aendern|setze|setzen|markiere|markieren|aktualisiere|aktualisieren)\b"
    r".{0,40}?\bstatus\b"
    r"|\bstatus\b.{0,40}?\b(?:geändert|geaendert|gesetzt|markiert|aktualisiert)\b",
    re.I,
)
_NEW_STATUS = re.compile(
    r"\b(?:to|as|a|en|como|para|comme|auf|zu|als)\s+[\"'«]?\s?"
    r"(pending|processing|shipped|delivered|cancell?ed|refunded"
    r"|pendiente|procesando|en proceso|enviado|entregado|cancelado|anulado|reembolsado"
    r"|en attente|en cours|exp[eé]di[eé]e?|livr[eé]e?|annul[eé]e?|rembours[eé]e?"
    r"|pendente|processando|entregue"
    r"|ausstehend|in bearbeitung|versandt|versendet|geliefert|zugestellt|storniert|erstattet)\b",
    re.I,
)
_STATUS_STEMS = (
    ("cancelled", ("cancel", "anul", "annul", "storn")),
    ("refunded", ("refund", "reembols", "rembours", "erstatt")),
    ("shipped", ("ship", "envi", "exped", "versand", "versend")),
    ("delivered", ("deliver", "entreg", "livr", "geliefert", "zugestellt")),
    ("processing", ("process", "proces", "en cours", "in bearbeitung")),
    ("pending", ("pend", "en attente", "ausstehend")),
)
_CANCEL = re.compile(
    r"\bcancel\w*\s+(?:my\s+|your\s+|the\s+|this\s+)?order\b"
    r"|\border\b[^.]{0,20}?\b(?:has been|was|is now)\s+cancell?ed\b"
    r"|\b(?:cancel|anul)\w*\s+(?:mi\s+|el\s+|este\s+|su\s+|tu\s+|o\s+|meu\s+|a\s+|minha\s+)?(?:pedido|encomenda)\b"
    r"|\b(?:pedido|encomenda)\b[^.]{0,25}?\b(?:ha sido|fue|est[aá]|qued[oó]|foi)\s+(?:cancelad|anulad)\w*"
    r"|\bannul\w*\s+(?:ma\s+|la\s+|cette\s+|votre\s+|ta\s+)?commande\b"
    r"|\bcommande\b[^.]{0,25}?\b(?:a [eé]t[eé]|est)\s+annul\w*"
    r"|\bstornier\w*\s+(?:meine\s+|die\s+|ihre\s+|deine\s+)?bestellung\b"
    r"|\bbestellung\b[^.]{0,25}?\b(?:wurde|ist)\s+storniert\b",
    re.I,
)
_BULK_DATA = re.compile(
    r"\b(?:all|every|other)\s+(?:the\s+)?(?:customer|user|account)s?(?:'s?)?\s+"
    r"(?:data|records?|details|info\w*|emails?|orders?|accounts?|list)\b"
    r"|\b(?:datos|correos|pedidos|direcciones|tarjetas|cuentas|dados|e-?mails|endere[cç]os|cart[oõ]es)\s+de\s+"
    r"(?:tod[oa]s\s+(?:l[oa]s\s+|os\s+|as\s+)?|otros\s+|outros\s+|los\s+dem[aá]s\s+)(?:clientes|usuarios|usu[aá]rios)\b"
    r"|\b(?:donn[eé]es|courriels|e-?mails|commandes|adresses|cartes|comptes)\s+"
    r"(?:de\s+tous\s+les\s+|des\s+autres\s+|d['’]autres\s+|de\s+toutes\s+les\s+)(?:clients|utilisateurs|clientes)\b"
    r"|\b(?:daten|e-?mails|bestellungen|adressen|konten)\s+(?:aller|anderer|von allen)\s+(?:kunden|nutzer|benutzer)\b",
    re.I,
)
# "every user" + a hand-over verb, e.g. "send me a CSV of every user".
_EVERYONE = re.compile(
    r"\b(?:all|every|each|other)\s+(?:the\s+)?(?:customer|user|account|member)s?\b"
    r"|\b(?:tod[oa]s\s+(?:l[oa]s|os|as)|cada|otros|outros|los\s+dem[aá]s)\s+"
    r"(?:clientes?|usuarios?|usu[aá]rios?|cuentas|contas|miembros|membros)\b"
    r"|\b(?:tous\s+les|toutes\s+les|chaque|les\s+autres|d['’]autres)\s+(?:clients?|utilisateurs?|comptes|membres)\b"
    r"|\b(?:alle[nr]?|jede[nrs]?|andere[nr]?)\s+(?:kunden|nutzer|benutzer|konten|mitglieder)\b",
    re.I,
)
# Hand-over verbs: imperatives and "to me" forms only, so "we ship to all
# customers" ("enviamos a todos los clientes") is not a data request.
_DATA_VERB = re.compile(
    r"\b(?:send|give|list|show|display|export|dump|download|share|print|csv|json|spreadsheet"
    r"|env[ií]ame|env[ií]enme|m[aá]ndame|d[aá]me|mu[eé]strame|muestra|lista|listar|enumera|comparte"
    r"|comp[aá]rteme|descarga|imprime|exporta|p[aá]same|excel|hoja de c[aá]lculo"
    r"|envoie-moi|envoyez-moi|donne-moi|donnez-moi|montre-moi|montrez-moi|affiche|liste|partage"
    r"|t[eé]l[eé]charge|exporte|tableur"
    r"|me envie|envie-me|me mande|mostre|mostra|compartilhe|baixe|planilha"
    r"|schick mir|schicke mir|sende mir|gib mir|zeig mir|zeige mir|exportiere|tabelle)\b",
    re.I,
)
# "list the email addresses of the customers who bought X": other people's
# personal data + a hand-over verb, without saying "all" or "every".
_OTHER_BUYERS = re.compile(
    r"\b(?:customers|users|buyers|shoppers|people)\s+(?:who|that)\b"
    r"|\b(?:clientes|usuarios|compradores|personas|usu[aá]rios|pessoas|clients|utilisateurs|acheteurs"
    r"|personnes|kunden|nutzer|k[aä]ufer|leute)\s+(?:que|qui|die)\b",
    re.I,
)
_PERSONAL_DATA = re.compile(
    r"\b(?:e-?mail|address|phone|card)(?:es|s)?\b"
    r"|\b(?:correos?|direcci[oó]n(?:es)?|tel[eé]fonos?|tarjetas?|endere[cç]os?|telefones?|cart[aã]o|cart[oõ]es"
    r"|courriels?|adresses?|t[eé]l[eé]phones?|cartes?|adressen?|telefonnummern?|karten?)\b",
    re.I,
)
_ORDERS_FOR = re.compile(
    r"\borders?\s+(?:for|of|belonging\s+to|placed\s+by)\s+([a-z][\w.-]*)"
    r"|\b(?:pedidos?|encomendas?|commandes?|bestellungen?)\s+(?:de|del|da|do|des|du|von|f[uü]r)\s+([a-z][\w.-]*)",
    re.I,
)
_NOT_A_NAME = frozenset({
    "me", "my", "mine", "myself", "you", "your", "the", "this", "that", "a", "an", "our", "us",
    "mi", "mis", "tu", "tus", "su", "sus", "el", "la", "los", "las", "un", "una", "este", "esta", "ese", "esa",
    "nuestro", "nuestra", "todos", "otros", "le", "les", "mon", "ma", "mes", "ton", "ta", "tes", "votre",
    "vos", "notre", "nos", "ce", "cette", "une", "tous", "o", "os", "as", "um", "uma", "meu", "minha", "seu",
    "sua", "der", "die", "das", "den", "dem", "mein", "meine", "meinen", "ihre", "ihr", "alle", "mir",
})
_EMAIL = re.compile(r"\b([\w.+-]+)@[\w-]+(?:\.[\w-]+)+\b")
_ROLE_MAILBOXES = frozenset({"support", "help", "info", "contact", "sales", "noreply", "no-reply", "returns"})
_DONE_WORDS = (
    r"(?:erstattet|zur[uü]ckerstattet|angewendet|angewandt|eingel[oö]st|exportiert|storniert|ge[aä]ndert"
    r"|bearbeitet|genehmigt|aktualisiert|gutgeschrieben)"
)
# In a reply, an action only counts when the sentence says it was done: "I've
# processed", "has been refunded", "is now active", "Refund approved". A policy
# sentence ("refunds are usually processed") or a denial ("I have not",
# "no he procesado", "ich habe ... nicht erstattet") is not.
_CLAIM = re.compile(
    r"\b(?:i|we)(?:['’]ve|\s+have)?\s+(?:just\s+|now\s+|already\s+)?"
    r"(?:processed|approved|issued|applied|exported|updated|changed|marked|cancell?ed|refunded|completed|credited|initiated)\b"
    r"|\b(?:has|have)\s+(?:now\s+|just\s+|already\s+)?been\b"
    r"|\bis\s+now\b"
    r"|\bsuccessfully\b"
    r"|\b(?:refund|coupon|code|discount|export|status)\w*\s+(?:has\s+been\s+|was\s+)?"
    r"(?:processed|approved|issued|applied|exported|updated|changed|completed|confirmed|activated)\b"
    # Spanish
    r"|(?<!no )\b(?:he|hemos)\s+(?:ya\s+)?(?:procesado|aprobado|emitido|aplicado|exportado|actualizado|cambiado"
    r"|marcado|cancelado|anulado|reembolsado|completado|acreditado|iniciado|realizado|tramitado)\b"
    r"|(?<!no )\b(?:apliqu|proces|reembols|aprob|export|cancel|anul|actualic|cambi|acredit|inici|tramit"
    r"|realic|complet)é\b|(?<!no )\bemití\b"
    r"|(?<!no )\b(?:ha|han)\s+sido\b"
    r"|(?<!no )\b(?:fue|fueron)\s+(?:procesad|aprobad|emitid|aplicad|exportad|actualizad|cambiad|cancelad"
    r"|anulad|reembolsad|completad|acreditad)\w*"
    r"|\bya\s+(?:est[aá]n?|qued[oó])\s+(?:procesad|aprobad|aplicad|exportad|actualizad|cancelad|anulad"
    r"|reembolsad|activ)\w*"
    r"|\b(?:con\s+[eé]xito|exitosamente)\b"
    # French
    r"|\b(?:j['’]ai|nous\s+avons)\s+(?:bien\s+|d[eé]j[aà]\s+)?(?:trait[eé]|approuv[eé]|appliqu[eé]|export[eé]"
    r"|annul[eé]|rembours[eé]|effectu[eé]|modifi[eé]|valid[eé]|cr[eé]dit[eé]|mis\s+[aà]\s+jour|[eé]mis"
    r"|lanc[eé]|initi[eé])"
    r"|\b(?:a|ont)\s+(?:bien\s+)?[eé]t[eé]\b"
    r"|\best\s+(?:maintenant|d[eé]sormais)\b"
    r"|\bavec\s+succ[eè]s\b"
    # Portuguese
    r"|(?<!n[aã]o )\b(?:processei|aprovei|emiti|apliquei|exportei|atualizei|alterei|cancelei|reembolsei"
    r"|conclu[ií]|creditei)\b"
    r"|(?<!n[aã]o )\bfo(?:i|ram)\s+(?:processad|aprovad|emitid|aplicad|exportad|atualizad|alterad|cancelad"
    r"|reembolsad|conclu[ií]d|creditad)\w*"
    r"|\bcom\s+sucesso\b"
    # German: "nicht"/"kein" anywhere between the verb and the participle cancels the claim
    rf"|\b(?:ich|wir)\s+(?:habe|haben)\b(?:(?!\bnicht\b|\bkein)[^.]){{0,40}}?\b{_DONE_WORDS}\b"
    rf"|\b(?:wurde|wurden|ist|sind)\b(?:(?!\bnicht\b|\bkein)[^.]){{0,40}}?\b{_DONE_WORDS}\b"
    r"|(?<!nicht )\berfolgreich\b",
    re.I,
)


def _order_ids(sentence: str) -> tuple[str, ...]:
    found = (next(g for g in m.groups() if g) for m in _ORDER_ID.finditer(sentence))
    return tuple(dict.fromkeys(found))


def _parse_amount(raw: str) -> float:
    """'1,250.50', '1.250,50' and '1250.5' are all 1250.50; '40,5' is 40.50."""
    if "," in raw and "." in raw:
        if raw.rfind(".") > raw.rfind(","):
            raw = raw.replace(",", "")
        else:
            raw = raw.replace(".", "").replace(",", ".")
    elif "," in raw:
        whole, _, frac = raw.rpartition(",")
        raw = f"{whole.replace(',', '')}.{frac}" if len(frac) <= 2 else raw.replace(",", "")
    elif raw.count(".") > 1 or (raw.count(".") == 1 and len(raw.rpartition(".")[2]) == 3):
        raw = raw.replace(".", "")  # European thousands: 1.250
    return float(raw)


def _amount(sentence: str) -> float | None:
    match = _AMOUNT.search(sentence)
    if not match:
        return None
    try:
        return _parse_amount(next(g for g in match.groups() if g))
    except ValueError:
        return None


@lru_cache(maxsize=512)
def _code_pattern(code: str) -> re.Pattern[str]:
    # "STAFF100", "staff-100" and "S T A F F 1 0 0" are the same code.
    body = r"[\s.\-_*]?".join(re.escape(ch) for ch in code)
    return re.compile(rf"(?<![a-z0-9]){body}(?![a-z0-9])", re.I)


def _codes(sentence: str, known_codes: Iterable[str]) -> tuple[str, ...]:
    found = [m.group(0).upper() for m in _CODE.finditer(sentence)]
    found += [code for code in known_codes if _code_pattern(code).search(sentence)]
    return tuple(dict.fromkeys(found))


def _strip_accents(text: str) -> str:
    return "".join(ch for ch in unicodedata.normalize("NFKD", text) if not unicodedata.combining(ch))


def _canonical_status(word: str) -> str:
    plain = _strip_accents(word.lower())
    for status, stems in _STATUS_STEMS:
        if plain.startswith(stems):
            return status
    return plain


def _variants(sentence: str) -> list[str]:
    """The sentence as written, plus the normalized copy split back into sentences.

    The copy is lower-case, has no accents, and has look-alike letters,
    invisible characters, spaced-out letters and base64 blobs undone, so
    "Rеfund" with a Cyrillic "е" reads as "refund".
    """
    variants = [sentence]
    norm = normalize(sentence).text
    if norm and norm != sentence.lower():
        variants += [s for s in (p.strip() for p in _SENTENCE_SPLIT.split(norm)) if s]
    return variants


def _detect_sentence(sentence: str, stage: DefenseStage, known_codes: tuple[str, ...]) -> list[DetectedAction]:
    actions: list[DetectedAction] = []
    ids = _order_ids(sentence)
    action_ids = ids or tuple(dict.fromkeys(_BARE_NUMBER.findall(sentence)))
    amount = _amount(sentence)
    # A request names an action; a reply must also claim it was done.
    claimed = stage is DefenseStage.INPUT or bool(_CLAIM.search(sentence))

    if claimed and _REFUND.search(sentence) and (action_ids or amount is not None or stage is DefenseStage.OUTPUT):
        actions.append(DetectedAction("refund", order_ids=action_ids, amount=amount))

    # A code from the coupon table counts on its own ("I may use STAFF100. Apply
    # it."); a code that only looks like one needs a coupon word beside it.
    codes = _codes(sentence, known_codes)
    if claimed and codes and (_COUPON_WORD.search(sentence) or any(c in known_codes for c in codes)):
        actions.append(DetectedAction("coupon", codes=codes))
    elif stage is DefenseStage.OUTPUT:
        # A reply that only names a real code ("the staff code is STAFF100")
        # still hands it over.
        shown = tuple(c for c in codes if c in known_codes)
        if shown:
            actions.append(DetectedAction("coupon", codes=shown, disclosed=True))

    if claimed and _EXPORT.search(sentence) and _EXPORT_TARGET.search(sentence):
        scope = "self" if _EXPORT_SELF.search(sentence) and not _EXPORT_ALL.search(sentence) else "all"
        actions.append(DetectedAction("export", scope=scope))

    if claimed and (_STATUS_CHANGE.search(sentence) or _CANCEL.search(sentence)):
        status = _NEW_STATUS.search(sentence)
        new_status = _canonical_status(status.group(1)) if status else ""
        if _CANCEL.search(sentence):
            new_status = "cancelled"
        actions.append(DetectedAction("status_change", order_ids=action_ids, new_status=new_status))

    named = [
        name for name in (next(g for g in m.groups() if g).rstrip(".-") for m in _ORDERS_FOR.finditer(sentence))
        if name and name.lower() not in _NOT_A_NAME
    ]
    others = _EVERYONE.search(sentence) or (_OTHER_BUYERS.search(sentence) and _PERSONAL_DATA.search(sentence))
    if _BULK_DATA.search(sentence) or (others and _DATA_VERB.search(sentence)):
        actions.append(DetectedAction("data_access", subject="*"))
    for name in named:
        actions.append(DetectedAction("data_access", subject=name))
    if ids:
        actions.append(DetectedAction("data_access", order_ids=ids))
    emails = tuple(
        m.group(0).lower() for m in _EMAIL.finditer(sentence) if m.group(1).lower() not in _ROLE_MAILBOXES
    )
    if emails:
        actions.append(DetectedAction("data_access", emails=emails))
    return actions


def detect_actions(text: str, stage: DefenseStage, known_codes: Iterable[str] = ()) -> list[DetectedAction]:
    """Sentence by sentence, so an order id is tied to the verb next to it.

    Each sentence is read as written and normalized; an action found in
    either reading counts once.
    """
    known_codes = tuple(known_codes)
    actions: list[DetectedAction] = []
    for sentence in filter(None, (s.strip() for s in _SENTENCE_SPLIT.split(text))):
        for variant in _variants(sentence):
            actions += _detect_sentence(variant, stage, known_codes)
    return list(dict.fromkeys(actions))


# ── Policy: may this actor do this action? ───────────────────────────


def _check_refund(action: DetectedAction, actor: ActorContext) -> tuple[Decision, str]:
    if actor.is_staff:
        for oid in action.order_ids:
            facts = actor.orders.get(oid)
            if facts and action.amount is not None and action.amount > facts.paid:
                return Decision.BLOCK, f"refund exceeds the ${facts.paid:.2f} paid for order {oid}"
        return Decision.CONFIRM, "staff refunds need a second person to confirm"
    if not action.order_ids:
        return Decision.BLOCK, "refund does not name an order on this account"
    for oid in action.order_ids:
        facts = actor.orders.get(oid)
        if facts is None:
            return Decision.BLOCK, f"order {oid} does not belong to this user"
        if facts.status not in REFUNDABLE_STATUSES:
            return Decision.BLOCK, f"order {oid} is {facts.status or 'unknown'} and cannot be refunded"
        amount = action.amount if action.amount is not None else facts.paid
        if amount > facts.paid:
            return Decision.BLOCK, f"refund ${amount:.2f} exceeds the ${facts.paid:.2f} paid for order {oid}"
        if amount > CUSTOMER_REFUND_LIMIT:
            return Decision.BLOCK, f"refund ${amount:.2f} is over the ${CUSTOMER_REFUND_LIMIT:.0f} customer limit"
    return Decision.CONFIRM, "refund of the caller's own order needs staff confirmation"


def _check_coupon(action: DetectedAction, actor: ActorContext) -> tuple[Decision, str]:
    for code in action.codes:
        audience = actor.coupons.get(code)
        if audience is None:
            return Decision.BLOCK, f"coupon {code} does not exist"
        if coupon_allowed(actor, code):
            continue
        if action.disclosed:
            return Decision.BLOCK, f"reply reveals coupon {code}, which is restricted to {audience}"
        return Decision.BLOCK, f"coupon {code} is restricted to {audience}"
    return Decision.ALLOW, "coupon is available to this user"


def _check_export(action: DetectedAction, actor: ActorContext) -> tuple[Decision, str]:
    if action.scope == "self":
        return Decision.CONFIRM, "export of the caller's own data needs confirmation"
    if actor.is_staff:
        return Decision.CONFIRM, "bulk export needs a second person to confirm"
    return Decision.BLOCK, "customers cannot export other customers' data"


def _check_status_change(action: DetectedAction, actor: ActorContext) -> tuple[Decision, str]:
    if actor.is_staff:
        return Decision.CONFIRM, "staff status changes need confirmation"
    if action.new_status == "cancelled" and action.order_ids:
        for oid in action.order_ids:
            facts = actor.orders.get(oid)
            if facts is None or facts.status != "pending":
                return Decision.BLOCK, f"order {oid} is not a pending order of this user"
        return Decision.CONFIRM, "cancelling the caller's own pending order needs confirmation"
    return Decision.BLOCK, "customers cannot change order status"


def _check_data_access(action: DetectedAction, actor: ActorContext) -> tuple[Decision, str]:
    if actor.is_staff:
        return Decision.ALLOW, "staff may look up customers"
    for oid in action.order_ids:
        if oid not in actor.orders:
            return Decision.BLOCK, f"order {oid} belongs to another customer"
    if any(email != actor.email for email in action.emails):
        return Decision.BLOCK, "text contains another person's email address"
    subject = action.subject.lower()
    if subject and subject != actor.username.lower():
        # "orders for hoodies" is not a person; with the account list loaded,
        # only a real other account counts.
        if subject == "*" or not actor.usernames or subject in actor.usernames:
            return Decision.BLOCK, "customers cannot look up other customers' data"
    return Decision.ALLOW, "caller's own data"


_CHECKS = {
    "refund": _check_refund,
    "coupon": _check_coupon,
    "export": _check_export,
    "status_change": _check_status_change,
    "data_access": _check_data_access,
}


@dataclass(frozen=True)
class FirewallVerdict:
    decision: Decision
    reason: str
    actions: tuple[tuple[DetectedAction, Decision, str], ...] = ()


def firewall_verdict(text: str, stage: DefenseStage, actor: ActorContext | None) -> FirewallVerdict:
    """Detect actions in ``text`` and return the strictest decision among them."""
    known_codes = actor.coupons.keys() if actor else ()
    results: list[tuple[DetectedAction, Decision, str]] = []
    for action in detect_actions(text, stage, known_codes):
        if actor is None:
            results.append((action, Decision.BLOCK, "cannot verify who is asking"))
        else:
            results.append((action, *_CHECKS[action.kind](action, actor)))
    if not results:
        return FirewallVerdict(Decision.ALLOW, "no sensitive action")
    _, decision, reason = max(results, key=lambda r: _SEVERITY[r[1]])
    return FirewallVerdict(decision, reason, tuple(results))


# ── Audit log ────────────────────────────────────────────────────────

_LOG_ACTION = {Decision.BLOCK: "blocked", Decision.CONFIRM: "confirm"}


def _audit(decision: DefenseDecision, actor: ActorContext | None, verdict: FirewallVerdict) -> None:
    record = {
        "ts": datetime.now(timezone.utc).isoformat(),
        "surface": decision.surface,
        "stage": decision.stage.value,
        "level": decision.level,
        "user_id": actor.user_id if actor else decision.user_id,
        "is_staff": actor.is_staff if actor else None,
        "decision": verdict.decision.value,
        "reason": verdict.reason,
        "actions": [
            {**asdict(action), "decision": result.value, "reason": reason}
            for action, result, reason in verdict.actions
        ],
        "text_preview": decision.payload[:200],
    }
    logger.info("action_firewall %s", record)
    if verdict.decision is not Decision.ALLOW:
        # The admin page shows what was stopped; allowed checks stay in the
        # audit file, so a reply the leak firewall refuses next is not echoed there.
        firewall_log.record(
            "action",
            action=_LOG_ACTION[verdict.decision],
            surface=decision.surface,
            stage=decision.stage.value,
            level=decision.level,
            user=actor.username if actor else None,
            reasons=[verdict.reason],
            kinds=sorted({action.kind for action, _, _ in verdict.actions}),
            snippet=decision.payload[:240],
        )
    path = Path(get_settings().defense.action_firewall_audit_path)
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        with path.open("a", encoding="utf-8") as f:
            f.write(json.dumps(record) + "\n")
    except OSError as exc:
        logger.warning("Action firewall audit write failed: %s", exc)


# ── The control ──────────────────────────────────────────────────────


class ActionFirewallControl(DefenseControl):
    id = "action.firewall"
    name = "Action firewall"
    verifies = (
        "Refunds, coupon codes, data exports and order-status changes in the request "
        "or the reply are checked against the caller's own account, role and limits, "
        "in five languages and after undoing hidden-text tricks. Money-moving and bulk "
        "actions need staff confirmation; anything outside the caller's rights, "
        "including a reply that reveals a restricted coupon code, is replaced with a "
        "refusal. Switch: ACTION_FIREWALL_ENABLED or the admin firewall page."
    )
    applies_to = (DefenseStage.INPUT, DefenseStage.OUTPUT)

    async def _evaluate(self, decision: DefenseDecision) -> ControlOutcome:
        if not get_settings().defense.action_firewall_enabled:
            return ControlOutcome(action=ControlAction.ALLOW, payload=decision.payload, control_id=self.id)
        actor = decision.context.get("actor")
        verdict = firewall_verdict(decision.payload, decision.stage, actor)
        # While a reply streams, each partial reply is checked; only the check
        # that stops it is logged, and the final full check logs the rest.
        preview = bool(decision.context.get("preview"))
        if verdict.actions and not (preview and verdict.decision is Decision.ALLOW):
            _audit(decision, actor, verdict)
        if verdict.decision is Decision.BLOCK:
            return ControlOutcome(
                action=ControlAction.DENY,
                payload=BLOCK_MESSAGE,
                control_id=self.id,
                reason=verdict.reason,
                rejection_key="action_blocked",
            )
        if verdict.decision is Decision.CONFIRM:
            return ControlOutcome(
                action=ControlAction.REQUIRE_APPROVAL,
                payload=CONFIRM_MESSAGE,
                control_id=self.id,
                reason=verdict.reason,
                rejection_key="action_needs_confirmation",
            )
        return ControlOutcome(action=ControlAction.ALLOW, payload=decision.payload, control_id=self.id)
