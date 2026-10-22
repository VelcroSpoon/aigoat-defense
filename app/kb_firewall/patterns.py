"""Multilingual cue patterns for instructions hidden inside knowledge-base text.

Patterns run on the output of ``normalize``: lowercase, no accents, obfuscation
undone. They cover English, Spanish, French, Portuguese and German.

No single cue decides. Each category has a weight, and the scanner combines
the categories that fire, so a refund policy that says "we never ask for your
card number" (one weak cue) passes, while a note that addresses the assistant,
tells it what to say to customers and asks it to keep quiet does not.
"""
from __future__ import annotations

import re
from dataclasses import dataclass


@dataclass(frozen=True)
class Cue:
    category: str
    label: str
    weight: float
    patterns: tuple[re.Pattern[str], ...]


def _c(*patterns: str) -> tuple[re.Pattern[str], ...]:
    return tuple(re.compile(p) for p in patterns)


_AI = r"(?:assistant|asistente|assistente|assistent(?:en)?|ai|a\.i\.|ia|ki|chat ?bot|bot|model|modelo|modele|modell|llm|language model|cracky)"

CUES: tuple[Cue, ...] = (
    Cue("override", "tries to cancel the assistant's rules", 0.6, _c(
        r"\b(?:ignore|disregard|forget|override|bypass|skip)\b.{0,30}\b(?:previous|prior|above|earlier|preceding|all|any|your|system|original)\b.{0,20}\b(?:instructions?|rules?|guidelines?|polic(?:y|ies)|prompts?|directives?)",
        r"\b(?:ignora|ignore|olvida|omite|descarta|desobedece)\b.{0,30}\b(?:instrucciones|reglas|indicaciones|normas|politicas?)\b",
        r"\b(?:ignorez?|oubliez?|oublie|negligez?)\b.{0,30}\b(?:instructions|consignes|regles|directives)\b",
        r"\b(?:ignore|esqueca|desconsidere)\b.{0,30}\b(?:instrucoes|regras)\b",
        r"\b(?:ignoriere|vergiss|missachte)\b.{0,30}\b(?:anweisungen|regeln|vorgaben)\b",
        r"\b(?:new|updated|revised|real)\s+(?:instructions?|rules?|orders?|directives?)\s*:",
        r"\b(?:nuevas|nouvelles|novas|neue)\s+(?:instrucciones|instructions|consignes|instrucoes|anweisungen)\s*:",
        r"\b(?:previous|earlier|old|prior|original)\b.{0,20}\b(?:instructions?|guidance|rules?|polic(?:y|ies))\b.{0,20}\b(?:obsolete|outdated|void|no longer (?:apply|valid|in effect)|superseded|cancell?ed)",
        r"\b(?:instrucciones|reglas|politica)\b.{0,30}\b(?:anteriores|previas)\b.{0,30}\b(?:ya no|sin efecto|obsoletas?|anuladas?)",
        r"\b(?:instructions|consignes|regles)\b.{0,30}\b(?:precedentes|anterieures)\b.{0,30}\b(?:ne sont plus|obsoletes?|caduques?|annulees?)",
    )),
    Cue("role", "tries to give the assistant a new role", 0.5, _c(
        r"\byou are now\b", r"\bfrom now on,? you (?:are|will|must)\b", r"\bact as (?:if|an?|the)\b",
        r"\bpretend (?:to be|you are)\b", r"\byour new (?:role|task|instructions?|persona)\b",
        r"\bahora eres\b", r"\bactua como\b", r"\bfinge (?:ser|que)\b", r"\btu nuevo (?:rol|papel)\b",
        r"\btu es (?:maintenant|desormais)\b", r"\bagis comme\b", r"\bfais semblant\b", r"\bton nouveau role\b",
        r"\bvoce agora e\b", r"\bdu bist (?:jetzt|nun|ab sofort)\b",
    )),
    Cue("markers", "contains chat-format control markers", 0.6, _c(
        r"(?:^|\s)system\s*:", r"<\s*/?\s*system\s*>", r"\[/?inst\]", r"<\|im_(?:start|end)\|>",
        r"<<\s*/?sys\s*>>", r"#{2,}\s*(?:instruction|system)", r"(?:^|\s)(?:assistant|user)\s*:\s",
    )),
    Cue("addresses_ai", "speaks directly to the assistant", 0.35, _c(
        rf"\b(?:note|message|instructions?|reminder|memo|directive|update|notice|alert|announcement)s?\b.{{0,15}}\b(?:to|for)\b.{{0,8}}\b{_AI}\b",
        rf"\b(?:attention|dear|hey|hello)\b,?\s*{_AI}\b",
        rf"\bif you are an? {_AI}\b",
        rf"\b(?:nota|mensaje|instrucciones?|aviso|recordatorio)\b.{{0,20}}\b(?:para|al|a la)\b.{{0,8}}\b{_AI}\b",
        rf"\bsi eres (?:un|una|el) {_AI}\b",
        rf"\b(?:note|message|consignes?|instructions?|rappel)\b.{{0,20}}\b(?:pour|a)\b.{{0,8}}\b(?:l'|l |le |la )?{_AI}\b",
        rf"\bsi tu es (?:un|une) {_AI}\b",
        rf"\b(?:nota|mensagem|instrucoes?)\b.{{0,20}}\bpara o\b.{{0,8}}\b{_AI}\b",
        rf"\b(?:hinweis|nachricht|anweisungen?)\b.{{0,20}}\b(?:an|fur|fuer)\b.{{0,8}}\b(?:den |die |das )?{_AI}\b",
    )),
    Cue("directive", "tells the assistant what to say or do", 0.3, _c(
        r"\b(?:you must|you should|you need to|always|be sure to|make sure (?:to|you))\b.{0,20}\b(?:tell|say|inform|respond|answer|reply|instruct|direct|ask|recommend)\b",
        r"\b(?:tell|inform|instruct|direct|ask|advise)\b (?:the |any |all )?(?:customers?|users?|clients?|shoppers?|buyers?)\b",
        r"\bwhen(?:ever)? (?:a |the |any )?(?:customer|user|client|shopper|buyer|someone)s? (?:asks?|inquires?|requests?|mentions?)\b",
        r"\blet (?:the |all |any )?(?:customers?|users?|shoppers?|clients?|buyers?|them) know\b",
        rf"\b(?:the |this |our )?{_AI} (?:should|must|will|needs to|has to|is to|shall)\b",
        r"\binform them\b",
        r"\b(?:dile|diles|indicale|indicales|informale|informales|pidele|pideles|responde|contesta|recomiendale)\b",
        r"\bcuando (?:un|el|algun) (?:cliente|usuario|comprador)\b.{0,15}\b(?:pregunte|consulte|pida|solicite)\b",
        r"\b(?:dis|dites|indique|indiquez|demande|demandez|reponds|repondez|conseille|conseillez)\b.{0,5}\b(?:lui|leur|au client|aux clients|a l'utilisateur)\b",
        r"\b(?:quand|lorsqu'?) ?(?:un|le|une) (?:client|utilisateur|cliente)\b.{0,15}\b(?:demande|pose|interroge)\b",
        r"\b(?:diga|informe|peca) (?:ao|aos) (?:cliente|usuario)s?\b",
        r"\b(?:sage|teile|sag) (?:dem|den) (?:kunden|nutzer|benutzer)\b",
    )),
    Cue("behavior_change", "announces a change of behavior from now on", 0.25, _c(
        r"\bfrom now on\b", r"\bstarting (?:now|today|immediately)\b", r"\bhenceforth\b", r"\bgoing forward\b",
        r"\ba partir de (?:ahora|este momento|hoy)\b", r"\bde ahora en adelante\b", r"\bdesde ahora\b",
        r"\bdesormais\b", r"\ba partir de maintenant\b", r"\bdorenavant\b", r"\ba compter d'aujourd'hui\b",
        r"\ba partir de agora\b", r"\bdaqui em diante\b", r"\bab sofort\b", r"\bvon nun an\b",
    )),
    Cue("conceal", "asks to keep the instruction secret", 0.45, _c(
        r"\b(?:do not|don't|never)\b.{0,10}\b(?:mention|reveal|disclose|tell|show|acknowledge|repeat)\b.{0,15}\b(?:this|these|the) (?:note|message|instructions?|text|section|change)\b",
        r"\bkeep (?:this|these)\b.{0,15}\b(?:secret|hidden|confidential|private)\b",
        r"\bno (?:menciones|reveles|digas|comentes|muestres|repitas)\b.{0,15}\b(?:esta|estas|este|esto|la|las)\b",
        r"\bmanten(?:ga|er)? (?:esto|esta nota)\b.{0,10}\b(?:secret|ocult|confidencial)",
        r"\bne (?:mentionn|revel|di|montr|repet)\w*\b.{0,10}\bpas\b",
        r"\bgardez? (?:ceci|cette note|ce message)\b.{0,10}\b(?:secret|confidentiel)",
        r"\bnao (?:mencione|revele|diga|mostre)\b",
        r"\b(?:erwahne|verrate|zeige)\b.{0,15}\bnicht\b",
    )),
    Cue("credentials", "asks for card numbers, CVV codes or passwords", 0.45, _c(
        r"\b(?:full|complete|entire)\b.{0,10}\b(?:card|credit card|debit card) (?:number|details)\b",
        r"\b(?:cvv|cvc|cvv2|security code|card verification)\b",
        r"\b(?:password|passcode|one[- ]time (?:code|password)|otp|2fa code|verification code|pin code|(?:online )?bank(?:ing)? (?:login|credentials|username)|social security number|ssn)\b",
        r"\bnumero (?:completo )?de (?:su |tu |la )?tarjeta\b", r"\bcodigo de seguridad\b", r"\bcontrasena\b", r"\bclave (?:bancaria|de acceso)\b",
        r"\bnumero (?:complet )?de (?:sa |votre |ta |la )?carte\b", r"\bcryptogramme\b", r"\bcode de securite\b", r"\bmot de passe\b",
        r"\bnumero do cartao\b", r"\bsenha\b", r"\bkartennummer\b", r"\bpasswort\b", r"\bprufziffer\b",
    )),
    Cue("redirect", "sends customers to an outside phone number or link", 0.2, _c(
        r"\b(?:moved|changed|relocated|is now|now at|se mudo|se ha mudado|ahora es|ahora esta en|est maintenant|a demenage|mudou)\b.{0,30}(?:\+?\d[\d\s().-]{8,}\d|https?://|www\.|\b[\w.-]+\.(?:example|com|net|org|io|xyz|shop|info)\b|\b[\w.-]+@[\w-]+\.\w+)",
        r"\b(?:through|via|using|at|on)\b (?:the |this |our )?(?:form|link|page|site|portal|website)\b.{0,10}(?:\+?\d[\d\s().-]{8,}\d|https?://|www\.|\b[\w.-]+\.(?:example|com|net|org|io|xyz|shop|info)\b|\b[\w.-]+@[\w-]+\.\w+)",
        r"\b(?:call|text|whatsapp|phone|dial|contact|email|visit|go to|send)\b.{0,40}(?:\+?\d[\d\s().-]{8,}\d|https?://|www\.|\b[\w.-]+@[\w-]+\.\w+)",
        r"\b(?:llame|llama|llamen|marque|escriba|envie|contacte|visite)\b.{0,40}(?:\+?\d[\d\s().-]{8,}\d|https?://|www\.|\b[\w.-]+@[\w-]+\.\w+)",
        r"\b(?:appelez|appelle|composez|ecrivez|envoyez|contactez|visitez)\b.{0,40}(?:\+?\d[\d\s().-]{8,}\d|https?://|www\.|\b[\w.-]+@[\w-]+\.\w+)",
    )),
    Cue("data_grab", "tries to pull other people's data or the hidden prompt", 0.5, _c(
        r"\b(?:reveal|print|show|repeat|output|list|share|include|append)\b.{0,20}\b(?:system prompt|hidden (?:prompt|instructions)|initial prompt|your instructions|internal config)",
        r"\b(?:list|share|include|reveal|send|append)\b.{0,25}\b(?:other|all)\b.{0,10}\b(?:customers?|users?|clients?)(?:'s?)?\b.{0,15}\b(?:emails?|addresses|orders|data|cards?|phone)",
        r"\b(?:revela|muestra|repite|imprime)\b.{0,15}\b(?:prompt|instrucciones (?:del sistema|internas|ocultas))\b",
        r"\b(?:datos|correos|pedidos|tarjetas|direcciones) de (?:otros|todos los) (?:clientes|usuarios)\b",
        r"\b(?:revele|affiche|repete|montre)\b.{0,15}\b(?:prompt|instructions (?:systeme|internes|cachees))\b",
        r"\b(?:donnees|courriels|commandes|cartes) (?:des|d'autres) (?:autres )?(?:clients|utilisateurs)\b",
    )),
)


# Double or curly quotes anywhere; straight single quotes only at word edges,
# so the apostrophes in "don't" and "customer's" never pair up into a quote.
_QUOTED = re.compile(
    r"[\"“«]([^\"”»]{4,200})[\"”»]"
    r"|(?:(?<=\s)|^)'([^']{4,200})'(?=[\s.,;:!?)]|$)"
)


def _inside_quotes(text: str, start: int, end: int) -> bool:
    for q in _QUOTED.finditer(text):
        group = 1 if q.group(1) is not None else 2
        if q.start(group) <= start and end <= q.end(group):
            return True
    return False


def match_cues(normalized_text: str) -> list[tuple[Cue, str, float]]:
    """Return each category that fired once: (cue, triggering text, weight).

    A phrase that only appears inside quotation marks is being mentioned, not
    used ("a mug printed with 'ignore previous instructions'"), so it counts half.
    """
    hits: list[tuple[Cue, str, float]] = []
    for cue in CUES:
        for pattern in cue.patterns:
            m = pattern.search(normalized_text)
            if m:
                quoted = _inside_quotes(normalized_text, m.start(), m.end())
                hits.append((cue, m.group(0), cue.weight * (0.5 if quoted else 1.0)))
                break
    return hits
