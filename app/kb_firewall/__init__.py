"""KB Firewall: write-time and read-time protection for the RAG knowledge base."""
from app.kb_firewall.firewall import QUARANTINE_TIER, get_kb_firewall

__all__ = ["QUARANTINE_TIER", "get_kb_firewall"]
