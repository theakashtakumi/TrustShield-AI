"""AI analysis of bounded text retrieved by the existing safe website scanner."""

from __future__ import annotations

from .common import run_analysis


def analyze_website_content(url, title, text, *, provider=None):
    visible_text = (text or "")[:12_000]
    if not visible_text.strip():
        return {"analysis_type": "website_content", "prompt_version": "trustshield-ai-1.0", "status": "skipped",
                "provider": "none", "model": "", "model_version": "unknown", "findings": [],
                "message": "No readable page text was retrieved for AI analysis."}
    payload = {"url": (url or "")[:2048], "title": (title or "")[:160], "visible_text": visible_text}
    result = run_analysis("website_content", "Identify limited, text-supported consumer-risk indicators in the retrieved webpage. Do not call promotions fraudulent by themselves. Return short exact evidence excerpts.", payload, "website", source_text=visible_text, provider=provider)
    result["source"] = "Retrieved page text; content is untrusted input"
    result["human_review"] = "AI observations are not threat-intelligence matches or human-verified findings."
    return result
