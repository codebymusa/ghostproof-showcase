"""Conservative offline intent rules; unknown language/ambiguity requires review.

No sentence lookup table, status-based shortcut or paid model call.
"""

import re
import unicodedata
from dataclasses import dataclass


@dataclass(frozen=True)
class Intent:
    authorization: str  # DELETE_AUDIT, NON_DELETION, UNKNOWN
    reasons: tuple[str, ...]


def normalize(text):
    # Accent-fold Latin only: decomposing Hangul would destroy Korean keywords.
    return "".join("".join(x for x in unicodedata.normalize("NFKD", c)
                            if not unicodedata.combining(x))
                   if "LATIN" in unicodedata.name(c, "") else c
                   for c in unicodedata.normalize("NFC", text.lower().replace("’", "'")))


def classify_intent(text):
    t = normalize(text)
    if not t.strip(): return Intent("UNKNOWN", ("Empty request",))
    # Scope-specific negation is evaluated before deletion keywords. Keep mixed
    # contradictory instructions unresolved rather than interpreting a keyword hit.
    negative_patterns = (
        r"\b(?:do not|don't|never|not to)\s+(?:permanently\s+)?(?:delete|erase|close|remove)\b",
        r"\b(?:do not|don't|not)\s+(?:want|wish|asking|ask)(?:\s+you)?(?:\s+to)?\s+(?:delete|erase|close|remove)\b",
        r"\b(?:do not|don't)\s+(?:want|wish)\s+(?:my|this|the)\s+(?:account|profile|data)(?:\s+to\s+be)?\s+(?:permanently\s+)?(?:deleted|erased|closed)\b",
        r"\b(?:do not|don't)\s+(?:want|request)\s+(?:an?\s+)?(?:deletion|erasure)\b",
        r"\bnot (?:a |an |asking for |requesting |a request (?:to |for ))(?:deletion|erase|erasure)",
        r"\bwithout (?:deleting|removing|closing|erasing)",
        r"\bno\s+(?:borres|borren|elimines|eliminen|eliminar|borrar|cierre|cerrar)\b",
        r"\bno\s+(?:quiero|solicito|deseo)\s+(?:la\s+)?(?:eliminacion|eliminar|borrar|cerrar)\b",
        r"\bne\s+(?:supprimez|fermez|effacez)\s+pas\b",
        r"\bne\s+(?:demande|souhaite)\s+pas\s+(?:la\s+)?(?:suppression|supprimer|effacement)\b",
        r"\bne\s+(?:veux|veut|voulons|souhaite)\s+pas\s+(?:la\s+)?(?:suppression|supprimer|effacer|fermer)\b",
        r"\bnao\s+(?:exclua|apague|elimine|excluir|apagar)\b",
        r"\bnao\s+(?:quero|solicito|desejo)\s+(?:a\s+)?(?:exclusao|excluir|apagar|eliminar)\b",
        r"\b(?:loschen|loeschen|loschung)\b[^.!?;]{0,80}\bnicht\b",
        r"\bnicht\b[^.!?;]{0,40}\b(?:loschen|loeschen|loschung)\b",
        r"\bnon\s+(?:cancellare|cancellate|eliminare|eliminate|voglio\s+cancellare)\b",
        r"(?:削除|消去)しない", r"삭제하지\s*(?:마|말)",
        r"(?:削除|消去)を(?:依頼|希望|要求)していません",
        r"(?:영구\s*)?삭제(?:를)?\s*(?:원하지|요청하지)\s*않(?:습니다|아요)",
    )
    negatives = [m for p in negative_patterns for m in re.finditer(p, t)]
    positive_patterns = (
        r"\b(?:please\s+)?(?:permanently\s+)?(?:delete|erase|close)\s+(?:my |this |the |an )?(?:account|profile|personal|data|records)\b",
        r"\b(?:permanent |account |personal.data )?(?:deletion|erasure)\b",
        r"\bremove\s+(?:my |this |the |any remaining |records |personal )?(?:profile|account|records|personal|name|contact|details)",
        r"\b(?:eliminacion|eliminar|borra|borrar|borre|borren|suprimir|supresion)\b",
        r"\b(?:suppression|supprimer|supprimez|effacement|effacer)\b",
        r"\b(?:exclusao|excluir|exclua|apagar|apague)\b",
        r"\b(?:loschen|loschung|loeschen|cancellazione|cancellare)\b",
        r"(?:完全な削除|削除を依頼|削除してください)", r"(?:영구 삭제|삭제를 요청|삭제해\s*주)",
        r"\b(?:verify|confirm|audit|check)\b.{0,100}\b(?:deleted|deletion|profile is gone|account is gone|fully removed)\b",
        r"\b(?:deleting|erased|deleted|closed) (?:my |this |the )?account\b",
        r"\baccount\s+(?:had been|has been|was|is)\s+(?:deleted|erased|closed)\b",
        r"\b(?:would like|want)\b[^.!?]{0,100}\b(?:permanently\s+)?(?:deleted|erased|closed)\b",
        r"\bbefore (?:deleting|closing|erasing) (?:it|the account)\b",
        r"\bremove.{0,30}(?:search result|export file|remaining copy)\b",
        r"\b(?:inspect|tell me|check).{0,140}(?:account|profile).{0,70}(?:removed|deleted|gone)\b",
        r"(?:deleted.account|account.{0,25}gone).{0,180}(?:remove|erase|redact)",
    )
    # Mask negative phrases, not whole clauses: a separate positive directive
    # in the same sentence must remain a contradiction requiring investigation.
    clauses = re.split(r"[.!?;。]\s*|\b(?:but|however|pero|mais)\b", t)
    positive_clauses = []
    for clause in clauses:
        masked = clause
        for pattern in negative_patterns: masked = re.sub(pattern, " ", masked)
        if any(re.search(p, masked) for p in positive_patterns): positive_clauses.append(masked)
    if not negatives and re.search(r"deleted.account|tombstone", t) and re.search(r"remove (?:the )?(?:rest|personal details|identifiers)", t):
        positive_clauses.append("Explicit removal of identifiers from a deleted-account record")
    marketing = bool(re.search(r"marketing|promotional|mailing list|promocional|publicit|newsletter|配信停止|광고", t))
    restricted = bool(re.search(r"\bonly\b|\bsolo\b|\bseulement\b|\bapenas\b|のみ", t))
    keep = bool(re.search(r"keep (?:my |the )?account|leave.{0,50}(?:profile|account)|still (?:use|need|want)|conserv|garder|mantener|manter|sem apagar", t))
    non_deletion = bool(re.search(r"download|portable|copy of|information request|resetting|reset (?:my |the )?(?:login|password)|login reset|\bcorrect(?:ion)?\b(?!\s+treatment)|replace.{0,30}(?:new|number|address)|change the email|change my email|access request|export|copia|copie|corrig|acces|情報開示", t))
    account_directive = bool(re.search(r"(?:delete|erase|close).{0,25}account|suppression.{0,30}compte|elimin.{0,30}cuenta|exclu.{0,30}conta", " ".join(positive_clauses)))
    if negatives and positive_clauses:
        return Intent("UNKNOWN", ("Mixed deletion and explicit account-preservation instructions",))
    if marketing and (restricted or keep) and not account_directive:
        return Intent("NON_DELETION", ("Marketing-only request preserves account",))
    if negatives and not positive_clauses:
        return Intent("NON_DELETION", ("Explicitly negated account/data deletion",))
    if non_deletion and keep and not account_directive:
        return Intent("NON_DELETION", ("Access/export/correction request preserves account",))
    if re.search(r"\b(?:how (?:do|can|would)|what happens if|thinking about|might want to|if i)\b.{0,60}(?:delet|eras|clos)", t):
        return Intent("UNKNOWN", ("Hypothetical/instructional deletion question is not authorization",))
    if positive_clauses:
        return Intent("DELETE_AUDIT", ("Explicit deletion or verification-of-prior-deletion language",))
    if non_deletion or marketing:
        return Intent("NON_DELETION", ("Recognized non-deletion request without deletion authorization",))
    return Intent("UNKNOWN", ("Language/scope not covered by conservative offline rules",))
