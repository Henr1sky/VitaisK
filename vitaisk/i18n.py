"""Lightweight bilingual i18n (EN / PT-BR). No external deps."""
from __future__ import annotations

import os
from functools import lru_cache

SUPPORTED = ("en", "pt")
_override = None

# Single source of truth. Keys are dotted, values are (en, pt) tuples.
_STRINGS: dict[str, tuple[str, str]] = {
    # ── CLI / general ───────────────────────────────────────────
    "app.tagline": (
        "VitaisK — multi-parameter vital signs monitor for Linux",
        "VitaisK — monitor multiparamétrico de sinais vitais do Linux",
    ),
    "app.version": ("version", "versão"),
    "app.goodbye": ("Bye.", "Até logo."),
    "app.requires_root": (
        "This command requires root (run with sudo).",
        "Este comando requer root (execute com sudo).",
    ),
    "app.not_implemented": (
        "This command will be implemented in part {part}.",
        "Este comando será implementado na parte {part}.",
    ),

    # ── doctor ──────────────────────────────────────────────────
    "doctor.check": ("check", "verificação"),
    "doctor.status": ("status", "estado"),
    "doctor.detail": ("detail", "detalhe"),
    "doctor.audit_unavailable": ("Audit log unavailable", "Log de auditoria indisponível"),
    "doctor.title": ("Dependency check", "Verificação de dependências"),
    "doctor.ok": ("ok", "ok"),
    "doctor.missing": ("missing", "ausente"),
    "doctor.optional": ("optional", "opcional"),
    "doctor.root": ("root privileges", "privilégios de root"),
    "doctor.root_yes": ("yes", "sim"),
    "doctor.root_no": ("no (some collectors will be limited)", "não (alguns coletores ficarão limitados)"),
    "doctor.kernel": ("kernel", "kernel"),
    "doctor.distro": ("distribution", "distribuição"),
    "doctor.python": ("python", "python"),
    "doctor.summary": ("{ok} ok, {missing} missing, {optional} optional missing", "{ok} ok, {missing} ausentes, {optional} opcionais ausentes"),

    # ── config ──────────────────────────────────────────────────
    "config.path": ("config path", "caminho da config"),
    "config.data": ("data dir", "diretório de dados"),
    "config.created": ("created default config at {path}", "config padrão criada em {path}"),
    "config.saved": ("saved {path}", "salvo em {path}"),
    "config.unknown_key": ("unknown key: {key}", "chave desconhecida: {key}"),
    "config.invalid_value": ("invalid value for {key}: {value}", "valor inválido para {key}: {value}"),
    "config.reset": ("config reset to defaults", "config restaurada para os padrões"),

    # ── watch ───────────────────────────────────────────────────
    "watch.starting": ("starting VitaisK monitor…", "iniciando monitor VitaisK…"),
    "watch.stopping": ("stopping VitaisK…", "parando VitaisK…"),
    "watch.session": ("session", "sessão"),
    "watch.saved_to": ("session saved to {path}", "sessão salva em {path}"),
    "watch.discarded": ("session discarded (not saved)", "sessão descartada (não salva)"),
    "watch.press_q": ("press Ctrl+C to stop", "pressione Ctrl+C para parar"),

    # ── severity ────────────────────────────────────────────────
    "sev.INFO":     ("INFO",     "INFO"),
    "sev.WARN":     ("WARN",     "AVISO"),
    "sev.ERROR":    ("ERROR",    "ERRO"),
    "sev.CRITICAL": ("CRITICAL", "CRÍTICO"),

    # ── sources ─────────────────────────────────────────────────
    "src.system":   ("system",   "sistema"),
    "src.network":  ("network",  "rede"),
    "src.metrics":  ("metrics",  "métricas"),
    "src.audit":    ("audit",    "auditoria"),
    "src.kernel":   ("kernel",   "kernel"),
    "src.auth":     ("auth",     "autenticação"),
    "src.firewall": ("firewall", "firewall"),

    # ── capture / export / sessions ─────────────────────────────
    "capture.collector": ("packet capture", "captura de pacotes"),
    "capture.tcpdump_required": ("Packet capture requires tcpdump.", "A captura de pacotes requer tcpdump."),
    "capture.positive_limits": ("Duration and size must be positive.", "A duração e o tamanho devem ser positivos."),
    "capture.failed": ("tcpdump did not produce a capture. Check the interface and permissions.",
                       "O tcpdump não gravou uma captura. Confira a interface e as permissões."),
    "capture.starting": ("capturing on {iface} ({duration}s)…", "capturando em {iface} ({duration}s)…"),
    "capture.done": ("pcap written to {path} ({size})", "pcap gravado em {path} ({size})"),
    "capture.no_tcpdump": (
        "tcpdump not found and scapy is not installed. Install one of them.",
        "tcpdump não encontrado e scapy não instalado. Instale um dos dois.",
    ),
    "export.same_file": ("Choose an output outside the source session", "Escolha um arquivo diferente da sessão original"),
    "export.done": ("exported to {path} ({size})", "exportado para {path} ({size})"),
    "sessions.empty": ("no saved sessions", "nenhuma sessão salva"),
    "sessions.not_found": ("Session not found", "Sessão não encontrada"),
    "sessions.prune_limit": ("Specify --keep or --max-size", "Informe --keep ou --max-size"),
    "sessions.removed": ("Sessions removed: {count}", "Sessões removidas: {count}"),
    "rules.not_found": ("Rule not found", "Regra não encontrada"),
    "sessions.header": ("ID", "ID"),
}


def _detect_lang() -> str:
    """Detect language: explicit override, then $LANG/$LC_ALL, else EN."""
    if _override is not None:
        return _override
    explicit = os.environ.get("VITAISK_LANG", "").strip().lower()
    if explicit in SUPPORTED:
        return explicit
    raw = (
        os.environ.get("LC_ALL")
        or os.environ.get("LC_MESSAGES")
        or os.environ.get("LANG")
        or ""
    ).lower()
    if raw.startswith("pt"):
        return "pt"
    return "en"


@lru_cache(maxsize=1)
def current_lang() -> str:
    return _detect_lang()


def set_lang(lang: str) -> None:
    """Force a language for this process. Accepts 'en', 'pt', 'auto'."""
    global _override
    if lang != "auto" and lang not in SUPPORTED:
        raise ValueError(f"unsupported language: {lang!r} (use one of {SUPPORTED})")
    _override = None if lang == "auto" else lang
    current_lang.cache_clear()


def t(key: str, **fmt) -> str:
    """Translate a dotted key. Falls back to the key itself if missing."""
    pair = _STRINGS.get(key)
    if pair is None:
        return key
    msg = pair[1] if current_lang() == "pt" else pair[0]
    return msg.format(**fmt) if fmt else msg


# Common alias — used everywhere as `_("key")`
_ = t