"""
Отчётность: вывод результатов анализа в терминал и Markdown.

Поддерживает:
- Цветной вывод в терминал через rich
- Экспорт в Markdown-файл
"""

from __future__ import annotations

import logging
from collections import Counter
from datetime import datetime
from pathlib import Path
from typing import Any

from rich.console import Console
from rich.panel import Panel
from rich.syntax import Syntax
from rich.table import Table

from secagent.models import Finding

logger = logging.getLogger(__name__)

# ─────────────────────────────────────────────
# Цвета и иконки по severity
# ─────────────────────────────────────────────

SEVERITY_COLORS = {
    "critical": "bold red",
    "high": "red",
    "medium": "yellow",
    "low": "blue",
    "info": "dim white",
}

SEVERITY_ICONS = {
    "critical": "🔴",
    "high": "🟠",
    "medium": "🟡",
    "low": "🔵",
    "info": "⚪",
}

SEVERITY_ORDER = ["critical", "high", "medium", "low", "info"]

console = Console()


# ─────────────────────────────────────────────
# Терминальный вывод
# ─────────────────────────────────────────────

def _lang_from_path(file_path: str) -> str:
    """Определяет язык по расширению файла для подсветки кода."""
    ext_map = {
        ".py": "python",
        ".js": "javascript",
        ".mjs": "javascript",
        ".ts": "typescript",
        ".tsx": "typescript",
        ".java": "java",
        ".go": "go",
        ".c": "c",
        ".h": "c",
        ".cpp": "cpp",
        ".cc": "cpp",
        ".cxx": "cpp",
        ".hpp": "cpp",
    }
    path = Path(file_path)
    return ext_map.get(path.suffix, "text")


def _extract_snippet(code: str, line_start: int, line_end: int) -> str:
    """
    Извлекает строки из кода по номерам.
    
    Args:
        code: полный текст кода чанка
        line_start: номер начальной строки (1-indexed)
        line_end: номер конечной строки (1-indexed, inclusive)
    
    Returns:
        Фрагмент кода со строками line_start..line_end
    """
    lines = code.split("\n")
    # line_start и line_end — 1-indexed из Finding
    start_idx = max(0, line_start - 1)
    end_idx = min(len(lines), line_end)
    snippet_lines = lines[start_idx:end_idx]
    return "\n".join(snippet_lines)


def _render_finding(finding: Finding, file_path: str | None = None) -> None:
    """
    Рендерит один Finding как Panel с цветной подсветкой.
    
    Args:
        finding: объект Finding для вывода
        file_path: путь файла (опционально, если не в finding)
    """
    severity_upper = finding.severity.upper()
    icon = SEVERITY_ICONS.get(finding.severity, "?")
    color = SEVERITY_COLORS.get(finding.severity, "white")
    
    # Заголовок с severity и CWE
    title = f"{icon} [{severity_upper}] {finding.cwe_id}: {finding.title}"
    
    # Мета-информация
    meta_lines = [
        f"[dim]Строки: {finding.line_start}–{finding.line_end}[/dim]",
        f"[dim]Уверенность: {int(finding.confidence * 100)}%[/dim]",
    ]
    meta = "  |  ".join(meta_lines)
    
    # Фрагмент кода с подсветкой
    lang = _lang_from_path(file_path or str(finding.file_path))
    syntax = Syntax(
        finding.code_snippet,
        lang,
        theme="monokai",
        line_numbers=True,
        start_line=finding.line_start,
        word_wrap=True,
    )
    
    # Описание и рекомендация
    description_text = f"[bold]Описание:[/bold]\n{finding.description}"
    recommendation_text = f"[bold]Рекомендация:[/bold]\n{finding.recommendation}"
    
    # Собираем содержимое Panel
    content = f"""
{meta}

[bold cyan]Код:[/bold cyan]
{syntax}

{description_text}

{recommendation_text}
"""
    
    # Выводим Panel с цветом по severity
    panel = Panel(
        content.strip(),
        title=title,
        border_style=color,
        expand=False,
    )
    console.print(panel)


def _render_summary(findings: list[Finding]) -> None:
    """
    Выводит сводку по findings: общее количество и распределение по severity.
    
    Args:
        findings: список валидированных Finding
    """
    if not findings:
        return
    
    # Подсчитываем по severity
    counts: dict[str, int] = Counter(f.severity for f in findings)
    
    # Сортируем по порядку severity
    summary_parts = []
    for sev in SEVERITY_ORDER:
        if sev in counts:
            icon = SEVERITY_ICONS[sev]
            count = counts[sev]
            color = SEVERITY_COLORS[sev]
            summary_parts.append(f"[{color}]{icon} {count} {sev}[/{color}]")
    
    total = len(findings)
    console.print("\n" + "=" * 60)
    console.print(f"[bold]Итого: {total} уязвимостей[/bold]  |  {' + '.join(summary_parts)}")
    console.print("=" * 60)


def render_terminal(findings: list[Finding]) -> None:
    """
    Основная функция: выводит все findings в терминал с цветной разметкой.
    
    Args:
        findings: список валидированных Finding
    """
    if not findings:
        console.print("\n[green]✓ Уязвимостей не обнаружено.[/green]\n")
        return
    
    # Заголовок
    console.print("\n[bold cyan]SecAgent — Отчёт об анализе[/bold cyan]\n")
    
    # Группируем по файлам
    by_file: dict[str, list[Finding]] = {}
    for f in findings:
        key = str(f.file_path)
        by_file.setdefault(key, []).append(f)
    
    # Выводим по файлам
    for file_path in sorted(by_file.keys()):
        file_findings = by_file[file_path]
        console.print(f"\n[bold yellow]📁 {file_path}[/bold yellow]")
        
        # Сортируем по line_start
        for f in sorted(file_findings, key=lambda x: x.line_start):
            _render_finding(f, file_path)
    
    # Итоговая сводка
    _render_summary(findings)


# ─────────────────────────────────────────────
# Markdown-отчёт
# ─────────────────────────────────────────────

def _lang_for_markdown(file_path: str) -> str:
    """
    Определяет язык программирования для fence в Markdown.
    
    Args:
        file_path: путь файла
    
    Returns:
        Язык для ```{язык}
    """
    ext_map = {
        ".py": "python",
        ".js": "javascript",
        ".mjs": "javascript",
        ".ts": "typescript",
        ".tsx": "typescript",
        ".java": "java",
        ".go": "go",
        ".c": "c",
        ".h": "c",
        ".cpp": "cpp",
        ".cc": "cpp",
        ".cxx": "cpp",
        ".hpp": "cpp",
    }
    path = Path(file_path)
    return ext_map.get(path.suffix, "text")


def render_markdown(findings: list[Finding], output: Path) -> None:
    """
    Генерирует Markdown-отчёт и сохраняет в файл.
    
    Args:
        findings: список валидированных Finding
        output: путь для сохранения отчёта
    """
    lines: list[str] = []
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    
    # ── Заголовок ──
    lines.append("# SecAgent — Отчёт об анализе\n")
    lines.append(f"**Дата и время:** {now}\n")
    
    if not findings:
        lines.append("✓ **Результат:** Уязвимостей не обнаружено.\n")
        output.write_text("\n".join(lines), encoding="utf-8")
        logger.info("Markdown-отчёт сохранён в %s", output)
        return
    
    # ── Сводка по severity ──
    counts: dict[str, int] = Counter(f.severity for f in findings)
    summary_parts = []
    for sev in SEVERITY_ORDER:
        if sev in counts:
            count = counts[sev]
            summary_parts.append(f"{count} {sev}")
    
    lines.append(f"**Найдено уязвимостей:** {len(findings)}\n")
    lines.append(f"**Распределение:** {', '.join(summary_parts)}\n")
    lines.append("---\n")
    
    # ── По файлам ──
    by_file: dict[str, list[Finding]] = {}
    for f in findings:
        key = str(f.file_path)
        by_file.setdefault(key, []).append(f)
    
    for file_path in sorted(by_file.keys()):
        file_findings = by_file[file_path]
        lines.append(f"## {file_path}\n")
        
        for f in sorted(file_findings, key=lambda x: x.line_start):
            severity_upper = f.severity.upper()
            icon = SEVERITY_ICONS.get(f.severity, "?")
            lang = _lang_for_markdown(file_path)
            
            lines.append(f"### {icon} [{severity_upper}] {f.cwe_id}: {f.title}\n")
            lines.append(f"**Строки:** {f.line_start}–{f.line_end}\n")
            lines.append(f"**Уверенность:** {int(f.confidence * 100)}%\n")
            lines.append(f"**Severity:** {f.severity.upper()}\n\n")
            
            # Блок кода
            lines.append(f"```{lang}")
            lines.append(f.code_snippet)
            lines.append("```\n")
            
            # Описание
            lines.append(f"**Описание:** {f.description}\n\n")
            
            # Рекомендация
            lines.append(f"**Рекомендация:** {f.recommendation}\n")
            
            lines.append("---\n")
    
    # ── Технические детали (опционально) ──
    lines.append("## Технические детали\n")
    lines.append(f"- **Инструмент:** SecAgent\n")
    lines.append(f"- **Версия:** 1.0\n")
    lines.append(f"- **Дата генерации:** {now}\n")
    
    # Сохраняем
    output.write_text("\n".join(lines), encoding="utf-8")
    logger.info("Markdown-отчёт сохранён в %s (%d уязвимостей)", output, len(findings))


# ─────────────────────────────────────────────
# Таблица для CLI вывода (альтернативный формат)
# ─────────────────────────────────────────────

def render_table(findings: list[Finding]) -> None:
    """
    Альтернативный формат: таблица с findings.
    
    Args:
        findings: список валидированных Finding
    """
    if not findings:
        console.print("\n[green]✓ Уязвимостей не обнаружено.[/green]\n")
        return
    
    # Создаём таблицу
    table = Table(title="Обнаруженные уязвимости", show_header=True, header_style="bold")
    table.add_column("Файл", style="cyan", width=30)
    table.add_column("CWE", style="magenta", width=10)
    table.add_column("Severity", width=12)
    table.add_column("Название", width=35)
    table.add_column("Строки", width=8)
    table.add_column("Уверенность", width=12)
    
    for f in sorted(findings, key=lambda x: (str(x.file_path), x.line_start)):
        icon = SEVERITY_ICONS.get(f.severity, "?")
        severity_display = f"{icon} {f.severity.upper()}"
        confidence_display = f"{int(f.confidence * 100)}%"
        lines_display = f"{f.line_start}-{f.line_end}"
        
        table.add_row(
            str(f.file_path),
            f.cwe_id,
            severity_display,
            f.title[:30] + ("..." if len(f.title) > 30 else ""),
            lines_display,
            confidence_display,
        )
    
    console.print(table)
    _render_summary(findings)