"""
SecAgent CLI — entry point приложения через Typer.

Команды:
  secagent scan ./path            # анализировать файлы
  secagent index --rebuild        # собрать базу знаний
  secagent languages              # список поддерживаемых языков
"""

from __future__ import annotations

import logging
import sys
from pathlib import Path
from typing import Optional

import typer
from rich.console import Console

from secagent.analyzer import analyze_chunk
from secagent.config import settings
from secagent.loader import load_files
from secagent.parser import parse_file
from secagent.rag.indexer import build_knowledge_base
from secagent.rag.retriever import Retriever
from secagent.reporter import render_markdown, render_terminal
from secagent.validator import validate

logger = logging.getLogger(__name__)
console = Console()

app = typer.Typer()


# ─────────────────────────────────────────────
# Логирование
# ─────────────────────────────────────────────

def _setup_logging(level: str = "INFO") -> None:
    """Настраивает логирование для приложения."""
    logging.basicConfig(
        level=level,
        format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
    )


# ─────────────────────────────────────────────
# Команда: scan
# ─────────────────────────────────────────────

@app.command()
def scan(
    path: Path = typer.Argument(
        ...,
        help="Путь к файлу или директории для анализа",
        exists=True,
    ),
    recursive: bool = typer.Option(
        True,
        "--recursive",
        "-r",
        help="Рекурсивно сканировать поддиректории",
    ),
    output: Optional[Path] = typer.Option(
        None,
        "--output",
        "-o",
        help="Сохранить отчёт в Markdown-файл",
    ),
    languages: Optional[list[str]] = typer.Option(
        None,
        "--language",
        "-l",
        help="Фильтр по языкам (можно указать несколько: -l python -l javascript)",
    ),
    min_confidence: float = typer.Option(
        0.5,
        "--min-confidence",
        "-c",
        help="Минимальный порог уверенности (0.0-1.0)",
        min=0.0,
        max=1.0,
    ),
    verbose: bool = typer.Option(
        False,
        "--verbose",
        "-v",
        help="Подробный вывод (debug логирование)",
    ),
) -> None:
    """
    Сканирует код на уязвимости.

    Примеры:
        secagent scan ./app.py
        secagent scan ./project --recursive --output report.md
        secagent scan ./src -l python -l javascript --min-confidence 0.7
    """
    try:
        # Логирование
        log_level = "DEBUG" if verbose else "INFO"
        _setup_logging(log_level)

        # Проверка, что ChromaDB существует
        if not settings.chroma_path.exists():
            console.print(
                "[red]❌ База знаний не найдена.[/red]\n"
                "[yellow]Запусти:[/yellow] [cyan]secagent index[/cyan]"
            )
            sys.exit(1)

        # 1. Загрузка файлов
        console.print(f"[cyan]📂 Сканируем: {path}[/cyan]")
        files = list(load_files(path, recursive=recursive, languages=languages))
        console.print(f"[dim]  Найдено файлов: {len(files)}[/dim]")

        if not files:
            console.print("[yellow]⚠️  Файлы не найдены.[/yellow]")
            return

        # 2. Парсинг чанков
        console.print("[cyan]🔍 Парсим код...[/cyan]")
        all_chunks = []
        for file in files:
            try:
                chunks = parse_file(file)
                all_chunks.extend(chunks)
            except Exception as e:
                logger.warning("Ошибка парсинга %s: %s", file.path, e)

        console.print(f"[dim]  Найдено чанков: {len(all_chunks)}[/dim]")

        if not all_chunks:
            console.print("[yellow]⚠️  Чанки не найдены.[/yellow]")
            return

        # 3. Инициализация retriever
        console.print("[cyan]🧠 Инициализируем RAG...[/cyan]")
        retriever = Retriever(settings)

        # 4. Анализ каждого чанка с прогресс-баром
        console.print("[cyan]🔬 Анализируем код...[/cyan]")
        all_findings = []

        from rich.progress import Progress, SpinnerColumn, TextColumn

        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
        ) as progress:
            task = progress.add_task("", total=len(all_chunks))

            for i, chunk in enumerate(all_chunks, 1):
                progress.update(
                    task,
                    description=f"[cyan]{chunk.name}[/cyan] ({i}/{len(all_chunks)})",
                )

                try:
                    # Получаем знания из базы
                    knowledge = retriever.retrieve(chunk, language_filter=True)

                    # Анализируем чанк
                    findings = analyze_chunk(chunk, knowledge)

                    # Добавляем файл в findings
                    for f in findings:
                        f.file_path = chunk.file_path

                    all_findings.extend(findings)
                except Exception as e:
                    logger.warning(
                        "Ошибка анализа %s:%s: %s",
                        chunk.file_path,
                        chunk.name,
                        e,
                    )

                progress.advance(task)

        console.print(f"[dim]  Сырых находок: {len(all_findings)}[/dim]")

        # 5. Валидация
        console.print("[cyan]✓ Валидируем результаты...[/cyan]")
        validated = validate(all_findings)
        console.print(f"[dim]  Валидных находок: {len(validated)}[/dim]")

        # 6. Отчёт в терминал
        console.print()
        render_terminal(validated)

        # 7. Экспорт в Markdown (опционально)
        if output:
            output.parent.mkdir(parents=True, exist_ok=True)
            render_markdown(validated, output)
            console.print(f"\n[green]✓ Отчёт сохранён:[/green] [cyan]{output}[/cyan]")

    except KeyboardInterrupt:
        console.print("\n[yellow]⚠️  Прервано пользователем.[/yellow]")
        sys.exit(0)
    except Exception as e:
        logger.exception("Неожиданная ошибка:")
        console.print(f"\n[red]❌ Ошибка:[/red] {e}")
        if verbose:
            import traceback
            traceback.print_exc()
        sys.exit(1)


# ─────────────────────────────────────────────
# Команда: index
# ─────────────────────────────────────────────

@app.command()
def index(
    rebuild: bool = typer.Option(
        False,
        "--rebuild",
        help="Пересобрать базу знаний (удалит старую)",
    ),
    verbose: bool = typer.Option(
        False,
        "--verbose",
        "-v",
        help="Подробный вывод",
    ),
) -> None:
    """
    Собирает (или пересобирает) базу знаний из CWE/OWASP/Semgrep.

    Это долгая операция (может занять несколько минут).

    Примеры:
        secagent index
        secagent index --rebuild
    """
    try:
        log_level = "DEBUG" if verbose else "INFO"
        _setup_logging(log_level)

        console.print("[cyan]📚 Собираем базу знаний...[/cyan]")
        if rebuild:
            console.print("[yellow]⚠️  Пересборка будет очень долгой...\\[/yellow]")

        count = build_knowledge_base(rebuild=rebuild)

        console.print(f"[green]✓ Готово![/green] Чанков в БД: {count}")

    except KeyboardInterrupt:
        console.print("\n[yellow]⚠️  Прервано пользователем.[/yellow]")
        sys.exit(0)
    except Exception as e:
        logger.exception("Ошибка индексации:")
        console.print(f"[red]❌ Ошибка:[/red] {e}")
        if verbose:
            import traceback
            traceback.print_exc()
        sys.exit(1)


# ─────────────────────────────────────────────
# Команда: languages
# ─────────────────────────────────────────────

@app.command()
def languages() -> None:
    """Показывает поддерживаемые языки программирования."""
    console.print("\n[bold cyan]Поддерживаемые языки:[/bold cyan]\n")

    lang_list = [
        ("python", ".py"),
        ("javascript", ".js, .mjs"),
        ("typescript", ".ts, .tsx"),
        ("java", ".java"),
        ("go", ".go"),
        ("c", ".c, .h"),
        ("c++", ".cpp, .cc, .hpp"),
    ]

    for lang, exts in lang_list:
        console.print(f"  • [green]{lang:12}[/green]  {exts}")

    console.print()


# ─────────────────────────────────────────────
# Main
# ─────────────────────────────────────────────

def main() -> None:
    """Entry point для secagent CLI."""
    app()


if __name__ == "__main__":
    main()