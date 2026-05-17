"""
Тесты для rag/sources/cwe.py

Запуск: pytest tests/test_cwe_parser.py -v
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from lxml import etree

from secagent.rag.sources.cwe import parse_cwe_xml, _guess_severity


# ─────────────────────────────────────────────
# Fixture: минимальный CWE XML
# ─────────────────────────────────────────────

_CWE_XML_TEMPLATE = """\
<?xml version="1.0" encoding="UTF-8"?>
<Weakness_Catalog
    xmlns="http://cwe.mitre.org/cwe-7"
    Name="CWE" Version="4.14">
  <Weaknesses>
    <Weakness ID="89" Name="Improper Neutralization of Special Elements used in an SQL Command"
              Status="Incomplete">
      <Description>The software constructs all or part of an SQL command using externally-influenced input.</Description>
      <Extended_Description>Without sufficient removal of SQL syntax, an attacker can alter logic.</Extended_Description>
      <Applicable_Platforms>
        <Language Name="Python" Prevalence="Often"/>
        <Language Name="Java" Prevalence="Often"/>
        <Language Name="PHP" Prevalence="Often"/>
      </Applicable_Platforms>
      <Demonstrative_Examples>
        <Demonstrative_Example>
          <Example_Code Nature="bad" Language="Python">
            query = "SELECT * FROM users WHERE id = " + user_id
            cursor.execute(query)
          </Example_Code>
        </Demonstrative_Example>
      </Demonstrative_Examples>
      <Potential_Mitigations>
        <Mitigation>
          <Description>Use parameterized queries or prepared statements.</Description>
        </Mitigation>
      </Potential_Mitigations>
    </Weakness>
    <Weakness ID="22" Name="Improper Limitation of a Pathname to a Restricted Directory"
              Status="Draft">
      <Description>The software uses external input to construct a pathname.</Description>
      <Applicable_Platforms>
        <Language Name="Python" Prevalence="Often"/>
        <Language Name="Go" Prevalence="Sometimes"/>
      </Applicable_Platforms>
    </Weakness>
    <Weakness ID="9999" Name="Deprecated Weakness" Status="Deprecated">
      <Description>This is deprecated and should be ignored.</Description>
    </Weakness>
  </Weaknesses>
</Weakness_Catalog>
"""


@pytest.fixture
def cwe_xml_file(tmp_path: Path) -> Path:
    """Создаёт временный CWE XML файл."""
    xml_path = tmp_path / "cwec_latest.xml"
    xml_path.write_text(_CWE_XML_TEMPLATE, encoding="utf-8")
    return xml_path


# ─────────────────────────────────────────────
# Тесты parse_cwe_xml
# ─────────────────────────────────────────────

def test_parse_cwe_xml_returns_chunks(cwe_xml_file: Path) -> None:
    """Парсер возвращает непустой список чанков."""
    chunks, valid_ids = parse_cwe_xml(cwe_xml_file)
    assert len(chunks) > 0, "Должен вернуть хотя бы один чанк"


def test_parse_cwe_xml_skips_deprecated(cwe_xml_file: Path) -> None:
    """Deprecated-уязвимости не попадают в чанки."""
    chunks, valid_ids = parse_cwe_xml(cwe_xml_file)
    cwe_ids_in_chunks = {ch.cwe_id for ch in chunks}
    assert "CWE-9999" not in cwe_ids_in_chunks, "Deprecated не должен попасть в чанки"


def test_parse_cwe_xml_deprecated_in_valid_ids(cwe_xml_file: Path) -> None:
    """Deprecated ID всё равно попадает в valid_ids (для валидатора он всё ещё существует)."""
    _, valid_ids = parse_cwe_xml(cwe_xml_file)
    assert "CWE-9999" in valid_ids, "Deprecated ID должен быть в valid_ids"


def test_parse_cwe_xml_sql_injection_chunk(cwe_xml_file: Path) -> None:
    """CWE-89 распарсен корректно."""
    chunks, _ = parse_cwe_xml(cwe_xml_file)
    sql_chunks = [ch for ch in chunks if ch.cwe_id == "CWE-89"]
    assert len(sql_chunks) == 1

    ch = sql_chunks[0]
    assert ch.source == "cwe"
    assert "CWE-89" in ch.title
    assert "SQL" in ch.title or "sql" in ch.text.lower()


def test_parse_cwe_xml_languages(cwe_xml_file: Path) -> None:
    """Языки правильно извлекаются из Applicable_Platforms."""
    chunks, _ = parse_cwe_xml(cwe_xml_file)
    sql_chunk = next(ch for ch in chunks if ch.cwe_id == "CWE-89")
    # Python и Java — поддерживаемые языки, PHP — тоже в _LANG_MAP но не в _SUPPORTED
    assert "python" in sql_chunk.languages
    assert "java" in sql_chunk.languages


def test_parse_cwe_xml_has_examples(cwe_xml_file: Path) -> None:
    """CWE-89 содержит пример уязвимого кода."""
    chunks, _ = parse_cwe_xml(cwe_xml_file)
    sql_chunk = next(ch for ch in chunks if ch.cwe_id == "CWE-89")
    assert len(sql_chunk.examples) > 0
    assert "SELECT" in sql_chunk.examples[0].upper() or "cursor" in sql_chunk.examples[0]


def test_parse_cwe_xml_valid_ids_format(cwe_xml_file: Path) -> None:
    """Все valid_ids имеют формат CWE-NNN."""
    _, valid_ids = parse_cwe_xml(cwe_xml_file)
    for cwe_id in valid_ids:
        assert cwe_id.startswith("CWE-"), f"Неверный формат: {cwe_id}"
        assert cwe_id[4:].isdigit(), f"После CWE- должны быть цифры: {cwe_id}"


def test_parse_cwe_xml_file_not_found(tmp_path: Path) -> None:
    """FileNotFoundError при отсутствии файла."""
    with pytest.raises(FileNotFoundError):
        parse_cwe_xml(tmp_path / "nonexistent.xml")


def test_parse_cwe_xml_text_not_empty(cwe_xml_file: Path) -> None:
    """Каждый чанк содержит непустой текст."""
    chunks, _ = parse_cwe_xml(cwe_xml_file)
    for ch in chunks:
        assert ch.text.strip(), f"Пустой текст у чанка {ch.cwe_id}"


def test_parse_cwe_xml_text_length_limit(cwe_xml_file: Path) -> None:
    """Текст чанка не превышает 2000 символов."""
    chunks, _ = parse_cwe_xml(cwe_xml_file)
    for ch in chunks:
        assert len(ch.text) <= 2000, f"Текст слишком длинный: {ch.cwe_id}"


# ─────────────────────────────────────────────
# Тесты _guess_severity
# ─────────────────────────────────────────────

@pytest.mark.parametrize("name,desc,expected", [
    ("SQL Injection", "arbitrary code", "critical"),
    ("Cross-Site Scripting", "cross-site scripting attack", "high"),
    ("Information Disclosure", "reveals internal info", "medium"),
    ("Weak Algorithm", "uses weak hash", "low"),
    ("Buffer Overflow", "", "high"),
    ("Remote Code Execution", "", "critical"),
])
def test_guess_severity(name: str, desc: str, expected: str) -> None:
    result = _guess_severity(name, desc)
    assert result == expected, f"Ожидали {expected}, получили {result} для ({name!r}, {desc!r})"


# ─────────────────────────────────────────────
# Тест: metadata структура
# ─────────────────────────────────────────────

def test_chunk_metadata_keys(cwe_xml_file: Path) -> None:
    """Метаданные содержат обязательные ключи."""
    chunks, _ = parse_cwe_xml(cwe_xml_file)
    required_keys = {"cwe_id", "source", "severity_hint", "languages"}
    for ch in chunks:
        missing = required_keys - set(ch.metadata.keys())
        assert not missing, f"В метаданных {ch.cwe_id} не хватает: {missing}"