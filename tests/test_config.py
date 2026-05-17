from secagent.config import Settings


def test_defaults():
    s = Settings()
    assert s.llm_model == "qwen2.5-coder:7b"
    assert s.embedding_model == "nomic-embed-text"
    assert s.retrieval_top_k == 5
    assert s.min_confidence == 0.5
    assert "python" in s.supported_languages


def test_env_override(monkeypatch):
    monkeypatch.setenv("SECAGENT_LLM_MODEL", "llama3:8b")
    s = Settings()
    assert s.llm_model == "llama3:8b"