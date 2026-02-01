import sys
import types
import importlib


def _reload_summarizer():
    if "src.ai.summarizer" in sys.modules:
        del sys.modules["src.ai.summarizer"]
    return importlib.import_module("src.ai.summarizer")


def make_fake_groq(attrs):
    m = types.ModuleType("groq")
    for k, v in attrs.items():
        setattr(m, k, v)
    return m


class DummyClient:
    def __init__(self, api_key=None):
        self.api_key = api_key

    def generate(self, prompt=None, model=None):
        return types.SimpleNamespace(text="generated")


def test_groq_with_groqclient_class(monkeypatch):
    fake = make_fake_groq({"GroqClient": DummyClient})
    monkeypatch.setitem(sys.modules, "groq", fake)

    summ = _reload_summarizer()
    # If no GROQ_API_KEY, should be False
    assert not summ.GROQ_AVAILABLE

    monkeypatch.setenv("GROQ_API_KEY", "key123")
    # Re-init
    ok, client = summ._init_groq_client()
    assert ok is True
    assert client is not None
    assert hasattr(client, "generate")


def test_groq_with_factory(monkeypatch):
    def factory(api_key=None):
        return DummyClient(api_key)

    fake = make_fake_groq({"create_client": factory})
    monkeypatch.setitem(sys.modules, "groq", fake)
    monkeypatch.setenv("GROQ_API_KEY", "abc")

    summ = _reload_summarizer()
    ok, client = summ._init_groq_client()
    assert ok is True
    assert client.api_key == "abc"


def test_groq_package_but_no_client(monkeypatch, capsys):
    fake = make_fake_groq({"some_helper": lambda: None})
    monkeypatch.setitem(sys.modules, "groq", fake)
    monkeypatch.delenv("GROQ_API_KEY", raising=False)

    summ = _reload_summarizer()
    ok, client = summ._init_groq_client()
    captured = capsys.readouterr()
    assert ok is False
    assert client is None
    assert "no client factory" in captured.out or "groq package installed" in captured.out
