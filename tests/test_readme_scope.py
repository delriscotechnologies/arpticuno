from pathlib import Path


def test_readme_documents_simple_v1_scope():
    text = Path("README.md").read_text(encoding="utf-8")

    assert "Arpticuno" in text
    assert "arpticuno scan" in text
    assert "first 7000 TCP ports" in text
    assert "Nmap" not in text
