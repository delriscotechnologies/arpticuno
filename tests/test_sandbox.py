from arpticuno.sandbox import main


def test_sandbox_preview_renders_banner_and_sections(capsys):
    code = main([])
    output = capsys.readouterr().out

    assert code == 0
    assert "Results:" in output
    assert "Target(s):" in output
    assert "│  Total ARP responders:" in output
    assert "ARP responders:" in output
    assert "192.168.1.1" in output
    banner_line = next(line for line in output.splitlines() if "Del Risco Technologies" in line)
    assert banner_line.startswith(" ")


def test_sandbox_json_contains_demo_flag(capsys):
    code = main(["--format", "json"])
    output = capsys.readouterr().out

    assert code == 0
    assert '"sandbox": true' in output
    assert '"tool": "Arpticuno"' in output
