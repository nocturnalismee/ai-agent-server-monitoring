from server_agent.ai import AIAnalyzer


def test_extract_text_from_gemini_response():
    response = {
        "candidates": [{
            "content": {"parts": [{"text": "Likely cause"}, {"text": ": high load"}]}
        }]
    }
    assert AIAnalyzer._extract_text(response) == "Likely cause: high load"


def test_extract_text_handles_missing_candidates():
    assert AIAnalyzer._extract_text({}) == ""
