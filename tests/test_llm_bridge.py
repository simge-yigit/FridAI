import sys
import os

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from llm_bridge import clean_code


class TestCleanCode:
    def test_strips_js_markdown_fence(self):
        raw = '```javascript\nJava.perform(function(){});\n```'
        assert clean_code(raw) == "Java.perform(function(){});"

    def test_strips_js_short_fence(self):
        raw = '```js\nconsole.log("hi");\n```'
        assert clean_code(raw) == 'console.log("hi");'

    def test_strips_plain_fence(self):
        raw = '```\nJava.perform(function(){});\n```'
        assert clean_code(raw) == "Java.perform(function(){});"

    def test_no_fences_finds_java_perform(self):
        raw = "Here is your code:\nJava.perform(function(){\n  // hook\n});"
        result = clean_code(raw)
        assert result.startswith("Java.perform")

    def test_no_fences_finds_interceptor(self):
        raw = "Explanation text\nInterceptor.attach(ptr, {});"
        result = clean_code(raw)
        assert result.startswith("Interceptor.attach")

    def test_returns_raw_when_no_markers(self):
        raw = "some random text"
        assert clean_code(raw) == "some random text"

    def test_empty_string(self):
        assert clean_code("") == ""

    def test_none_returns_none(self):
        assert clean_code(None) is None

    def test_multiple_fences_takes_first(self):
        raw = (
            "```javascript\nfirst();\n```\n"
            "```javascript\nsecond();\n```"
        )
        assert clean_code(raw) == "first();"

    def test_whitespace_only(self):
        assert clean_code("   \n\n  ") == ""

    def test_preamble_before_java_perform(self):
        raw = "Sure! Here is the code.\n\nJava.perform(function(){\n  hook();\n});"
        result = clean_code(raw)
        assert "Java.perform" in result
        assert "Sure!" not in result
