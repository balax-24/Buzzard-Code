import pytest
import os
import base64
from unittest.mock import MagicMock
from security_agent.tools.registry import ToolRegistry
from security_agent.storage.db import StorageManager
from security_agent.tools.browser import (
    browser_open,
    browser_goto,
    browser_click,
    browser_fill,
    browser_press,
    browser_back,
    browser_get_text,
    browser_get_links,
    browser_get_url,
    browser_screenshot,
    browser_close,
    register_browser_tools
)

# A sample HTML page using data URI
TEST_HTML = (
    "data:text/html;charset=utf-8,"
    "<html>"
    "<head><title>Test Page</title></head>"
    "<body>"
    "<h1>Hello World</h1>"
    "<a href='http://localhost:3000/about'>About Us</a>"
    "<form>"
    "<input type='text' id='username' name='username' />"
    "<button type='button' id='submit-btn' onclick='document.body.innerHTML=\"Clicked\"'>Submit</button>"
    "</form>"
    "</body>"
    "</html>"
)

def test_register_browser_tools():
    registry = ToolRegistry()
    register_browser_tools(registry)
    
    assert "browser.open" in registry.tools
    assert "browser.goto" in registry.tools
    assert "browser.click" in registry.tools
    assert "browser.fill" in registry.tools
    assert "browser.press" in registry.tools
    assert "browser.back" in registry.tools
    assert "browser.get_text" in registry.tools
    assert "browser.get_links" in registry.tools
    assert "browser.get_url" in registry.tools
    assert "browser.screenshot" in registry.tools
    assert "browser.close" in registry.tools

def test_browser_workflow():
    # 1. Open browser
    res = browser_open()
    assert "BROWSER" in res
    assert "URL: about:blank" in res

    # 2. Goto test HTML
    res = browser_goto(TEST_HTML)
    assert "BROWSER" in res
    assert "Test Page" in res
    
    # 3. Get url and title
    res = browser_get_url()
    assert "Test Page" in res

    # 4. Get text
    text = browser_get_text("h1")
    assert "Hello World" in text
    
    # 5. Get links
    links = browser_get_links()
    assert "About Us" in links
    assert "http://localhost:3000/about" in links

    # 6. Fill input
    res = browser_fill("#username", "myuser")
    assert "Test Page" in res
    
    # 7. Click button
    res = browser_click("#submit-btn")
    assert "BROWSER" in res
    
    # Text should change to Clicked
    text = browser_get_text("body")
    assert "Clicked" in text

    # 8. Close browser
    res = browser_close()
    assert "closed successfully" in res

def test_browser_screenshot(temp_db):
    storage = StorageManager(temp_db)
    session_id = "test-session"
    storage.create_session(session_id, "localhost", ["localhost"], "Test Screenshot")
    
    # Ensure browser is freshly opened
    browser_close()
    browser_open(TEST_HTML)
    
    res = browser_screenshot(session_id, storage, name="Verification Page")
    assert "Screenshot logged successfully" in res
    
    evidence_list = storage.get_evidence_list(session_id)
    assert len(evidence_list) == 1
    evidence = evidence_list[0]
    assert evidence.type.value == "screenshot"
    assert "Verification Page" in evidence.description
    
    browser_close()

def test_browser_get_links_with_selector_and_resilient_registry():
    registry = ToolRegistry()
    register_browser_tools(registry)
    
    browser_open(TEST_HTML)
    # Test selector argument directly
    links = browser_get_links(selector="body")
    assert "About Us" in links
    
    # Test through ToolRegistry with None / unexpected arguments
    res = registry.execute("browser.get_links", {"selector": None, "unexpected_param": "ignore_me"})
    assert "About Us" in res
    
    # Test with selector="None" string
    res2 = registry.execute("browser.get_links", {"selector": "None"})
    assert "About Us" in res2
    
    browser_close()
