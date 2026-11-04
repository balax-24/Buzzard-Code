"""
Tests for DOMReducer context reduction, token efficiency, and signal extraction.
"""

from security_agent.browser.dom import DOMReducer


def test_dom_reduction_ratio_and_signal():
    bloated_html = """
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <style>
            .header { background: red; padding: 20px; font-size: 14px; }
            .sidebar { width: 300px; display: flex; flex-direction: column; }
            .btn-primary { color: white; background-color: #007bff; border-color: #007bff; }
            /* Massive stylesheet simulation */
            """ + "body { margin: 0; } \n" * 50 + """
        </style>
        <svg viewBox="0 0 100 100" xmlns="http://www.w3.org/2000/svg">
            <circle cx="50" cy="50" r="50"/>
            <path d="M 10,30 A 20,20 0,0,1 50,30 A 20,20 0,0,1 90,30 Q 90,60 50,90 Q 10,60 10,30 z"/>
        </svg>
    </head>
    <body>
        <div class="header">
            <span>Logo</span>
            <nav>
                <a href="/home">Home</a>
                <a href="/login">Sign In</a>
                <a href="/contact">Contact</a>
            </nav>
        </div>
        <div class="container">
            <h1>Login to Portal</h1>
            <form action="/login" method="POST">
                <input type="text" name="username" placeholder="Username" />
                <input type="password" name="password" placeholder="Password" />
                <button type="submit">Log In</button>
            </form>
        </div>
    </body>
    </html>
    """

    snap = DOMReducer.reduce(
        html_content=bloated_html,
        url="http://target.local/login",
        status_code=200
    )

    # Reduction ratio must be positive and significant (typically > 30% reduction on bloated pages)
    assert snap.reduction_ratio > 0.30
    assert snap.reduced_size < snap.raw_size

    planner_str = snap.to_planner_context()
    assert "=== DOM SNAPSHOT" in planner_str
    assert "URL: http://target.local/login" in planner_str
    assert "FORMS:" in planner_str
    assert "username:text" in planner_str
    assert "password:password" in planner_str
    assert "style" not in planner_str.lower()
    assert "<svg" not in planner_str.lower()
