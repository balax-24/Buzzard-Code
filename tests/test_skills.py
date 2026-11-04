import pytest
from pathlib import Path
from unittest.mock import patch, MagicMock
from security_agent.agent.skills import SkillManager

def test_skill_manager_load_and_parse(tmp_path):
    # Setup mock local skills folder
    local_dir = tmp_path / "skills"
    local_dir.mkdir()
    
    # Create a skill with frontmatter
    skill_1 = local_dir / "sql_injection.md"
    skill_1.write_text("""---
name: SQL Injection Playbook
description: Guidelines for auditing and exploiting SQL injection.
tags: web, sqli, database
---
# SQL Injection Guide
First paragraph content of SQL injection.""")

    # Create a skill without frontmatter
    skill_2 = local_dir / "simple_skill.md"
    skill_2.write_text("""# Simple Skill
This is the description paragraph.
Some other details here.""")

    # Create a readme to ensure it gets ignored
    readme = local_dir / "README.md"
    readme.write_text("# Skills Overview")

    # Initialize manager pointing to tmp local_dir
    with patch("security_agent.agent.skills.Path") as mock_path:
        # Mock global_skills_dir not existing to simplify
        def side_effect(path_str):
            if path_str == "skills":
                return local_dir
            return Path("/nonexistent/global/skills")
        mock_path.side_effect = side_effect
        
        manager = SkillManager(local_skills_dir="skills")
        
        assert len(manager.skills) == 2
        
        # Verify sql_injection skill details
        sqli_skill = next(s for s in manager.skills if s["name"] == "SQL Injection Playbook")
        assert sqli_skill["description"] == "Guidelines for auditing and exploiting SQL injection."
        assert sqli_skill["frontmatter"]["tags"] == "web, sqli, database"
        assert sqli_skill["is_global"] is False
        
        # Verify simple_skill details
        simple_skill = next(s for s in manager.skills if s["name"] == "simple_skill")
        assert simple_skill["description"] == "This is the description paragraph."
        assert simple_skill["is_global"] is False

def test_skill_manager_get_relevant_skills(tmp_path):
    local_dir = tmp_path / "skills"
    local_dir.mkdir()
    
    # Create two skills
    skill_1 = local_dir / "xss.md"
    skill_1.write_text("""---
name: Cross-Site Scripting Playbook
description: Guidance on identifying and validating XSS.
tags: web, frontend, security
---
XSS content here.""")

    skill_2 = local_dir / "buffer_overflow.md"
    skill_2.write_text("""---
name: Buffer Overflow Playbook
description: Guidance on finding buffer overflows in native binaries.
tags: binary, memory, pwn
---
Buffer overflow content here.""")

    with patch("security_agent.agent.skills.Path") as mock_path:
        def side_effect(path_str):
            if path_str == "skills":
                return local_dir
            return Path("/nonexistent/global/skills")
        mock_path.side_effect = side_effect
        
        manager = SkillManager(local_skills_dir="skills")
        
        # Query matching XSS
        relevant_xss = manager.get_relevant_skills("Check if target has frontend web vulnerability like XSS")
        assert len(relevant_xss) == 1
        assert relevant_xss[0]["name"] == "Cross-Site Scripting Playbook"
        
        # Query matching buffer overflow
        relevant_bo = manager.get_relevant_skills("Audit native binary memory safety buffer overflow")
        assert len(relevant_bo) == 1
        assert relevant_bo[0]["name"] == "Buffer Overflow Playbook"
        
        # Query matching nothing
        relevant_none = manager.get_relevant_skills("Something completely unrelated")
        assert len(relevant_none) == 0

@patch("subprocess.run")
def test_skill_manager_install(mock_run, tmp_path):
    local_dir = tmp_path / "skills"
    # We do not mkdir to test creation
    
    with patch("security_agent.agent.skills.Path") as mock_path:
        def side_effect(path_str):
            if path_str == "skills":
                return local_dir
            return Path("/nonexistent/global/skills")
        mock_path.side_effect = side_effect
        
        manager = SkillManager(local_skills_dir="skills")
        manager.install_skills()
        
        # Check folder creation was called / exists
        assert local_dir.exists()
        
        # Two repos should be cloned/updated
        assert mock_run.call_count == 2
        # First call args
        args_1 = mock_run.call_args_list[0][0][0]
        assert "git" in args_1
        assert "clone" in args_1
