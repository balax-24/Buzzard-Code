import os
import re
import subprocess
from pathlib import Path
from typing import List, Dict, Any
from cli.renderer import console

class SkillManager:
    """
    Manages loading, updating, and selecting skills for the autonomous agent.
    """
    def __init__(self, local_skills_dir: str = "skills"):
        self.local_skills_dir = Path(local_skills_dir)
        # Portable: overridable via BUZZARD_GLOBAL_SKILLS, defaults to ~/.buzzard/skills
        self.global_skills_dir = Path(
            os.environ.get("BUZZARD_GLOBAL_SKILLS", str(Path.home() / ".buzzard" / "skills"))
        )
        self.skills = []
        self.load_skills()

    def load_skills(self):
        """
        Recursively scans both local and global skills folders for any .md files.
        """
        self.skills = []
        
        # Scan local skills
        if self.local_skills_dir.exists():
            for p in self.local_skills_dir.glob("**/*.md"):
                if p.is_file() and not p.name.lower() == "readme.md":
                    self._try_load_skill(p, is_global=False)
                    
        # Scan global skills
        if self.global_skills_dir.exists():
            for p in self.global_skills_dir.glob("**/*.md"):
                if p.is_file() and not p.name.lower() == "readme.md":
                    self._try_load_skill(p, is_global=True)

    def _try_load_skill(self, path: Path, is_global: bool):
        try:
            content = path.read_text(errors="ignore")
            # Parse YAML frontmatter if present
            frontmatter = {}
            body = content
            
            match = re.match(r"^---\s*\n(.*?)\n---\s*\n", content, re.DOTALL)
            if match:
                fm_text = match.group(1)
                body = content[match.end():]
                # Simple parser to avoid dependency on PyYAML
                for line in fm_text.split("\n"):
                    line = line.strip()
                    if not line or line.startswith("#") or ":" not in line:
                        continue
                    k, v = line.split(":", 1)
                    frontmatter[k.strip().lower()] = v.strip().strip('"').strip("'")
            
            if path.name.lower() in ["skill.md", "index.md", "readme.md"]:
                name = frontmatter.get("name") or path.parent.name
            else:
                name = frontmatter.get("name") or path.stem
            description = frontmatter.get("description") or ""
            
            if not description:
                # Fallback: grab first lines that don't start with headers
                lines = [l.strip() for l in body.split("\n") if l.strip()]
                for line in lines:
                    if not line.startswith("#"):
                        description = line[:200]
                        break
                if not description and lines:
                    description = lines[0][:200]
            
            self.skills.append({
                "name": name,
                "description": description,
                "content": body,
                "path": str(path),
                "is_global": is_global,
                "frontmatter": frontmatter
            })
        except Exception:
            pass

    STOP_WORDS = {"hi", "hello", "hey", "the", "a", "an", "in", "on", "at", "to", "for", "of", "and", "is", "it", "me", "my", "this", "that", "with", "from"}

    def get_relevant_skills(self, query: str, limit: int = 4) -> List[Dict[str, Any]]:
        """
        Retrieves matching skills based on keyword overlap (excluding generic stop words).
        """
        if not query:
            return []
            
        raw_words = set(re.findall(r"\w+", query.lower()))
        query_words = raw_words - self.STOP_WORDS
        if not query_words:
            return []

        scored_skills = []
        for skill in self.skills:
            score = 0
            
            # Check name match
            name_words = set(re.findall(r"\w+", skill["name"].lower()))
            score += len(query_words.intersection(name_words)) * 10
            
            # Check description match
            desc_words = set(re.findall(r"\w+", skill["description"].lower()))
            score += len(query_words.intersection(desc_words)) * 3
            
            # Check tags
            tags = skill["frontmatter"].get("tags", "")
            if tags:
                tag_list = [t.strip().lower() for t in tags.split(",") if t.strip()]
                score += len(query_words.intersection(set(tag_list))) * 5
                
            if score >= 10:
                scored_skills.append((score, skill))
                
        # Sort by score descending
        scored_skills.sort(key=lambda x: x[0], reverse=True)
        return [skill for _, skill in scored_skills[:limit]]

    def install_skills(self):
        """
        Clones and updates target repositories containing external agent skills.
        """
        self.local_skills_dir.mkdir(exist_ok=True)
        repos = {
            "agent-skills": "https://github.com/addyosmani/agent-skills.git",
            "hack-skills": "https://github.com/yaklang/hack-skills.git"
        }
        
        for name, url in repos.items():
            repo_path = self.local_skills_dir / name
            if repo_path.exists():
                console.print(f"[cyan]Skill repository '{name}' already exists. Updating...[/cyan]")
                try:
                    subprocess.run(["git", "pull"], cwd=repo_path, check=True, capture_output=True, timeout=30)
                    console.print(f"[bold green]Updated '{name}' successfully.[/bold green]")
                except Exception as e:
                    console.print(f"[bold red]Failed to update '{name}': {e}[/bold red]")
            else:
                console.print(f"[cyan]Cloning skill repository '{name}' from {url}...[/cyan]")
                try:
                    subprocess.run(["git", "clone", url, str(repo_path)], check=True, capture_output=True, timeout=60)
                    console.print(f"[bold green]Cloned '{name}' successfully.[/bold green]")
                except Exception as e:
                    console.print(f"[bold red]Failed to clone '{name}': {e}[/bold red]")
                    
        # Re-load
        self.load_skills()
