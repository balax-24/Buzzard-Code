"""
CLI Entrypoint for Qwythos Production TUI (qsecurity).
"""

from __future__ import annotations

import sys
import click
from tui.app import QwythosTUIApp
from tui.config import TUIConfig


@click.command()
@click.option("--model", "-m", default=None, help="Initial model name (e.g. qwythos:latest, qwen-cyber:latest).")
@click.option("--mode", default=None, help="Initial operating mode (CHAT, ASSIST, INVESTIGATE, BROWSER, REVIEW).")
@click.option("--resume", "-r", is_flag=True, default=False, help="Resume most recent interrupted session.")
@click.option("--session", "-s", default=None, help="Specific session/checkpoint ID to resume.")
@click.option("--fake", is_flag=True, default=False, help="Run with deterministic FakeModelProvider (no Ollama required).")
def main(model: str | None, mode: str | None, resume: bool, session: str | None, fake: bool) -> None:
    """
    Launch the Qwythos Production Terminal User Interface (TUI).
    """
    config = TUIConfig.load()
    if model:
        config.default_model = model
    if mode:
        config.default_mode = mode.upper()

    resume_id = session
    if resume and not resume_id:
        from tui.controller import TUIController
        ctrl = TUIController(config=config, use_fake_model=fake)
        resume_id = ctrl.detect_interrupted_session()

    app = QwythosTUIApp(
        config=config,
        use_fake_model=fake,
        initial_model=model,
        initial_mode=mode,
        resume_session_id=resume_id,
    )
    app.run()


if __name__ == "__main__":
    main()
