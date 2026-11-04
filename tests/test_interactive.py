import pytest
from unittest.mock import patch, MagicMock
from security_agent.cli.interactive import start_interactive_session, _extract_targets_from_text

def test_target_extraction_ignores_sentence_fragments_that_look_like_domains():
    assert _extract_targets_from_text("Do not test third-party systems.Assess the login flow.") == []
    assert _extract_targets_from_text("Assess https://Example.COM/login and example.com.") == ["example.com"]

@patch("security_agent.model.ollama.OllamaProvider.is_available", return_value=True)
@patch("security_agent.model.ollama.OllamaProvider.get_available_models", return_value=["qwen3.6:27b-uncensored"])
@patch("security_agent.cli.interactive.load_config", return_value={"model": "qwen3.6:27b-uncensored", "ollama_host": "http://localhost:11434"})
def test_interactive_session_help_exit(mock_config, mock_models, mock_available):
    """
    Verifies that the interactive REPL outputs help and exits correctly.
    """
    # Simulate entering /help, then /exit
    inputs = ["/help", "/exit"]
    
    with patch("builtins.input", side_effect=inputs):
        with patch("security_agent.cli.renderer.console.print") as mock_print:
            start_interactive_session(skip_toolchain=True)
            
            # Verify /help print output was triggered
            help_printed = False
            for call in mock_print.call_args_list:
                args = call[0]
                if args and "Interactive Commands:" in str(args[0]):
                    help_printed = True
                    break
            assert help_printed
            
            # Verify exit message was printed
            mock_print.assert_any_call("[bold cyan]Exiting interactive session. Goodbye![/bold cyan]")

@patch("security_agent.model.ollama.OllamaProvider.is_available", return_value=True)
@patch("security_agent.model.ollama.OllamaProvider.get_available_models", return_value=["qwen3.6:27b-uncensored"])
@patch("security_agent.cli.interactive.load_config", return_value={"model": "qwen3.6:27b-uncensored", "ollama_host": "http://localhost:11434"})
@patch("security_agent.cli.interactive.StorageManager")
def test_interactive_session_pause_stop(mock_storage_cls, mock_config, mock_models, mock_available):
    """
    Verifies /pause and /stop commands update session status.
    """
    mock_storage = MagicMock()
    mock_storage_cls.return_value = mock_storage
    mock_storage.get_session.return_value = {"id": "session-1234", "status": "running"}
    
    inputs = ["/pause session-1234", "/stop session-1234", "/exit"]
    with patch("builtins.input", side_effect=inputs):
        with patch("security_agent.cli.renderer.console.print") as mock_print:
            start_interactive_session(skip_toolchain=True)
            
            # Verify update_session_status called with TaskStatus.PAUSED and TaskStatus.FAILED
            from security_agent.storage.db import TaskStatus
            mock_storage.update_session_status.assert_any_call("session-1234", TaskStatus.PAUSED)
            mock_storage.update_session_status.assert_any_call("session-1234", TaskStatus.FAILED)

@patch("security_agent.model.ollama.OllamaProvider.is_available", return_value=True)
@patch("security_agent.model.ollama.OllamaProvider.get_available_models", return_value=["qwen3.6:27b-uncensored", "qwythos"])
@patch("security_agent.cli.interactive.load_config", return_value={"model": "qwythos", "ollama_host": "http://localhost:11434"})
@patch("security_agent.cli.interactive.save_config")
def test_interactive_session_model_command(mock_save_config, mock_config, mock_models, mock_available):
    """
    Verifies /model commands (list and change active model).
    """
    inputs = ["/model", "/model qwen3.6:27b-uncensored", "/exit"]
    with patch("builtins.input", side_effect=inputs):
        with patch("security_agent.cli.renderer.console.print") as mock_print:
            start_interactive_session(skip_toolchain=True)
            
            # Verify list output contains active marker
            models_listed = False
            for call in mock_print.call_args_list:
                args = call[0]
                if args and "qwythos" in str(args[0]) and "active" in str(args[0]):
                    models_listed = True
                    break
            assert models_listed
            
            # Verify success message when model switched
            mock_print.assert_any_call("[bold green]Model switched successfully to 'qwen3.6:27b-uncensored'.[/bold green]")
            mock_save_config.assert_called_with({"model": "qwen3.6:27b-uncensored", "ollama_host": "http://localhost:11434"})
