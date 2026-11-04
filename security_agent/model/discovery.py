"""
Model Capability Discovery for local Ollama models.
Inspects parameters, context lengths, chat templates, tool calling support, and quantization.
"""

import httpx
from dataclasses import dataclass, field
from typing import Dict, Any, List, Optional
from rich.panel import Panel
from rich.table import Table
from rich.text import Text
from security_agent.cli.renderer import console


@dataclass
class ModelCapabilities:
    name: str
    family: str = "unknown"
    parameter_size: str = "unknown"
    quantization: str = "unknown"
    context_length: int = 4096
    template_type: str = "custom"
    has_tool_support: bool = False
    has_reasoning_support: bool = False
    status: str = "READY"
    raw_details: Dict[str, Any] = field(default_factory=dict)

    def format_card(self) -> Panel:
        """Renders an inspection card for the model."""
        table = Table(show_header=False, box=None, padding=(0, 1))
        table.add_column("Property", style="bold cyan", width=22)
        table.add_column("Value", style="bright_white")

        table.add_row("Name:", self.name)
        table.add_row("Runtime:", "Ollama (Local)")
        table.add_row("Family:", self.family)
        table.add_row("Parameters:", self.parameter_size)
        table.add_row("Quantization:", self.quantization)
        
        ctx_k = f"{self.context_length // 1024}K" if self.context_length >= 1024 else str(self.context_length)
        table.add_row("Context Length:", f"{ctx_k} ({self.context_length} tokens)")
        
        tool_icon = "[bold green]✓[/bold green]" if self.has_tool_support else "[yellow]Strict JSON Fallback[/yellow]"
        table.add_row("Tool Calling:", tool_icon)
        
        reasoning_icon = "[bold green]✓[/bold green]" if self.has_reasoning_support else "[dim]Standard[/dim]"
        table.add_row("Reasoning (<think>):", reasoning_icon)
        table.add_row("Streaming:", "[bold green]✓[/bold green]")
        
        status_styled = "[bold green]READY[/bold green]" if self.status == "READY" else f"[bold yellow]{self.status}[/bold yellow]"
        table.add_row("Status:", status_styled)

        return Panel(table, title="╭─ Model Capabilities ─╮", border_style="bright_blue")


class ModelDiscoverer:
    """
    Queries local Ollama instance and determines capability metadata for models.
    """
    def __init__(self, host: str = "http://localhost:11434"):
        self.host = host.rstrip("/")

    def list_models(self) -> List[str]:
        """Lists all model tags available in local Ollama instance."""
        try:
            with httpx.Client(timeout=4.0) as client:
                res = client.get(f"{self.host}/api/tags")
                if res.status_code == 200:
                    models = res.json().get("models", [])
                    return [m.get("name") for m in models if m.get("name")]
        except Exception:
            pass
        return []

    def inspect_model(self, model_name: str) -> ModelCapabilities:
        """
        Queries Ollama /api/show for full metadata and inspects capabilities.
        """
        caps = ModelCapabilities(name=model_name)
        try:
            with httpx.Client(timeout=6.0) as client:
                res = client.post(f"{self.host}/api/show", json={"name": model_name})
                if res.status_code == 200:
                    data = res.json()
                    caps.raw_details = data
                    
                    details = data.get("details", {})
                    caps.family = details.get("family", "qwen" if "qwen" in model_name.lower() else "llama")
                    caps.parameter_size = details.get("parameter_size", "8B" if "8b" in model_name.lower() else ("27B" if "27b" in model_name.lower() else "unknown"))
                    caps.quantization = details.get("quantization_level", "Q5_K_M" if "q5" in model_name.lower() else "Q4_K_M")

                    template = data.get("template", "")
                    modelfile = data.get("modelfile", "")
                    parameters = data.get("parameters", "")

                    # Check context length
                    import re
                    ctx_match = re.search(r"num_ctx\s+(\d+)", parameters + "\n" + modelfile)
                    if ctx_match:
                        caps.context_length = int(ctx_match.group(1))
                    elif "27b" in model_name.lower():
                        caps.context_length = 32768
                    else:
                        caps.context_length = 8192

                    # Check tool calling support
                    if "<tools>" in template or "tool_call" in template or "tools" in template or "k3-sec" in model_name.lower() or "qwen" in model_name.lower():
                        caps.has_tool_support = True
                        caps.template_type = "ChatML / Tool-Enabled"
                    else:
                        caps.has_tool_support = False
                        caps.template_type = "Raw Prompt"

                    # Check reasoning support
                    if "<think>" in template or "qwen" in model_name.lower() or "deep" in model_name.lower() or "mythos" in model_name.lower():
                        caps.has_reasoning_support = True
                        
                    caps.status = "READY"
        except Exception as e:
            caps.status = f"Unreachable: {e}"

        return caps

    def render_models_overview(self, active_model: str = "") -> None:
        """
        Renders the /models list view.
        """
        models = self.list_models()
        if not models:
            console.print("[bold yellow]No local models found in Ollama. Run `ollama list` to check.[/bold yellow]")
            return

        console.print("\n[bold cyan]Available Security Models:[/bold cyan]\n")
        for m in models:
            caps = self.inspect_model(m)
            is_active = (m == active_model)
            active_marker = "[bold green]✓[/bold green] " if is_active else "  "
            
            tool_text = "[green]Tools: ✓[/green]" if caps.has_tool_support else "[yellow]Tools: Strict JSON[/yellow]"
            ctx_text = f"Context: {caps.context_length // 1024}K"
            status_text = f"[bold green]Status: {caps.status}[/bold green]"
            
            name_styled = f"[bold white]{m}[/bold white]" if is_active else f"[bright_cyan]{m}[/bright_cyan]"
            console.print(f"{active_marker}{name_styled}")
            console.print(f"    {tool_text}  ·  {ctx_text}  ·  {status_text}\n")
