import os
import json
import httpx
from typing import List, Dict, Any, Generator, Optional
from security_agent.model.provider import ModelProvider

class OllamaProvider(ModelProvider):
    """
    Implementation of ModelProvider for local Ollama server.
    """
    
    # 4096 accommodates prompt and tool schemas comfortably while preventing CUDA OOM on consumer GPUs.
    DEFAULT_NUM_CTX = 4096
    
    def __init__(
        self,
        host: Optional[str] = None,
        model_name: Optional[str] = None,
        num_ctx: Optional[int] = None,
        num_gpu: Optional[int] = None,
        think: Optional[bool] = None,
        keep_alive: Optional[str] = None,
    ):
        # Resolve Ollama host: check parameter first, then env variable, then default
        env_host = os.environ.get("OLLAMA_HOST", "http://localhost:11434")
        self.host = host or env_host
        # Strip trailing slash if present
        if self.host.endswith("/"):
            self.host = self.host[:-1]
            
        # Resolve Model name: parameter, then env variable, then default qwen3.6:27b-uncensored
        env_model = os.environ.get("OLLAMA_MODEL", "qwen3.6:27b-uncensored")
        self.model_name = model_name or env_model
        
        # Resolve context window size
        env_ctx = os.environ.get("OLLAMA_NUM_CTX")
        self.num_ctx = num_ctx or (int(env_ctx) if env_ctx else self.DEFAULT_NUM_CTX)
        env_num_gpu = os.environ.get("OLLAMA_NUM_GPU")
        self.num_gpu = num_gpu if num_gpu is not None else (int(env_num_gpu) if env_num_gpu else None)

        # Reasoning models such as Qwythos can spend the whole output budget in
        # hidden thinking and never emit a tool call. Tool agents need a direct
        # response by default; users can opt back in per configuration.
        env_think = os.environ.get("OLLAMA_THINK", "false").strip().lower()
        self.think = think if think is not None else env_think in {"1", "true", "yes", "on"}
        self.keep_alive = keep_alive or os.environ.get("OLLAMA_KEEP_ALIVE", "30m")
        
        self.client = httpx.Client(timeout=900.0)  # 15 min — large models on CPU need time

    def switch_model(self, model_name: str) -> str:
        """Switch the active model. Returns the previous model name."""
        previous = self.model_name
        if model_name and model_name != previous:
            self.model_name = model_name
        return previous

    @property
    def current_model(self) -> str:
        return self.model_name

    def _build_options(self, options: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """
        Merges num_ctx into options to ensure context window is always set.
        """
        merged = {"num_ctx": self.num_ctx}
        if self.num_gpu is not None:
            merged["num_gpu"] = self.num_gpu
        if options:
            merged.update(options)
        return merged

    def is_available(self) -> bool:
        """
        Check if Ollama service is reachable. Attempts to auto-start if not.
        """
        try:
            response = self.client.get(self.host)
            if response.status_code == 200:
                return True
        except Exception:
            pass

        # Try auto-starting ollama serve in the background
        import shutil
        import subprocess
        import time
        if shutil.which("ollama"):
            try:
                subprocess.Popen(["ollama", "serve"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                for _ in range(5):
                    time.sleep(1)
                    try:
                        response = self.client.get(self.host)
                        if response.status_code == 200:
                            return True
                    except Exception:
                        pass
            except Exception:
                pass
        return False


    def get_available_models(self) -> List[str]:
        """
        Query Ollama for installed models.
        """
        try:
            response = self.client.get(f"{self.host}/api/tags")
            if response.status_code == 200:
                data = response.json()
                return [model["name"] for model in data.get("models", [])]
            return []
        except Exception:
            return []

    def generate(
        self, 
        prompt: str, 
        system_prompt: Optional[str] = None, 
        options: Optional[Dict[str, Any]] = None
    ) -> str:
        """
        Direct completion using Ollama's /api/generate endpoint.
        """
        url = f"{self.host}/api/generate"
        payload = {
            "model": self.model_name,
            "prompt": prompt,
            "stream": False,
            "keep_alive": self.keep_alive,
            "options": self._build_options(options)
        }
        if system_prompt:
            payload["system"] = system_prompt

        try:
            response = self.client.post(url, json=payload)
            if response.status_code == 200:
                return response.json().get("response", "")
            else:
                raise Exception(f"Ollama API returned status code {response.status_code}: {response.text}")
        except Exception as e:
            raise Exception(f"Error during Ollama generate: {e}")

    def generate_stream(
        self,
        prompt: str,
        system_prompt: Optional[str] = None,
        options: Optional[Dict[str, Any]] = None
    ) -> Generator[str, None, None]:
        """
        Streams response tokens from Ollama's /api/generate endpoint.
        """
        url = f"{self.host}/api/generate"
        payload = {
            "model": self.model_name,
            "prompt": prompt,
            "stream": True,
            "keep_alive": self.keep_alive,
            "options": self._build_options(options)
        }
        if system_prompt:
            payload["system"] = system_prompt

        with self.client.stream("POST", url, json=payload) as response:
            if response.status_code != 200:
                body = response.read().decode("utf-8", errors="replace")
                raise Exception(f"Ollama API returned status code {response.status_code}: {body}")
            for line in response.iter_lines():
                if line:
                    data = json.loads(line)
                    chunk = data.get("response", "")
                    if chunk:
                        yield chunk

    def _compute_expanded_context(self, error_body: str, current_ctx: int) -> int:
        import re
        match = re.search(r"n_prompt_tokens[^\d]*(\d+)", error_body)
        if not match:
            match = re.search(r"request \((\d+) tokens\)", error_body)
        if match:
            needed = int(match.group(1))
            new_ctx = max(current_ctx * 2, needed + 4096)
        else:
            new_ctx = current_ctx * 2
        return min(new_ctx, 131072)

    def _normalize_chat_messages(self, messages: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Ensures system message is only at index 0 to satisfy strict Jinja chat templates."""
        normalized = []
        for i, m in enumerate(messages):
            mc = dict(m)
            if i > 0 and mc.get("role") == "system":
                mc["role"] = "user"
            normalized.append(mc)
        return normalized

    def capabilities(self) -> Dict[str, Any]:
        """Declares native tools only when this model's own metadata lists them."""
        declared = super().capabilities()
        declared["local"] = True
        declared["native_tools"] = "tools" in self._model_capabilities()
        return declared

    def _model_capabilities(self) -> List[str]:
        cached = getattr(self, "_capabilities_cache", None)
        if cached is not None and cached[0] == self.model_name:
            return cached[1]
        try:
            response = self.client.post(f"{self.host}/api/show", json={"name": self.model_name}, timeout=5.0)
            listed = response.json().get("capabilities") or [] if response.status_code == 200 else []
        except (httpx.HTTPError, ValueError):
            listed = []
        self._capabilities_cache = (self.model_name, listed)
        return listed

    def chat(
        self, 
        messages: List[Dict[str, Any]], 
        tools: Optional[List[Dict[str, Any]]] = None,
        options: Optional[Dict[str, Any]] = None
    ) -> Dict[str, Any]:
        """
        Sends a chat request to Ollama with optional function/tool definitions.
        Includes automated retries and adaptive context reduction on CUDA OOM.
        """
        url = f"{self.host}/api/chat"
        norm_messages = self._normalize_chat_messages(messages)
        max_retries = 3
        for attempt in range(max_retries):
            merged_options = self._build_options(options)
            payload = {
                "model": self.model_name,
                "messages": norm_messages,
                "stream": False,
                "think": self.think,
                "keep_alive": self.keep_alive,
                "options": merged_options,
            }
            if tools:
                payload["tools"] = tools

            try:
                response = self.client.post(url, json=payload)
                low_text = response.text.lower()
                if response.status_code == 200:
                    result = response.json()
                    return {
                        "message": result.get("message", {}),
                        "done": result.get("done", True),
                        "metrics": {
                            "total_duration": result.get("total_duration"),
                            "load_duration": result.get("load_duration"),
                            "prompt_eval_count": result.get("prompt_eval_count"),
                            "prompt_eval_duration": result.get("prompt_eval_duration"),
                            "eval_count": result.get("eval_count"),
                            "eval_duration": result.get("eval_duration"),
                        }
                    }
                elif response.status_code == 400 and "exceed" in low_text and "context" in low_text:
                    if attempt < max_retries - 1:
                        current_ctx = merged_options.get("num_ctx", self.num_ctx)
                        new_ctx = self._compute_expanded_context(response.text, current_ctx)
                        self.num_ctx = new_ctx
                        import sys
                        print(f"\033[33m[context-fix] Prompt exceeds {current_ctx} tokens, auto-expanding num_ctx to {new_ctx} and retrying...\033[0m", file=sys.stderr)
                        continue
                    else:
                        raise Exception(f"Ollama API returned status code {response.status_code}: {response.text}")
                elif response.status_code == 400 and tools and "does not support tools" in response.text.lower():
                    # Some useful local GGUFs (for example Dolphin variants)
                    # are not tagged for Ollama native tools. The agent prompt
                    # also supports a strict text JSON fallback, so retry once
                    # without the unsupported API field instead of failing.
                    payload = {key: value for key, value in payload.items() if key != "tools"}
                    response = self.client.post(url, json=payload)
                    if response.status_code == 200:
                        result = response.json()
                        return {
                            "message": result.get("message", {}),
                            "done": result.get("done", True),
                            "metrics": {
                                "total_duration": result.get("total_duration"),
                                "load_duration": result.get("load_duration"),
                                "prompt_eval_count": result.get("prompt_eval_count"),
                                "prompt_eval_duration": result.get("prompt_eval_duration"),
                                "eval_count": result.get("eval_count"),
                                "eval_duration": result.get("eval_duration"),
                            }
                        }
                elif response.status_code == 500 and ("out of memory" in response.text.lower() or "cudamalloc" in response.text.lower() or "allocate compute" in response.text.lower()):
                    # CUDA VRAM allocation failure — reduce context window and retry
                    if attempt < max_retries - 1:
                        current_ctx = merged_options.get("num_ctx", self.num_ctx)
                        new_ctx = max(2048, current_ctx // 2)
                        self.num_ctx = new_ctx
                        import sys
                        print(f"\033[33m[gpu-memory-fix] CUDA out of memory with num_ctx={current_ctx}, reducing to num_ctx={new_ctx} for this and future steps...\033[0m", file=sys.stderr)
                        continue
                    else:
                        raise Exception(f"Ollama API returned status code {response.status_code}: {response.text}")
                else:
                    raise Exception(f"Ollama API returned status code {response.status_code}: {response.text}")
            except Exception as e:
                if attempt < max_retries - 1 and ("exceed" in str(e).lower() and "context" in str(e).lower()):
                    continue
                if attempt < max_retries - 1 and ("out of memory" in str(e).lower() or "cudamalloc" in str(e).lower()):
                    continue
                raise Exception(f"Error during Ollama chat: {e}")
        
        raise Exception("Ollama chat failed after retries")

    def stream_chat(
        self, 
        messages: List[Dict[str, Any]], 
        tools: Optional[List[Dict[str, Any]]] = None,
        options: Optional[Dict[str, Any]] = None
    ) -> Generator[Dict[str, Any], None, None]:
        """
        Streams a chat response token-by-token.

        Mirrors the retry behaviour of ``chat``: if Ollama returns a 500
        because the GPU cannot allocate the requested context window (CUDA
        OOM / cudaMalloc failure), halve ``num_ctx`` and retry so the agent
        keeps running on constrained hardware instead of failing the whole
        task. Non-OOM errors are raised with the response body for diagnosis.
        """
        url = f"{self.host}/api/chat"
        norm_messages = self._normalize_chat_messages(messages)
        max_retries = 3
        for attempt in range(max_retries):
            merged_options = self._build_options(options)
            payload = {
                "model": self.model_name,
                "messages": norm_messages,
                "stream": True,
                "think": self.think,
                "keep_alive": self.keep_alive,
                "options": merged_options,
            }
            if tools:
                payload["tools"] = tools

            try:
                with self.client.stream("POST", url, json=payload) as response:
                    if response.status_code != 200:
                        body = response.read().decode("utf-8", errors="replace")
                        low = body.lower()
                        if response.status_code == 400 and "exceed" in low and "context" in low and attempt < max_retries - 1:
                            current_ctx = self.num_ctx
                            new_ctx = self._compute_expanded_context(body, current_ctx)
                            self.num_ctx = new_ctx
                            import sys
                            print(
                                f"\033[33m[context-fix] Prompt exceeds {current_ctx} tokens, "
                                f"auto-expanding num_ctx to {new_ctx} and retrying...\033[0m",
                                file=sys.stderr,
                            )
                            continue
                        oom = (
                            "out of memory" in low
                            or "cudamalloc" in low
                            or "allocate compute" in low
                            or "no space left" in low
                        )
                        if oom and attempt < max_retries - 1:
                            current_ctx = self.num_ctx
                            new_ctx = max(2048, current_ctx // 2)
                            self.num_ctx = new_ctx
                            import sys
                            print(
                                f"\033[33m[gpu-memory-fix] CUDA out of memory with "
                                f"num_ctx={current_ctx}, reducing to num_ctx={new_ctx} "
                                f"and retrying...\033[0m",
                                file=sys.stderr,
                            )
                            continue
                        raise Exception(
                            f"Ollama API returned status code {response.status_code}: {body[:500]}"
                        )

                    for line in response.iter_lines():
                        if not line:
                            continue
                        data = json.loads(line)
                        yield {
                            "message": data.get("message", {}),
                            "done": data.get("done", False),
                            "metrics": {
                                "total_duration": data.get("total_duration"),
                                "load_duration": data.get("load_duration"),
                                "prompt_eval_count": data.get("prompt_eval_count"),
                                "prompt_eval_duration": data.get("prompt_eval_duration"),
                                "eval_count": data.get("eval_count"),
                                "eval_duration": data.get("eval_duration"),
                            } if data.get("done", False) else None
                        }
                    return
            except Exception as e:
                if attempt < max_retries - 1 and (
                    "out of memory" in str(e).lower() or "cudamalloc" in str(e).lower()
                ):
                    continue
                raise Exception(f"Error streaming from Ollama: {e}")

        raise Exception("Ollama streaming failed after retries")
