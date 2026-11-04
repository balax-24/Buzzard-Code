"""
Canonical Prompt Formatter for Buzzard-Sec.

Provides an authoritative, deterministic, and tokenizer-aware prompt formatting path
shared across:
- Dataset training and transition tokenization
- Checkpoint evaluation and probing
- Benchmark prompt construction
- Adversarial holdout evaluation
"""

from enum import Enum
from typing import Any, Dict, List, Optional
import torch


class FormatMode(str, Enum):
    """
    Canonical prompt formatting mode.
    """
    DIRECT = "direct"                  # Canonical raw format (<s>{prompt} {completion}</s>) matching Dataset V2.1
    CHAT_TEMPLATE = "chat_template"    # Tokenizer chat template (<s>[INST] {prompt} [/INST] {completion}</s>)


class CanonicalPromptFormatter:
    """
    Authoritative prompt formatter ensuring synchronization between training,
    evaluation, benchmarking, and inference.
    """

    DEFAULT_MODE: FormatMode = FormatMode.DIRECT

    @classmethod
    def build_task_state_prompt(
        cls,
        task_goal: str,
        target: str,
        scope: Optional[str] = None,
        observation: Optional[str] = None,
    ) -> str:
        """
        Constructs canonical task-state prompt matching the Buzzard-Sec Dataset V2.1 structure:
        Goal: ...
        Scope: ...
        Target: ...
        Current Observation: ...
        """
        scope_val = scope.strip() if scope else target.strip()
        obs_val = observation.strip() if observation else f"Initial assessment of target {target.strip()}"
        return (
            f"Goal: {task_goal.strip()}\n"
            f"Scope: {scope_val}\n"
            f"Target: {target.strip()}\n"
            f"Current Observation: {obs_val}"
        )

    @classmethod
    def format_user_prompt(
        cls,
        prompt_text: Optional[str] = None,
        system_prompt: Optional[str] = None,
        tokenizer: Optional[Any] = None,
        mode: FormatMode = FormatMode.DIRECT,
        prompt: Optional[str] = None,
    ) -> str:
        """
        Formats a user prompt for model inference / evaluation.
        """
        active_mode = mode or cls.DEFAULT_MODE
        raw_p = prompt_text if prompt_text is not None else (prompt or "")
        clean_prompt = raw_p.strip()

        if active_mode == FormatMode.CHAT_TEMPLATE and tokenizer is not None and hasattr(tokenizer, "apply_chat_template"):
            messages = []
            if system_prompt:
                messages.append({"role": "system", "content": system_prompt.strip()})
            messages.append({"role": "user", "content": clean_prompt})
            return tokenizer.apply_chat_template(
                messages,
                tokenize=False,
                add_generation_prompt=True,
            )

        # DIRECT mode: return canonical prompt directly without adding unaligned wrappers
        if system_prompt and not clean_prompt.startswith("System:"):
            return f"System: {system_prompt.strip()}\n\n{clean_prompt}"
        return clean_prompt

    @classmethod
    def format_training_pair(
        cls,
        prompt_text: Optional[str] = None,
        completion_text: Optional[str] = None,
        system_prompt: Optional[str] = None,
        tokenizer: Optional[Any] = None,
        mode: FormatMode = FormatMode.DIRECT,
        prompt: Optional[str] = None,
        completion: Optional[str] = None,
    ) -> str:
        """
        Formats a training prompt-completion pair text.
        """
        active_mode = mode or cls.DEFAULT_MODE
        raw_p = prompt_text if prompt_text is not None else (prompt or "")
        raw_c = completion_text if completion_text is not None else (completion or "")
        clean_prompt = raw_p.strip()
        clean_completion = raw_c.strip()

        if active_mode == FormatMode.CHAT_TEMPLATE and tokenizer is not None and hasattr(tokenizer, "apply_chat_template"):
            messages = []
            if system_prompt:
                messages.append({"role": "system", "content": system_prompt.strip()})
            messages.append({"role": "user", "content": clean_prompt})
            messages.append({"role": "assistant", "content": clean_completion})
            return tokenizer.apply_chat_template(
                messages,
                tokenize=False,
            )

        # DIRECT mode: canonical 'prompt completion' text
        if system_prompt and not clean_prompt.startswith("System:"):
            clean_prompt = f"System: {system_prompt.strip()}\n\n{clean_prompt}"
        return f"{clean_prompt} {clean_completion}"

    @classmethod
    def tokenize_training_transition(
        cls,
        record: Any,
        tokenizer: Any,
        max_seq_length: int = 512,
        mode: Optional[FormatMode] = None,
    ) -> Dict[str, torch.Tensor]:
        """
        Tokenizes a transition record with exact prompt instruction masking (-100 for labels on prompt tokens).
        """
        active_mode = mode or cls.DEFAULT_MODE
        prompt = record.prompt_text.strip()
        completion = record.target_completion.strip()

        if active_mode == FormatMode.CHAT_TEMPLATE and hasattr(tokenizer, "apply_chat_template"):
            messages_prompt = [{"role": "user", "content": prompt}]
            prompt_str = tokenizer.apply_chat_template(messages_prompt, tokenize=False, add_generation_prompt=True)

            messages_full = [
                {"role": "user", "content": prompt},
                {"role": "assistant", "content": completion},
            ]
            full_str = tokenizer.apply_chat_template(messages_full, tokenize=False)

            prompt_tokens = tokenizer(prompt_str, add_special_tokens=False, truncation=False)["input_ids"]
            full_tokens = tokenizer(full_str, add_special_tokens=False, truncation=True, max_length=max_seq_length)["input_ids"]
        else:
            # DIRECT mode: <s>{prompt} {completion}</s>
            full_str = f"{prompt} {completion}"
            prompt_tokens = tokenizer(
                prompt,
                add_special_tokens=True,
                truncation=False,
                return_tensors=None,
            )["input_ids"]

            full_tokens = tokenizer(
                full_str,
                add_special_tokens=True,
                truncation=True,
                max_length=max_seq_length,
                return_tensors=None,
            )["input_ids"]

        input_ids = list(full_tokens)
        if input_ids[-1] != tokenizer.eos_token_id:
            if len(input_ids) < max_seq_length:
                input_ids.append(tokenizer.eos_token_id)
            else:
                input_ids[-1] = tokenizer.eos_token_id

        attention_mask = [1] * len(input_ids)

        # Mask labels: prompt tokens get -100 so loss is only calculated on completion
        prompt_len = min(len(prompt_tokens), len(input_ids))
        labels = [-100] * prompt_len + input_ids[prompt_len:]

        return {
            "input_ids": torch.tensor(input_ids, dtype=torch.long),
            "attention_mask": torch.tensor(attention_mask, dtype=torch.long),
            "labels": torch.tensor(labels, dtype=torch.long),
        }
