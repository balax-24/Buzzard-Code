"""Score a saved decision dataset's held-out split with resumable per-case output."""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
import time
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any

import torch
from peft import PeftModel
from transformers import AutoModelForCausalLM, AutoTokenizer, StoppingCriteriaList

REPO_ROOT = Path(__file__).resolve().parents[2]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from benchmark.run_corrected_benchmark import JsonClosingBraceStoppingCriteria
from benchmark.decision_metrics import format_benchmark_prompt
from model.decision_contract import DecisionType, ModelDecisionParser


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _load_rows(path: Path) -> list[dict[str, Any]]:
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]


def _action_matches(expected: dict[str, Any], actual: Any) -> bool:
    if expected.get("decision_type") != "TOOL_CALL":
        return actual is None
    selected = expected.get("selected_action") or {}
    if actual is None or actual.tool_name != selected.get("tool_name"):
        return False
    expected_args = selected.get("arguments") or {}
    actual_args = actual.arguments or {}
    return all(actual_args.get(key) == value for key, value in expected_args.items())


def _case_correct(expected: dict[str, Any], decision: Any) -> bool:
    if decision.decision_type.value != expected.get("decision_type"):
        return False
    if not _action_matches(expected, decision.selected_action):
        return False
    expected_completion = expected.get("completion_assessment") or {}
    if expected.get("decision_type") == "COMPLETE":
        actual = decision.completion_assessment
        return actual is not None and actual.status == expected_completion.get("status")
    expected_recovery = expected.get("recovery_decision") or {}
    if expected.get("decision_type") == "RECOVERY" and expected_recovery.get("failure_category"):
        actual = decision.recovery_decision
        return actual is not None and actual.failure_category == expected_recovery["failure_category"]
    return True


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--test-jsonl", type=Path, required=True)
    parser.add_argument("--adapter", type=Path, required=True)
    parser.add_argument("--output-dir", type=Path, required=True)
    parser.add_argument("--base-model", default="unsloth/mistral-7b-instruct-v0.3-bnb-4bit")
    parser.add_argument("--tokenizer", default="mistralai/Mistral-7B-Instruct-v0.3")
    args = parser.parse_args()

    rows = _load_rows(args.test_jsonl)
    args.output_dir.mkdir(parents=True, exist_ok=True)
    predictions_path = args.output_dir / "heldout_predictions.json"
    metrics_path = args.output_dir / "heldout_metrics.json"
    manifest_path = args.output_dir / "run_manifest.json"
    manifest = {
        "test_sha256": sha256(args.test_jsonl),
        "adapter": str(args.adapter.resolve()),
        "base_model": args.base_model,
        "tokenizer": args.tokenizer,
        "prompt_mode": "CanonicalPromptFormatter.DIRECT",
        "max_new_tokens": 130,
    }
    prior: dict[str, dict[str, Any]] = {}
    if predictions_path.exists():
        if not manifest_path.exists() or json.loads(manifest_path.read_text()) != manifest:
            raise RuntimeError("Existing held-out outputs do not match this dataset/model; use a fresh output directory.")
        prior = {row["transition_id"]: row for row in json.loads(predictions_path.read_text())}
    else:
        manifest_path.write_text(json.dumps(manifest, indent=2), encoding="utf-8")

    pending = [row for row in rows if row["transition_id"] not in prior]
    print(f"Held-out rows: {len(rows)}; already complete: {len(prior)}; remaining: {len(pending)}", flush=True)
    if pending:
        tokenizer = AutoTokenizer.from_pretrained(args.tokenizer, local_files_only=True)
        base = AutoModelForCausalLM.from_pretrained(
            args.base_model, device_map="auto", torch_dtype=torch.float16,
        )
        model = PeftModel.from_pretrained(base, str(args.adapter), is_trainable=False)
        model.eval()
        for index, row in enumerate(pending, 1):
            expected = json.loads(row["target_completion"])
            formatted = format_benchmark_prompt(row["prompt_text"])
            inputs = tokenizer(formatted, return_tensors="pt", add_special_tokens=True).to(model.device)
            prompt_len = inputs["input_ids"].shape[1]
            stopping = StoppingCriteriaList([
                JsonClosingBraceStoppingCriteria(tokenizer, prompt_len, max_tokens=130)
            ])
            start = time.perf_counter()
            with torch.no_grad():
                output = model.generate(
                    **inputs,
                    max_length=prompt_len + 130,
                    do_sample=False,
                    stopping_criteria=stopping,
                    pad_token_id=tokenizer.eos_token_id,
                )
            latency_ms = (time.perf_counter() - start) * 1000
            raw = tokenizer.decode(output[0][prompt_len:], skip_special_tokens=True).strip()
            decision = ModelDecisionParser.parse(raw_content=raw, model_name=args.adapter.name)
            schema_valid = (
                decision.decision_type != DecisionType.FALLBACK
                and not decision.is_malformed_recovery
            )
            record = {
                "transition_id": row["transition_id"],
                "trajectory_id": row.get("trajectory_id"),
                "category": row.get("category"),
                "expected_decision_type": expected.get("decision_type"),
                "expected_tool": (expected.get("selected_action") or {}).get("tool_name"),
                "expected_arguments": (expected.get("selected_action") or {}).get("arguments"),
                "raw_output": raw[:500],
                "parsed_decision_type": decision.decision_type.value,
                "selected_tool": decision.selected_action.tool_name if decision.selected_action else None,
                "selected_arguments": decision.selected_action.arguments if decision.selected_action else None,
                "completion_status": decision.completion_assessment.status if decision.completion_assessment else None,
                "recovery_failure_category": decision.recovery_decision.failure_category if decision.recovery_decision else None,
                "schema_valid": schema_valid,
                "decision_correct": _case_correct(expected, decision),
                "latency_ms": round(latency_ms, 1),
            }
            prior[row["transition_id"]] = record
            # Persist each completed row so an interrupted generation run resumes safely.
            ordered = [prior[r["transition_id"]] for r in rows if r["transition_id"] in prior]
            predictions_path.write_text(json.dumps(ordered, indent=2), encoding="utf-8")
            print(
                f"[{index}/{len(pending)}] {row['transition_id']} "
                f"{record['parsed_decision_type']} {'PASS' if record['decision_correct'] else 'FAIL'} "
                f"{record['latency_ms']:.0f}ms",
                flush=True,
            )

    ordered = [prior[r["transition_id"]] for r in rows]
    by_category: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for prediction in ordered:
        by_category[str(prediction.get("category") or "UNKNOWN")].append(prediction)
    metrics = {
        "test_cases": len(ordered),
        "schema_valid": sum(row["schema_valid"] for row in ordered),
        "schema_valid_rate": sum(row["schema_valid"] for row in ordered) / max(1, len(ordered)),
        "decision_correct": sum(row["decision_correct"] for row in ordered),
        "decision_correct_rate": sum(row["decision_correct"] for row in ordered) / max(1, len(ordered)),
        "latency_ms_avg": round(sum(row["latency_ms"] for row in ordered) / max(1, len(ordered)), 1),
        "category_breakdown": {
            category: {
                "correct": sum(row["decision_correct"] for row in cases),
                "total": len(cases),
                "accuracy": sum(row["decision_correct"] for row in cases) / len(cases),
            }
            for category, cases in sorted(by_category.items())
        },
        "confusion_matrix": {
            f"{expected}->{actual}": count
            for (expected, actual), count in Counter(
                (row["expected_decision_type"], row["parsed_decision_type"]) for row in ordered
            ).items()
        },
    }
    metrics_path.write_text(json.dumps(metrics, indent=2), encoding="utf-8")
    print(json.dumps(metrics, indent=2), flush=True)


if __name__ == "__main__":
    main()
