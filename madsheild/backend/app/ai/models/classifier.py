"""Explainable document rules and inference with an existing model; no training."""
import json
import math
import re
from pathlib import Path
from threading import Lock
from urllib.parse import urlparse

import httpx

from ... import config
from ..feature_extractor import FEATURE_NAMES

RULES_VERSION = "document-rules-1"
MAX_FINDINGS = 100
RULES = (
    ("encoded_powershell", "Encoded PowerShell command", "high", 70,
     r"\b(?:powershell|pwsh)\b[^\n]{0,500}-(?:enc|encodedcommand)\b",
     "Encoded commands can hide instructions. Review the surrounding context."),
    ("download_and_execute", "Download piped to an interpreter", "high", 70,
     r"\b(?:curl|wget|invoke-webrequest|downloadstring)\b[^\n]{0,1000}\|\s*(?:bash|sh|iex|invoke-expression)\b",
     "This pattern downloads content and passes it to an interpreter."),
    ("shadow_delete", "Shadow-copy deletion command", "high", 70,
     r"\b(?:vssadmin\s+delete\s+shadows|wmic\s+shadowcopy\s+delete)\b",
     "Removing shadow copies can interfere with recovery. Check the command's purpose."),
    ("dynamic_execution", "Dynamic execution expression", "medium", 30,
     r"\b(?:eval|exec)\s*\(|\b(?:iex|invoke-expression)\b",
     "Dynamic execution also occurs in legitimate code; review before drawing conclusions."),
)
COMPILED_RULES = tuple((*rule[:4], re.compile(rule[4], re.IGNORECASE), rule[5]) for rule in RULES)


def rule_analysis(segments: list[dict], features: dict) -> dict:
    findings, weights, match_count = [], {}, 0
    for segment in segments:
        for rule_id, title, severity, weight, pattern, reason in COMPILED_RULES:
            match = pattern.search(segment["text"])
            if match is None:
                continue
            weights[rule_id] = weight
            match_count += 1
            if len(findings) < MAX_FINDINGS:
                start = max(0, match.start() - 60)
                findings.append({
                    "source": "rules", "rule_id": rule_id, "title": title,
                    "severity": severity, "reason": reason,
                    "location": {k: v for k, v in segment.items() if k != "text"},
                    "excerpt": segment["text"][start:start + 300],
                })
    for feature, rule_id, title, weight in (
        ("macro_present", "embedded_macro", "Macro artifact in DOCX archive", 70),
        ("embedded_object_count", "embedded_object", "Embedded objects in DOCX archive", 30),
    ):
        if features.get(feature, 0):
            weights[rule_id] = weight
            match_count += 1
            if len(findings) < MAX_FINDINGS:
                findings.append({
                    "source": "rules", "rule_id": rule_id, "title": title,
                    "severity": "high" if weight >= 70 else "medium",
                    "reason": "This archive artifact requires review; its presence alone does not prove malware.",
                    "location": {"scope": "document_archive"}, "excerpt": "",
                })
    return {"risk_score": min(100, sum(weights.values())), "findings": findings,
            "match_count": match_count, "findings_truncated": match_count > len(findings)}


def finite_number(value) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)) or not math.isfinite(value):
        raise ValueError("Expected a finite number.")
    return float(value)


class Classifier:
    def __init__(self):
        self._lock = Lock()
        self._loaded_signature = None
        self._artifact = None

    def signature(self) -> tuple:
        try:
            stat = Path(config.MODEL_PATH).stat() if config.MODEL_PATH else None
            stamp = (stat.st_mtime_ns, stat.st_size) if stat else None
        except OSError:
            stamp = "missing"
        return (config.MODEL_PATH, stamp, config.MODEL_ENDPOINT, config.MODEL_NAME,
                config.MODEL_API_KEY, config.MODEL_MAX_SEGMENTS, config.MODEL_MAX_TEXT_CHARACTERS)

    def configured_mode(self) -> str:
        if config.MODEL_PATH and config.MODEL_ENDPOINT:
            return "invalid_configuration"
        return "local" if config.MODEL_PATH else "service" if config.MODEL_ENDPOINT else "not_configured"

    def _local_model(self) -> dict:
        signature = self.signature()
        with self._lock:
            if self._loaded_signature == signature:
                return self._artifact
            path = Path(config.MODEL_PATH)
            if path.stat().st_size > 1024 * 1024:
                raise ValueError("Model artifact is too large.")
            artifact = json.loads(path.read_text(encoding="utf-8"))
            names, weights = artifact.get("feature_names"), artifact.get("weights")
            if (artifact.get("format") != "madshield-logistic-v1" or not isinstance(names, list)
                    or not names or any(not isinstance(name, str) for name in names)
                    or len(set(names)) != len(names) or not set(names) <= set(FEATURE_NAMES)
                    or not isinstance(weights, list) or len(weights) != len(names)):
                raise ValueError("Unsupported model artifact.")
            means = artifact.get("means", [0] * len(names))
            scales = artifact.get("scales", [1] * len(names))
            if not isinstance(means, list) or not isinstance(scales, list) or len(means) != len(names) or len(scales) != len(names):
                raise ValueError("Invalid normalization parameters.")
            checked = {"feature_names": names, "weights": [finite_number(x) for x in weights],
                       "means": [finite_number(x) for x in means], "scales": [finite_number(x) for x in scales],
                       "bias": finite_number(artifact.get("bias"))}
            if any(x <= 0 for x in checked["scales"]):
                raise ValueError("Scales must be positive.")
            self._artifact, self._loaded_signature = checked, signature
            return checked

    def _service_inputs(self, segments: list[dict]) -> tuple[list[dict], dict]:
        inputs, used = [], 0
        total = sum(len(segment["text"]) for segment in segments)
        for segment in segments:
            for offset in range(0, len(segment["text"]), 2000):
                available = config.MODEL_MAX_TEXT_CHARACTERS - used
                if len(inputs) >= config.MODEL_MAX_SEGMENTS or available <= 0:
                    break
                text = segment["text"][offset:offset + min(2000, available)]
                inputs.append({"id": str(len(inputs)), "text": text,
                               "location": {**{k: v for k, v in segment.items() if k != "text"}, "character_offset": offset}})
                used += len(text)
            if len(inputs) >= config.MODEL_MAX_SEGMENTS or used >= config.MODEL_MAX_TEXT_CHARACTERS:
                break
        return inputs, {"analyzed_characters": used, "total_characters": total,
                        "input_count": len(inputs), "complete": used == total}

    def _service_model(self, segments: list[dict], features: dict) -> dict:
        endpoint = urlparse(config.MODEL_ENDPOINT)
        if endpoint.scheme not in {"http", "https"} or not endpoint.hostname or endpoint.username or endpoint.password:
            raise ValueError("Invalid model service URL.")
        inputs, coverage = self._service_inputs(segments)
        if not inputs:
            return {"status": "skipped", "mode": "service", "malware_probability": None,
                    "findings": [], "coverage": coverage, "message": "No body text was available for model inference."}
        headers = {"Authorization": f"Bearer {config.MODEL_API_KEY}"} if config.MODEL_API_KEY else {}
        with httpx.Client(timeout=config.MODEL_TIMEOUT_SECONDS, follow_redirects=False, trust_env=False) as client:
            with client.stream("POST", config.MODEL_ENDPOINT, headers=headers,
                               json={"model": config.MODEL_NAME, "segments": inputs, "features": features}) as response:
                response.raise_for_status()
                content = bytearray()
                for chunk in response.iter_bytes():
                    content.extend(chunk)
                    if len(content) > 1024 * 1024:
                        raise ValueError("Model response is too large.")
        predictions = json.loads(content).get("predictions")
        if not isinstance(predictions, list) or len(predictions) != len(inputs):
            raise ValueError("Incomplete model predictions.")
        by_id = {item["id"]: item for item in inputs}
        seen, probabilities, findings = set(), [], []
        for prediction in predictions:
            if not isinstance(prediction, dict):
                raise ValueError("Invalid prediction.")
            identity = prediction.get("id")
            if not isinstance(identity, str) or identity not in by_id or identity in seen:
                raise ValueError("Invalid prediction ID.")
            seen.add(identity)
            probability = finite_number(prediction.get("malware_probability"))
            reason = prediction.get("reason", "Model prediction exceeds the configured review threshold.")
            if not 0 <= probability <= 1 or not isinstance(reason, str):
                raise ValueError("Invalid model probability or reason.")
            probabilities.append(probability)
            if probability >= config.MODEL_THRESHOLD:
                findings.append({"source": "model", "title": "Model flagged this text segment", "severity": "high",
                                 "reason": reason[:500], "malware_probability": probability,
                                 "location": by_id[identity]["location"], "excerpt": by_id[identity]["text"][:300]})
        return {"status": "completed", "mode": "service", "model_name": config.MODEL_NAME[:200],
                "malware_probability": max(probabilities), "aggregation": "maximum_segment_probability",
                "coverage": coverage, "findings": findings}

    def predict(self, segments: list[dict], features: dict) -> dict:
        mode = self.configured_mode()
        if mode == "not_configured":
            return {"status": "not_configured", "mode": mode, "malware_probability": None, "findings": []}
        try:
            if mode == "service":
                return self._service_model(segments, features)
            if mode != "local":
                raise ValueError("Choose one model source.")
            artifact = self._local_model()
            score = artifact["bias"] + sum(
                ((features[name] - mean) / scale) * weight
                for name, mean, scale, weight in zip(artifact["feature_names"], artifact["means"], artifact["scales"], artifact["weights"])
            )
            finite_number(score)
            probability = 1 / (1 + math.exp(-score)) if score >= 0 else math.exp(score) / (1 + math.exp(score))
            findings = []
            if probability >= config.MODEL_THRESHOLD:
                findings.append({"source": "model", "title": "Model flagged this document", "severity": "high",
                                 "reason": "This model predicts from whole-document features and cannot identify an exact line.",
                                 "location": {"scope": "whole_document"}, "excerpt": "", "malware_probability": probability})
            return {"status": "completed", "mode": mode, "model_name": config.MODEL_NAME[:200],
                    "malware_probability": probability, "aggregation": "document_feature_prediction",
                    "coverage": {"complete": True}, "findings": findings}
        except (ValueError, TypeError, AttributeError, KeyError, OSError, httpx.HTTPError, OverflowError):
            return {"status": "failed", "mode": mode, "malware_probability": None, "findings": [],
                    "message": "Model inference was unavailable or returned an invalid response. Static analysis is still available."}
