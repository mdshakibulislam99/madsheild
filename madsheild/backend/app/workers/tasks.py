"""Bounded document analysis, reusable results, and persisted reports."""
from collections import OrderedDict
from copy import deepcopy
from datetime import datetime, timezone
from threading import Lock
from time import monotonic, perf_counter
from uuid import uuid4

from .. import config
from ..ai.feature_extractor import extract_features
from ..ai.models.classifier import Classifier, RULES_VERSION, rule_analysis
from ..services.file_manager import calculate_sha256, save_report, save_uploaded_file, validate_file


class AnalysisEngine:
    def __init__(self):
        self.classifier = Classifier()
        self._cache = OrderedDict()
        self._cache_lock = Lock()

    def analyze(self, extension: str, content: bytes) -> dict:
        started = perf_counter()
        key = (calculate_sha256(content), extension, RULES_VERSION, self.classifier.signature(), config.MODEL_THRESHOLD)
        now = monotonic()
        with self._cache_lock:
            for old_key, (expires, _) in list(self._cache.items()):
                if expires <= now:
                    del self._cache[old_key]
            if key in self._cache:
                self._cache.move_to_end(key)
                result = deepcopy(self._cache[key][1])
                result["cache_hit"] = True
                result["timings_ms"] = {"analysis": round((perf_counter() - started) * 1000, 3)}
                return result
        extracted = extract_features(content, extension)
        extraction_done = perf_counter()
        rules = rule_analysis(extracted["segments"], extracted["features"])
        rules_done = perf_counter()
        model = self.classifier.predict(extracted["segments"], extracted["features"])
        finished = perf_counter()
        result = {"rules_version": RULES_VERSION, "features": extracted["features"],
                  "rules": rules, "model": model, "cache_hit": False,
                  "timings_ms": {"extraction": round((extraction_done - started) * 1000, 3),
                                 "rules": round((rules_done - extraction_done) * 1000, 3),
                                 "model": round((finished - rules_done) * 1000, 3),
                                 "analysis": round((finished - started) * 1000, 3)}}
        if model["status"] not in {"failed", "skipped"}:
            with self._cache_lock:
                self._cache[key] = (monotonic() + config.ANALYSIS_CACHE_TTL_SECONDS, deepcopy(result))
                self._cache.move_to_end(key)
                while len(self._cache) > config.ANALYSIS_CACHE_SIZE:
                    self._cache.popitem(last=False)
        return result


engine = AnalysisEngine()


def extract_and_analyze_task(filename: str, content: bytes, content_type: str | None) -> dict:
    started = perf_counter()
    extension = validate_file(filename, len(content))
    analysis = engine.analyze(extension, content)
    rules, model = analysis["rules"], analysis["model"]
    probability = model["malware_probability"]
    if rules["risk_score"] >= 70 or (probability is not None and probability >= config.MODEL_THRESHOLD):
        verdict = "suspicious"
    elif rules["risk_score"] or model["status"] in {"failed", "skipped"} or not model.get("coverage", {}).get("complete", True):
        verdict = "review_required"
    else:
        verdict = "no_indicators_found"
    limitations = [
        "Files are inspected without execution. No indicators found does not prove a file is safe.",
        "Rules can flag legitimate examples and documentation; review the reported context.",
        "DOCX text analysis covers body paragraphs and tables, not headers, footers, images, or OCR.",
        "Model probabilities, when available, require independent validation; confidence is not calculated.",
    ]
    if model["status"] == "not_configured":
        limitations.append("No trained model is configured. This report contains static rules only; AI probability is unavailable.")
    elif model["status"] in {"failed", "skipped"}:
        limitations.append(model["message"])
    if not model.get("coverage", {}).get("complete", True):
        limitations.append("The model analyzed only the text within its configured budget. Static rules analyzed all extracted segments.")
    if rules["findings_truncated"]:
        limitations.append("Only the first 100 static-rule findings are included.")
    scan_id = uuid4().hex
    saved = save_uploaded_file(filename, content, scan_id)
    findings = [{**finding, "filename": saved["filename"]} for finding in rules["findings"] + model["findings"]]
    report = {"scan_id": scan_id, "status": "completed", "created_at": datetime.now(timezone.utc).isoformat(),
              "filename": saved["filename"], "content_type": content_type, "size_bytes": saved["size_bytes"],
              "relative_path": saved["relative_path"],
              "sha256": saved["sha256"], "verdict": verdict, "risk_score": rules["risk_score"],
              "risk_score_type": "heuristic_rule_score", "malware_probability": probability, "confidence": None,
              "threats": findings, "summary": {"suspicious": "Suspicious indicators found. Review the findings.",
              "review_required": "Review is required; see findings and analysis limitations.",
              "no_indicators_found": "No indicators found by the available analysis. This is not a safety guarantee."}[verdict],
              "limitations": limitations, "model": {k: v for k, v in model.items() if k != "findings"},
              "analysis": {k: v for k, v in analysis.items() if k not in {"rules", "model"}}}
    report["analysis"]["timings_ms"]["total"] = round((perf_counter() - started) * 1000, 3)
    save_report(report)
    return report
