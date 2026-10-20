"""Local ONNX URL predictor used by the PhishGuard Node server."""
from __future__ import annotations

import json
import sys
from pathlib import Path

import numpy as np

from features_url import vector

ROOT = Path(__file__).resolve().parent
MODEL_PATH = ROOT / "models" / "url_device.onnx"


def create_session():
    if not MODEL_PATH.exists():
        raise FileNotFoundError(f"Model file not found: {MODEL_PATH}")

    import onnxruntime as ort

    return ort.InferenceSession(
        str(MODEL_PATH),
        providers=["CPUExecutionProvider"],
    )


def predict(url: str, session=None) -> dict[str, object]:
    session = session or create_session()
    values = np.asarray([vector(url)], dtype=np.float32)
    input_name = session.get_inputs()[0].name
    outputs = session.run(None, {input_name: values})
    if len(outputs) < 2:
        raise RuntimeError("The ONNX model returned no probability output")

    probabilities = np.asarray(outputs[1])
    if probabilities.ndim != 2 or probabilities.shape[0] < 1 or probabilities.shape[1] < 2:
        raise RuntimeError("The ONNX probability output has an unexpected shape")

    probability = float(probabilities[0][1])
    return {
        "available": True,
        "model": "scumlens-url-device",
        "probability": round(probability, 6),
    }


def serve() -> int:
    try:
        session = create_session()
    except Exception as error:
        for line in sys.stdin:
            request = json.loads(line)
            print(json.dumps({"id": request.get("id"), "error": str(error)}), flush=True)
        return 1
    for line in sys.stdin:
        request: dict[str, object] = {}
        try:
            request = json.loads(line)
            result = predict(str(request["url"]), session)
            result["id"] = request.get("id")
        except Exception as error:
            result = {"id": request.get("id"), "error": str(error)}
        print(json.dumps(result), flush=True)
    return 0


def main() -> int:
    if len(sys.argv) == 2 and sys.argv[1] == "--server":
        return serve()
    if len(sys.argv) != 2:
        print(json.dumps({"error": "Usage: predictor.py URL"}))
        return 2
    try:
        print(json.dumps(predict(sys.argv[1])))
        return 0
    except Exception as error:
        print(json.dumps({"error": str(error)}))
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
