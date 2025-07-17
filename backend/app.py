from flask import Flask, request, jsonify
from flask_cors import CORS
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
import joblib
import urllib.parse
import pandas as pd
import re
import logging
from logging.handlers import RotatingFileHandler
from feature_extractor import combine_features, TRUSTED_DOMAINS, is_suspicious

app = Flask(__name__)
CORS(app)

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        RotatingFileHandler("logs/app.log", maxBytes=1_000_000, backupCount=3),
        logging.StreamHandler()
    ]
)

logger = logging.getLogger(__name__)

limiter = Limiter(
    app=app,
    key_func=get_remote_address,
    default_limits=["200 per day", "50 per hour"]
)

try:
    pipeline = joblib.load("model/phishing_pipeline.joblib")
    with open("model/feature_names.txt") as f:
        model_features = [line.strip() for line in f.readlines()]
except Exception as e:
    logger.critical(f"Failed to load model: {e}")
    raise

@app.route("/api/predict", methods=["POST"])
@limiter.limit("5 per second")
def predict():
    try:
        data = request.get_json()
        url = data.get("url", "").strip().lower()

        if not url or not re.match(r"^https?://", url):
            return jsonify({"error": "Invalid URL format"}), 400

        parsed_url = urllib.parse.urlparse(url)
        domain = parsed_url.netloc.lower()

        if any(domain.endswith(f".{trusted}") or domain == trusted for trusted in TRUSTED_DOMAINS):
            logger.info(f"[Trusted] {url}")
            return jsonify({
                "prediction": "legitimate",
                "confidence": 99.0,
                "url": url
            })

        suspicious, reason = is_suspicious(url)
        if suspicious:
            logger.info(f"[Heuristic] {url} flagged for: {reason}")
            return jsonify({
                "prediction": "phishing",
                "confidence": 95.0 if reason == "dns_failure" else 99.0,
                "reason": reason,
                "url": url
            })

        try:
            input_df = combine_features(url, network_calls=False)
            input_df = input_df.reindex(columns=model_features, fill_value=0)

            prediction = pipeline.predict(input_df)[0]
            proba = pipeline.predict_proba(input_df)[0]
            confidence = round(max(proba) * 100, 2)
            confidence = min(confidence, 99.0)

            label = "phishing" if prediction == 1 else "legitimate"
            logger.info(f"[Model] {url} => {label} ({confidence}%)")

            return jsonify({
                "prediction": label,
                "confidence": confidence,
                "url": url
            })

        except Exception as e:
            logger.error(f"Prediction error for {url}: {e}")
            return jsonify({
                "prediction": "phishing",
                "confidence": 85.0,
                "reason": "prediction_error",
                "url": url
            })

    except Exception as e:
        logger.critical(f"Fatal server error: {e}")
        return jsonify({"error": "Internal server error"}), 500

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=False)
