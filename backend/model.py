import pandas as pd
import joblib
import os
import json
import logging
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler
from sklearn.ensemble import RandomForestClassifier
from sklearn.pipeline import Pipeline
from sklearn.impute import SimpleImputer
from sklearn.feature_selection import SelectKBest, f_classif
from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score, classification_report, confusion_matrix

os.makedirs("logs", exist_ok=True)

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler("logs/training.log"),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

MODEL_PATH = "model/phishing_pipeline.joblib"
FEATURE_PATH = "model/feature_names.txt"
METRICS_PATH = "model/metrics.json"

PIPELINE_CONFIG = {
    "imputer_strategy": "median",
    "scaling": True,
    "select_k_best": 30,
    "classifier": {
        "n_estimators": 200,
        "max_depth": 15,
        "min_samples_split": 5,
        "class_weight": "balanced",
        "random_state": 42
    },
    "test_size": 0.2,
    "random_state": 42
}

def train_model():

    logger.info("Loading dataset...")
    df = pd.read_csv("phishing.csv").drop(columns=["Index"], errors="ignore")
    X = df.drop(columns=["class"])
    y = df["class"]

    X_train, X_test, y_train, y_test = train_test_split(
        X, y,
        test_size=PIPELINE_CONFIG["test_size"],
        stratify=y,
        random_state=PIPELINE_CONFIG["random_state"]
    )

    pipeline = Pipeline([
        ('imputer', SimpleImputer(strategy=PIPELINE_CONFIG["imputer_strategy"])),
        ('scaler', StandardScaler()),
        ('feature_selector', SelectKBest(score_func=f_classif, k=PIPELINE_CONFIG["select_k_best"])),
        ('classifier', RandomForestClassifier(**PIPELINE_CONFIG["classifier"]))
    ])

    logger.info("Training model...")
    pipeline.fit(X_train, y_train)
    y_pred = pipeline.predict(X_test)

    metrics = {
        "accuracy": round(accuracy_score(y_test, y_pred), 4),
        "precision": round(precision_score(y_test, y_pred), 4),
        "recall": round(recall_score(y_test, y_pred), 4),
        "f1_score": round(f1_score(y_test, y_pred), 4),
        "confusion_matrix": confusion_matrix(y_test, y_pred).tolist()
    }

    logger.info("Model Evaluation:")
    for key, value in metrics.items():
        logger.info(f"{key:>15}: {value}")

    os.makedirs("model", exist_ok=True)
    joblib.dump(pipeline, MODEL_PATH)
    logger.info(f"Model saved to: {MODEL_PATH}")

    selected_features = X.columns[pipeline.named_steps['feature_selector'].get_support()]
    with open(FEATURE_PATH, "w") as f:
        f.write("\n".join(selected_features))
    logger.info(f"Selected features saved to: {FEATURE_PATH}")

    with open(METRICS_PATH, "w") as f:
        json.dump(metrics, f, indent=2)
    logger.info(f"Metrics saved to: {METRICS_PATH}")

if __name__ == "__main__":
    train_model()
