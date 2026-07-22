# 🛡️ Network Intrusion Detection System (NIDS) — End-to-End ML Pipeline & API

An end-to-end Machine Learning pipeline and FastAPI REST API that performs binary classification on network traffic to determine whether incoming connection attempts are **Normal** or a **Malicious Attack**. Built with Scikit-Learn, XGBoost, and FastAPI, and deployed on Render.

Live API Documentation (Swagger UI): https://network-intrusion-prediction.onrender.com/docs

---

## 📌 Project Overview

Traditional intrusion detection often relies on rigid, static rules. This project leverages an ensemble machine learning pipeline trained on network metric distributions (derived from the NSL-KDD benchmark) to classify network connection attempts as either NORMAL TRAFFIC or a MALICIOUS ATTACK / ANOMALY.

### Key Highlights
* Zero Data Leakage Architecture: Feature engineering (StandardScaler, OrdinalEncoder) and feature selection (SelectKBest) occur strictly on training data after train-test splitting.
* Unified Model Pipeline Serialization: Preprocessing transformers, selection criteria, and the trained XGBoost model are serialized together into a single .pkl artifact.
* Production REST API: Built with FastAPI and Pydantic for strict input validation, automatic handling of unseen categorical features, and real-time confidence scores.
* Cloud Deployed: Hosted on Render with live interactive Swagger UI testing.

---

## 🏗️ End-to-End Pipeline Architecture

Raw Network Input Payload (JSON)
              │
              ▼
1. Pydantic Input Validation & Padding
   (Fills default values for non-provided attributes)
              │
              ▼
2. ColumnTransformer Preprocessing
   ├── Numerical Features: StandardScaler()
   └── Categorical Features: OrdinalEncoder()
              │
              ▼
3. Feature Selection
   └── SelectKBest()
              │
              ▼
4. Inference
   └── XGBoost Classifier
              │
              ▼
Prediction Response JSON
({ "prediction_label": "MALICIOUS ATTACK / ANOMALY", "confidence_score": 99.12 })

---

## 📓 Notebook Workflow Summary

The model was developed systematically in Jupyter Notebook following these core steps:

1. Environment Setup & EDA: Inspecting column distributions, data types, and checking for missing values.
2. Data Splitting: Stratified 70/30 train-test split executed before fitting transformers to prevent test set data leakage.
3. Pipeline Construction: Wrapping StandardScaler, OrdinalEncoder, and SelectKBest into a unified Scikit-Learn Pipeline.
4. Model Training & Evaluation: Comparing LogisticRegression against XGBoostClassifier using classification reports, F1-scores, and Seaborn confusion matrices.
5. Feature Importance Analysis: Visualizing the top 12 mutual information features driving the XGBoost decision-making process.
6. Artifact Export: Serializing the full pipeline object using joblib.

---

## 🚀 Quickstart & Local Setup

### Prerequisites
* Python 3.10+
* Git

### Installation & Execution

1. Clone the repository:
   git clone https://github.com/Layan003/network-intrusion-prediction.git
   cd network-intrusion-prediction

2. Create and activate a virtual environment:
   # macOS/Linux
   python -m venv venv
   source venv/bin/activate

   # Windows (Command Prompt)
   python -m venv venv
   venv\Scripts\activate.bat

3. Install dependencies:
   pip install -r requirements.txt

4. Run the FastAPI server locally:
   uvicorn main:app --reload

5. Open http://127.0.0.1:8000/docs in your browser to test endpoints interactively.

---

## 🧪 Example API Requests & Responses

### 1. Malicious Threat Sample (DoS Attack)

Request (POST /predict):
{
  "protocol_type": "tcp",
  "service": "private",
  "flag": "S0",
  "src_bytes": 0,
  "dst_bytes": 0,
  "logged_in": 0,
  "diff_srv_rate": 0.06,
  "same_srv_rate": 0.05,
  "serror_rate": 1.0,
  "srv_serror_rate": 1.0,
  "dst_host_srv_count": 10,
  "dst_host_same_srv_rate": 0.04,
  "dst_host_diff_srv_rate": 0.06
}

Response:
{
  "status": "success",
  "prediction_code": 1,
  "prediction_label": "MALICIOUS ATTACK / ANOMALY",
  "confidence_score": 99.12
}

---

### 2. Normal Web Session Sample

Request (POST /predict):
{
  "protocol_type": "tcp",
  "service": "http",
  "flag": "SF",
  "src_bytes": 215,
  "dst_bytes": 4500,
  "logged_in": 1,
  "diff_srv_rate": 0.0,
  "same_srv_rate": 1.0,
  "serror_rate": 0.0,
  "srv_serror_rate": 0.0,
  "dst_host_srv_count": 255,
  "dst_host_same_srv_rate": 1.0,
  "dst_host_diff_srv_rate": 0.0
}

Response:
{
  "status": "success",
  "prediction_code": 0,
  "prediction_label": "NORMAL TRAFFIC",
  "confidence_score": 98.45
}

---

## 🛠️ Tech Stack & Dependencies
* Core Language: Python 3.10+
* Machine Learning: Scikit-Learn, XGBoost, Pandas, NumPy, Joblib
* Data Visualization: Matplotlib, Seaborn
* API Framework: FastAPI, Uvicorn, Pydantic
* Deployment & Version Control: Render, Git