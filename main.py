import os
import joblib
import pandas as pd
from typing import Dict, Any, Optional
from fastapi import FastAPI, HTTPException, status
from pydantic import BaseModel, Field

# 1. Initialize FastAPI App
app = FastAPI(
    title="Network Intrusion Detection System (NIDS) API",
    description="Production API using an XGBoost Pipeline to detect cyber threats.",
    version="1.0.0"
)

# 2. Global Model Artifact Loading
MODEL_PATH = "network_ids_pipeline.pkl"
pipeline = None
EXPECTED_FEATURES = []

@app.on_event("startup")
def load_model():
    """Load the pipeline and extract expected feature columns on startup."""
    global pipeline, EXPECTED_FEATURES
    
    if not os.path.exists(MODEL_PATH):
        raise RuntimeError(f"Model file '{MODEL_PATH}' not found in root directory!")
    
    try:
        pipeline = joblib.load(MODEL_PATH)
        # Extract the exact feature names the preprocessor was trained on
        preprocessor = pipeline.named_steps['preprocessor']
        EXPECTED_FEATURES = list(preprocessor.feature_names_in_)
        print(f"✅ Loaded pipeline successfully! Expecting {len(EXPECTED_FEATURES)} input features.")
    except Exception as e:
        raise RuntimeError(f"Failed to load model pipeline: {str(e)}")

# 3. Pydantic Input Validation Schemas
class NetworkTrafficInput(BaseModel):
    """
    Input schema for network connection metrics.
    Fields without defaults are required; optional fields default to 0.
    """
    # Key Categorical Features
    protocol_type: str = Field(..., example="tcp", description="Protocol type: tcp, udp, icmp")
    service: str = Field(..., example="private", description="Network service (e.g., http, private, ftp)")
    flag: str = Field(..., example="S0", description="Connection status flag (e.g., SF, S0, REJ)")
    
    # Key Traffic Metrics
    src_bytes: int = Field(0, example=0, description="Bytes sent from source to destination")
    dst_bytes: int = Field(0, example=0, description="Bytes sent from destination to source")
    logged_in: int = Field(0, example=0, description="1 if successfully logged in; 0 otherwise")
    
    # Key Error & Service Rate Metrics
    diff_srv_rate: float = Field(0.0, example=0.06, description="Percentage of connections to different services")
    same_srv_rate: float = Field(0.0, example=0.05, description="Percentage of connections to same service")
    serror_rate: float = Field(0.0, example=1.0, description="Percentage of connections with SYN errors")
    srv_serror_rate: float = Field(0.0, example=1.0, description="Percentage of connections with SYN errors on same service")
    
    # Host Metrics
    dst_host_srv_count: int = Field(0, example=10, description="Number of connections with same destination & service")
    dst_host_same_srv_rate: float = Field(0.0, example=0.04, description="Same service rate on destination host")
    dst_host_diff_srv_rate: float = Field(0.0, example=0.06, description="Different service rate on destination host")

    # Allow extra fields if client passes additional network metrics dynamically
    class Config:
        extra = "allow"

class PredictionOutput(BaseModel):
    status: str
    prediction_code: int
    prediction_label: str
    confidence_score: float

# 4. API Endpoints
@app.get("/", tags=["Health Check"])
def health_check():
    """Health check endpoint to verify API status."""
    return {
        "status": "online",
        "service": "Network Intrusion Detection System (NIDS)",
        "model_loaded": pipeline is not None
    }

@app.post("/predict", response_model=PredictionOutput, tags=["Inference"])
def predict_threat(payload: NetworkTrafficInput):
    """
    Accepts raw network connection metrics and returns threat classification.
    """
    if pipeline is None:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Model is not loaded."
        )
    
    try:
        # Convert Pydantic model to dict
        raw_data = payload.dict()
        
        # Auto-fill missing dataset columns with default value (0 / 0.0)
        full_input = {col: 0 for col in EXPECTED_FEATURES}
        full_input.update(raw_data)
        
        # Convert to DataFrame
        input_df = pd.DataFrame([full_input])[EXPECTED_FEATURES]
        
        # Model Prediction
        pred_code = int(pipeline.predict(input_df)[0])
        probabilities = pipeline.predict_proba(input_df)[0]
        confidence = float(probabilities[pred_code])
        
        # Map label
        label_map = {0: "NORMAL TRAFFIC", 1: "MALICIOUS ATTACK / ANOMALY"}
        
        return PredictionOutput(
            status="success",
            prediction_code=pred_code,
            prediction_label=label_map.get(pred_code, "UNKNOWN"),
            confidence_score=round(confidence * 100, 2)
        )
        
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Inference error: {str(e)}"
        )