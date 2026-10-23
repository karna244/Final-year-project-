<<<<<<< HEAD
# AI-Based Cyber Incident Prioritization and Risk-Aware Alert Triage

**Academic Program:** B.Tech Computer Science & Engineering (Batch 2023)  
**Institution:** Ramaiah University of Applied Sciences, Bangalore  
**Course:** B.Tech Project Work-I (Group No: 26PB82)  
**Supervisor:** Ms. Megharani H M (RTC, Peenya)  
**Team Members:**  
* Anoop K (23ETCS002014)  
* Karan S (23ETCS002055)  
* Kishen G Raj (23ETCS002060)  

---

## 1. System Overview

Security Operations Centers (SOCs) are overwhelmed by thousands of security alerts daily with high false-positive rates, redundant triggers, and lack of operational context. 

This repository delivers an **applied, explainable, and lightweight AI triage system** that reduces alert fatigue and assists Tier-1 analysts by:
1. **Filtering & Deduplication:** Eliminating repetitive noise and calculating alert reduction rates.
2. **Contextual Provenance Graphing:** Modeling IP-to-IP and entity relationships in NetworkX (inspired by *NoDoze*, NDSS 2019) to calculate topological connectivity weights.
3. **Machine Learning Classification:** Training a Scikit-learn Random Forest classifier to predict calibrated malicious probability.
4. **Hybrid Risk Engine:** Computing a transparent composite risk score ($0\text{--}100$) and categorizing alerts into **Low, Medium, High, and Critical** priority tiers.
5. **Human-AI Decision Support:** Providing human-readable reason codes (e.g. `RC-ML-ANOMALY`, `RC-GRAPH-HUB`) and an interactive Streamlit triage dashboard.

---

## 2. Mathematical Risk Scoring Formula

$$R = w_1 M + w_2 S + w_3 C + w_4 F$$

* **$M$ (Machine Learning Probability, $0\text{--}100$):** Random Forest malicious confidence ($P(\text{Malicious}) \times 100$). Weight: $w_1 = 0.40$.
* **$S$ (Reported Severity Proxy, $0\text{--}100$):** Normalized baseline severity (Low=25, Med=50, High=75, Crit=100). Weight: $w_2 = 0.25$.
* **$C$ (Graph Context Weight, $0\text{--}100$):** NetworkX topological degree centrality of communicating entities. Weight: $w_3 = 0.20$.
* **$F$ (Burst Frequency Factor, $0\text{--}100$):** Rolling time-window event velocity per source IP. Weight: $w_4 = 0.15$.

### Priority Cutoffs
* **Critical (80 – 100):** Immediate isolation, active incident escalation ($< 15$ min SLA).
* **High (60 – 79):** Dedicated tier-2 forensic investigation ($< 1$ hour SLA).
* **Medium (30 – 59):** Aggregated review, automated correlation checks ($< 24$ hours SLA).
* **Low (0 – 29):** Automated suppression / benign audit logging.

---

## 3. Quick Start & Local Execution

### Step 1: Navigate to Project Directory
```bash
cd ai-cyber-incident-triage
```

### Step 2: Install Dependencies
```bash
python -m pip install -r requirements.txt
```

### Step 3: Run the Full Pipeline & Train Model
```bash
python -c "from src.pipeline import run_full_pipeline; run_full_pipeline(retrain=True)"
```

### Step 4: Launch the Streamlit SOC Dashboard
```bash
streamlit run app.py
```
The dashboard will open automatically in your browser at `http://localhost:8501`.

---

## 4. Running the Automated Test Suite

Verify that preprocessing, deduplication, scoring bounds, and pipeline integration pass all unit tests:
```bash
pytest tests/ -v
```

---

## 5. Free Cloud Deployment (1-Click)

### Option A: Streamlit Community Cloud (Recommended)
1. Push this repository to your GitHub account (`ai-cyber-incident-triage`).
2. Go to [share.streamlit.io](https://share.streamlit.io) and log in with GitHub.
3. Select your repository, branch (`main`), and main file (`app.py`).
4. Click **Deploy**. Your app is live with a public URL!

### Option B: Render.com
1. Create a free account at [render.com](https://render.com).
2. Create a new **Web Service** linked to your GitHub repo.
3. Set **Start Command**:
   ```bash
   streamlit run app.py --server.port $PORT --server.address 0.0.0.0
   ```
4. Click **Create Web Service**.

---

## 6. Project Architecture

```
ai-cyber-incident-triage/
├── app.py                      # Main Streamlit SOC triage dashboard
├── requirements.txt            # Python dependencies
├── README.md                   # Complete documentation
│
├── config/
│   └── settings.yaml           # Configurable risk weights and thresholds
│
├── data/
│   ├── raw/                    # Raw cybersecurity benchmark alerts (1,280 events)
│   └── processed/              # Cleaned, scored, and prioritized dataset
│
├── src/
│   ├── data_loader.py          # Data ingestion and schema validation
│   ├── preprocessing.py       # Deduplication, normalization, frequency burst
│   ├── features.py             # Feature encoding and temporal extraction
│   ├── graph_analysis.py       # NetworkX entity graph & contextual weights
│   ├── risk_scoring.py         # Multi-factor risk engine & reason codes
│   ├── train_model.py          # Random Forest training & metric reporting
│   ├── predict.py              # Inference pipeline for new alerts
│   └── pipeline.py             # Orchestrates entire workflow
│
├── models/
│   ├── random_forest_model.joblib # Saved trained model
│   └── preprocessor.joblib     # Fitted column transformers
│
├── reports/
│   ├── metrics_summary.json    # Test accuracy, precision, recall, FPR, F1
│   └── confusion_matrix.png    # Evaluation confusion matrix heatmap
│
├── docs/
│   └── dataset_notes.md        # Data dictionary and attack anatomy
│
└── tests/
    ├── test_preprocessing.py   # Deduplication & cleaning unit tests
    ├── test_risk_scoring.py    # Risk formula & reason codes tests
    └── test_pipeline.py        # End-to-end integration tests
```
=======
# Final-year-project-
>>>>>>> 8834fb0b372d230efdeb1aea0b81ed746801a917
