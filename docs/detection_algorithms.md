# Detection Algorithms

This document provides an in-depth explanation of the detection algorithms used in the DDoS Defense Platform. The platform employs a multi‑layer ensemble approach combining signature‑based, statistical anomaly, and machine learning methods to achieve high accuracy with low false positives.

## Overview

The detection pipeline consists of three independent detectors running in parallel:

1. **Signature Detector** – matches known attack patterns against packet/flow data
2. **Anomaly Detector** – identifies deviations from normal behavior using statistical methods
3. **ML Detector** – classifies flows using pre‑trained machine learning models

The results are then combined by the **Ensemble Detector**, which applies weighted voting to produce a final alert.

---

## 1. Signature Detector

### Purpose
Quickly identify known attacks with deterministic rules, ensuring immediate response to well‑documented threats.

### Implementation
- **Rule Engine**: Supports Snort and Suricata rule formats.
- **Rules Location**: Rules are stored in `config/detection/signature.rules` (or a directory specified in config).
- **Processing**: Each packet (or flow) is matched against the rule set. Rules are reloaded periodically (default 300 seconds) to incorporate updates.

### Example Rule
```snort
alert tcp $HOME_NET any -> $EXTERNAL_NET 80 (msg:"Possible HTTP Flood"; flow:to_server; threshold:type both, track by_src, count 100, seconds 10; sid:1000001;)
Strengths
Fast, deterministic detection

Low false positives

Immediate mitigation for known attacks

Limitations
Cannot detect zero‑day or polymorphic attacks

Requires regular rule updates

2. Anomaly Detector
Purpose
Detect deviations from established traffic baselines that may indicate new or evolving attacks.

Techniques
2.1 Volumetric Detection
Monitors traffic volume metrics over sliding windows:

Bandwidth (Mbps)

Packet rate (pps)

Flow rate (flows/sec)

Thresholds are set in configuration. When a threshold is exceeded, an alert is raised.

2.2 Entropy‑Based Detection
Shannon entropy is computed for various dimensions (source IP, destination IP, ports, protocols). Low entropy (i.e., high concentration) suggests a flood attack.

Formula:

H
(
X
)
=
−
∑
i
=
1
n
p
(
x
i
)
log
⁡
2
p
(
x
i
)
H(X)=− 
i=1
∑
n
​
 p(x 
i
​
 )log 
2
​
 p(x 
i
​
 )
For example, if a single destination IP receives 99% of traffic, entropy will be low (< 3.5), indicating a potential attack.

2.3 Protocol‑Specific Thresholds
SYN Flood: SYN packets per second per destination exceeding a limit

ICMP Flood: ICMP packets per second exceeding a limit

UDP Flood: UDP packets per second exceeding a limit

2.4 TCP Flag Anomalies
Ratio of SYN to ACK packets

Frequency of RST packets

Number of half‑open connections

2.5 Behavioral Analysis
Flow duration statistics (mean, std)

Packet size distribution (mean, std, small packet ratio)

Inter‑arrival times (periodicity detection)

Baseline Learning
The system learns normal behavior over a configurable period (default 24 hours). Baselines are stored and updated daily. Detection thresholds are based on median ± N * IQR (interquartile range) to be robust to outliers.

Strengths
Detects novel attacks without prior knowledge

Adapts to changing traffic patterns

Limitations
Potential for false positives during traffic spikes (e.g., flash crowds)

Requires careful calibration of thresholds

3. Machine Learning Detector
Purpose
Use supervised learning to classify flows as benign or malicious with high precision.

Feature Engineering
Features are extracted from flows aggregated over time windows (default 10 seconds). The current feature set includes:

Category	Features
Volume	total bytes, total packets, avg bytes/packet
Rate	bytes/sec, packets/sec, flows/sec
Packet Size	mean, std, min, max, small packet ratio
Duration	mean, std, min, max
Entropy	src_ip, dst_ip, src_port, dst_port, protocol
TCP Flags	SYN ratio, RST ratio, FIN ratio, ACK ratio
Uniqueness	unique src IPs, unique dst IPs, unique src ports, unique dst ports
Models
We train and evaluate multiple models to select the best performer:

Random Forest – ensemble of decision trees, handles non‑linear relationships well.

XGBoost – gradient boosting, often achieves higher accuracy with proper tuning.

Neural Network (optional) – for deeper pattern learning (requires more data).

The final ensemble uses a weighted average of the best models.

Training Pipeline
Data Collection: Historical flows with ground truth labels (e.g., from CIC‑IDS2017, CSE‑CIC‑IDS2018).

Preprocessing: Cleaning, normalization, handling missing values.

Feature Extraction: Compute window‑based features.

Train/Validation Split: 80% training, 10% validation, 10% test.

Hyperparameter Tuning: Grid search with cross‑validation.

Evaluation: Metrics: precision, recall, F1, AUC‑ROC.

Model Deployment: Export model (joblib) to production location.

Inference
Batch processing: flows are buffered and classified in batches of 100 (configurable).

Confidence threshold: default 0.85. Alerts are generated only when the model’s confidence exceeds the threshold.

Strengths
High accuracy for known attack patterns

Can detect subtle, low‑rate attacks that bypass simple thresholds

Limitations
Requires labeled training data

May suffer from concept drift; periodic retraining is required

4. Ensemble Detector
Purpose
Combine outputs of individual detectors to improve overall detection reliability and reduce false positives.

Voting Mechanisms
Weighted Voting
Each detector contributes a weight and a confidence score. The final score is:

S
=
w
s
i
g
⋅
c
s
i
g
+
w
a
n
o
m
⋅
c
a
n
o
m
+
w
m
l
⋅
c
m
l
w
s
i
g
+
w
a
n
o
m
+
w
m
l
S= 
w 
sig
​
 +w 
anom
​
 +w 
ml
​
 
w 
sig
​
 ⋅c 
sig
​
 +w 
anom
​
 ⋅c 
anom
​
 +w 
ml
​
 ⋅c 
ml
​
 
​
 
Default weights:

Signature: 0.2

Anomaly: 0.4

ML: 0.4

If 
S
S ≥ alert threshold (default 0.6), an alert is generated.

Majority Voting
Alert is raised if at least 
⌈
N
/
2
⌉
+
1
⌈N/2⌉+1 detectors agree (N = number of detectors).

Consensus
All detectors must agree (rarely used).

Correlation Window
Alerts from different detectors within a configurable time window (default 10 seconds) are considered correlated and combined into a single ensemble alert.

Alert Enrichment
Before final publication, the ensemble alert is enriched with:

Human‑readable description

Suggested mitigation actions

Attack category

Geo‑IP information (optional)

5. Performance Metrics
Detection effectiveness is measured using:

Precision = TP / (TP + FP) – correctness of positive alerts

Recall = TP / (TP + FN) – ability to catch attacks

F1‑Score = 2 * (Precision * Recall) / (Precision + Recall)

False Positive Rate = FP / (FP + TN) – important to avoid alert fatigue

Target values (production):

Precision ≥ 0.95

Recall ≥ 0.98

F1 ≥ 0.96

FPR ≤ 0.01

6. Configuration Tuning
Key parameters can be adjusted in the configuration files:

Volumetric thresholds – config/detection/volumetric.yaml

Entropy threshold – config/detection/behavioral.yaml

ML confidence threshold – config/detection/ml_models.yaml

Ensemble weights – config/detection/ml_models.yaml

It is recommended to calibrate thresholds based on your network’s normal traffic profile. Start with the defaults, monitor false positives, and adjust incrementally.

7. Future Improvements
Online Learning: Incrementally update models using feedback from mitigation actions.

Deep Learning: Experiment with LSTM networks for sequence‑based detection (flow sequences).

Graph Neural Networks: Model network topology to detect distributed attacks.

Explainability: Integrate SHAP/LIME to explain ML decisions for security analysts.

For more details, refer to the Configuration Guide and API Reference.