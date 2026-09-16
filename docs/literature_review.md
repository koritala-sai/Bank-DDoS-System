# Literature Review & Background Research

## 1. Existing Research

Distributed Denial of Service (DDoS) attacks present a critical threat to financial institutions and banking networks, where service availability is directly tied to customer trust and operational stability. Prior research in network security has explored various methodologies for DDoS detection:

- **Rule-Based & Signature-Based Systems**: Traditional Intrusion Detection Systems (IDS) like Snort and Suricata rely heavily on known attack signatures. While effective against legacy attacks, they fail against zero-day threats and dynamic botnet behaviors.
- **Statistical Anomaly Detection**: Methods examining threshold metrics (e.g., Packets Per Second spikes) can detect volumetric floods but frequently produce high false-positive rates during legitimate traffic spikes (e.g., flash crowds during peak banking hours).
- **Machine Learning Classifiers**: Recent literature highlights the application of Supervised ML algorithms (Random Forest, Support Vector Machines, XGBoost) trained on benchmark datasets such as CICIDS2017 and CICDDoS2019 to identify subtle attack signatures.

---

## 2. Identified Problem

Modern banking networks handle high-volume financial transactions requiring low latency and high availability. Traditional defense mechanisms face key limitations:

1. **High False Positive Rates**: Standard threshold-based firewalls disrupt legitimate user transactions during high traffic volume events.
2. **Detection Latency**: Offline log processing fails to detect ongoing attacks in real-time, resulting in service outages before countermeasures can be deployed.
3. **Complex Attack Vectors**: Multi-vector DDoS attacks (combining SYN floods with application-layer HTTP floods) evade simple network layer monitoring.

---

## 3. Research Gap

While existing literature proposes advanced ML models for DDoS detection, several gaps remain in real-world deployment:

- **Lack of Integration**: Many studies focus solely on offline model accuracy using static datasets without connecting to live packet capturing systems.
- **Resource Constraints**: High-dimensional feature sets increase inference latency, making real-time flow evaluation impractical on production network interfaces.
- **Absence of Risk-Aware Alerting**: ML models often output binary labels (Attack / Benign) without evaluating multi-tiered risk levels necessary for automated mitigation decisions.

---

## 4. Proposed Improvement

To address these gaps, this project proposes an **AI-Based DDoS Detection and Intelligent Network Monitoring System for Banking Networks**:

1. **Sliding-Window Real-time Feature Extraction**: Efficient feature aggregation using Scapy to maintain low CPU overhead.
2. **Hybrid ML Classification**: Lightweight, high-accuracy Random Forest / XGBoost classifiers optimized for low inference latency.
3. **Multi-Tier Risk Assessment**: Context-aware risk scoring (`Low`, `Medium`, `High`, `Critical`) combining model prediction confidence with packet rate parameters.
4. **End-to-End Monitoring Dashboard**: Full integration from live packet capture to a responsive React management interface.

---

## 5. References

1. Sharafaldin, I., Lashkari, A. H., & Ghorbani, A. A. (2018). *Toward Generating a Dataset for Security Analysis: CICIDS2017*. International Conference on Information Systems Security and Privacy (ICISSP).
2. Elsayed, M. S., Le-Khac, N. A., & Jurcut, A. D. (2020). *Infiltration Detection in Cyber-Physical Systems Using Machine Learning*. IEEE Access.
3. Al-Eryani, G., et al. (2021). *Real-Time DDoS Attack Detection in Software Defined Networks Using Machine Learning*. Journal of Network and Computer Applications.
4. Samarji, L., & Salamah, M. (2023). *A Survey on Machine Learning Approaches for DDoS Detection in Financial Networks*. Cybersecurity Journal.
