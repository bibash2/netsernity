[INSTITUTION / UNIVERSITY NAME]

[Faculty / Department Name]

\

\

\

::: {custom-style="CoverTitle"}
NIDS: A Machine-Learning Based Network Intrusion Detection and Prevention System
:::

\

A PROJECT REPORT

\

Submitted in partial fulfillment of the requirements for the degree of
Bachelor in Computer Application (BCA)

\

Course Code: CACS452, Project III

\

\

**Submitted by:**

[Student Name 1], [Roll No.]

[Student Name 2], [Roll No.]

\

**Submitted to:**

[Supervisor Name]

[Department Name]

\

[Month, Year]

```{=openxml}
<w:p><w:pPr><w:sectPr><w:type w:val="nextPage"/><w:pgSz w:w="11906" w:h="16838"/><w:pgMar w:top="1440" w:right="1440" w:bottom="1440" w:left="1800" w:header="720" w:footer="720" w:gutter="0"/><w:cols w:space="720"/><w:docGrid w:linePitch="360"/></w:sectPr></w:pPr></w:p>
```

::: {custom-style="FrontHeading"}
Supervisor's Recommendation
:::

I hereby recommend that this project report prepared under my supervision by **[Student Name 1]** and **[Student Name 2]**, entitled **"NIDS: A Machine-Learning Based Network Intrusion Detection and Prevention System"**, be accepted as fulfilling in part the requirements for the degree of Bachelor in Computer Application. In my opinion, the work is satisfactory and is ready for evaluation.

\

\

\

………………………………………

**[Supervisor Name]**

Supervisor

[Department Name]

[Institution Name]

```{=openxml}
<w:p><w:r><w:br w:type="page"/></w:r></w:p>
```

::: {custom-style="FrontHeading"}
Letter of Approval
:::

This is to certify that this project report prepared by **[Student Name 1]** and **[Student Name 2]**, entitled **"NIDS: A Machine-Learning Based Network Intrusion Detection and Prevention System"**, in partial fulfillment of the requirements for the degree of Bachelor in Computer Application, has been evaluated by the internal and external examiners. In our opinion it is satisfactory in the scope and quality as a project for the required degree.

\

\

………………………………………  ………………………………………

**[Supervisor Name]**     **[Internal Examiner Name]**

Supervisor          Internal Examiner

\

\

………………………………………  ………………………………………

**[HoD / Coordinator Name]**   **[External Examiner Name]**

HoD / Coordinator        External Examiner

```{=openxml}
<w:p><w:r><w:br w:type="page"/></w:r></w:p>
```

# Acknowledgement

We thank our supervisor, **[Supervisor Name]**, for the guidance and feedback that shaped this project, and the Head and faculty of the **[Department Name]** for the academic foundation and resources that made it possible.

We also acknowledge the researchers whose published algorithms and datasets this work builds on, in particular the Canadian Institute for Cybersecurity for the CIC-IDS2017 dataset and the DistriNet group at KU Leuven for its corrected re-extraction, and the open-source community whose tools supported the engineering of the system.

Finally, we thank our families and friends for their patience and encouragement throughout the development of NIDS.

```{=openxml}
<w:p><w:r><w:br w:type="page"/></w:r></w:p>
```

# Abstract

Signature-based defences cannot recognise attacks they have not seen before, and machine-learning detectors that only exist inside a notebook cannot protect a network. **NIDS** (Network Intrusion Detection System; implemented as the code base *NIDS*) is a complete intrusion detection system with an optional prevention mode. It captures live packets from a network interface, aggregates them into bidirectional flows described by thirty statistical features, and classifies every flow as benign or as one of six attack types, DDoS, Port Scan, Brute Force, Botnet, Infiltration or Web Attack. Every learning algorithm is implemented from first principles in NumPy: a Random Forest and a Multi-Layer Perceptron recognise known attack patterns, an Isolation Forest flags never-before-seen behaviour, and an ensemble layer fuses them with a weighted vote and an anomaly-override rule. Around the detector the project delivers a REST API, an operator dashboard with a real-time WebSocket feed, severity-ranked alerting, a policy-driven enforcement layer that can rate-limit or block attacking addresses, a metrics endpoint, and a from-scratch JWT authentication layer with two roles.

The models were trained on the corrected CIC-IDS2017 dataset (Liu, Engelen et al., 2022) using real flows only, 215,307 deduplicated flows after class capping, and evaluated on a stratified held-out split of 43,062 flows. The ensemble reached 99.94 % accuracy, a macro-averaged F1-score of 97.3 %, a false-positive rate of 0.03 % and a detection rate of 99.86 %, at 0.5 ms per flow. Re-scoring the project's earlier model, which had been trained on a 15 % subsample padded with synthetic rows, on the same held-out flows gave 69.1 % accuracy and a 35.8 % false-positive rate; the comparison shows that data provenance, not model complexity, decided detection quality. A further contribution is a live feature extractor that reproduces the CICFlowMeter conventions of the training data exactly, so that the model behaves on captured traffic the way it behaves on the benchmark.

**Keywords:** Network Intrusion Detection, Machine Learning, Random Forest, Neural Network, Isolation Forest, Ensemble Learning, CIC-IDS2017, Live Packet Capture, Intrusion Prevention, Role-Based Access Control.

```{=openxml}
<w:p><w:r><w:br w:type="page"/></w:r></w:p>
```

::: {custom-style="FrontHeading"}
Table of Contents
:::

```{=openxml}
<w:p><w:r><w:fldChar w:fldCharType="begin" w:dirty="true"/></w:r><w:r><w:instrText xml:space="preserve"> TOC \o "1-3" \h \z \u </w:instrText></w:r><w:r><w:fldChar w:fldCharType="separate"/></w:r><w:r><w:t xml:space="preserve">Right-click and choose Update Field (or press F9) to build the table of contents.</w:t></w:r><w:r><w:fldChar w:fldCharType="end"/></w:r></w:p>
```

```{=openxml}
<w:p><w:r><w:br w:type="page"/></w:r></w:p>
```

# List of Abbreviations

| Abbreviation | Full Form |
| --- | --- |
| API | Application Programming Interface |
| AUC | Area Under the (ROC) Curve |
| CIC-IDS2017 | Canadian Institute for Cybersecurity – Intrusion Detection System dataset, 2017 |
| CIDR | Classless Inter-Domain Routing (network prefix notation) |
| CSV | Comma-Separated Values |
| DDoS | Distributed Denial of Service |
| DR | Detection Rate (share of attack flows flagged as attacks) |
| F1 | F1-Score (harmonic mean of precision and recall) |
| FIN / SYN / RST / ACK / PSH / URG | TCP control flags |
| FPR | False-Positive Rate (share of benign flows flagged as attacks) |
| HMAC | Hash-based Message Authentication Code |
| HTTP / HTTPS | Hypertext Transfer Protocol (Secure) |
| IAT | Inter-Arrival Time between packets |
| IDS / IPS | Intrusion Detection / Prevention System |
| JSON | JavaScript Object Notation |
| JWT | JSON Web Token |
| MLP | Multi-Layer Perceptron |
| NIC | Network Interface Card |
| OOB | Out-Of-Bag (Random Forest validation estimate) |
| PBKDF2 | Password-Based Key Derivation Function 2 |
| RBAC | Role-Based Access Control |
| REST | Representational State Transfer |
| ROC | Receiver Operating Characteristic |
| SOC | Security Operations Centre |
| TCP / UDP | Transmission Control / User Datagram Protocol |
| TLS | Transport Layer Security |
| TTL | Time To Live (duration of a block) |
| UML | Unified Modeling Language |
| WS / WSS | WebSocket (Secure) |

```{=openxml}
<w:p><w:r><w:br w:type="page"/></w:r></w:p>
```

# List of Figures

```{=openxml}
<w:p><w:r><w:fldChar w:fldCharType="begin" w:dirty="true"/></w:r><w:r><w:instrText xml:space="preserve"> TOC \h \z \t "Figure Caption,1" </w:instrText></w:r><w:r><w:fldChar w:fldCharType="separate"/></w:r><w:r><w:t xml:space="preserve">Right-click and choose Update Field (or press F9) to build the list of figures.</w:t></w:r><w:r><w:fldChar w:fldCharType="end"/></w:r></w:p>
```

```{=openxml}
<w:p><w:r><w:br w:type="page"/></w:r></w:p>
```

# List of Tables

```{=openxml}
<w:p><w:r><w:fldChar w:fldCharType="begin" w:dirty="true"/></w:r><w:r><w:instrText xml:space="preserve"> TOC \h \z \t "Table Caption,1" </w:instrText></w:r><w:r><w:fldChar w:fldCharType="separate"/></w:r><w:r><w:t xml:space="preserve">Right-click and choose Update Field (or press F9) to build the list of tables.</w:t></w:r><w:r><w:fldChar w:fldCharType="end"/></w:r></w:p>
```

```{=openxml}
<w:p><w:pPr><w:sectPr><w:footerReference w:type="default" r:id="rIdftr1"/><w:type w:val="nextPage"/><w:pgSz w:w="11906" w:h="16838"/><w:pgMar w:top="1440" w:right="1440" w:bottom="1440" w:left="1800" w:header="720" w:footer="720" w:gutter="0"/><w:pgNumType w:fmt="lowerRoman" w:start="1"/><w:cols w:space="720"/><w:docGrid w:linePitch="360"/></w:sectPr></w:pPr></w:p>
```

# Chapter 1: Introduction

## 1.1 Introduction

Organisations run on their networks, and their networks are under constant, automated attack: denial-of-service floods, port scans, password guessing, botnet traffic, infiltration and web-application attacks arrive around the clock and change faster than hand-written rules can follow. Protecting a network therefore needs more than a perimeter firewall, it needs a system that watches traffic continuously, recognises malicious behaviour, and can react before damage is done.

A **Network Intrusion Detection System (NIDS)** does exactly that. Classical systems match traffic against *signatures* of known attacks; they are precise for what they know and blind to everything else. Machine learning offers a way out: a model can learn the statistical shape of benign and malicious traffic from labelled examples and generalise to variations it has never seen.

This project, **NIDS**, a Network Intrusion Detection System, implemented as the *NIDS* code base, is a complete machine-learning intrusion detection and prevention system, and it differs from a typical academic detector in three ways. First, every model is written from first principles: the decision tree, Random Forest, Multi-Layer Perceptron and Isolation Forest are implemented in NumPy alone, without scikit-learn, TensorFlow or PyTorch, so every step of every decision can be read and audited. Second, it works on live traffic end to end: a packet-capture module turns raw packets into flows whose thirty features are computed exactly as the training dataset computed them, flows are classified within seconds and shown on a dashboard in real time, and, when enforcement is enabled, the attacking address is rate-limited or blocked. Third, it is evaluated honestly on real data: the models are trained on the corrected CIC-IDS2017 benchmark using real flows only, and the report documents what happened when an earlier, synthetically padded model was scored on the same held-out traffic.

Around the detector the project delivers a complete operational system: a REST API for single and batch classification, alerts, blocks and capture control; an operator dashboard fed over WebSocket with every packet and every verdict; severity-ranked alerting with a recommended action per attack class; a policy-driven enforcement layer with a confidence gate, allowlist, duplicate check and capacity cap; a metrics endpoint and structured JSON logs; a from-scratch JWT authentication layer with two roles (Administrator and Viewer) and PBKDF2 password storage; and container images and a suite of 150 automated tests.

## 1.2 Problem Statement

Network attacks today are frequent, automated and constantly changing, and the tools available to a small organisation struggle with three problems at once:

I.  **Signature-based tools miss new attacks.** Any variation that does not match a stored rule passes undetected, and manual monitoring cannot fill the gap because even a small network produces far more flows than an analyst can inspect.
II.  **Machine-learning detectors are usually black boxes.** They depend on large libraries whose internals the developer cannot audit, and a model that only exists in a notebook is not a security system: detection must run continuously on live traffic, respond within milliseconds and raise actionable alerts.
III.  **Benchmark results often do not transfer.** Attack classes are rare and dissimilar, and models trained on small or synthetic samples report high accuracy while failing on real flows.

## 1.3 Objectives

The objectives of the project are:

I.  **To implement the core machine-learning models from first principles:** a decision tree, a Random Forest, a Multi-Layer Perceptron and an Isolation Forest written in NumPy alone and combined into an ensemble that classifies network flows into benign traffic and six attack classes.
II.  **To build a complete real-time detection and prevention service:** live packet capture, a REST API, a WebSocket dashboard, alerting, policy-driven enforcement and role-based authentication around the models, so the detector protects a network rather than a dataset.
III.  **To evaluate the system honestly on real traffic:** training and testing on the corrected CIC-IDS2017 dataset without synthetic data, and reporting per-class results, the false-positive rate and the effect of training-data quality on detection.

## 1.4 Scope and Limitation

### Scope

I.  **Flow-level, seven-class detection.** Each conversation is summarised by thirty numerical features from the CIC-IDS family and classified as benign or one of six attack classes with a confidence value and an anomaly score.
II.  **Live capture and an API.** Traffic reaches the detector from a network interface or mirror port with immediate classification, or as flow records from external sensors through a REST interface.
III.  **Alerting, optional prevention and a dashboard.** Severity-ranked alerts, policy-driven rate-limit, block or drop actions under safety controls, and an operator dashboard fed over WebSocket with two user roles.
IV.  **Reproducible training and deployment.** Download, cleaning, training, weight tuning and an old-versus-new comparison are scripted, and the system is packaged with Docker Compose.

### Limitations

I.  **Flow statistics only.** Payloads are never inspected, so attacks visible only in encrypted or application content are out of reach.
II.  **One benchmark testbed.** The training data comes from CIC-IDS2017 alone; cross-dataset studies show that accuracy drops on other networks, and the rare classes (36 Infiltration and 104 Web Attack flows) give indicative figures only.
III.  **Offline training.** Models do not learn continuously, so adapting to new traffic requires retraining.
IV.  **Platform requirements.** Live capture needs raw-socket (root) access and sees only the traffic that reaches the interface, and real blocking uses the Linux nftables firewall; other platforms run enforcement in log-only mode.

## 1.5 Development Methodology

The project used an **iterative and incremental** methodology: the system decomposes into layers (data, models, training, inference, capture, API, dashboard, alerting, enforcement), each of which was built, tested and integrated in its own cycle, with later cycles revisiting earlier ones as evaluation results came in. The work proceeded through six stages:

I.  **Requirements:** attack classes, feature set, interfaces, performance and safety targets.
II.  **Design:** a modular architecture with a strict dependency rule under which inner layers (data, models, utilities) never depend on outer layers (inference, API, training).
III.  **Incremental implementation:** preprocessing and data loading; the four models; the ensemble; the training pipeline; the inference engine; the API, authentication and dashboard; alerting, metrics and enforcement; finally live packet capture.
IV.  **Testing alongside development:** unit tests for algorithms and utilities, integration tests for the API, enforcement and capture paths.
V.  **Evaluation and correction:** the first evaluation exposed that the initial training subsample contained almost no real rows for three attack classes, so the data pipeline was rebuilt around the corrected CIC-IDS2017 dataset, the live feature extractor was aligned with the dataset's conventions, and the models were retrained and re-evaluated (Chapter 4).
VI.  **Deployment preparation:** container images, a metrics endpoint for monitoring and a continuous-integration pipeline.

A single YAML configuration file holds every tunable value; any value can be overridden by an environment variable, so the same code runs unchanged in development, testing and production.

## 1.6 Report Organization

**Chapter 1: Introduction**

Introduces the problem, states the objectives, the scope and the limitations of the project, and describes the development methodology.

**Chapter 2: Background Study and Literature Review**

Explains flows, intrusion detection, the four learning algorithms and the benchmark datasets, and reviews four related systems together with the research on dataset quality.

**Chapter 3: System Analysis and Design**

Presents the requirements, the feasibility study with the project schedule, the UML models (use case, class, state, sequence, activity and deployment), the layered architecture, the live feature-extraction rules and the algorithms.

**Chapter 4: Implementation and Testing**

Describes the tools, the implementation of each module, the test suite, the training data and the evaluation results.

**Chapter 5: Conclusion and Future Recommendations**

Summarises the outcomes and proposes further work.

```{=openxml}
<w:p><w:r><w:br w:type="page"/></w:r></w:p>
```

# Chapter 2: Background Study and Literature Review

## 2.1 Background Study

Computers exchange data as packets. Inspecting each packet is expensive and, for encrypted traffic, uninformative, so intrusion detectors usually work on flows: all packets of one conversation between two endpoints, identified by source and destination address, source and destination port and protocol, in both directions. A flow is summarised by statistics such as its duration, the packets and bytes sent in each direction, the mean and variance of packet lengths, inter-arrival times, counts of the TCP control flags SYN, ACK, RST and FIN, the initial window sizes and the active and idle periods. NIDS represents every flow by thirty such features, the same family that the CICFlowMeter tool [1] computes for the public CIC-IDS datasets, which keeps the system compatible with real traffic-extraction tools.

An Intrusion Detection System observes traffic and raises alerts; an Intrusion Prevention System also blocks or limits the offending traffic [2]. Signature (misuse) detection compares traffic with known attack patterns and is precise but blind to new attacks; anomaly detection models normal behaviour and flags deviations, which can catch novel attacks at the cost of more false alarms [3]. NIDS combines both: its supervised models act as a learned, generalised form of misuse detection, its Isolation Forest is an anomaly detector, and the enforcement layer turns the system into a prevention system when it is enabled. The six attack classes it detects differ widely in shape. DDoS floods have very high packet and byte rates; port scans consist of thousands of tiny two-packet flows; brute-force attacks repeat similar authentication connections; botnet traffic is periodic and automated; infiltration is low-volume and hard to separate from normal use; and web attacks show unusual request shapes towards a web server. Because these differ so much, no single model handles all of them equally well, which is the main motivation for an ensemble.

Detecting known attack types is a supervised, multi-class classification task. A decision tree splits the data by threshold questions on features, choosing at each step the split that makes the resulting groups purest, measured by Gini impurity or entropy. A single tree memorises its training data, so a Random Forest trains many trees on bootstrap samples with random feature subsets and averages their votes [4], which is far more stable and also yields feature importances and a free out-of-bag accuracy estimate. A Multi-Layer Perceptron passes the features through layers of weighted neurons with non-linear activations to a final layer of class probabilities and learns by backpropagation [5] with the Adam optimiser [6]; the network used here has three hidden layers (256, 128 and 64 neurons), dropout and weight decay against overfitting, and early stopping on a validation set. The Isolation Forest [7] builds random trees by splitting on random features at random thresholds; anomalies, being few and different, are isolated after few splits, so a short average path length means a high anomaly score. NIDS trains it on benign flows only, so any flow that is distinctly unlike normal traffic scores high even if it belongs to an attack type the supervised models never saw. Because different models make different mistakes, the ensemble blends the Random Forest and MLP probabilities with weights chosen on a validation set and then applies an anomaly override: when the blended vote is benign but the Isolation Forest score is high and the supervised models still assign meaningful attack probability, the flow is reclassified as the most likely attack.

Research in this field depends on public benchmark datasets. The KDD Cup 99 family dominated for a decade until its duplicated records and outdated traffic were shown to inflate results [8]; CIC-IDS2017 [9] replaced it with five days of realistic benign traffic and staged attacks, labelled per flow and distributed as CICFlowMeter features, and it is the dataset this project trains on. Real flow data contains infinities and missing values (a zero-duration flow has an infinite byte rate), so preprocessing cleans them, standardises each feature with statistics learned on the training split only, and splits the data into training, validation and test sets while preserving class proportions. Evaluation uses accuracy, per-class precision, recall and F1, the false-positive rate (benign flows flagged as attacks), the detection rate (attack flows flagged as attacks), the confusion matrix and ROC-AUC for the anomaly detector; all of these are implemented from scratch as well. Around the detector, a REST API lets other programs submit flows and read results, a WebSocket connection lets the server push each verdict to the dashboard the moment it is made, a metrics endpoint exposes counters and latency histograms to monitoring tools, JSON Web Tokens carry a signed, expiring statement of who the user is and what role they hold, and containers package the service so it runs identically everywhere.

## 2.2 Literature Review

Automated misuse detection dates to Anderson's audit-trail monitoring [10], and Denning's intrusion-detection model formalised anomaly detection as deviation from a learned profile of normal behaviour [11]. NIST's guide consolidates operational practice for detection and prevention systems [2], and Buczak and Guven's survey of machine-learning methods finds that no single algorithm dominates across attack types [3]. Four systems and studies are closely related to this project.

**Snort** [12] is the most widely deployed open-source network intrusion detection system. It inspects packets against a rule set written by analysts and raises an alert when a rule matches. Its strengths are precision and a mature alerting and logging model; its weakness is that every detection needs a rule written in advance, so novel or modified attacks pass. NIDS keeps the operational model of a continuously running sensor with alerts and blocking, but replaces hand-written rules with a learned classifier.

**Zeek (formerly Bro)** [13] turns raw packets into structured connection records and lets analysts script detection logic over those records. Its connection logs are conceptually the same object as the flows NIDS classifies, and it showed that summarising a conversation by its statistics is enough for real-time analysis. Zeek does not learn from data, however; the detection logic remains manual.

**Kitsune** [14] is an online, unsupervised intrusion detector built from an ensemble of small autoencoders that learn what normal traffic looks like per feature group and flag deviations; it runs on a Raspberry Pi and needs no labelled data. It detects only anomalies and cannot name the attack, whereas NIDS classifies the attack type with supervised models and reserves anomaly detection for the override that catches what those models have not seen.

**Machine-learning evaluations on CIC-IDS2017** [9], [15] benchmark library implementations of Random Forests, decision trees, k-nearest neighbours and deep networks on the original dataset and report Random Forests among the strongest models, which motivated the model choice here. Both use the original labels, which later work found to contain systematic errors [16], [17], and both stop at the classifier. NIDS trains on the corrected re-extraction released with a fixed CICFlowMeter and an explicit marker for attempted attacks [16], [18], implements the models from first principles, and wraps them in a complete detection and prevention service.

Two further findings shaped the design. Sommer and Paxson explain why machine-learning detectors that excel in the laboratory disappoint in deployment: costly false alarms, scarce labelled data, the gap between research datasets and live traffic, and the need for interpretable output [19]. Cross-dataset studies show that detectors trained on one benchmark generalise poorly to another [20], partly because flow exporters compute features differently [1], which is why NIDS reproduces the training data's feature conventions in its live extractor rather than approximating them.

```{=openxml}
<w:p><w:r><w:br w:type="page"/></w:r></w:p>
```

# Chapter 3: System Analysis and Design

## 3.1 System Analysis

### 3.1.1 Requirement Analysis

#### i. Functional Requirements

NIDS has three actors: the **Administrator** (operates the system, classifies traffic, controls capture and enforcement, manages users, trains models), the **Viewer**, a security analyst with read-only access to the dashboard, alerts, blocked addresses and metrics, and the **External System / Traffic Sensor**, a program that submits flow records through the API using an API key or a token.

The system shall:

I.  Capture packets from a network interface, aggregate them into bidirectional flows and compute the thirty flow features exactly as the training dataset defines them.
II.  Classify a completed flow as benign or as one of six attack classes, returning the class, a confidence value, an anomaly score, per-class probabilities and whether the anomaly override fired.
III.  Accept single flows and batches of up to one thousand flows through the REST API.
IV.  Classify long-lived flows while they are still active, and flows that end with RST or FIN immediately, so that verdicts appear within seconds.
V.  Push every captured packet and every verdict to connected dashboards over WebSocket.
VI.  Generate a severity-ranked alert with a recommended action for every detected attack, keep recent alerts in memory and append them to a log file.
VII.  Aggregate alerts by source address so the dashboard can show the most active attackers and whether they are blocked.
VIII.  Optionally enforce a per-attack-class action (rate-limit, block or drop, each with a duration) when enforcement is enabled, the confidence exceeds the policy threshold, the address is not allowlisted, is not already blocked and the block cap is not reached.
IX.  Allow an administrator to list, filter and clear alerts, list and remove blocks, and start or stop live capture.
X.  Expose health, readiness and metrics endpoints without authentication, and all other endpoints only to authenticated users of the required role.
XI.  Authenticate users by username and password, issue signed JWTs with an expiry, and let users change their own passwords; let administrators create, list and delete users.
XII.  Train, evaluate and save all models from the dataset with a single command, tune the ensemble weights on the validation split, and report metrics per model and per class.

Figure 3.1 summarises the interactions between actors and system.

::: {custom-style="FigureCenter"}
![](figures/usecase.png){width=6.0in}
:::

::: {custom-style="Figure Caption"}
Figure 3.1: Use Case Diagram of NIDS
:::

::: {custom-style="Table Caption"}
Table 3.1: Use Case Descriptions
:::

| Use Case | Actor | Description |
| --- | --- | --- |
| Login / Authenticate | All | Username and password are verified against PBKDF2 hashes and a signed JWT valid for 24 hours is returned; external systems may present an API key instead, which grants the Administrator role. |
| Classify single flow / batch | External System, Administrator | One flow or up to 1,000 flows are preprocessed and classified; each result carries class, confidence, anomaly score and probabilities. Attack verdicts create alerts and may trigger enforcement. |
| Start / stop live packet capture | Administrator | The in-process sniffer is started on a chosen interface; flows are classified as they complete and streamed to the dashboard. |
| Probe a flow (Try-it panel) | Administrator | A preset or hand-edited flow is submitted from the dashboard to demonstrate a verdict. |
| View live traffic & verdicts | Viewer (and Administrator) | The live table shows every packet; the feed shows every verdict as it is pushed over WebSocket. |
| View & filter alerts | Viewer | Recent alerts are listed with severity, class, confidence and source address, filterable by severity. |
| View blocked IPs / top source IPs | Viewer | Active blocks with remaining time, and the source addresses with the most alerts. |
| View metrics & statistics | Viewer | Prediction counts, attack rate, latency percentiles, alert and block summaries. |
| Change own password | Viewer, Administrator | The current password is verified before the new one is stored. |
| Clear alerts / unblock IPs | Administrator | Clears the alert history, removes one block or flushes all blocks. |
| Manage users | Administrator | Creates, lists and deletes accounts and assigns roles. |
| Train / retrain models | Administrator | Runs the training pipeline from the command line; artifacts and the metrics report are written to disk and loaded at the next start-up. |

Functional requirement 8, automated response, is governed by a per-class policy (Table 3.2). Each attack class maps to an action, a duration and a minimum confidence.

::: {custom-style="Table Caption"}
Table 3.2: Enforcement Policy per Attack Class
:::

| Attack class | Action | Duration | Minimum confidence |
| --- | --- | --- | --- |
| BENIGN | allow | - |, |
| PortScan | rate-limit | 1 hour | 0.90 |
| WebAttack | rate-limit | 1 hour | 0.90 |
| BruteForce | block | 24 hours | 0.85 |
| Botnet | block | 24 hours | 0.85 |
| Infiltration | block | 24 hours | 0.85 |
| DDoS | drop | 24 hours | 0.80 |

A global gate (`min_confidence_to_enforce`, 0.85 in the shipped configuration) can raise the per-class thresholds, enforcement is off unless explicitly enabled, a dry-run mode logs what would be blocked without touching the firewall, and the default allowlist protects the local host.

#### ii. Non-Functional Requirements

::: {custom-style="Table Caption"}
Table 3.3: Non-Functional Requirements
:::

| Quality | Requirement |
| --- | --- |
| Performance | Classification of one flow in about one millisecond including preprocessing; verdicts for captured flows within a few seconds of the flow completing. |
| Accuracy | False-positive rate below 0.1 % on the held-out benchmark split; detection rate above 99 %. |
| Reliability | Health and readiness checks; the service refuses traffic if model artifacts are missing; capture failures never crash the API. |
| Transparency | Every verdict exposes each model's probabilities and the anomaly score; the training report records per-class metrics. |
| Security | JWT authentication with RBAC, PBKDF2-SHA256 password storage, request rate limiting, strict input validation, and an allowlist of networks that can never be blocked. |
| Maintainability | Modular code with an inward-only dependency rule; 150 automated tests; a single configuration file. |
| Portability | Runs on any host with Python 3.10+; identical behaviour in containers through external configuration. |
| Observability | Structured JSON logs with request identifiers, a metrics endpoint, an alert stream and a WebSocket event stream. |

The security requirement is realised with two roles whose permissions are fixed per endpoint (Table 3.4).

::: {custom-style="Table Caption"}
Table 3.4: Role-Based Access Control Matrix
:::

| Capability | Viewer | Administrator |
| --- | :---: | :---: |
| View dashboard, live feed, alerts, blocked IPs, statistics | Yes | Yes |
| Change own password | Yes | Yes |
| Submit flows for classification (API, batch, Try-it probe) | No | Yes |
| Start / stop live packet capture | No | Yes |
| Clear alerts, unblock IPs, flush blocks | No | Yes |
| Create, list and delete user accounts | No | Yes |
| Health, readiness and metrics endpoints | Public | Public |

External systems that present a valid API key act with Administrator rights so that they can submit traffic; API keys are configured, not stored as users.

### 3.1.2 Feasibility Analysis

**i. Technical Feasibility.** Python, NumPy, FastAPI and scapy are mature and run on ordinary hardware; the four algorithms are well documented in the literature and were implemented and validated against known results. The full training run takes about six minutes on a laptop.

**ii. Operational Feasibility.** The system slots into an existing workflow: it watches an interface or receives flows from a sensor, shows verdicts on a dashboard, and can act automatically only under explicit, conservative conditions (confidence gate, allowlist, dry run). Two roles keep read-only monitoring separate from operational control.

**iii. Economic Feasibility.** Only free, open-source software is used; no specialised hardware is needed, and inference costs about half a millisecond of CPU per flow.

**iv. Schedule Feasibility.** The layered, incremental plan allowed each module to be built and tested within the semester, including one full rebuild of the data pipeline after evaluation exposed the training-data problem. Figure 3.2 shows the planned timeline against the semester's proposal, mid-term and final-defence milestones.

::: {custom-style="FigureCenter"}
![](figures/gantt.png){width=6.0in}
:::

::: {custom-style="Figure Caption"}
Figure 3.2: Gantt Chart of the Project Schedule
:::

### 3.1.3 Object Modelling: Class Diagram

Figure 3.3 shows the core classes. All models share the `BaseModel` interface; the `RandomForest` is composed of `DecisionTree` objects; `EnsembleNIDS` combines the three model types. `PacketSniffer` builds `FlowAccumulator` objects from packets and hands completed flows to the `InferenceEngine`, which uses the `Preprocessor` and the ensemble and reports results to the `AlertManager`. Alerts flow to the `ResponseExecutor`, which consults the `Allowlist` and delegates to a pluggable `FirewallBackend` (nftables, log-only or no-op).

::: {custom-style="FigureCenter"}
![](figures/class.png){width=6.0in}
:::

::: {custom-style="Figure Caption"}
Figure 3.3: Class Diagram of the Core Modules
:::


### 3.1.4 Dynamic Modelling: State and Sequence Diagrams

**State diagram.** Under enforcement a source address is *observed* until an attack verdict passes the policy gates, after which it is *rate-limited* (Port Scan, Web Attack) or *blocked/dropped* (Brute Force, Botnet, Infiltration, DDoS) for the duration fixed in Table 3.2, returning to *observed* when the timer expires or an administrator unblocks it (Figure 3.4).

::: {custom-style="FigureCenter"}
![](figures/state.png){width=6.0in}
:::

::: {custom-style="Figure Caption"}
Figure 3.4: State Diagram of a Source Address under Enforcement
:::

**Sequence diagram.** Figure 3.5 shows a prediction request: the API authenticates, rate-limits and validates the request, the engine preprocesses and runs the ensemble, and, only if the verdict is an attack, the alert manager records an alert and asks the response executor to enforce it. The verdict is pushed to the dashboard over WebSocket and returned to the caller. Flows from the live sniffer follow the same path from `predict()` onward.

::: {custom-style="FigureCenter"}
![](figures/sequence.png){width=6.0in}
:::

::: {custom-style="Figure Caption"}
Figure 3.5: Sequence Diagram of a Prediction Request
:::

### 3.1.5 Process Modelling: Activity Diagram

Figure 3.6 traces one flow from arrival to telemetry, including the anomaly-override decision and the five conditions that must all hold before any enforcement action is taken.

::: {custom-style="FigureCenter"}
![](figures/activity.png){width=5.7in}
:::

::: {custom-style="Figure Caption"}
Figure 3.6: Activity Diagram of Detection and Enforcement
:::

## 3.2 System Design

### 3.2.1 Refinement of Class, State, Sequence and Activity Diagrams

During design the analysis models of Section 3.1 were refined into implementable structures. The abstract `BaseModel` received explicit `fit`, `predict`, `predict_proba`, `save` and `load` operations so that every model and the ensemble are interchangeable and persistable. `FirewallBackend` was refined into an abstract interface with three concrete implementations (nftables, log-only, no-op) so the enforcement layer can be switched without touching its logic. `Preprocessor` was refined to store the fitted scaling parameters so that inference applies exactly the transformation learned in training. `PacketSniffer` and `FlowAccumulator` were added to the class model once live capture became a requirement, together with the CICFlowMeter rules that make their output comparable with the training data. The state, sequence and activity models were refined to include the confidence gate, the allowlist, the duplicate-block check and the capacity cap that together make automated enforcement safe. The refined design is summarised by the architecture in Figure 3.7 and by the feature-extraction rules in Table 3.5.

**Architecture.** Figure 3.7 shows the system layer by layer. Traffic enters as raw packets from the network interface or as flow records from external sensors. The API and security layer authenticates the caller, validates and rate-limits the request and pushes results to the dashboard. The detection layer cleans and scales the thirty features, runs the Random Forest and MLP vote, applies the Isolation Forest override and produces a verdict per flow. The response layer turns attack verdicts into alerts, rate-limit, block or drop actions and dashboard updates. The data and training layer, which runs offline, turns the corrected CIC-IDS2017 dataset into the trained model artifacts that the detection layer loads at start-up.

::: {custom-style="FigureCenter"}
![](figures/arch.png){width=5.7in}
:::

::: {custom-style="Figure Caption"}
Figure 3.7: Overall System Architecture of NIDS
:::

**Live feature extraction.** The model can only be as good on live traffic as the match between live features and training features. The training data was produced by CICFlowMeter, whose conventions differ from a naive implementation in several ways; the sniffer reproduces each one (Table 3.5), and unit tests pin them.

::: {custom-style="Table Caption"}
Table 3.5: Live Feature Extraction Rules Mirrored from CICFlowMeter
:::

| Feature family | Rule reproduced in NIDS |
| --- | --- |
| Packet-length mean / std / variance, segment sizes, bytes per second | Computed on **transport payload bytes** (IP total length minus IP and transport headers), never on frame length; Ethernet padding is excluded. |
| Forward header length | Sum of **transport headers only** (TCP data offset × 4; 8 bytes for UDP). |
| Active / idle periods | A silence longer than **5 s** ends an active period *at the last packet before the gap*; flows without such a gap keep both at 0. |
| Flow lifetime | A flow is cut **120 s** after its first packet; it ends immediately on **RST** or when **both** directions have sent FIN. |
| Zero-duration flows | Byte and packet rates are reported as 0 (the dataset stores the tool's division-by-zero as 0). |
| Minimum flow size | Two packets, a probe and its reply, form a classifiable flow, so scan probes are judged as soon as the reply arrives. |
| Direction and timing | Forward is the direction of the first packet; durations and inter-arrival times are in microseconds. |

Long-lived flows are additionally classified *in flight* every two seconds once they have accumulated twenty new packets, so a flood is reported while it is happening rather than after it stops.

### 3.2.2 Deployment Diagram

Figure 3.8 shows the deployment. A single server running Docker hosts the API container (FastAPI, the inference engine and the packet sniffer on port 8000) together with the model artifacts and the alert log. The monitored network feeds it raw packets from a switch mirror port or the host interface, analysts reach the login page and the dashboard from a web browser over HTTP and WebSocket, and a one-shot trainer container rewrites the model artifacts whenever the models are retrained.

::: {custom-style="FigureCenter"}
![](figures/deployment.png){width=6.0in}
:::

::: {custom-style="Figure Caption"}
Figure 3.8: Deployment Diagram of NIDS
:::

## 3.3 Algorithm Details

**Random Forest (training and prediction).**

```
1. For each of N = 150 trees:
   a. Draw a bootstrap sample (with replacement) of the training rows.
   b. Grow a decision tree on the sample: at each node consider sqrt(30) random
      features, choose the threshold that minimises Gini impurity, stop at
      depth 20, at a pure node, or at fewer than 2 rows per leaf.
   c. Remember the rows the tree did not see (out-of-bag).
2. Predict: average the class-probability vectors of all trees (soft vote).
3. The out-of-bag rows give an accuracy estimate without a separate set;
   averaging each feature's impurity reduction gives feature importances.
```

**Multi-Layer Perceptron (training).**

```
1. Layers 30 -> 256 -> 128 -> 64 -> 7 with ReLU activations and softmax output;
   He initialisation.
2. For up to 50 epochs over shuffled mini-batches of 512 rows:
   a. Forward pass with dropout (p = 0.3) on hidden layers.
   b. Cross-entropy loss with L2 penalty (1e-4).
   c. Backward pass to obtain weight gradients; Adam update (lr = 0.001).
   d. Stop early when the validation loss has not improved for 8 epochs
      (the best weights are kept).
```

**Isolation Forest (anomaly scoring).**

```
1. Build 150 trees, each on a random subsample of 256 BENIGN training rows,
   splitting on a random feature at a random threshold until isolation.
2. Score a flow by its average path length across trees, normalised to [0, 1]:
   short paths (isolated quickly) mean high anomaly scores.
3. A threshold calibrated on training data (contamination 3 %) marks anomalies.
```

**Ensemble fusion.**

```
1. P = 0.9 * P_RandomForest + 0.1 * P_MLP
   (weights chosen on the validation split)
2. Verdict = argmax P.
3. Anomaly override: if the verdict is BENIGN, the Isolation Forest score is
   at least 0.9 and the highest attack probability is at least 0.15, the
   verdict becomes that attack class.
4. Return the verdict with every component's probabilities and the anomaly score.
```

```{=openxml}
<w:p><w:r><w:br w:type="page"/></w:r></w:p>
```

# Chapter 4: Implementation and Testing

## 4.1 Implementation

### 4.1.1 Tools Used

::: {custom-style="Table Caption"}
Table 4.1: Tools and Technologies Used
:::

| Category | Tool / Technology | Purpose |
| --- | --- | --- |
| Language | Python 3.10+ | All components. |
| Numerical computing | NumPy | The only library used for the machine-learning mathematics. |
| Packet capture | scapy | Reads packets from the interface for the live sniffer (optional dependency). |
| Web framework | FastAPI, Uvicorn | REST API, WebSocket endpoint and dashboard hosting. |
| Validation / configuration | Pydantic, PyYAML | Request schemas; central configuration with environment overrides. |
| Testing | pytest, httpx | 150 unit and integration tests; API test client. |
| Monitoring | Built-in metrics registry | Counters, gauges and latency histograms exposed on a metrics endpoint in a standard text format for external monitoring tools. |
| Enforcement | nftables | Real blocking on Linux hosts; log-only and no-op backends elsewhere. |
| Deployment | Docker, Docker Compose | Container images for the API and the trainer. |
| Version control / CI | Git, GitHub Actions | Source control; lint, test and image build on every push. |
| CASE / diagramming | Python + matplotlib (scripted UML), pandoc | Every diagram and this report are generated from version-controlled scripts (`docs/figures/make_figures.py`, `docs/build_docs.py`). |
| Database platform | None, JSON files and in-memory stores | Users in `users.json` (PBKDF2 hashes), alerts in `alerts.jsonl`, model artifacts on disk, block table in memory; no relational database is required. |
| Dataset | Corrected CIC-IDS2017 (DistriNet, KU Leuven) | Training and evaluation data (downloaded by the project's script). |

No machine-learning library, scikit-learn, TensorFlow, PyTorch or similar, is used anywhere in the system.

### 4.1.2 Implementation Details of Modules

I.  **Data module.** `real_dataset.py` loads the corrected CIC-IDS2017 CSVs, maps the CICFlowMeter column names onto the thirty NIDS features, maps the fine-grained labels onto the seven classes, drops flows marked *Attempted*, removes exact duplicate rows, caps the large classes and writes a single training CSV. The `Preprocessor` replaces infinities and missing values (median imputation), clips extreme values, standardises each feature with training-set statistics, performs the stratified train/validation/test split, and is saved with the models so inference applies exactly the same transformation. A synthetic generator remains only for unit tests and quick demonstrations.
II.  **Models module.** `DecisionTree` (Gini or entropy splits, iterative construction so deep trees cannot exhaust the call stack), `RandomForestClassifier` (bootstrap sampling, random feature subsets, multi-process training, out-of-bag score, feature importances), `MLPClassifier` (forward and backward passes, Adam, dropout, L2, early stopping), `IsolationForest` (random trees on benign data, path-length scoring, calibrated threshold) and `EnsembleNIDS` (weighted soft vote, anomaly override, per-component detail) all share the `BaseModel` interface and save and load themselves.
III.  **Training module.** `TrainingPipeline` loads the prepared CSV, splits it, fits the preprocessor on the training rows, trains the Random Forest, the MLP (with the validation split for early stopping) and the Isolation Forest (benign rows only), assembles the ensemble, evaluates every model on the test split and writes the artifacts and a JSON metrics report. `tune_ensemble.py` searches the vote weight on the validation split and re-scores the test split; `compare_models.py` scores two artifact sets on the identical held-out rows.
IV.  **Capture module.** `PacketSniffer` runs scapy in a background thread, parses each packet into CICFlowMeter-style fields (`parse_packet`), keys flows bidirectionally by their five-tuple and feeds `FlowAccumulator` objects. A flow is classified when it closes (RST or both FINs), when it is idle for 30 s, when it reaches the 120 s lifetime, or in flight after twenty new packets. Every packet and every verdict is broadcast to the dashboard. The command-line capture tool and the pcap evaluator import the same code, so the three paths cannot drift apart.
V.  **Inference module.** `InferenceEngine` loads the preprocessor and ensemble once, converts feature dictionaries into matrices, classifies single flows or batches, and tracks latency percentiles. `AlertManager` maps attack classes to severities and recommended actions, keeps the last thousand alerts, appends every alert to `alerts.jsonl` and invokes the enforcement callback.
VI.  **Authentication module.** `JWTHandler` signs and verifies tokens with HMAC-SHA256 and enforces expiry; `UserStore` keeps accounts in a JSON file with atomic writes and hashes passwords with PBKDF2-SHA256 (100,000 iterations, per-user random salt); `require_role()` guards each endpoint; two accounts (administrator, viewer) are seeded on first start and should be changed immediately.
VII.  **API module.** Health, readiness and metrics endpoints are public. Authenticated endpoints cover prediction (single and batch), alerts, blocked addresses, statistics, capture control and user management, each guarded by the role in Table 3.4 and by a sliding-window rate limiter (240 requests per minute per client). A WebSocket endpoint streams packet and verdict events to the dashboard, which is served with its login page from the same process.
VIII.  **Enforcement module.** `ResponseExecutor` evaluates every alert against the policy in Table 3.2, applies the confidence gate, allowlist, duplicate check and capacity cap (10,000 blocks), and delegates to the configured backend; blocks carry a time-to-live and can be listed, removed or flushed.
IX.  **Monitoring and utilities.** A small metrics registry renders counters, gauges and histograms in a standard text format; utilities provide configuration loading with environment overrides, structured JSON logging with request identifiers, and the from-scratch evaluation metrics.

## 4.2 Testing

All tests run with pytest, locally and in the continuous-integration pipeline.

### 4.2.1 Test Cases for Unit Testing

::: {custom-style="Table Caption"}
Table 4.2: Unit Test Cases
:::

| ID | Component | Test Case | Expected Result |
| --- | --- | --- | --- |
| U1 | Decision Tree | Fit and predict on separable data | Labels reproduced; probabilities sum to one |
| U2 | Decision Tree | Gini and entropy criteria | Both yield valid, consistent splits |
| U3 | Random Forest | Out-of-bag score and importances | Score in [0, 1]; importances non-negative and sum to one |
| U4 | MLP | Fit, predict, early stopping | Learns the data; stops when validation stops improving |
| U5 | Isolation Forest | Outlier scoring | Clear outliers receive high anomaly scores |
| U6 | Ensemble | Fusion and override | Combined verdict with per-component detail |
| U7 | Preprocessor | Stratified split; infinity and NaN handling | Class proportions preserved; invalid values cleaned |
| U8 | Metrics | Confusion matrix, F1, ROC-AUC | Match hand-computed values; AUC = 1 for a perfect ranker |
| U9 | Dataset loader | Label mapping | *Attempted* flows dropped; *Infiltration – Portscan* mapped to PortScan |
| U10 | Capture | Payload and header semantics | TCP payload = IP length − headers; header = transport only; padding ignored |
| U11 | Capture | Flow termination | Flow closes on RST or on FIN in both directions |
| U12 | Capture | Active/idle accounting | 5 s threshold; active period ends at the last packet before the gap |
| U13 | Capture | Zero-duration flow | Byte and packet rates reported as 0 |
| U14 | Capture | In-flight classification | Long-lived flow classified without eviction; no duplicate verdict without growth |
| U15 | Enforcement policy | Every attack class has a policy | All classes map to an action, duration and threshold |
| U16 | Allowlist | Private and public addresses | Trusted networks allowed; others not |
| U17 | JWT handler | Create, verify, expire, tamper | Valid claims returned; expired or altered tokens rejected |
| U18 | User store | Seed, authenticate, create, delete, change password | Defaults created; wrong password rejected; changes persist |

### 4.2.2 Test Cases for System Testing

::: {custom-style="Table Caption"}
Table 4.3: System / Integration Test Cases
:::

| ID | Scenario | Test Case | Expected Result |
| --- | --- | --- | --- |
| S1 | Health | Call health and readiness endpoints | Status, version and model-loaded flag returned |
| S2 | Detection | Submit a benign flow | Classified benign; no alert |
| S3 | Detection | Submit a real DDoS flow from the dataset | Classified as an attack; alert created |
| S4 | Batch | Submit a mixed batch | One result per flow and an alert count |
| S5 | Alerts | List and filter after attacks | Recent alerts returned; severity filter works |
| S6 | Enforcement | High-confidence attack with source address | Address blocked with the policy's action and duration |
| S7 | Enforcement | Low-confidence attack | No block applied |
| S8 | Allowlist | Attack from a trusted address | Never blocked |
| S9 | Enforcement | Same attacker seen twice | Blocked once |
| S10 | Block lifecycle | Block, list, unblock, flush | Records created and removed |
| S11 | Capacity | Exceed the block cap | Further blocks refused safely |
| S12 | Simulation | Replay a traffic mix | Alerts and statistics reflect the traffic |
| S13 | Authentication | Valid and invalid login | Token with role, or 401 |
| S14 | RBAC | Protected endpoint without token | 401 |
| S15 | RBAC | Viewer reads statistics; Viewer submits a flow | 200; 403 |
| S16 | RBAC | Administrator submits a flow; non-admin manages users | 200; 403 |
| S17 | Users | Administrator creates, lists, deletes | Operations succeed |
| S18 | Password | User changes own password | Old password no longer works |
| S19 | Public | Health, readiness, metrics without token | 200 |

All **150 tests pass**. The continuous-integration pipeline lints the code, runs the suite and builds the container image on every change.

## 4.3 Result Analysis

### 4.3.1 Training Data

The models were trained on the corrected CIC-IDS2017 dataset published by Liu, Engelen et al. [18]: about 2.1 million flows re-extracted from the original packet captures with a fixed CICFlowMeter and relabelled. Three rules were applied when loading it:

I.  Flows labelled *Attempted*, attack traffic that never exhibited malicious behaviour (no payload sent, closed port, tool start-up artefacts), were **dropped**. The dataset's authors state that they must not be treated as a separate label; training on them as attacks teaches the model that every failed connection is hostile, and training on them as benign hides real attack shapes.
II.  The port scan launched from the infiltrated host (*Infiltration – Portscan*) was labelled **PortScan**, by behaviour rather than by campaign.
III.  The DoS and DDoS tools and Heartbleed form one **DDoS** class; FTP and SSH password guessing form **BruteForce**; the three web attacks form **WebAttack**.

Exact duplicate rows were removed before splitting, so no test flow has a twin in the training set (port-scan probes are nearly identical, and 230,000 raw rows collapse to 7,498 unique ones). BENIGN was capped at 150,000 rows and DDoS at 50,000; the other classes were used in full. Table 4.4 shows the result; the split was 70 % training, 10 % validation and 20 % test, stratified by class.

::: {custom-style="Table Caption"}
Table 4.4: Composition of the Training Data
:::

| Class | Flows | Share | Test rows |
| --- | ---: | ---: | ---: |
| BENIGN | 150,000 | 69.7 % | 30,000 |
| DDoS | 50,000 | 23.2 % | 10,000 |
| PortScan | 7,498 | 3.5 % | 1,500 |
| BruteForce | 6,933 | 3.2 % | 1,387 |
| Botnet | 736 | 0.3 % | 147 |
| WebAttack | 104 | < 0.1 % | 21 |
| Infiltration | 36 | < 0.1 % | 7 |
| **Total** | **215,307** | **100 %** | **43,062** |

No synthetic rows were used. The complete pipeline, loading 2.1 million rows, deduplication, training all models with eight worker processes and evaluation, took about six minutes on a ten-core laptop.

### 4.3.2 Overall Performance

::: {custom-style="Table Caption"}
Table 4.5: Overall Model Performance on the Test Split (43,062 flows)
:::

| Model | Accuracy | Macro F1 | False-positive rate | Detection rate | Inference | Training |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| Random Forest | 99.94 % | 96.9 % | 0.03 % | 99.86 % | 0.36 ms/flow | 262 s |
| Multi-Layer Perceptron | 99.83 % | 89.9 % | 0.11 % | 99.69 % | 0.001 ms/flow | 27 s |
| **Ensemble (RF 0.9 / MLP 0.1)** | **99.94 %** | **97.3 %** | **0.03 %** | **99.86 %** | 0.51 ms/flow | - |
| Isolation Forest (benign vs anomaly) | 86.3 % | F1 0.73 | - | ROC-AUC 0.939 | - | 16 s |

The Random Forest is the strongest single model. The MLP is almost as accurate overall but weaker on the rare classes, which drags its macro-F1 down. The ensemble weights were therefore chosen on the *validation* split, never on the test split: at the original 0.6/0.4 weighting the ensemble's macro-F1 was 0.905 and its Infiltration recall 0.29; at 0.9/0.1 the validation macro-F1 was highest, and on the test split the ensemble then reached 0.973 while keeping the false-positive rate at 0.03 %, nine benign flows out of thirty thousand. The Isolation Forest, judged alone as a benign-versus-attack detector, is deliberately weaker: its job is not to classify known attacks but to catch unusual flows the supervised models would pass as benign.

### 4.3.3 Per-Class Performance

::: {custom-style="Table Caption"}
Table 4.6: Per-Class Performance of the Ensemble Model
:::

| Class | Precision | Recall | F1-Score | Test rows |
| --- | ---: | ---: | ---: | ---: |
| BENIGN | 0.999 | 1.000 | 1.000 | 30,000 |
| DDoS | 1.000 | 1.000 | 1.000 | 10,000 |
| PortScan | 0.995 | 0.996 | 0.996 | 1,500 |
| BruteForce | 0.999 | 0.996 | 0.997 | 1,387 |
| Botnet | 1.000 | 1.000 | 1.000 | 147 |
| Infiltration | 1.000 | 0.857 | 0.923 | 7 |
| WebAttack | 1.000 | 0.810 | 0.895 | 21 |

The five well-represented classes are separated almost perfectly. The two rare classes are the honest weak points: one of seven Infiltration flows and four of twenty-one Web Attack flows were read as benign. With so few real examples these figures are indicative only, and the report makes no stronger claim for them. Figure 4.1 shows every classification of the test split.

::: {custom-style="FigureCenter"}
![](figures/confusion.png){width=6.0in}
:::

::: {custom-style="Figure Caption"}
Figure 4.1: Ensemble Confusion Matrix on the Held-Out Test Split
:::

Of the 43,062 test flows, 43,035 lie on the diagonal. The off-diagonal cells are small and explainable: nine benign flows were flagged (seven as PortScan, two as BruteForce), and eighteen attack flows were missed, all of them read as benign, one DDoS, six PortScan, six BruteForce, one Infiltration and four WebAttack. No attack was confused with a *different* attack class.

### 4.3.4 Effect of Training-Data Quality

The project's first model had been trained on a widely circulated 15 % subsample of the original CIC-IDS2017 CSVs. That subsample contained 26 real PortScan flows, 2 Botnet flows and no Infiltration flows at all; the loader padded each class to 1,000 rows with synthetic data, and the model reported 99.4 % accuracy on its own split. Table 4.7 shows what happened when both models were scored on the same 43,062 real held-out flows of the corrected dataset.

::: {custom-style="Table Caption"}
Table 4.7: Previous versus Retrained Model on Identical Held-Out Flows
:::

| Metric | Previous model | Retrained model |
| --- | ---: | ---: |
| Accuracy | 69.1 % | 99.94 % |
| False-positive rate | 35.8 % | 0.03 % |
| Detection rate | 98.3 % | 99.86 % |
| Recall: BENIGN | 64.2 % | 99.97 % |
| Recall: DDoS | 91.4 % | 99.99 % |
| Recall: PortScan | 80.1 % | 99.60 % |
| Recall: BruteForce | 0.0 % | 99.57 % |
| Recall: Botnet | 95.9 % | 100 % |
| Recall: Infiltration | 100 % (7 rows) | 85.7 % (7 rows) |
| Recall: WebAttack | 0.0 % | 81.0 % |


The previous model flagged more than a third of real benign traffic as attacks and recognised no Brute Force or Web Attack flows; its published accuracy measured how well it had learned the synthetic generator, not real attacks. Nothing about the algorithms changed between the two rows of Table 4.7, only the data. This is the project's most important empirical result: for intrusion detection, the provenance and labelling of the training data decide detection quality more than model choice does, which is exactly the caution raised in the literature [16], [18], [19].

### 4.3.5 Live Operation

With the retrained model loaded, the API classifies a flow in about half a millisecond (median 1.3 ms end to end including request handling), pushes each verdict to the dashboard as it is made, and rate-limits or blocks attacking addresses under the policy in Table 3.2. Replaying real dataset flows through the running service reproduced the test-split accuracy, and the aligned feature extractor closes verdicts on scan probes as soon as the reply packet arrives instead of after a 30-second idle timeout.

```{=openxml}
<w:p><w:r><w:br w:type="page"/></w:r></w:p>
```

# Chapter 5: Conclusion and Future Recommendations

## 5.1 Conclusion

This project set out to build a transparent, deployable, machine-learning network intrusion detection system and to evaluate it honestly. All objectives were met. Four learning algorithms, decision tree, Random Forest, Multi-Layer Perceptron and Isolation Forest, were implemented in NumPy alone and fused into an ensemble that classifies flows into benign traffic and six attack classes with 99.94 % accuracy, a 97.3 % macro-F1, a 0.03 % false-positive rate and a 99.86 % detection rate on 43,062 real held-out flows, at about half a millisecond per flow.

The detector runs as a complete service: live packet capture whose features match the training data exactly, a REST API, a WebSocket-driven dashboard, severity-ranked alerts, a metrics endpoint, a policy-driven enforcement layer with safety controls, JWT authentication with two roles, containers, and 150 automated tests.

The most valuable lesson came from evaluation. A model trained on a small, synthetically padded subsample had looked excellent on its own split and failed on real traffic; rebuilding the data pipeline around the corrected CIC-IDS2017 dataset and aligning the live feature extractor with the dataset's conventions turned a 36 % false-positive rate into 0.03 % without changing a single algorithm. Transparent models made this diagnosis possible, and correct data made the system work.

## 5.2 Future Recommendations

I.  **Cross-dataset validation.** Score the model on the corrected CSE-CIC-IDS2018 dataset and on locally captured traffic to measure how far the results transfer beyond one testbed, and retrain on the union if the drop is large.
II.  **More real examples of rare attacks.** Infiltration and Web Attack have too few real flows; adding traffic from newer datasets or controlled lab captures would make their figures meaningful.
III.  **Online and incremental learning.** Let the models update from newly labelled flows without a full retraining cycle.
IV.  **Encrypted-traffic features.** Add TLS handshake metadata to the feature set so that some application-level attacks become visible without payload inspection.
V.  **Per-alert explanations.** Attach Random Forest feature importances and the anomaly components to each alert on the dashboard.
VI.  **Distributed deployment.** Move the rate limiter and block state to a shared store and add load balancing so several detector nodes can protect a large network.
VII.  **Adversarial robustness.** Test the detector against traffic deliberately shaped to evade flow-level features and harden it accordingly.

```{=openxml}
<w:p><w:r><w:br w:type="page"/></w:r></w:p>
```

# References

[1] A. H. Lashkari, G. Draper-Gil, M. S. I. Mamun, and A. A. Ghorbani, "Characterization of Tor Traffic Using Time Based Features," in *Proc. ICISSP*, 2017, the CICFlowMeter feature extractor used for the CIC-IDS datasets.

[2] K. Scarfone and P. Mell, "Guide to Intrusion Detection and Prevention Systems (IDPS)," National Institute of Standards and Technology, NIST Special Publication 800-94, 2007.

[3] A. L. Buczak and E. Guven, "A Survey of Data Mining and Machine Learning Methods for Cyber Security Intrusion Detection," *IEEE Communications Surveys & Tutorials*, vol. 18, no. 2, pp. 1153–1176, 2016.

[4] L. Breiman, "Random Forests," *Machine Learning*, vol. 45, no. 1, pp. 5–32, 2001.

[5] D. E. Rumelhart, G. E. Hinton, and R. J. Williams, "Learning Representations by Back-Propagating Errors," *Nature*, vol. 323, pp. 533–536, 1986.

[6] D. P. Kingma and J. Ba, "Adam: A Method for Stochastic Optimization," in *Proc. International Conference on Learning Representations (ICLR)*, 2015.

[7] F. T. Liu, K. M. Ting, and Z.-H. Zhou, "Isolation Forest," in *Proc. IEEE International Conference on Data Mining (ICDM)*, 2008, pp. 413–422.

[8] M. Tavallaee, E. Bagheri, W. Lu, and A. A. Ghorbani, "A Detailed Analysis of the KDD CUP 99 Data Set," in *Proc. IEEE Symposium on Computational Intelligence for Security and Defense Applications (CISDA)*, 2009.

[9] I. Sharafaldin, A. H. Lashkari, and A. A. Ghorbani, "Toward Generating a New Intrusion Detection Dataset and Intrusion Traffic Characterization," in *Proc. International Conference on Information Systems Security and Privacy (ICISSP)*, 2018, pp. 108–116.

[10] J. P. Anderson, "Computer Security Threat Monitoring and Surveillance," James P. Anderson Co., Technical Report, 1980.

[11] D. E. Denning, "An Intrusion-Detection Model," *IEEE Transactions on Software Engineering*, vol. SE-13, no. 2, pp. 222–232, 1987.

[12] M. Roesch, "Snort: Lightweight Intrusion Detection for Networks," in *Proc. 13th USENIX Systems Administration Conference (LISA)*, 1999, pp. 229–238.

[13] V. Paxson, "Bro: A System for Detecting Network Intruders in Real-Time," *Computer Networks*, vol. 31, no. 23–24, pp. 2435–2463, 1999.

[14] Y. Mirsky, T. Doitshman, Y. Elovici, and A. Shabtai, "Kitsune: An Ensemble of Autoencoders for Online Network Intrusion Detection," in *Proc. Network and Distributed System Security Symposium (NDSS)*, 2018.

[15] R. Vinayakumar, M. Alazab, K. P. Soman, P. Poornachandran, A. Al-Nemrat, and S. Venkatraman, "Deep Learning Approach for Intelligent Intrusion Detection System," *IEEE Access*, vol. 7, pp. 41525–41550, 2019.

[16] G. Engelen, V. Rimmer, and W. Joosen, "Troubleshooting an Intrusion Detection Dataset: the CICIDS2017 Case Study," in *Proc. IEEE Security and Privacy Workshops (SPW)*, 2021, pp. 7–12.

[17] M. Lanvin, P.-F. Gimenez, Y. Han, F. Majorczyk, L. Mé, and E. Totel, "Errors in the CICIDS2017 Dataset and the Significant Differences in Detection Performances It Makes," in *Risks and Security of Internet and Systems (CRiSIS 2022)*, LNCS vol. 13857, Springer, 2023.

[18] L. Liu, G. Engelen, T. Lynar, D. Essam, and W. Joosen, "Error Prevalence in NIDS Datasets: A Case Study on CIC-IDS-2017 and CSE-CIC-IDS-2018," in *Proc. IEEE Conference on Communications and Network Security (CNS)*, 2022. Corrected datasets: https://intrusion-detection.distrinet-research.be/CNS2022/

[19] R. Sommer and V. Paxson, "Outside the Closed World: On Using Machine Learning for Network Intrusion Detection," in *Proc. IEEE Symposium on Security and Privacy*, 2010, pp. 305–316.

[20] M. Cantone, C. Marrocco, and A. Bria, "Machine Learning in Network Intrusion Detection: A Cross-Dataset Generalization Study," *IEEE Access*, vol. 12, 2024. Preprint: arXiv:2402.10974, "On the Cross-Dataset Generalization of Machine Learning for Network Intrusion Detection."

```{=openxml}
<w:p><w:r><w:br w:type="page"/></w:r></w:p>
```

# Bibliography

Sources studied during the project but not cited in the text:

I.  Canadian Institute for Cybersecurity, *CICFlowMeter* source code and documentation, https://github.com/ahlashkari/CICFlowMeter
II.  S. Ramírez, *FastAPI documentation*, https://fastapi.tiangolo.com/
III.  P. Biondi et al., *Scapy documentation*, https://scapy.readthedocs.io/
IV.  C. R. Harris et al., "Array programming with NumPy," *Nature*, vol. 585, pp. 357–362, 2020, and the NumPy reference, https://numpy.org/doc/
V.  M. Jones, J. Bradley, and N. Sakimura, "JSON Web Token (JWT)," IETF RFC 7519, 2015.
VI.  K. Moriarty, B. Kaliski, and A. Rusch, "PKCS #5: Password-Based Cryptography Specification Version 2.1," IETF RFC 8018, 2017.
VII.  Netfilter Project, *nftables wiki*, https://wiki.nftables.org/
VIII.  Docker Inc., *Docker Compose documentation*, https://docs.docker.com/compose/

```{=openxml}
<w:p><w:r><w:br w:type="page"/></w:r></w:p>
```

# Appendices

**Appendix A: Screenshots of the Running System**

The screenshots were captured from the NIDS build described in this report while real dataset flows were replayed through the API. Live packet capture was stopped, so the packet table is empty; the pipeline counters, verdict feed, alerts and blocks come from the replay. The response time shown on the dashboard (6.6 ms) is measured per HTTP request and includes alert creation and enforcement, whereas the 0.5 ms figure in Chapter 4 is model inference alone.

::: {custom-style="FigureCenter"}
![](figures/screen_login.png){width=6.0in}
:::

::: {custom-style="Figure Caption"}
Figure A.1: Login page with the two seeded roles (Administrator, Viewer)
:::

::: {custom-style="FigureCenter"}
![](figures/screen_dashboard.png){width=6.0in}
:::

::: {custom-style="Figure Caption"}
Figure A.2: Operator dashboard with capture control, detection-pipeline counters and live traffic monitor
:::

::: {custom-style="FigureCenter"}
![](figures/screen_dashboard_panels.png){width=6.0in}
:::

::: {custom-style="Figure Caption"}
Figure A.3: Dashboard panels with threat and severity breakdown, blocked IPs and top source IPs
:::

::: {custom-style="FigureCenter"}
![](figures/screen_api_docs.png){width=6.0in}
:::

::: {custom-style="Figure Caption"}
Figure A.4: Interactive API documentation generated from the FastAPI schemas
:::
