[INSTITUTION / UNIVERSITY NAME]

[Faculty / Department Name]

\

\

\

::: {custom-style="CoverTitle"}
NIDS — A Machine-Learning Based Network Intrusion Detection and Prevention System
:::

\

A PROJECT REPORT

\

Submitted in partial fulfillment of the requirements for the degree of
Bachelor in Computer Application (BCA)

\

Course Code: CACS452 — Project III

\

\

**Submitted by:**

[Student Name 1] — [Roll No.]

[Student Name 2] — [Roll No.]

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

I hereby recommend that this project report prepared under my supervision by **[Student Name 1]** and **[Student Name 2]**, entitled **"NIDS — A Machine-Learning Based Network Intrusion Detection and Prevention System"**, be accepted as fulfilling in part the requirements for the degree of Bachelor in Computer Application. In my opinion, the work is satisfactory and is ready for evaluation.

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
Certificate of Approval
:::

This is to certify that this project report prepared by **[Student Name 1]** and **[Student Name 2]**, entitled **"NIDS — A Machine-Learning Based Network Intrusion Detection and Prevention System"**, in partial fulfillment of the requirements for the degree of Bachelor in Computer Application, has been evaluated. In our opinion it is satisfactory in the scope and quality as a project for the required degree.

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

We would like to express our sincere gratitude to everyone who supported us throughout this project. First, we thank our supervisor, **[Supervisor Name]**, for the continuous guidance, encouragement, and valuable feedback that shaped the direction of this work. We are equally grateful to the Head of Department and the faculty members of the **[Department Name]** for providing the academic foundation and the resources that made this project possible.

We also acknowledge the authors of the foundational research in machine learning and network security whose work made this project's from-scratch implementations possible, and the open-source community whose tools supported the engineering and deployment of the system.

Finally, we thank our families and friends for their patience and constant motivation during the development of NIDS.

```{=openxml}
<w:p><w:r><w:br w:type="page"/></w:r></w:p>
```

# Abstract

Computer networks face a growing number of automated and continuously evolving attacks, while traditional signature-based defences are unable to recognize new or modified threats. This project, **NIDS**, is a complete, production-style Network Intrusion Detection System with optional Intrusion Prevention capability that classifies network traffic flows as normal or as one of six attack types — Distributed Denial of Service (DDoS), Port Scan, Brute Force, Botnet, Infiltration, and Web Attack — using machine learning.

The distinguishing feature of NIDS is that all of its machine-learning models are implemented from first principles using only the NumPy numerical library, with no external machine-learning framework. The system combines a Random Forest and a Multi-Layer Perceptron, which recognize known attack patterns, with an Isolation Forest, which detects unusual, never-before-seen behaviour. An ensemble layer fuses these models using a weighted vote and an anomaly-override rule that allows the system to flag potential zero-day attacks. Around this detection core, the project delivers a full operational system: a data-processing and training pipeline, a real-time inference engine, a REST API, an operator dashboard, structured logging, Prometheus-style monitoring, an alerting subsystem, and an optional automated enforcement layer that can block malicious source addresses under safe, configurable conditions. The system is containerized and supplied with deployment configuration for a reverse proxy and a container-orchestration platform.

Evaluated on a labelled subset of the real-world CIC-IDS2017 dataset containing 66,721 network flows described by thirty flow-level features across seven classes, the ensemble model achieved an overall accuracy of about 99.3% and a macro-averaged F1-score of about 98.6%, with an average inference time of roughly half a millisecond per flow. These results show that transparent, hand-built models can reach high detection quality while remaining fully auditable and fast enough for real-time use.

**Keywords:** Network Intrusion Detection, Machine Learning, Random Forest, Neural Network, Isolation Forest, Ensemble Learning, Anomaly Detection, Network Security.

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
| AI | Artificial Intelligence |
| API | Application Programming Interface |
| AUC | Area Under the Curve |
| CART | Classification and Regression Trees |
| CIC-IDS | Canadian Institute for Cybersecurity – Intrusion Detection System (dataset) |
| CORS | Cross-Origin Resource Sharing |
| CPU | Central Processing Unit |
| CSV | Comma-Separated Values |
| DDoS | Distributed Denial of Service |
| F1 | F1-Score (harmonic mean of precision and recall) |
| HTTP | Hypertext Transfer Protocol |
| IDS | Intrusion Detection System |
| IPS | Intrusion Prevention System |
| JSON | JavaScript Object Notation |
| MDI | Mean Decrease in Impurity |
| ML | Machine Learning |
| MLP | Multi-Layer Perceptron |
| NIDS | Network Intrusion Detection System |
| OOB | Out-Of-Bag |
| REST | Representational State Transfer |
| ReLU | Rectified Linear Unit |
| ROC | Receiver Operating Characteristic |
| SLA | Service Level Agreement |
| SOC | Security Operations Centre |
| SOAR | Security Orchestration, Automation and Response |
| TCP | Transmission Control Protocol |
| TLS | Transport Layer Security |
| UML | Unified Modeling Language |

```{=openxml}
<w:p><w:r><w:br w:type="page"/></w:r></w:p>
```

# List of Figures

| Figure | Title |
| --- | --- |
| Figure 3.1 | Use Case Diagram of NIDS |
| Figure 3.2 | Class Diagram of the Core Modules |
| Figure 3.3 | Object Diagram of a Detection Scenario |
| Figure 3.4 | State Diagram of an IP Block Lifecycle |
| Figure 3.5 | Sequence Diagram of a Prediction Request |
| Figure 3.6 | Activity Diagram of Detection and Enforcement |
| Figure 3.7 | Overall System Architecture of NIDS |
| Figure 3.8 | Component Diagram of NIDS |
| Figure 3.9 | Deployment Diagram of NIDS |
| Figure 4.1 | Ensemble Confusion Matrix (Test Set) |

# List of Tables

| Table | Title |
| --- | --- |
| Table 3.1 | Use Case Descriptions |
| Table 3.2 | Non-Functional Requirements |
| Table 4.1 | Tools and Technologies Used |
| Table 4.2 | Unit Test Cases |
| Table 4.3 | System / Integration Test Cases |
| Table 4.4 | Overall Model Performance on the Test Set |
| Table 4.5 | Per-Class Performance of the Ensemble Model |

```{=openxml}
<w:p><w:pPr><w:sectPr><w:footerReference w:type="default" r:id="rIdftr1"/><w:type w:val="nextPage"/><w:pgSz w:w="11906" w:h="16838"/><w:pgMar w:top="1440" w:right="1440" w:bottom="1440" w:left="1800" w:header="720" w:footer="720" w:gutter="0"/><w:pgNumType w:fmt="lowerRoman" w:start="1"/><w:cols w:space="720"/><w:docGrid w:linePitch="360"/></w:sectPr></w:pPr></w:p>
```

# Chapter 1: Introduction

## 1.1 Introduction

Modern organizations depend on computer networks to carry almost every part of their daily operations, from internal communication and file sharing to customer-facing services and financial transactions. As this dependence has grown, networks have also become one of the most attractive targets for attackers. Threats such as distributed denial-of-service (DDoS) floods, port scanning, password brute-forcing, botnet activity, host infiltration, and web-application attacks are now common, automated, and continuously evolving. A single successful intrusion can lead to service downtime, data theft, financial loss, and lasting damage to an organization's reputation. Protecting a network therefore requires more than a firewall at the perimeter; it requires the ability to continuously observe traffic, recognize malicious behaviour, and respond before serious harm is done.

A **Network Intrusion Detection System (NIDS)** is a security tool designed for exactly this purpose. It inspects network activity, decides whether each unit of traffic is normal or malicious, and raises an alert when it detects a likely attack. Traditional intrusion detection systems rely heavily on *signatures* — fixed rules that describe known attacks. While signature-based systems are accurate against threats they already know, they are unable to recognize new or slightly modified attacks for which no rule has been written yet. To overcome this weakness, the security industry has increasingly turned to **machine learning**, which allows a system to *learn* the statistical patterns that separate benign traffic from attacks, and to generalize to variations it has not seen before.

This project, **NIDS**, is a complete, production-style Network Intrusion Detection System that classifies network traffic flows into normal traffic and six distinct attack categories using machine learning. What distinguishes NIDS from a typical academic project is that **all of its machine-learning models are implemented from first principles using only the NumPy numerical library** — without relying on ready-made machine-learning frameworks such as scikit-learn, TensorFlow, or PyTorch. The system combines three complementary models: a Random Forest and a Multi-Layer Perceptron (a type of neural network) that recognize known attack patterns, and an Isolation Forest that detects unusual, never-before-seen behaviour. The predictions of these three models are then merged by an ensemble layer to produce a single, reliable decision for each network flow.

Beyond the detection logic, NIDS is built as a full working system rather than a standalone script. It includes a data-processing pipeline, a training pipeline, a real-time inference engine, a REST Application Programming Interface (API) for receiving traffic and returning verdicts, an operator dashboard for security staff, a monitoring and alerting subsystem, and an optional enforcement mode that can automatically block malicious source addresses. The system is also packaged for realistic deployment using containers and orchestration tooling. In this way, NIDS demonstrates not only the design of intrusion-detection algorithms but also the engineering required to operate such a system in a real environment.

## 1.2 Problem Statement

Network attacks today are frequent, automated, and constantly changing, while the volume of traffic that must be examined is enormous. This creates several specific problems that existing approaches struggle to solve together:

- **Signature-based systems cannot detect new attacks.** Rule-based detection tools only recognize threats that exactly match a previously written signature. Attackers routinely modify their methods, and entirely new ("zero-day") attacks appear regularly. Any small change can allow an attack to slip past a purely signature-based defence.

- **Manual monitoring does not scale.** The amount of traffic on even a modest network is far too large for human analysts to inspect directly. Without automated classification, genuine attacks are easily lost in the noise of normal activity.

- **Machine-learning solutions are often treated as black boxes.** Many machine-learning intrusion detectors depend on large external libraries whose internal behaviour is hidden from the developer. In a security context this is a serious weakness: analysts need to understand *why* a flow was flagged, and developers need to be able to audit and trust every step of the computation.

- **Detection alone is not enough.** A model that produces an accuracy figure in a notebook is not a usable security system. To be effective, a detector must run continuously, accept live traffic, respond within milliseconds, raise meaningful alerts, expose its health to monitoring tools, and ideally take protective action automatically.

- **Class imbalance and varied attack behaviour make accurate classification difficult.** Normal traffic vastly outnumbers attacks, and different attacks (for example, a high-volume DDoS flood versus a quiet infiltration attempt) have very different statistical fingerprints. A single model often handles some of these well and others poorly.

The core problem this project addresses is therefore: **how to build a network intrusion detection system that can accurately distinguish normal traffic from multiple types of attacks, can detect unknown attacks as well as known ones, remains fully transparent and auditable in its decision-making, and operates as a complete, deployable real-time service rather than an isolated experiment.**

## 1.3 Objectives

The main objectives of the NIDS project are as follows:

1. **To design and implement core machine-learning models from scratch** — a decision tree, a Random Forest, a Multi-Layer Perceptron, and an Isolation Forest — using only basic numerical operations, so that the entire detection logic is transparent and auditable.

2. **To build an ensemble classifier** that combines the strengths of supervised models (for recognizing known attacks) and an anomaly-detection model (for surfacing unknown or zero-day behaviour) into a single reliable decision per network flow.

3. **To accurately classify network traffic** into normal traffic and six attack categories — DDoS, Port Scan, Brute Force, Botnet, Infiltration, and Web Attack — using a realistic, flow-level feature set.

4. **To develop a complete real-time detection service**, including a data-processing pipeline, a training pipeline, an inference engine, a REST API, and an operator dashboard, so the models can be used in practice and not only in testing.

5. **To provide monitoring, alerting, and optional automated response**, including severity-based alerts, performance metrics, and an enforcement mode capable of blocking malicious sources under safe, configurable conditions.

## 1.4 Scope and Limitation

### Scope

The scope of the NIDS project covers the following:

- **Flow-level intrusion detection.** The system analyzes summarized network *flow records* (described by thirty numerical features such as packet counts, byte rates, inter-arrival times, and TCP flag counts) rather than raw packet payloads. This is the same style of feature set used by well-known public intrusion-detection datasets.
- **Multi-class classification.** NIDS classifies each flow as benign or as one of six attack types, giving security staff specific information about the nature of a threat rather than a simple "good/bad" label.
- **From-scratch model implementation.** All learning algorithms are written directly using numerical array operations, with no external machine-learning library.
- **End-to-end system.** The project includes data generation and preprocessing, model training and evaluation, real-time inference, a REST API, an operator dashboard, structured logging, performance metrics, and alerting.
- **Optional automated enforcement.** An enforcement subsystem can translate high-confidence detections into protective actions (such as rate-limiting or blocking a source address) through a pluggable backend, with safety features such as a dry-run mode and a list of always-allowed networks.
- **Realistic deployment.** The system is containerized and includes deployment configuration suitable for running behind a reverse proxy and on a container-orchestration platform.

### Limitations

The project also has the following limitations:

- **Dependence on an external traffic sensor.** NIDS consumes pre-extracted flow records. It does not capture packets from the wire itself; in a real deployment a separate flow-extraction tool would feed traffic into the system.
- **Evaluated on a benchmark dataset.** A bundled synthetic generator is used only for quick demonstrations, continuous-integration runs, and unit tests. The evaluation results reported in this document were obtained on a real, labelled subset of the CIC-IDS2017 dataset. As with any benchmark dataset, these results approximate — but do not perfectly reproduce — the behaviour of a specific live production network.
- **Flow-level analysis only.** Because the system inspects flow summaries rather than packet contents, it cannot examine encrypted payloads or detect threats that are only visible at the application-content level.
- **Offline (batch) training.** Models are trained beforehand on collected data. The system does not currently learn continuously from live traffic, so adapting to new patterns requires retraining.
- **Single-node operational features.** Some operational components, such as the request rate limiter, are designed for single-node deployment and would require additional engineering to scale across many servers.
- **Platform-specific enforcement.** The active blocking backend targets a Linux firewall mechanism, so automated enforcement is limited to compatible host environments.

## 1.5 Development Methodology

The project followed an **iterative and incremental development methodology**. This approach was chosen because the system is composed of clearly separable layers — data handling, models, training, inference, transport, monitoring, and enforcement — that could each be built, tested, and improved in successive cycles rather than all at once. Each increment produced a working, testable piece of the system, and later increments built on top of earlier ones.

The development proceeded through the following stages:

1. **Requirement identification and analysis.** The functional and non-functional requirements were established first: which attack types to detect, what feature set to use, what interfaces were needed, and what performance and reliability targets the service should meet.

2. **Design.** A modular architecture was defined with strict boundaries between layers, so that inner components (such as the models) never depend on outer components (such as the web interface). This made each module independently testable and replaceable.

3. **Incremental implementation.** The data generator and preprocessing pipeline were built first, followed by the individual machine-learning models, the ensemble layer, the training pipeline, the inference engine, the REST API and dashboard, the monitoring and alerting subsystem, and finally the optional enforcement layer. Each component was implemented and verified before the next one depended on it.

4. **Testing.** Unit tests were written for individual algorithms and utilities (including the hand-built evaluation metrics), and integration tests were written for the API and the enforcement workflow. Testing ran alongside development so that defects were caught early.

5. **Integration and evaluation.** Once the models and services were connected, the full system was evaluated end-to-end, measuring classification accuracy, per-class performance, and inference latency.

6. **Deployment preparation.** The system was containerized and supplied with configuration for reverse-proxy, monitoring, and orchestrated deployment, along with a continuous-integration pipeline that automatically lints, tests, and builds the project.

A single configuration file acts as the central source of all tunable settings, and any value can be overridden at deployment time through environment variables. This supports the incremental philosophy by allowing the same code to behave differently in development, testing, and production without modification.

## 1.6 Report Organization

The remainder of this report is organized into the following chapters:

- **Chapter 2 — Background Study and Literature Review** presents the fundamental theories, general concepts, and terminologies related to network intrusion detection and the machine-learning techniques used in the project, and reviews similar projects, datasets, and research results produced by other researchers.

- **Chapter 3 — System Analysis and Design** describes the requirement analysis (functional and non-functional requirements, illustrated with use-case diagrams), the feasibility analysis, and the system models, including class, object, state, sequence, activity, component, and deployment diagrams, together with relevant algorithm details.

- **Chapter 4 — Implementation and Testing** explains the tools and technologies used, the implementation details of the major modules, and the testing performed, including unit and system test cases and an analysis of the results obtained.

- **Chapter 5 — Conclusion and Future Recommendations** summarizes the outcomes of the project, reflects on the objectives achieved, and outlines possible directions for future enhancement.


```{=openxml}
<w:p><w:r><w:br w:type="page"/></w:r></w:p>
```

# Chapter 2: Background Study and Literature Review

## 2.1 Background Study

This section explains the fundamental concepts and terminology needed to understand the NIDS system. The aim is to relate each concept directly to the way it is used in the project rather than to present general definitions in isolation.

### 2.1.1 Network Traffic and Flows

When two computers communicate over a network, they exchange a stream of small units of data called *packets*. Examining every individual packet is expensive and, when traffic is encrypted, often unhelpful. A more practical unit of analysis is the **network flow**: a summary of a single conversation between two endpoints over a period of time. Instead of recording raw content, a flow records statistical properties — for example, how long the conversation lasted, how many packets and bytes were sent in each direction, how quickly packets arrived, the average packet size, and how often particular control flags (such as SYN, ACK, RST, and FIN, which mark stages of a connection) appeared. NIDS works entirely at this flow level, representing each conversation as a fixed list of thirty numerical features. This is the same kind of feature representation used by widely studied public intrusion-detection datasets, which makes the system both efficient and compatible with real traffic-extraction tools.

### 2.1.2 Intrusion Detection and Prevention

An **Intrusion Detection System (IDS)** observes activity and reports suspected attacks, while an **Intrusion Prevention System (IPS)** goes a step further and actively blocks or limits malicious traffic [1]. Detection approaches are usually grouped into two families. **Signature-based** (or misuse) detection compares activity against a database of known attack patterns; it is precise for known threats but blind to new ones. **Anomaly-based** detection builds a model of normal behaviour and flags anything that deviates significantly from it; it can catch novel attacks but may produce more false alarms [2]. NIDS deliberately combines both philosophies: its supervised models behave like a learned, generalized form of misuse detection, recognizing the fingerprints of known attack classes, while its Isolation Forest performs anomaly detection to surface traffic that does not resemble normal behaviour. The optional enforcement layer gives the system an IPS capability, mapping confident detections to protective actions.

### 2.1.3 Common Network Attacks

NIDS is trained to distinguish benign traffic from six attack categories, each with a distinct behavioural fingerprint:

- **DDoS (Distributed Denial of Service):** a flood of traffic from many sources intended to overwhelm a service, characterized by extremely high packet and byte rates.
- **Port Scan:** systematic probing of many network ports to discover open services, characterized by many short connection attempts.
- **Brute Force:** repeated login attempts to guess credentials, characterized by many similar, repetitive connections to an authentication service.
- **Botnet:** traffic generated by compromised machines communicating with a controller, often showing periodic, automated patterns.
- **Infiltration:** stealthy unauthorized access following an initial compromise, typically low-volume and difficult to distinguish from normal activity.
- **Web Attack:** attacks aimed at web applications, such as injection or cross-site scripting attempts, visible through unusual request patterns.

Because these attacks differ so widely — from very loud (DDoS) to very quiet (Infiltration) — no single model recognizes all of them equally well, which is one of the main reasons NIDS uses an ensemble.

### 2.1.4 Machine Learning for Classification

**Machine learning** allows a system to learn patterns from examples instead of following hand-written rules. In **supervised learning**, the model is trained on data that is already labelled with the correct answer; it learns to map input features to the correct class so that it can later classify new, unlabelled data. Intrusion detection of known attack types is naturally a supervised **classification** problem, where the classes are "benign" and the various attack categories. In **unsupervised** or **anomaly detection**, the model is trained mostly on normal data and learns to recognize anything that does not fit, which is useful for catching unknown attacks. NIDS uses supervised learning for its Random Forest and neural network, and anomaly detection for its Isolation Forest.

### 2.1.5 Decision Trees and Random Forests

A **decision tree** classifies data by asking a sequence of simple yes/no questions about the feature values, splitting the data at each step into purer and purer groups until it can confidently assign a class. The quality of each split is measured by how well it separates the classes. A single tree, however, can easily "memorize" its training data and perform poorly on new data. A **Random Forest** addresses this by training many different trees, each on a random sample of the data and a random subset of the features, and then combining their votes [3]. This averaging makes the overall model far more stable and accurate than any single tree, and it provides a useful by-product: an estimate of which features were most important in making decisions, which helps analysts understand the model's reasoning. In NIDS, the Random Forest is the strongest single classifier for the known attack types.

### 2.1.6 Neural Networks (Multi-Layer Perceptron)

A **Multi-Layer Perceptron (MLP)** is a basic form of artificial neural network. It is made up of layers of simple processing units ("neurons") connected by adjustable weights. Input features pass through one or more hidden layers, where each layer transforms the data and passes it on, until the final layer produces a probability for each class. The network *learns* by comparing its predictions to the correct answers and gradually adjusting its weights to reduce the error, a process known as **backpropagation** [4]. Modern training also uses an optimization technique that adapts how much each weight is changed on every step, making learning faster and more stable [5]. Neural networks are especially good at capturing complex, non-linear relationships between features, which lets the NIDS MLP recognize attack patterns that simpler models might miss. The project also applies standard techniques such as dropout (temporarily ignoring some neurons during training) and early stopping (halting training once performance stops improving) to prevent the network from overfitting.

### 2.1.7 Anomaly Detection with Isolation Forest

The **Isolation Forest** is a method designed specifically to find rare, unusual data points [6]. Its key idea is simple and elegant: anomalies are "few and different," so they are easier to separate from the rest of the data than normal points are. The algorithm repeatedly splits the data at random; points that become isolated after only a few splits are judged to be anomalies, while points that require many splits are considered normal. In NIDS, the Isolation Forest is trained on normal traffic so that any flow which looks distinctly unusual receives a high anomaly score — even if it belongs to an attack type the supervised models have never been trained on. This is the project's main mechanism for detecting potential **zero-day** attacks.

### 2.1.8 Ensemble Learning

**Ensemble learning** is the practice of combining several models so that their collective decision is better than any individual one. Different models tend to make different mistakes, so combining them often cancels out individual errors. NIDS's ensemble uses two rules. First, it blends the probability outputs of the Random Forest and the MLP using a weighted average, giving more influence to the model that is generally more accurate while still benefiting from the other's strengths. Second, it applies an *anomaly override*: if the supervised models judge a flow to be benign but the Isolation Forest reports a strong anomaly, the ensemble overrides the benign verdict and treats the flow as suspicious. Importantly, the ensemble can explain its decision by reporting each model's contribution, preserving the transparency that is central to the project.

### 2.1.9 Data Preprocessing and Evaluation

Before any model can learn, raw data must be cleaned and prepared. NIDS's preprocessing handles missing or invalid values, scales every feature to a comparable range so that no single large-valued feature dominates, and selects the most informative features by measuring how strongly each one separates the classes. The data is split into training, validation, and test sets in a way that preserves the proportion of each class, which is important because attacks are far rarer than normal traffic. To judge how well the models perform, the project relies on standard evaluation measures — **accuracy** (overall correctness), **precision** (how many flagged attacks were truly attacks), **recall** (how many real attacks were caught), and the **F1-score** (a balance of precision and recall) — all summarized in a **confusion matrix** that shows exactly which classes were confused with which. In keeping with the project's transparency goal, these evaluation measures are also implemented from scratch rather than taken from an external library.

### 2.1.10 Supporting System Concepts

To function as a real service, NIDS uses several standard software and operations concepts. A **REST API** is a standard way for other programs to send data to the system and receive results over the web. A **dashboard** provides a visual interface for human operators. **Monitoring metrics** expose numerical indicators of the system's health and performance in a format that monitoring tools can collect and chart. **Containerization** packages the application together with everything it needs to run, so it behaves identically across different machines, and **orchestration** manages running and scaling those containers. These concepts allow the intrusion-detection logic to be operated reliably in a realistic production setting.

## 2.2 Literature Review

The idea of automatically monitoring computer systems for misuse dates back several decades. Anderson's early work introduced the concept of using audit data to detect security threats [7], and Denning's foundational intrusion-detection model formalized the idea of building a profile of normal behaviour and flagging deviations from it [8]. These works established the two enduring approaches — misuse (signature) detection and anomaly detection — that still shape intrusion-detection research today, and that NIDS deliberately combines.

Early operational intrusion-detection systems were predominantly signature-based, with widely deployed open-source tools relying on hand-written rules to match known attacks [1]. The U.S. National Institute of Standards and Technology consolidated best practices for such systems in its guide to intrusion detection and prevention, which also describes the distinction between detection-only and prevention-capable systems [1]. While signature-based tools remain valuable for their precision against known threats, the security community recognized early that they cannot detect novel attacks, motivating the shift toward learning-based methods that NIDS follows.

A large body of research has since applied machine learning to intrusion detection. Buczak and Guven surveyed a wide range of data-mining and machine-learning methods for cyber-security intrusion detection, comparing decision trees, support-vector machines, neural networks, and ensemble approaches, and noting the practical trade-offs between accuracy, training cost, and interpretability [2]. Their survey highlights that no single algorithm dominates across all attack types — a finding that directly supports NIDS's ensemble design, in which different models cover different weaknesses.

The individual algorithms used in this project each have well-established research foundations. The decision-tree and Random Forest methods build on Breiman's work, which demonstrated that combining many randomized trees produces a model that is both highly accurate and resistant to overfitting, while still offering measures of feature importance [3]. The neural-network component rests on the backpropagation algorithm for training multi-layer networks [4], combined with the adaptive optimization method introduced by Kingma and Ba, which has become a standard technique for training neural networks efficiently [5]. For anomaly detection, Liu, Ting, and Zhou's Isolation Forest provided an efficient way to identify rare points without first modelling the entire distribution of normal data [6]; NIDS adopts this method precisely because of its efficiency and its suitability for highlighting previously unseen attacks. More recent research has explored deep-learning approaches to intrusion detection, reporting strong results on benchmark datasets using larger and more complex networks [9]; NIDS intentionally uses a compact, fully transparent multi-layer perceptron instead, prioritizing auditability and modest computational requirements over model complexity.

The quality of an intrusion-detection study depends heavily on the data used to evaluate it. Earlier research relied on datasets such as KDD Cup 99 and its refined version, but these were later criticized for redundant records and outdated traffic that no longer reflect modern networks [10]. To address these shortcomings, Sharafaldin, Lashkari, and Ghorbani produced the CIC-IDS2017 dataset, which contains realistic, labelled benign and attack traffic described by flow-level features, and which has become a widely used benchmark for evaluating modern intrusion detectors [11]. NIDS adopts the same thirty-feature, flow-level representation and the same attack categories used in this family of datasets, and its data pipeline is able to import such real datasets directly; this alignment makes the project's design and feature set consistent with current research practice.

An influential and cautionary contribution to this field is the work of Sommer and Paxson, who examined why machine-learning intrusion detectors that perform well in the laboratory often disappoint in real deployments [12]. They identified problems such as the high cost of false alarms, the difficulty of obtaining good labelled data, the gap between research datasets and live traffic, and — crucially — the need for results to be *interpretable* so that analysts can act on them. These observations strongly influenced the design priorities of NIDS: the system is built to be transparent and auditable, it reports the reasoning behind each detection, it includes confidence thresholds and safety controls before taking any automated action, and it is engineered as a complete operational service rather than an isolated classifier.

In summary, the literature establishes three consistent themes that this project builds upon. First, combining misuse and anomaly detection is more effective than either alone, which justifies NIDS's hybrid ensemble. Second, no single learning algorithm is best for all attack types, which justifies combining a Random Forest, a neural network, and an Isolation Forest. Third, practical intrusion detection demands interpretability, careful evaluation on realistic data, and genuine operational engineering — not merely a high accuracy score. NIDS's distinctive contribution within this landscape is to implement the core learning algorithms entirely from first principles, ensuring full transparency, while wrapping them in a complete, deployable detection-and-response system.

```{=openxml}
<w:p><w:r><w:br w:type="page"/></w:r></w:p>
```

# Chapter 3: System Analysis and Design

## 3.1 System Analysis

System analysis identifies what the system must do and how its parts relate to one another. This section presents the requirement analysis, the feasibility analysis, and the object, dynamic, and process models of NIDS.

### 3.1.1 Requirement Analysis

#### i. Functional Requirements

The functional requirements describe the services the system provides. NIDS has two main groups of users: the **Security Operator** (a human analyst who monitors threats through the dashboard and manages alerts and blocks) and the **External System / Sensor** (an automated traffic source or another program that submits flows for classification through the API). An **Administrator** role configures and trains the system.

The system shall:

1. Accept a single network flow and classify it as benign or as a specific attack type.
2. Accept a batch of up to one thousand flows and classify them together.
3. Return, for every classification, the predicted class, a confidence value, an anomaly score, the per-class probabilities, and whether the anomaly override was triggered.
4. Generate a severity-ranked alert whenever an attack is detected, and store recent alerts for review.
5. Allow an operator to list and filter alerts by severity and to clear the alert history.
6. Optionally enforce protective actions (rate-limit, block, or drop) against malicious source addresses when enforcement is enabled and the confidence is high enough.
7. Never block addresses that belong to a configured allowlist of trusted networks.
8. Allow an operator to list currently blocked addresses, unblock a specific address, and clear all blocks.
9. Expose health and readiness endpoints and machine-readable performance metrics.
10. Train all models from a dataset and produce a stored set of model artifacts and an evaluation report.

The following use case diagram summarizes the interactions between the actors and the system.

::: {custom-style="FigureCenter"}
![](/Users/portpro/Documents/netsentry 3/docs/figures/usecase.png){width=6.0in}
:::

::: {custom-style="FigureCenter"}
**Figure 3.1: Use Case Diagram of NIDS**
:::

The main use cases are described in Table 3.1.

**Table 3.1: Use Case Descriptions**

| Use Case | Actor | Description |
| --- | --- | --- |
| Classify Single Flow | External System | The system receives one flow, preprocesses it, runs the ensemble, and returns a classification with confidence and anomaly information. |
| Classify Batch of Flows | External System | The system receives many flows at once and classifies them in a single request, returning one result per flow and a count of alerts generated. |
| View / Filter Alerts | Security Operator | The operator retrieves recent alerts, optionally filtered by severity level, to review detected threats. |
| Clear Alerts | Security Operator | The operator clears the in-memory alert history (requires authentication). |
| View Blocked IPs | Security Operator | The operator lists the addresses currently blocked by the enforcement layer, with the reason and expiry time. |
| Unblock IP / Flush Blocks | Security Operator | The operator removes a specific block or clears all active blocks (requires authentication). |
| Monitor Dashboard / Metrics | Security Operator | The operator views live statistics, alert summaries, and performance metrics. |
| Train Models | Administrator | The administrator runs the training pipeline, which builds and evaluates all models and stores the artifacts. |
| Configure / Enable Enforcement | Administrator | The administrator sets configuration values and turns the enforcement (prevention) mode on or off. |

#### ii. Non-Functional Requirements

The non-functional requirements describe the qualities the system must satisfy, summarized in Table 3.2.

**Table 3.2: Non-Functional Requirements**

| Quality | Requirement |
| --- | --- |
| Performance | A single prediction should complete in only a few milliseconds, including request validation, to support real-time use. |
| Scalability | The detection service should run as multiple stateless worker processes that can be scaled horizontally. |
| Reliability | The system must expose health and readiness checks and fail safely; missing model artifacts must prevent the service from accepting traffic. |
| Transparency | Every detection decision must be explainable, exposing each model's contribution and the anomaly score. |
| Security | The API must support key-based authentication, rate limiting, input validation, and a trusted-network allowlist that is never blocked. |
| Maintainability | The code must be modular, with inner layers independent of outer layers, and covered by automated tests. |
| Portability | The system must run identically across environments through containerization and external configuration. |
| Observability | The system must emit structured logs, numerical metrics, and an alert stream suitable for external monitoring tools. |

### 3.1.2 Feasibility Analysis

**Technical Feasibility.** The project is technically feasible. It uses widely available, mature technologies — the Python language, the NumPy numerical library, and a standard web framework — all of which run on ordinary hardware. The machine-learning algorithms chosen are well documented in published research and were successfully implemented from first principles, which confirms that the technical approach is sound.

**Operational Feasibility.** The system is operationally feasible because it fits naturally into an existing security workflow. It receives flows from a traffic sensor, returns clear results, presents alerts on a dashboard for analysts, and can optionally take automated action. Safety features such as a dry-run mode and a trusted-network allowlist make it practical to adopt gradually.

**Economic Feasibility.** The project is economically feasible. It relies only on free and open-source software and a small number of lightweight libraries, so there are no licensing costs. Because the models are compact and run quickly on a standard processor, the system does not require expensive specialized hardware.

**Schedule Feasibility.** The project was schedule-feasible. The modular, incremental development approach allowed each component to be built and tested in a defined period, so the work fit within the semester timeline. The use of automated testing reduced the time spent on debugging integration problems.

### 3.1.3 Object Modelling using Class and Object Diagrams

The system is organized into classes with clear responsibilities. The class diagram below shows the main classes and their relationships.

::: {custom-style="FigureCenter"}
![](/Users/portpro/Documents/netsentry 3/docs/figures/class.png){width=6.0in}
:::

::: {custom-style="FigureCenter"}
**Figure 3.2: Class Diagram of the Core Modules**
:::

The diagram shows that all models share a common `BaseModel` interface; the `RandomForest` is composed of many `DecisionTree` objects; and the `EnsembleNIDS` combines the three model types. The `InferenceEngine` uses the ensemble and the `Preprocessor`, and feeds its results to the `AlertManager` and, optionally, the `ResponseExecutor`, which in turn uses a pluggable `FirewallBackend` and an `Allowlist`.

While the class diagram captures the static structure, an object diagram shows a single runtime snapshot. Figure 3.3 illustrates the objects that exist while one high-confidence DDoS flow is being processed — from the incoming flow, through the engine and ensemble, to the resulting prediction, the alert it raises, and the enforcement block.

::: {custom-style="FigureCenter"}
![](/Users/portpro/Documents/netsentry 3/docs/figures/object.png){width=6.2in}
:::

::: {custom-style="FigureCenter"}
**Figure 3.3: Object Diagram of a Detection Scenario**
:::

### 3.1.4 Dynamic Modelling using State and Sequence Diagrams

**State Diagram.** When enforcement is active, a malicious source address moves through a small set of states. The state diagram below shows the lifecycle of an IP block.

::: {custom-style="FigureCenter"}
![](/Users/portpro/Documents/netsentry 3/docs/figures/state.png){width=6.0in}
:::

::: {custom-style="FigureCenter"}
**Figure 3.4: State Diagram of an IP Block Lifecycle**
:::

**Sequence Diagram.** The sequence diagram below shows the order of messages when an external system submits a flow for classification.

::: {custom-style="FigureCenter"}
![](/Users/portpro/Documents/netsentry 3/docs/figures/sequence.png){width=6.5in}
:::

::: {custom-style="FigureCenter"}
**Figure 3.5: Sequence Diagram of a Prediction Request**
:::

### 3.1.5 Process Modelling using Activity Diagrams

The activity diagram below shows the overall flow of processing a single request through detection and optional enforcement.

::: {custom-style="FigureCenter"}
![](/Users/portpro/Documents/netsentry 3/docs/figures/activity.png){width=4.2in}
:::

::: {custom-style="FigureCenter"}
**Figure 3.6: Activity Diagram of Detection and Enforcement**
:::

## 3.2 System Design

The overall architecture of NIDS, bringing together the edge, API, detection core, alerting, enforcement, observability, and offline training layers described in this report, is shown in Figure 3.7.

::: {custom-style="FigureCenter"}
![](/Users/portpro/Documents/netsentry 3/docs/figures/arch.png){width=5.6in}
:::

::: {custom-style="FigureCenter"}
**Figure 3.7: Overall System Architecture of NIDS**
:::


### 3.2.1 Refinement of Diagrams

During design, the analysis models were refined into concrete, implementable structures. The abstract `BaseModel` was given explicit methods for fitting, predicting, returning probabilities, and saving and loading, so that every model — and the ensemble — can be used interchangeably and persisted to disk. The `FirewallBackend` was refined into an abstract interface with three concrete implementations (a Linux firewall backend, a log-only backend for dry runs, and a no-operation backend for testing), so the enforcement layer can be switched without touching its logic. The `Preprocessor` was refined to store the fitted scaling parameters and the selected feature indices so that the exact same transformation learned during training is reapplied at inference time. The sequence and activity models were refined to include the confidence gate, the allowlist check, the duplicate-block check, and the capacity limit, which together make automated enforcement safe.

### 3.2.2 Component Diagram

The component diagram shows the major building blocks of the system and how they depend on one another.

::: {custom-style="FigureCenter"}
![](/Users/portpro/Documents/netsentry 3/docs/figures/component.png){width=6.0in}
:::

::: {custom-style="FigureCenter"}
**Figure 3.8: Component Diagram of NIDS**
:::

A strict dependency rule is enforced: inner components (utils, data, models) never depend on outer components (API, inference, training). This keeps the models independently usable and the system easy to test.

### 3.2.3 Deployment Diagram

The deployment diagram shows how the system is deployed in a production-style environment.

::: {custom-style="FigureCenter"}
![](/Users/portpro/Documents/netsentry 3/docs/figures/deployment.png){width=6.2in}
:::

::: {custom-style="FigureCenter"}
**Figure 3.9: Deployment Diagram of NIDS**
:::

## 3.3 Algorithm Details

The detection logic is built on four algorithms, each implemented from first principles. They are described here in simple, step-by-step terms.

**Random Forest (training).**

```
1. Repeat for each of N trees:
   a. Draw a random sample (with replacement) from the training data.
   b. Grow a decision tree on this sample.
      - At each node, consider a random subset of the features.
      - Choose the split that best separates the classes.
      - Stop when the node is pure or limits (depth, leaf size) are reached.
   c. Remember which samples were NOT used (out-of-bag) for that tree.
2. To predict: ask every tree for its class probabilities and average them;
   the class with the highest average wins (soft voting).
3. The out-of-bag samples give a free accuracy estimate without a separate
   validation set.
```

**Multi-Layer Perceptron (training, high level).**

```
1. Initialize the connection weights with small random values.
2. For each training round (epoch):
   a. Shuffle the data and split it into small batches.
   b. Forward pass: push each batch through the layers to get predictions.
   c. Compare predictions with the correct labels to measure the error.
   d. Backward pass: work out how much each weight contributed to the error.
   e. Update the weights to reduce the error (using the Adam update rule).
3. Use dropout during training to avoid over-reliance on any neuron, and stop
   early if accuracy on a validation set stops improving.
```

**Isolation Forest (anomaly scoring).**

```
1. Build many small trees, each on a random subset of NORMAL traffic.
   - At each node pick a random feature and a random split value.
2. To score a flow: drop it through every tree and record how many splits
   were needed to isolate it.
3. Flows that are isolated quickly (short paths) get a HIGH anomaly score;
   flows that need many splits get a LOW score.
4. A threshold, calibrated from the training data, decides which scores count
   as anomalies.
```

**Ensemble fusion.**

```
1. Take the averaged class probabilities from the Random Forest and the MLP.
2. Blend them with fixed weights that favour the stronger model.
3. Pick the class with the highest blended probability.
4. Anomaly override: if the blended result says "benign" but the Isolation
   Forest score is above the boost threshold, change the result to the most
   likely attack class instead.
5. Return the final class plus every component's contribution for auditing.
```

```{=openxml}
<w:p><w:r><w:br w:type="page"/></w:r></w:p>
```

# Chapter 4: Implementation and Testing

## 4.1 Implementation

### 4.1.1 Tools Used

The tools and technologies used to build NIDS are listed in Table 4.1.

**Table 4.1: Tools and Technologies Used**

| Category | Tool / Technology | Purpose in the Project |
| --- | --- | --- |
| Programming Language | Python 3.10+ | Main implementation language for all components. |
| Numerical Computing | NumPy | The only library used for the machine-learning math (arrays and vector operations). |
| Web Framework | FastAPI + Uvicorn | Serves the REST API and the operator dashboard. |
| Request Validation | Pydantic | Validates and parses incoming JSON request bodies. |
| Configuration | PyYAML | Loads the central configuration file. |
| Testing | pytest, httpx | Runs unit and integration tests; httpx drives the API test client. |
| Monitoring | Custom Prometheus exporter | Emits counters, gauges, and histograms in Prometheus text format. |
| Containerization | Docker, Docker Compose | Packages the application and its monitoring stack. |
| Orchestration | Kubernetes | Manifests for deployment, autoscaling, ingress, and training jobs. |
| Reverse Proxy | Nginx | Terminates TLS and applies edge rate limiting. |
| Enforcement Backend | nftables (Linux firewall) | Applies real IP blocks in prevention mode. |
| Version Control / CI | Git, GitHub Actions | Source control and an automated lint-test-build pipeline. |
| Visualization | Grafana | Dashboards built on the exported metrics. |

It is important to note that no external machine-learning library (such as scikit-learn, TensorFlow, or PyTorch) was used. Every model and every evaluation measure was written by hand using NumPy.

### 4.1.2 Implementation Details of Modules

**Data Module.** This module generates a labelled synthetic dataset that imitates the statistical fingerprints of real attacks, loads real public datasets when available, and preprocesses the data. The `Preprocessor` cleans invalid values, scales features to a comparable range, selects the most informative features, and performs a class-preserving split into training, validation, and test sets. The transformation parameters learned on the training set are stored and reused, which prevents information from the test set leaking into training.

**Models Module.** This module contains the four from-scratch models behind a shared interface. The `DecisionTree` builds itself using an information-gain split search and an iterative (non-recursive) build loop so that deep trees do not exhaust the program's call stack. The `RandomForestClassifier` trains many such trees on bootstrap samples with random feature subsets, can train them across multiple processes, and reports feature importances and an out-of-bag accuracy estimate. The `MLPClassifier` implements a feed-forward neural network with forward and backward passes, the Adam update rule, dropout, weight regularization, and early stopping. The `IsolationForest` builds random trees on normal traffic and scores anomalies by how quickly each flow is isolated. The `EnsembleNIDS` combines the three models using a weighted vote and the anomaly-override rule, and can report each component's contribution.

**Training Module.** The `TrainingPipeline` orchestrates the whole workflow: it loads or generates data, splits it, fits the preprocessor, trains the Random Forest, the MLP (with a validation set for early stopping), and the Isolation Forest (on benign traffic only), assembles the ensemble, evaluates every model on the held-out test set, and saves all artifacts together with a JSON evaluation report.

**Inference Module.** The `InferenceEngine` loads the saved preprocessor and ensemble once at startup and serves predictions for single flows or batches. It converts incoming feature dictionaries into a numeric matrix, applies the stored preprocessing, runs the ensemble, and returns a JSON-ready result with the prediction, confidence, anomaly score, and per-class probabilities. It also tracks latency percentiles for monitoring. The `AlertManager` turns attack predictions into severity-ranked alerts, stores recent alerts in a fixed-size buffer, and appends them to a log file.

**API Module.** The API layer exposes the system over HTTP. It provides health and readiness checks, a metrics endpoint, single and batch prediction endpoints, alert listing and clearing, and enforcement-management endpoints for listing, removing, and flushing blocks. It applies API-key authentication and rate limiting, validates all inputs, and serves the operator dashboard.

**Enforcement Module.** The `ResponseExecutor` evaluates each alert against a response policy that maps every attack type to an action (allow, rate-limit, block, or drop) with a required confidence and a block duration. Before acting, it validates the address format, checks the confidence gate, checks the trusted-network allowlist, avoids duplicate blocks, and respects a maximum-blocks safety cap. Actual blocking is delegated to a pluggable firewall backend, and a dry-run mode allows the policy to be validated without taking real action.

**Monitoring and Utilities.** A custom Prometheus exporter records counters, gauges, and histograms and renders them in the standard text format, with no external metrics library. The utilities provide configuration loading (with environment-variable overrides), structured JSON logging with request correlation, and the from-scratch evaluation metrics.

## 4.2 Testing

The system was tested using automated unit tests for individual components and integration (system) tests for end-to-end behaviour, all run with the pytest framework.

### 4.2.1 Test Cases for Unit Testing

Unit tests verify that each component behaves correctly in isolation. A representative selection is shown in Table 4.2.

**Table 4.2: Unit Test Cases**

| ID | Component | Test Case | Expected Result |
| --- | --- | --- | --- |
| U1 | Decision Tree | Fit on sample data and predict | Predictions match known labels; probabilities sum to one |
| U2 | Decision Tree | Compute Gini and entropy splits | Both criteria produce valid, consistent splits |
| U3 | Random Forest | Out-of-bag score | Score lies within a valid range (0 to 1) |
| U4 | Random Forest | Feature importances | Importances are non-negative and sum to one |
| U5 | MLP | Fit and predict | Network learns and classifies correctly |
| U6 | MLP | Output probabilities | Class probabilities sum to one |
| U7 | MLP | Early stopping | Training stops when validation stops improving |
| U8 | Isolation Forest | Detect anomalies | Clear outliers receive high anomaly scores |
| U9 | Ensemble | End-to-end fusion | Combined prediction is produced with component details |
| U10 | Preprocessor | Stratified split | Class proportions are preserved across splits |
| U11 | Preprocessor | Handle infinity and NaN | Invalid values are cleaned without errors |
| U12 | Metrics | Confusion matrix and accuracy | Hand-computed values match expected results |
| U13 | Metrics | ROC-AUC | AUC is one for a perfect ranker and about a half for random scores |
| U14 | Enforcement Policy | Every attack type has a policy | All attack classes map to a defined action |
| U15 | Allowlist | Private and public IPs | Private/trusted IPs are allowed; public IPs are not |

### 4.2.2 Test Cases for System Testing

System tests verify that the components work correctly together through the API and the enforcement workflow. A representative selection is shown in Table 4.3.

**Table 4.3: System / Integration Test Cases**

| ID | Scenario | Test Case | Expected Result |
| --- | --- | --- | --- |
| S1 | API health | Call the health endpoint | Returns status, version, and model-loaded flag |
| S2 | Detection | Submit a benign flow | Classified as benign; no alert generated |
| S3 | Detection | Submit a DDoS-like flow | Classified as an attack; an alert is created |
| S4 | Batch detection | Submit mixed traffic in one batch | Correct per-flow results and alert count |
| S5 | Alerts | List alerts after attacks | Recent alerts are returned and filterable |
| S6 | Enforcement | High-confidence attack with source IP | Source IP is blocked |
| S7 | Enforcement | Low-confidence attack | No block is applied |
| S8 | Allowlist | Attack from a trusted/private IP | IP is never blocked |
| S9 | Enforcement | Same attacking IP seen twice | IP is blocked only once (no duplicates) |
| S10 | Block lifecycle | Block then unblock an IP | Block is created and then successfully removed |
| S11 | Capacity | Exceed the maximum-blocks limit | Further blocks are refused safely |
| S12 | Traffic simulation | Run a realistic traffic mix | Alerts and statistics reflect the traffic |

All tests pass in the project's continuous-integration pipeline, which automatically lints the code, runs the full test suite, and builds the container image on every change.

## 4.3 Result Analysis

All models were trained and evaluated on a labelled subset of the real-world CIC-IDS2017 dataset, comprising 66,721 network flows, each described by thirty flow-level features and belonging to one of seven classes. The classes were balanced during loading so that the rarer attack types were not overwhelmed by the majority traffic. The data was split so that the models were evaluated on a held-out test set of 13,344 flows that they had never seen during training. The complete pipeline — data loading, training of all models, evaluation, and report generation — finished in about six minutes on a standard laptop. Table 4.4 summarizes the overall performance of each model.

**Table 4.4: Overall Model Performance on the Test Set**

| Model | Accuracy | Macro F1 | Avg. Inference Time |
| --- | --- | --- | --- |
| Random Forest | 99.39% | 98.90% | ~0.35 ms/flow |
| Multi-Layer Perceptron | 98.42% | 97.84% | ~0.002 ms/flow |
| Ensemble | 99.27% | 98.57% | ~0.48 ms/flow |
| Isolation Forest (anomaly, binary) | 74.71% accuracy | ROC-AUC 0.86 | — |

The supervised models and the ensemble all reached very high accuracy. The Random Forest was the strongest single classifier on these tabular features, and the MLP was extremely fast at prediction time. The ensemble closely matched the Random Forest while adding the Isolation Forest's ability to flag unusual traffic. The Isolation Forest, judged only on its own as a benign-versus-attack detector, scored lower — which is expected, because its role in the system is not to classify known attacks but to catch unusual flows that the supervised models might otherwise pass as benign.

Table 4.5 breaks down the ensemble's performance for each individual class.

**Table 4.5: Per-Class Performance of the Ensemble Model**

| Class | Precision | Recall | F1-Score |
| --- | --- | --- | --- |
| BENIGN | 0.989 | 0.995 | 0.992 |
| DDoS | 0.999 | 0.993 | 0.996 |
| PortScan | 1.000 | 0.975 | 0.987 |
| BruteForce | 0.998 | 0.996 | 0.997 |
| Botnet | 1.000 | 1.000 | 1.000 |
| Infiltration | 1.000 | 1.000 | 1.000 |
| WebAttack | 0.920 | 0.935 | 0.927 |

The per-class results show that the system performs strongly across every attack type; even the low-volume classes such as Botnet and Infiltration are detected perfectly. The Web Attack class records the lowest score (an F1 of about 0.93), because a small number of web-attack flows are statistically very close to ordinary web traffic. The confusion matrix in Figure 4.1 shows exactly how the test flows were classified.

::: {custom-style="FigureCenter"}
![](/Users/portpro/Documents/netsentry 3/docs/figures/confusion.png){width=5.2in}
:::

::: {custom-style="FigureCenter"}
**Figure 4.1: Ensemble Confusion Matrix (Test Set)**
:::

Almost every flow lies on the diagonal, meaning it was classified correctly. The small number of errors are concentrated between the BENIGN and Web Attack classes — a few normal flows are flagged as web attacks and a few web attacks are read as normal — because some web-application requests are statistically very close to ordinary web traffic. A handful of DDoS and Port Scan flows are also predicted as benign. These results confirm that the from-scratch ensemble meets the project's accuracy goal while remaining fast enough for real-time use and fully transparent in its decisions.

```{=openxml}
<w:p><w:r><w:br w:type="page"/></w:r></w:p>
```

# Chapter 5: Conclusion and Future Recommendations

## 5.1 Conclusion

This project set out to build a complete, transparent, and deployable Network Intrusion Detection System using machine-learning models written entirely from first principles. All of the objectives were met. Four core algorithms — a decision tree, a Random Forest, a Multi-Layer Perceptron, and an Isolation Forest — were implemented using only the NumPy library, and were combined into an ensemble that fuses the strengths of supervised classification with anomaly detection. The ensemble classifies network flows into normal traffic and six attack types with very high accuracy (about 99.3% overall and a macro-averaged F1-score of about 98.6%), while keeping the average prediction time to roughly half a millisecond per flow.

Beyond the models, the project delivered a full operational system rather than an isolated experiment. It includes a data and training pipeline, a real-time inference engine, a REST API, an operator dashboard, structured logging, monitoring metrics, a severity-based alerting subsystem, and an optional enforcement layer that can automatically and safely block malicious sources. The system is containerized and supplied with deployment configuration for a reverse proxy and a container-orchestration platform, and it is covered by an automated test suite and a continuous-integration pipeline.

The most important outcome is the demonstration that hand-built, fully auditable machine-learning models can reach the same high detection quality usually associated with large external libraries, while remaining transparent enough for a security analyst to understand why each decision was made. This combination of accuracy, transparency, and production-readiness is the central contribution of the NIDS project.

## 5.2 Future Recommendations

While the project achieved its goals, several enhancements could extend its value:

1. **Training on large-scale real traffic.** Although the pipeline already supports importing real public datasets, future work could train and validate the system on large volumes of live or recorded production traffic to further confirm its real-world performance.

2. **Online and incremental learning.** The models are currently trained offline. Adding the ability to update the models continuously as new traffic arrives would help the system adapt to changing attack patterns without a full retraining cycle.

3. **Direct integration with traffic sensors.** Building ready-made connectors to common flow-extraction tools would allow the system to consume live network traffic directly, removing the need for an external feeding step.

4. **Distributed and high-availability deployment.** Replacing the in-process rate limiter with a shared store and adding load balancing across many nodes would allow the system to protect very large networks.

5. **Richer explainability and analyst tools.** Future work could add per-prediction explanations and trend visualizations to the dashboard to help analysts investigate incidents more quickly.

6. **Expanded attack coverage and adversarial robustness.** Adding more attack categories and testing the models against deliberately crafted evasive traffic would make the system more comprehensive and resilient.

```{=openxml}
<w:p><w:r><w:br w:type="page"/></w:r></w:p>
```

# References

[1] K. Scarfone and P. Mell, "Guide to Intrusion Detection and Prevention Systems (IDPS)," National Institute of Standards and Technology, NIST Special Publication 800-94, 2007.

[2] A. L. Buczak and E. Guven, "A Survey of Data Mining and Machine Learning Methods for Cyber Security Intrusion Detection," *IEEE Communications Surveys & Tutorials*, vol. 18, no. 2, pp. 1153–1176, 2016.

[3] L. Breiman, "Random Forests," *Machine Learning*, vol. 45, no. 1, pp. 5–32, 2001.

[4] D. E. Rumelhart, G. E. Hinton, and R. J. Williams, "Learning Representations by Back-Propagating Errors," *Nature*, vol. 323, pp. 533–536, 1986.

[5] D. P. Kingma and J. Ba, "Adam: A Method for Stochastic Optimization," in *Proc. International Conference on Learning Representations (ICLR)*, 2015.

[6] F. T. Liu, K. M. Ting, and Z.-H. Zhou, "Isolation Forest," in *Proc. IEEE International Conference on Data Mining (ICDM)*, 2008, pp. 413–422.

[7] J. P. Anderson, "Computer Security Threat Monitoring and Surveillance," James P. Anderson Co., Technical Report, 1980.

[8] D. E. Denning, "An Intrusion-Detection Model," *IEEE Transactions on Software Engineering*, vol. SE-13, no. 2, pp. 222–232, 1987.

[9] R. Vinayakumar, M. Alazab, K. P. Soman, P. Poornachandran, A. Al-Nemrat, and S. Venkatraman, "Deep Learning Approach for Intelligent Intrusion Detection System," *IEEE Access*, vol. 7, pp. 41525–41550, 2019.

[10] M. Tavallaee, E. Bagheri, W. Lu, and A. A. Ghorbani, "A Detailed Analysis of the KDD CUP 99 Data Set," in *Proc. IEEE Symposium on Computational Intelligence for Security and Defense Applications (CISDA)*, 2009.

[11] I. Sharafaldin, A. H. Lashkari, and A. A. Ghorbani, "Toward Generating a New Intrusion Detection Dataset and Intrusion Traffic Characterization," in *Proc. International Conference on Information Systems Security and Privacy (ICISSP)*, 2018, pp. 108–116.

[12] R. Sommer and V. Paxson, "Outside the Closed World: On Using Machine Learning for Network Intrusion Detection," in *Proc. IEEE Symposium on Security and Privacy*, 2010, pp. 305–316.

```{=openxml}
<w:p><w:r><w:br w:type="page"/></w:r></w:p>
```

# Appendices

**Appendix A — Selected Source Code.** *(Insert key source listings here, e.g. `src/models/random_forest.py`, `src/models/ensemble.py`, and `src/inference/engine.py`.)*

**Appendix B — Screenshots.** *(Insert screenshots of the operator dashboard, the API documentation page, the prediction response, and the monitoring/Grafana dashboard here.)*

