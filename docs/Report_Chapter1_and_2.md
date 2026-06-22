# Chapter 1: Introduction

## 1.1 Introduction

Modern organizations depend on computer networks to carry almost every part of their daily operations, from internal communication and file sharing to customer-facing services and financial transactions. As this dependence has grown, networks have also become one of the most attractive targets for attackers. Threats such as distributed denial-of-service (DDoS) floods, port scanning, password brute-forcing, botnet activity, host infiltration, and web-application attacks are now common, automated, and continuously evolving. A single successful intrusion can lead to service downtime, data theft, financial loss, and lasting damage to an organization's reputation. Protecting a network therefore requires more than a firewall at the perimeter; it requires the ability to continuously observe traffic, recognize malicious behaviour, and respond before serious harm is done.

A **Network Intrusion Detection System (NIDS)** is a security tool designed for exactly this purpose. It inspects network activity, decides whether each unit of traffic is normal or malicious, and raises an alert when it detects a likely attack. Traditional intrusion detection systems rely heavily on *signatures* — fixed rules that describe known attacks. While signature-based systems are accurate against threats they already know, they are unable to recognize new or slightly modified attacks for which no rule has been written yet. To overcome this weakness, the security industry has increasingly turned to **machine learning**, which allows a system to *learn* the statistical patterns that separate benign traffic from attacks, and to generalize to variations it has not seen before.

This project, **NetSentry**, is a complete, production-style Network Intrusion Detection System that classifies network traffic flows into normal traffic and six distinct attack categories using machine learning. What distinguishes NetSentry from a typical academic project is that **all of its machine-learning models are implemented from first principles using only the NumPy numerical library** — without relying on ready-made machine-learning frameworks such as scikit-learn, TensorFlow, or PyTorch. The system combines three complementary models: a Random Forest and a Multi-Layer Perceptron (a type of neural network) that recognize known attack patterns, and an Isolation Forest that detects unusual, never-before-seen behaviour. The predictions of these three models are then merged by an ensemble layer to produce a single, reliable decision for each network flow.

Beyond the detection logic, NetSentry is built as a full working system rather than a standalone script. It includes a data-processing pipeline, a training pipeline, a real-time inference engine, a REST Application Programming Interface (API) for receiving traffic and returning verdicts, an operator dashboard for security staff, a monitoring and alerting subsystem, and an optional enforcement mode that can automatically block malicious source addresses. The system is also packaged for realistic deployment using containers and orchestration tooling. In this way, NetSentry demonstrates not only the design of intrusion-detection algorithms but also the engineering required to operate such a system in a real environment.

## 1.2 Problem Statement

Network attacks today are frequent, automated, and constantly changing, while the volume of traffic that must be examined is enormous. This creates several specific problems that existing approaches struggle to solve together:

- **Signature-based systems cannot detect new attacks.** Rule-based detection tools only recognize threats that exactly match a previously written signature. Attackers routinely modify their methods, and entirely new ("zero-day") attacks appear regularly. Any small change can allow an attack to slip past a purely signature-based defence.

- **Manual monitoring does not scale.** The amount of traffic on even a modest network is far too large for human analysts to inspect directly. Without automated classification, genuine attacks are easily lost in the noise of normal activity.

- **Machine-learning solutions are often treated as black boxes.** Many machine-learning intrusion detectors depend on large external libraries whose internal behaviour is hidden from the developer. In a security context this is a serious weakness: analysts need to understand *why* a flow was flagged, and developers need to be able to audit and trust every step of the computation.

- **Detection alone is not enough.** A model that produces an accuracy figure in a notebook is not a usable security system. To be effective, a detector must run continuously, accept live traffic, respond within milliseconds, raise meaningful alerts, expose its health to monitoring tools, and ideally take protective action automatically.

- **Class imbalance and varied attack behaviour make accurate classification difficult.** Normal traffic vastly outnumbers attacks, and different attacks (for example, a high-volume DDoS flood versus a quiet infiltration attempt) have very different statistical fingerprints. A single model often handles some of these well and others poorly.

The core problem this project addresses is therefore: **how to build a network intrusion detection system that can accurately distinguish normal traffic from multiple types of attacks, can detect unknown attacks as well as known ones, remains fully transparent and auditable in its decision-making, and operates as a complete, deployable real-time service rather than an isolated experiment.**

## 1.3 Objectives

The main objectives of the NetSentry project are as follows:

1. **To design and implement core machine-learning models from scratch** — a decision tree, a Random Forest, a Multi-Layer Perceptron, and an Isolation Forest — using only basic numerical operations, so that the entire detection logic is transparent and auditable.

2. **To build an ensemble classifier** that combines the strengths of supervised models (for recognizing known attacks) and an anomaly-detection model (for surfacing unknown or zero-day behaviour) into a single reliable decision per network flow.

3. **To accurately classify network traffic** into normal traffic and six attack categories — DDoS, Port Scan, Brute Force, Botnet, Infiltration, and Web Attack — using a realistic, flow-level feature set.

4. **To develop a complete real-time detection service**, including a data-processing pipeline, a training pipeline, an inference engine, a REST API, and an operator dashboard, so the models can be used in practice and not only in testing.

5. **To provide monitoring, alerting, and optional automated response**, including severity-based alerts, performance metrics, and an enforcement mode capable of blocking malicious sources under safe, configurable conditions.

## 1.4 Scope and Limitation

### Scope

The scope of the NetSentry project covers the following:

- **Flow-level intrusion detection.** The system analyzes summarized network *flow records* (described by thirty numerical features such as packet counts, byte rates, inter-arrival times, and TCP flag counts) rather than raw packet payloads. This is the same style of feature set used by well-known public intrusion-detection datasets.
- **Multi-class classification.** NetSentry classifies each flow as benign or as one of six attack types, giving security staff specific information about the nature of a threat rather than a simple "good/bad" label.
- **From-scratch model implementation.** All learning algorithms are written directly using numerical array operations, with no external machine-learning library.
- **End-to-end system.** The project includes data generation and preprocessing, model training and evaluation, real-time inference, a REST API, an operator dashboard, structured logging, performance metrics, and alerting.
- **Optional automated enforcement.** An enforcement subsystem can translate high-confidence detections into protective actions (such as rate-limiting or blocking a source address) through a pluggable backend, with safety features such as a dry-run mode and a list of always-allowed networks.
- **Realistic deployment.** The system is containerized and includes deployment configuration suitable for running behind a reverse proxy and on a container-orchestration platform.

### Limitations

The project also has the following limitations:

- **Dependence on an external traffic sensor.** NetSentry consumes pre-extracted flow records. It does not capture packets from the wire itself; in a real deployment a separate flow-extraction tool would feed traffic into the system.
- **Synthetic data by default.** For demonstration and testing, the system uses a synthetic dataset that imitates the statistical signatures of real attacks. Although the pipeline also supports importing real public datasets, the headline results are produced on generated traffic that approximates, but does not perfectly reproduce, live network conditions.
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

---

# Chapter 2: Background Study and Literature Review

## 2.1 Background Study

This section explains the fundamental concepts and terminology needed to understand the NetSentry system. The aim is to relate each concept directly to the way it is used in the project rather than to present general definitions in isolation.

### 2.1.1 Network Traffic and Flows

When two computers communicate over a network, they exchange a stream of small units of data called *packets*. Examining every individual packet is expensive and, when traffic is encrypted, often unhelpful. A more practical unit of analysis is the **network flow**: a summary of a single conversation between two endpoints over a period of time. Instead of recording raw content, a flow records statistical properties — for example, how long the conversation lasted, how many packets and bytes were sent in each direction, how quickly packets arrived, the average packet size, and how often particular control flags (such as SYN, ACK, RST, and FIN, which mark stages of a connection) appeared. NetSentry works entirely at this flow level, representing each conversation as a fixed list of thirty numerical features. This is the same kind of feature representation used by widely studied public intrusion-detection datasets, which makes the system both efficient and compatible with real traffic-extraction tools.

### 2.1.2 Intrusion Detection and Prevention

An **Intrusion Detection System (IDS)** observes activity and reports suspected attacks, while an **Intrusion Prevention System (IPS)** goes a step further and actively blocks or limits malicious traffic [1]. Detection approaches are usually grouped into two families. **Signature-based** (or misuse) detection compares activity against a database of known attack patterns; it is precise for known threats but blind to new ones. **Anomaly-based** detection builds a model of normal behaviour and flags anything that deviates significantly from it; it can catch novel attacks but may produce more false alarms [2]. NetSentry deliberately combines both philosophies: its supervised models behave like a learned, generalized form of misuse detection, recognizing the fingerprints of known attack classes, while its Isolation Forest performs anomaly detection to surface traffic that does not resemble normal behaviour. The optional enforcement layer gives the system an IPS capability, mapping confident detections to protective actions.

### 2.1.3 Common Network Attacks

NetSentry is trained to distinguish benign traffic from six attack categories, each with a distinct behavioural fingerprint:

- **DDoS (Distributed Denial of Service):** a flood of traffic from many sources intended to overwhelm a service, characterized by extremely high packet and byte rates.
- **Port Scan:** systematic probing of many network ports to discover open services, characterized by many short connection attempts.
- **Brute Force:** repeated login attempts to guess credentials, characterized by many similar, repetitive connections to an authentication service.
- **Botnet:** traffic generated by compromised machines communicating with a controller, often showing periodic, automated patterns.
- **Infiltration:** stealthy unauthorized access following an initial compromise, typically low-volume and difficult to distinguish from normal activity.
- **Web Attack:** attacks aimed at web applications, such as injection or cross-site scripting attempts, visible through unusual request patterns.

Because these attacks differ so widely — from very loud (DDoS) to very quiet (Infiltration) — no single model recognizes all of them equally well, which is one of the main reasons NetSentry uses an ensemble.

### 2.1.4 Machine Learning for Classification

**Machine learning** allows a system to learn patterns from examples instead of following hand-written rules. In **supervised learning**, the model is trained on data that is already labelled with the correct answer; it learns to map input features to the correct class so that it can later classify new, unlabelled data. Intrusion detection of known attack types is naturally a supervised **classification** problem, where the classes are "benign" and the various attack categories. In **unsupervised** or **anomaly detection**, the model is trained mostly on normal data and learns to recognize anything that does not fit, which is useful for catching unknown attacks. NetSentry uses supervised learning for its Random Forest and neural network, and anomaly detection for its Isolation Forest.

### 2.1.5 Decision Trees and Random Forests

A **decision tree** classifies data by asking a sequence of simple yes/no questions about the feature values, splitting the data at each step into purer and purer groups until it can confidently assign a class. The quality of each split is measured by how well it separates the classes. A single tree, however, can easily "memorize" its training data and perform poorly on new data. A **Random Forest** addresses this by training many different trees, each on a random sample of the data and a random subset of the features, and then combining their votes [3]. This averaging makes the overall model far more stable and accurate than any single tree, and it provides a useful by-product: an estimate of which features were most important in making decisions, which helps analysts understand the model's reasoning. In NetSentry, the Random Forest is the strongest single classifier for the known attack types.

### 2.1.6 Neural Networks (Multi-Layer Perceptron)

A **Multi-Layer Perceptron (MLP)** is a basic form of artificial neural network. It is made up of layers of simple processing units ("neurons") connected by adjustable weights. Input features pass through one or more hidden layers, where each layer transforms the data and passes it on, until the final layer produces a probability for each class. The network *learns* by comparing its predictions to the correct answers and gradually adjusting its weights to reduce the error, a process known as **backpropagation** [4]. Modern training also uses an optimization technique that adapts how much each weight is changed on every step, making learning faster and more stable [5]. Neural networks are especially good at capturing complex, non-linear relationships between features, which lets the NetSentry MLP recognize attack patterns that simpler models might miss. The project also applies standard techniques such as dropout (temporarily ignoring some neurons during training) and early stopping (halting training once performance stops improving) to prevent the network from overfitting.

### 2.1.7 Anomaly Detection with Isolation Forest

The **Isolation Forest** is a method designed specifically to find rare, unusual data points [6]. Its key idea is simple and elegant: anomalies are "few and different," so they are easier to separate from the rest of the data than normal points are. The algorithm repeatedly splits the data at random; points that become isolated after only a few splits are judged to be anomalies, while points that require many splits are considered normal. In NetSentry, the Isolation Forest is trained on normal traffic so that any flow which looks distinctly unusual receives a high anomaly score — even if it belongs to an attack type the supervised models have never been trained on. This is the project's main mechanism for detecting potential **zero-day** attacks.

### 2.1.8 Ensemble Learning

**Ensemble learning** is the practice of combining several models so that their collective decision is better than any individual one. Different models tend to make different mistakes, so combining them often cancels out individual errors. NetSentry's ensemble uses two rules. First, it blends the probability outputs of the Random Forest and the MLP using a weighted average, giving more influence to the model that is generally more accurate while still benefiting from the other's strengths. Second, it applies an *anomaly override*: if the supervised models judge a flow to be benign but the Isolation Forest reports a strong anomaly, the ensemble overrides the benign verdict and treats the flow as suspicious. Importantly, the ensemble can explain its decision by reporting each model's contribution, preserving the transparency that is central to the project.

### 2.1.9 Data Preprocessing and Evaluation

Before any model can learn, raw data must be cleaned and prepared. NetSentry's preprocessing handles missing or invalid values, scales every feature to a comparable range so that no single large-valued feature dominates, and selects the most informative features by measuring how strongly each one separates the classes. The data is split into training, validation, and test sets in a way that preserves the proportion of each class, which is important because attacks are far rarer than normal traffic. To judge how well the models perform, the project relies on standard evaluation measures — **accuracy** (overall correctness), **precision** (how many flagged attacks were truly attacks), **recall** (how many real attacks were caught), and the **F1-score** (a balance of precision and recall) — all summarized in a **confusion matrix** that shows exactly which classes were confused with which. In keeping with the project's transparency goal, these evaluation measures are also implemented from scratch rather than taken from an external library.

### 2.1.10 Supporting System Concepts

To function as a real service, NetSentry uses several standard software and operations concepts. A **REST API** is a standard way for other programs to send data to the system and receive results over the web. A **dashboard** provides a visual interface for human operators. **Monitoring metrics** expose numerical indicators of the system's health and performance in a format that monitoring tools can collect and chart. **Containerization** packages the application together with everything it needs to run, so it behaves identically across different machines, and **orchestration** manages running and scaling those containers. These concepts allow the intrusion-detection logic to be operated reliably in a realistic production setting.

## 2.2 Literature Review

The idea of automatically monitoring computer systems for misuse dates back several decades. Anderson's early work introduced the concept of using audit data to detect security threats [7], and Denning's foundational intrusion-detection model formalized the idea of building a profile of normal behaviour and flagging deviations from it [8]. These works established the two enduring approaches — misuse (signature) detection and anomaly detection — that still shape intrusion-detection research today, and that NetSentry deliberately combines.

Early operational intrusion-detection systems were predominantly signature-based, with widely deployed open-source tools relying on hand-written rules to match known attacks [1]. The U.S. National Institute of Standards and Technology consolidated best practices for such systems in its guide to intrusion detection and prevention, which also describes the distinction between detection-only and prevention-capable systems [1]. While signature-based tools remain valuable for their precision against known threats, the security community recognized early that they cannot detect novel attacks, motivating the shift toward learning-based methods that NetSentry follows.

A large body of research has since applied machine learning to intrusion detection. Buczak and Guven surveyed a wide range of data-mining and machine-learning methods for cyber-security intrusion detection, comparing decision trees, support-vector machines, neural networks, and ensemble approaches, and noting the practical trade-offs between accuracy, training cost, and interpretability [2]. Their survey highlights that no single algorithm dominates across all attack types — a finding that directly supports NetSentry's ensemble design, in which different models cover different weaknesses.

The individual algorithms used in this project each have well-established research foundations. The decision-tree and Random Forest methods build on Breiman's work, which demonstrated that combining many randomized trees produces a model that is both highly accurate and resistant to overfitting, while still offering measures of feature importance [3]. The neural-network component rests on the backpropagation algorithm for training multi-layer networks [4], combined with the adaptive optimization method introduced by Kingma and Ba, which has become a standard technique for training neural networks efficiently [5]. For anomaly detection, Liu, Ting, and Zhou's Isolation Forest provided an efficient way to identify rare points without first modelling the entire distribution of normal data [6]; NetSentry adopts this method precisely because of its efficiency and its suitability for highlighting previously unseen attacks. More recent research has explored deep-learning approaches to intrusion detection, reporting strong results on benchmark datasets using larger and more complex networks [9]; NetSentry intentionally uses a compact, fully transparent multi-layer perceptron instead, prioritizing auditability and modest computational requirements over model complexity.

The quality of an intrusion-detection study depends heavily on the data used to evaluate it. Earlier research relied on datasets such as KDD Cup 99 and its refined version, but these were later criticized for redundant records and outdated traffic that no longer reflect modern networks [10]. To address these shortcomings, Sharafaldin, Lashkari, and Ghorbani produced the CIC-IDS2017 dataset, which contains realistic, labelled benign and attack traffic described by flow-level features, and which has become a widely used benchmark for evaluating modern intrusion detectors [11]. NetSentry adopts the same thirty-feature, flow-level representation and the same attack categories used in this family of datasets, and its data pipeline is able to import such real datasets directly; this alignment makes the project's design and feature set consistent with current research practice.

An influential and cautionary contribution to this field is the work of Sommer and Paxson, who examined why machine-learning intrusion detectors that perform well in the laboratory often disappoint in real deployments [12]. They identified problems such as the high cost of false alarms, the difficulty of obtaining good labelled data, the gap between research datasets and live traffic, and — crucially — the need for results to be *interpretable* so that analysts can act on them. These observations strongly influenced the design priorities of NetSentry: the system is built to be transparent and auditable, it reports the reasoning behind each detection, it includes confidence thresholds and safety controls before taking any automated action, and it is engineered as a complete operational service rather than an isolated classifier.

In summary, the literature establishes three consistent themes that this project builds upon. First, combining misuse and anomaly detection is more effective than either alone, which justifies NetSentry's hybrid ensemble. Second, no single learning algorithm is best for all attack types, which justifies combining a Random Forest, a neural network, and an Isolation Forest. Third, practical intrusion detection demands interpretability, careful evaluation on realistic data, and genuine operational engineering — not merely a high accuracy score. NetSentry's distinctive contribution within this landscape is to implement the core learning algorithms entirely from first principles, ensuring full transparency, while wrapping them in a complete, deployable detection-and-response system.

## References

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
