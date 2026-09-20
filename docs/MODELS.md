# NetSentry — From-Scratch Models

Implementation notes for every ML component. The goal is that a reader can open any file in `src/models/` and follow the algorithm from the mathematics down to the NumPy line.

---

## 1. Decision Tree — `src/models/decision_tree.py`

Implements the **CART algorithm** (Breiman et al., 1984). No external tree library.

### Impurity

Two criteria, both computed from the per-class count vector:

```
Gini:     I(S) = 1 − Σ pᵢ²
Entropy:  H(S) = − Σ pᵢ log₂ pᵢ       (pᵢ = 0 handled explicitly)
```

### Best-split search

For each candidate feature (or a random subset of size `max_features` when used inside a forest):

1. Sort the feature column.
2. Walk through the sorted values left-to-right, maintaining running class counts for the left and right partitions.
3. At each valid split position (respecting `min_samples_leaf`), compute the weighted-impurity of the two children and its information gain over the parent.
4. Track the (feature, threshold) pair that maximizes gain.

Complexity: **O(m · n log n)** per node where `m = feature subset size`, `n = samples at the node`. The sort is the dominant cost; the sweep is linear.

### Tree construction

The build loop is **iterative** (work stack) instead of recursive so deep trees don't blow the Python recursion limit. Pre-pruning via `max_depth`, `min_samples_split`, `min_samples_leaf`. At a leaf the class distribution is stored so `predict_proba` can return Laplace-smoothed probabilities:

```
P(class = k | leaf) = (count_k + 1) / (Σ counts + n_classes)
```

### Extras

- `tree_depth()` and `n_leaves()` for diagnostic output
- Random-state-seeded `max_features` sampling, identical API to sklearn's so Random Forest can drop it in

---

## 2. Random Forest — `src/models/random_forest.py`

Breiman (2001). A bagging ensemble of the decision tree above.

### Bootstrap aggregation

For each of `n_estimators` trees:

1. Draw a bootstrap sample of size `n` with replacement from the training set.
2. Train a tree on the sample with `max_features="sqrt"` so each node splits over a fresh random feature subset.
3. Track the **out-of-bag** indices — samples *not* drawn — for that tree.

### OOB score

After training, each sample `x` has been excluded from some subset of trees. We gather every tree's prediction on samples it hasn't seen, average them, and measure accuracy against ground truth. This gives a **free validation estimate** without holding out data — often within 1–2% of a dedicated val set.

### Parallelism

`n_jobs > 1` trains trees in a `ProcessPoolExecutor`. The worker function is kept top-level so it's picklable.

### Feature importances

Approximate **Mean Decrease in Impurity**:

```
imp(f) = Σ (n_samples_at_node · impurity_at_node)   for all internal nodes splitting on f
```

Normalized to sum to 1 across features. Useful for explaining model behavior to a SOC analyst.

### Prediction

**Soft voting**: average per-tree probability vectors, then argmax. Soft voting consistently outperforms hard voting when trees are calibrated (which they are — each leaf reports a class distribution).

---

## 3. Multi-Layer Perceptron — `src/models/neural_network.py`

A fully-connected feed-forward network trained with backprop and Adam — written out explicitly.

### Architecture

`input → [dense + activation + dropout] × len(hidden_layers) → dense → softmax`

Default: `(128, 64)` hidden, ReLU, output size = number of classes.

### Initialization

- **He init** for ReLU:  `W ~ N(0, √(2/fan_in))`
- **Xavier init** for tanh/sigmoid: `W ~ N(0, √(1/fan_in))`
- Biases start at zero.

### Forward pass

Per layer:
```
z = a_prev @ W + b
a = activation(z)
if training: a ← inverted dropout mask × a
```

Softmax is computed with the max-subtraction trick for numerical stability.

### Backward pass

For softmax + cross-entropy, the output gradient simplifies to `(ŷ − y) / batch_size`. Propagating backward through the hidden layers:

```
dW_ℓ = aᵀ_{ℓ−1} @ δ_ℓ + λ · W_ℓ           (with L2 regularization)
db_ℓ = Σ δ_ℓ   (along batch axis)
δ_{ℓ−1} = (δ_ℓ @ W_ℓᵀ) ⊙ mask_{ℓ−1} ⊙ activation'(z_{ℓ−1})
```

Dropout masks are reused from the forward pass so the backward pass is consistent.

### Adam optimizer

Per-parameter first/second-moment running averages with bias correction:

```
m_t = β₁ · m_{t−1} + (1 − β₁) · g
v_t = β₂ · v_{t−1} + (1 − β₂) · g²
m̂  = m_t / (1 − β₁ᵗ)
v̂  = v_t / (1 − β₂ᵗ)
θ  ← θ − η · m̂ / (√v̂ + ε)
```

Defaults: `β₁=0.9`, `β₂=0.999`, `ε=1e-8`.

### Training loop

- Mini-batch SGD with per-epoch shuffle
- Optional validation set enables **early stopping** with configurable patience
- Best weights are restored after training so the final model is the best-val checkpoint

### Loss

Cross-entropy with epsilon-smoothed logs to avoid `log(0)` when a probability is exactly zero.

---

## 4. Isolation Forest — `src/models/isolation_forest.py`

Liu, Ting, Zhou (ICDM 2008). Detects anomalies by measuring how quickly random partitioning isolates each sample.

### Tree construction

Each iTree is built on a subsample of size `ψ = 256` (the paper's default). At every internal node:

1. Pick a random feature that has variation in the current subset.
2. Pick a random split threshold uniformly in `[min, max]` of that feature.
3. Recurse until the node has ≤1 sample or depth reaches `ceil(log₂(ψ))`.

### Anomaly score

For a sample `x`, compute the average path length across all trees:

```
E[h(x)] = (1/T) · Σ path_length(x, tree_t)
```

Score normalizes to `[0, 1]`:

```
s(x, ψ) = 2 ^ ( − E[h(x)] / c(ψ) )
c(ψ) = 2 · (H(ψ−1)) − (2(ψ−1)/ψ),     H = harmonic number
```

Values near 1 are anomalies; values near 0 are normal. The threshold is calibrated from training data using the `contamination` parameter (default 10%).

### Why it pairs with the supervised models

Supervised classifiers can only recognize attack patterns they've seen labelled. The IF was trained on benign flows only, so an attack it's never seen still scores high — giving the ensemble a shot at **zero-day** detection. The ensemble's `anomaly_boost` threshold reclassifies any "benign" supervised prediction as an attack when the IF score exceeds 0.75.

---

## 5. Ensemble — `src/models/ensemble.py`

Combines the three above with two fusion rules.

### Rule 1 — Weighted soft-voting (supervised models)

```
P_ens(class) = (w_rf · P_rf(class) + w_mlp · P_mlp(class)) / (w_rf + w_mlp)
```

Default weights 0.55 / 0.45 favor the Random Forest (which on tabular features consistently scores higher F1 than the MLP), but the MLP contributes nonlinear generalization on harder examples.

### Rule 2 — Anomaly override

If the supervised vote says "benign" *and* the IF anomaly score exceeds `anomaly_boost` (default 0.75), re-route the prediction to the highest-probability attack class. This is how NetSentry surfaces zero-day traffic that doesn't match any labelled attack profile yet.

### Auditability

`predict_with_detail(X)` returns each component's probability vector, the IF score, and whether the anomaly override fired — letting a security analyst trace **why** a flow was flagged.

---

## 6. Preprocessing — `src/data/preprocessor.py`

Every transform fits on training data only; validation and test sets are transformed with the same parameters to prevent leakage.

### Cleaning

- `±inf` → `NaN` → per-column median imputation
- Clip extreme outliers (default bounds `[-1e9, 1e9]`)

### Feature selection — ANOVA F-ratio

For each feature, compute the ratio of between-class variance to within-class variance:

```
F = ( B / (K−1) ) / ( W / (N−K) )

B = Σ_c n_c · (mean_c − overall_mean)²     (between-class)
W = Σ_c Σ_{x∈c} (x − mean_c)²              (within-class)
```

Keep the top-k features. A pure-NumPy implementation, identical in spirit to `sklearn.feature_selection.f_classif`.

### Scaling

Z-score: `(x − μ_train) / σ_train`. Near-zero standard deviations are clamped to 1 to avoid divide-by-zero on constant columns.

### Stratified split

Class-preserving partition into train / val / test. Explicitly walks each class, shuffles its indices, takes exact per-class counts — stronger guarantee than a simple random split for skewed datasets.

---

## 7. From-scratch metrics — `src/utils/metrics.py`

All evaluation numbers in the training report come from this module, not sklearn:

- **Confusion matrix** — direct counting into an `(n_classes × n_classes)` array
- **Accuracy** — `mean(y_true == y_pred)`
- **Precision / Recall / F1** — per class, plus macro / micro / weighted averages
- **ROC AUC (binary)** — build TPR/FPR curve by sorting scores, integrate with trapezoidal rule

Each is validated with handcrafted test cases in `tests/test_data_and_metrics.py`.


---

## 8. Training data — corrected CIC-IDS2017

`scripts/download_dataset.py --dataset cicids2017-improved` fetches the re-extracted
CIC-IDS2017 published with *"Error Prevalence in NIDS datasets: A Case Study on CIC-IDS-2017 and
CSE-CIC-IDS-2018"* (Liu, Engelen, Lynar, Essam, Joosen — IEEE CNS 2022). Compared with the
original CSVs it fixes CICFlowMeter bugs (TCP termination, flag counting, duplicated flows) and
relabels traffic (e.g. the previously unlabelled port scan launched from the infiltrated host).

`src/data/real_dataset.py` maps its CICFlowMeter-v4 column names onto the 30 NetSentry features
and applies three rules:

| Rule | Why |
| --- | --- |
| `<attack> - Attempted` flows are **dropped** | The authors mark flows that were part of an attack but show no malicious behaviour (no payload, closed port, tool start-up). As attacks they teach "any failed connection is hostile"; as benign they hide real attack shapes. |
| `Infiltration - Portscan` → **PortScan** | Label by behaviour, not campaign — these flows *are* port scans and would otherwise collide with the real PortScan class. |
| DoS Hulk / GoldenEye / Slowloris / Slowhttptest / Heartbleed → **DDoS** | One denial-of-service family; the sniffer cannot tell one tool from another by flow shape anyway. |

Exact-duplicate rows are removed **before** the stratified split, so no test row has a twin in
training (PortScan collapses from 230 k raw rows to 7,498 unique ones — scan probes are nearly
identical). Class caps for the shipped model: BENIGN 150,000 · DDoS 50,000 · everything else
uncapped (PortScan 7,498 · BruteForce 6,933 · Botnet 736 · WebAttack 104 · Infiltration 36).
`--min-per-class 0` disables the synthetic generator: **every training row is real traffic.**

### Live feature alignment (`src/capture/sniffer.py`)

The model only generalises to live traffic if the sniffer computes features exactly as
CICFlowMeter did for the training data (verified against `BasicFlow.java`, `FlowGenerator.java`,
`Cmd.java` and the corrected CSVs):

| Feature family | CICFlowMeter convention now mirrored |
| --- | --- |
| Packet length mean/std/var, segment sizes, Flow Bytes/s | **transport payload bytes** (not frame length) |
| Fwd Header Length | **transport header only** — TCP data offset ×4, 8 for UDP (no IP header) |
| Active / Idle | a silence > **5 s** ends an active period *at the last packet before it*; flows without such a gap keep 0 |
| Flow lifetime | cut **120 s** after the first packet; ends immediately on **RST** or once **both** sides sent FIN |
| Zero-duration flows | rates emitted as 0 (CICFlowMeter writes `Infinity`, which the loader stores as 0) |
| Minimum flow size | 2 packets — a probe and its reply is a complete, classifiable flow |

`scripts/live_capture.py` and `scripts/evaluate_model.py --pcap` import this one implementation
instead of carrying their own copies, so the API server, the CLI capture tool and offline pcap
evaluation cannot drift apart again. Tests: `tests/test_capture_features.py`.

### Ensemble weights

`scripts/tune_ensemble.py` grid-searches the RF/MLP soft-voting weight on the **validation**
split (macro-F1, so the rare classes count) and writes the winner into `ensemble.pkl` and
`config.yaml`. On the corrected data the MLP dragged Infiltration recall from 0.86 to 0.29 at
the old 0.6/0.4 weights; 0.9/0.1 restores it and lifts test macro-F1 from 0.905 to 0.973.

