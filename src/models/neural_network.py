"""
Multi-Layer Perceptron (MLP) — built from scratch.

Implements a fully-connected feed-forward neural network with:
    - Configurable hidden-layer architecture
    - ReLU, tanh, sigmoid, softmax activations
    - Cross-entropy loss for multi-class classification
    - Adam optimizer with bias correction
    - L2 weight regularization
    - Dropout at training time
    - Xavier/He weight initialization
    - Mini-batch gradient descent

Uses only NumPy. Everything — forward pass, backprop, optimizer state,
dropout mask — is written explicitly so every computation is auditable.

References: Goodfellow, Bengio, Courville, "Deep Learning" (2016), chapter 6.
"""

from __future__ import annotations

import time
from typing import Optional

import numpy as np

from .base import BaseModel


# ----------------------------------------------------------------------
# Activation functions and their derivatives
# ----------------------------------------------------------------------
def _relu(z: np.ndarray) -> np.ndarray:
    return np.maximum(0.0, z)


def _relu_grad(z: np.ndarray) -> np.ndarray:
    return (z > 0).astype(z.dtype)


def _sigmoid(z: np.ndarray) -> np.ndarray:
    # Numerically stable sigmoid
    out = np.empty_like(z)
    pos = z >= 0
    neg = ~pos
    out[pos] = 1.0 / (1.0 + np.exp(-z[pos]))
    exp_z = np.exp(z[neg])
    out[neg] = exp_z / (1.0 + exp_z)
    return out


def _sigmoid_grad(z: np.ndarray) -> np.ndarray:
    s = _sigmoid(z)
    return s * (1.0 - s)


def _tanh(z: np.ndarray) -> np.ndarray:
    return np.tanh(z)


def _tanh_grad(z: np.ndarray) -> np.ndarray:
    return 1.0 - np.tanh(z) ** 2


def _softmax(z: np.ndarray) -> np.ndarray:
    # Subtract max for numerical stability
    z_shift = z - np.max(z, axis=1, keepdims=True)
    exp_z = np.exp(z_shift)
    return exp_z / np.sum(exp_z, axis=1, keepdims=True)


ACTIVATIONS = {
    "relu": (_relu, _relu_grad),
    "tanh": (_tanh, _tanh_grad),
    "sigmoid": (_sigmoid, _sigmoid_grad),
}


# ----------------------------------------------------------------------
# MLP classifier
# ----------------------------------------------------------------------
class MLPClassifier(BaseModel):
    """Multi-layer perceptron classifier.

    Parameters
    ----------
    hidden_layers : tuple[int, ...]
        Sizes of the hidden layers. e.g. (64, 32) = two hidden layers.
    activation : {"relu", "tanh", "sigmoid"}
        Activation for hidden layers. Output layer is always softmax.
    learning_rate : float
        Adam initial learning rate.
    batch_size : int
        Mini-batch size.
    epochs : int
        Number of passes over the training set.
    l2_reg : float
        L2 regularization strength (weight decay).
    dropout : float
        Dropout probability for hidden layers (0 disables dropout).
    early_stopping_patience : int or None
        Stop if validation loss doesn't improve for this many epochs.
    random_state : int or None
        Seed for reproducibility.
    verbose : bool
        Print training progress.
    """

    def __init__(
        self,
        hidden_layers: tuple[int, ...] = (128, 64),
        activation: str = "relu",
        learning_rate: float = 1e-3,
        batch_size: int = 128,
        epochs: int = 50,
        l2_reg: float = 1e-4,
        dropout: float = 0.2,
        early_stopping_patience: Optional[int] = 8,
        beta1: float = 0.9,
        beta2: float = 0.999,
        adam_eps: float = 1e-8,
        random_state: Optional[int] = None,
        verbose: bool = False,
    ) -> None:
        super().__init__()
        if activation not in ACTIVATIONS:
            raise ValueError(f"Unknown activation: {activation}")
        self.hidden_layers = tuple(hidden_layers)
        self.activation = activation
        self.learning_rate = learning_rate
        self.batch_size = batch_size
        self.epochs = epochs
        self.l2_reg = l2_reg
        self.dropout = dropout
        self.early_stopping_patience = early_stopping_patience
        self.beta1 = beta1
        self.beta2 = beta2
        self.adam_eps = adam_eps
        self.random_state = random_state
        self.verbose = verbose

        # Parameters populated after fit
        self.weights_: list[np.ndarray] = []
        self.biases_: list[np.ndarray] = []
        self.history_: dict[str, list[float]] = {"train_loss": [], "val_loss": [], "val_acc": []}
        self._rng = np.random.default_rng(random_state)

    # ------------------------------------------------------------------
    # Parameter initialization
    # ------------------------------------------------------------------
    def _init_parameters(self, n_features: int) -> None:
        layer_sizes = [n_features, *self.hidden_layers, self.n_classes_]
        self.weights_ = []
        self.biases_ = []
        for fan_in, fan_out in zip(layer_sizes[:-1], layer_sizes[1:]):
            # He initialization for ReLU, Xavier otherwise
            if self.activation == "relu":
                std = np.sqrt(2.0 / fan_in)
            else:
                std = np.sqrt(1.0 / fan_in)
            W = self._rng.normal(0.0, std, size=(fan_in, fan_out))
            b = np.zeros((1, fan_out))
            self.weights_.append(W)
            self.biases_.append(b)

    # ------------------------------------------------------------------
    # Forward / backward pass
    # ------------------------------------------------------------------
    def _forward(
        self, X: np.ndarray, training: bool = False
    ) -> tuple[list[np.ndarray], list[np.ndarray], list[Optional[np.ndarray]]]:
        """Compute the forward pass, returning (activations, pre_activations, dropout_masks)."""
        act_fn, _ = ACTIVATIONS[self.activation]
        activations: list[np.ndarray] = [X]
        pre_activations: list[np.ndarray] = []
        dropout_masks: list[Optional[np.ndarray]] = []

        a = X
        num_layers = len(self.weights_)
        for layer_idx in range(num_layers):
            z = a @ self.weights_[layer_idx] + self.biases_[layer_idx]
            pre_activations.append(z)
            if layer_idx < num_layers - 1:
                a = act_fn(z)
                if training and self.dropout > 0.0:
                    # Inverted dropout: scale during training so inference is unchanged
                    keep = 1.0 - self.dropout
                    mask = (self._rng.random(a.shape) < keep).astype(a.dtype) / keep
                    a = a * mask
                    dropout_masks.append(mask)
                else:
                    dropout_masks.append(None)
            else:
                # Output layer — softmax
                a = _softmax(z)
                dropout_masks.append(None)
            activations.append(a)

        return activations, pre_activations, dropout_masks

    def _backward(
        self,
        y_onehot: np.ndarray,
        activations: list[np.ndarray],
        pre_activations: list[np.ndarray],
        dropout_masks: list[Optional[np.ndarray]],
    ) -> tuple[list[np.ndarray], list[np.ndarray]]:
        """Compute gradients for all parameters via backpropagation."""
        _, act_grad = ACTIVATIONS[self.activation]
        num_layers = len(self.weights_)
        batch_size = y_onehot.shape[0]

        grad_w: list[np.ndarray] = [np.zeros_like(W) for W in self.weights_]
        grad_b: list[np.ndarray] = [np.zeros_like(b) for b in self.biases_]

        # For softmax + cross-entropy, dL/dz at the output layer simplifies to (y_hat - y)
        delta = (activations[-1] - y_onehot) / batch_size

        for layer_idx in range(num_layers - 1, -1, -1):
            a_prev = activations[layer_idx]
            grad_w[layer_idx] = a_prev.T @ delta + self.l2_reg * self.weights_[layer_idx]
            grad_b[layer_idx] = np.sum(delta, axis=0, keepdims=True)

            if layer_idx > 0:
                # Propagate gradient back through activation of previous layer
                delta = delta @ self.weights_[layer_idx].T
                mask = dropout_masks[layer_idx - 1]
                if mask is not None:
                    delta = delta * mask
                delta = delta * act_grad(pre_activations[layer_idx - 1])

        return grad_w, grad_b

    # ------------------------------------------------------------------
    # Loss
    # ------------------------------------------------------------------
    @staticmethod
    def _cross_entropy(y_onehot: np.ndarray, y_pred: np.ndarray) -> float:
        eps = 1e-12
        return float(-np.mean(np.sum(y_onehot * np.log(y_pred + eps), axis=1)))

    def _l2_penalty(self) -> float:
        if self.l2_reg <= 0:
            return 0.0
        return 0.5 * self.l2_reg * float(sum(np.sum(W * W) for W in self.weights_))

    # ------------------------------------------------------------------
    # Training loop
    # ------------------------------------------------------------------
    def fit(
        self,
        X: np.ndarray,
        y: np.ndarray,
        X_val: Optional[np.ndarray] = None,
        y_val: Optional[np.ndarray] = None,
    ) -> "MLPClassifier":
        X = np.asarray(X, dtype=np.float64)
        y = np.asarray(y, dtype=np.int64)
        if X.shape[0] != y.shape[0]:
            raise ValueError("X and y have different numbers of samples")
        if X_val is not None:
            X_val = np.asarray(X_val, dtype=np.float64)
            y_val = np.asarray(y_val, dtype=np.int64)

        start = time.time()
        self.n_features_ = X.shape[1]
        self.classes_ = np.unique(y)
        self.n_classes_ = int(self.classes_.max()) + 1
        self._init_parameters(self.n_features_)

        # One-hot labels
        y_onehot = np.zeros((y.shape[0], self.n_classes_), dtype=np.float64)
        y_onehot[np.arange(y.shape[0]), y] = 1.0

        # Adam optimizer state
        m_w = [np.zeros_like(W) for W in self.weights_]
        v_w = [np.zeros_like(W) for W in self.weights_]
        m_b = [np.zeros_like(b) for b in self.biases_]
        v_b = [np.zeros_like(b) for b in self.biases_]
        step = 0

        best_val_loss = float("inf")
        best_weights: list[np.ndarray] = [W.copy() for W in self.weights_]
        best_biases: list[np.ndarray] = [b.copy() for b in self.biases_]
        patience_counter = 0

        n_samples = X.shape[0]
        for epoch in range(1, self.epochs + 1):
            # Shuffle at the start of each epoch
            perm = self._rng.permutation(n_samples)
            X_shuf = X[perm]
            y_shuf = y_onehot[perm]

            epoch_losses: list[float] = []
            for batch_start in range(0, n_samples, self.batch_size):
                X_batch = X_shuf[batch_start : batch_start + self.batch_size]
                y_batch = y_shuf[batch_start : batch_start + self.batch_size]

                activations, pre_activations, dropout_masks = self._forward(X_batch, training=True)
                loss = self._cross_entropy(y_batch, activations[-1]) + self._l2_penalty() / max(1, X_batch.shape[0])
                epoch_losses.append(loss)

                grad_w, grad_b = self._backward(y_batch, activations, pre_activations, dropout_masks)
                step += 1

                # Adam update with bias correction
                for i in range(len(self.weights_)):
                    m_w[i] = self.beta1 * m_w[i] + (1.0 - self.beta1) * grad_w[i]
                    v_w[i] = self.beta2 * v_w[i] + (1.0 - self.beta2) * (grad_w[i] ** 2)
                    m_hat = m_w[i] / (1.0 - self.beta1 ** step)
                    v_hat = v_w[i] / (1.0 - self.beta2 ** step)
                    self.weights_[i] -= self.learning_rate * m_hat / (np.sqrt(v_hat) + self.adam_eps)

                    m_b[i] = self.beta1 * m_b[i] + (1.0 - self.beta1) * grad_b[i]
                    v_b[i] = self.beta2 * v_b[i] + (1.0 - self.beta2) * (grad_b[i] ** 2)
                    m_hat_b = m_b[i] / (1.0 - self.beta1 ** step)
                    v_hat_b = v_b[i] / (1.0 - self.beta2 ** step)
                    self.biases_[i] -= self.learning_rate * m_hat_b / (np.sqrt(v_hat_b) + self.adam_eps)

            train_loss = float(np.mean(epoch_losses))
            self.history_["train_loss"].append(train_loss)

            # Validation & early stopping
            if X_val is not None and y_val is not None:
                val_proba = self._predict_proba_no_dropout(X_val)
                val_onehot = np.zeros((y_val.shape[0], self.n_classes_), dtype=np.float64)
                val_onehot[np.arange(y_val.shape[0]), y_val] = 1.0
                val_loss = self._cross_entropy(val_onehot, val_proba)
                val_acc = float(np.mean(np.argmax(val_proba, axis=1) == y_val))
                self.history_["val_loss"].append(val_loss)
                self.history_["val_acc"].append(val_acc)

                if self.verbose:
                    print(
                        f"  [MLP] Epoch {epoch:3d}/{self.epochs}  "
                        f"train_loss={train_loss:.4f}  val_loss={val_loss:.4f}  val_acc={val_acc:.4f}"
                    )

                if val_loss < best_val_loss - 1e-6:
                    best_val_loss = val_loss
                    best_weights = [W.copy() for W in self.weights_]
                    best_biases = [b.copy() for b in self.biases_]
                    patience_counter = 0
                else:
                    patience_counter += 1
                    if (
                        self.early_stopping_patience is not None
                        and patience_counter >= self.early_stopping_patience
                    ):
                        if self.verbose:
                            print(f"  [MLP] Early stopping at epoch {epoch}")
                        break
            elif self.verbose:
                print(f"  [MLP] Epoch {epoch:3d}/{self.epochs}  train_loss={train_loss:.4f}")

        # Restore best parameters
        if X_val is not None:
            self.weights_ = best_weights
            self.biases_ = best_biases

        self.is_fitted = True
        self.training_time_ = time.time() - start
        return self

    def _predict_proba_no_dropout(self, X: np.ndarray) -> np.ndarray:
        activations, _, _ = self._forward(X, training=False)
        return activations[-1]

    def predict_proba(self, X: np.ndarray) -> np.ndarray:
        self._check_fitted()
        X = self._validate_input(X)
        return self._predict_proba_no_dropout(X)

    def predict(self, X: np.ndarray) -> np.ndarray:
        return np.argmax(self.predict_proba(X), axis=1).astype(np.int64)
