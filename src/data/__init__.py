"""Data pipeline: synthetic generation, real dataset loading, preprocessing, and IO."""

from .generator import (
    CLASS_NAMES,
    CLASS_TO_ID,
    FEATURE_NAMES,
    generate_dataset,
    load_dataset_csv,
    save_dataset_csv,
)
from .loader import load_or_generate
from .preprocessor import Preprocessor, PreprocessorArtifacts
from .real_dataset import (
    load_cic_ids2017_csv,
    load_cic_ids2017_directory,
    load_real_dataset,
    balance_classes,
)

__all__ = [
    "CLASS_NAMES",
    "CLASS_TO_ID",
    "FEATURE_NAMES",
    "generate_dataset",
    "load_dataset_csv",
    "save_dataset_csv",
    "load_or_generate",
    "load_cic_ids2017_csv",
    "load_cic_ids2017_directory",
    "load_real_dataset",
    "balance_classes",
    "Preprocessor",
    "PreprocessorArtifacts",
]
