"""
models/__init__.py — ML model interface exports.
"""

from .base_model import BaseMLModel, SklearnWrapper

__all__ = [
    "BaseMLModel",
    "SklearnWrapper",
]
