"""
models/base_model.py — Base classes for ML model wrappers.
"""

from __future__ import annotations
from abc import ABC, abstractmethod
from typing import Any, Optional


class BaseMLModel(ABC):
    @abstractmethod
    def predict(self, features: Any) -> Any:
        ...

    @abstractmethod
    def train(self, data: Any, labels: Any) -> None:
        ...

    @abstractmethod
    def save(self, path: str) -> None:
        ...

    @abstractmethod
    def load(self, path: str) -> None:
        ...


class SklearnWrapper(BaseMLModel):
    def __init__(self, model: Optional[Any] = None):
        self._model = model

    def predict(self, features: Any) -> Any:
        if self._model is None:
            return None
        return self._model.predict(features)

    def train(self, data: Any, labels: Any) -> None:
        if self._model is not None:
            self._model.fit(data, labels)

    def save(self, path: str) -> None:
        import joblib
        joblib.dump(self._model, path)

    def load(self, path: str) -> None:
        import joblib
        self._model = joblib.load(path)
