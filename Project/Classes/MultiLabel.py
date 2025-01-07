import json

from typing import Dict, Set
from Classes.Label import Label
from Classes.Pattern import Pattern


class MultiLabel:
    """
    Generalizes the Label class in order to be able to represent distinct labels
    corresponding to different patterns.
    """

    def __init__(self, mapping=None) -> None:
        if mapping is None:
            mapping = {}
        self.mapping = mapping

    def get_patterns(self) -> Set[Pattern]:
        return set(self.mapping.keys())

    def get_label(self, pattern: Pattern) -> Label:
        if pattern not in self.mapping:
            return Label()
        return self.mapping[pattern]

    def add_label(self, label: Label, pattern: Pattern) -> None:
        self.mapping[pattern] = label

    def combine(self, other: "MultiLabel") -> "MultiLabel":
        combined_mapping = {}
        patterns = self.get_patterns().union(other.get_patterns())
        for pattern in patterns:
            combined_mapping[pattern] = self.get_label(pattern).combine(other.get_label(pattern))
        combined = MultiLabel(combined_mapping)
        return combined

    def to_json(self) -> Dict:
        return {
            "mapping": [
                (pattern.to_json(), label.to_json())
                for pattern, label in self.mapping.items()
            ]
        }

    def __repr__(self) -> str:
        return json.dumps(self.to_json(), indent=2)