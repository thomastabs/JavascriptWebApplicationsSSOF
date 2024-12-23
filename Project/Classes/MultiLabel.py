from .Label import Label
from .Pattern import Pattern

from typing import Dict, List

class MultiLabel:
    """
    Generalized Label class to represent distinct labels corresponding to different patterns.
    Each pattern has a corresponding Label object to track sources and sanitizers.
    """

    def __init__(self, mapping=None) -> None:
        if mapping is None:
            mapping = {}
        self.mapping = mapping

    def get_label(self, pattern: Pattern):
        if pattern not in self.mapping:
            return Label()
        return self.mapping[pattern]

    def get_patterns(self):
        return set(self.mapping.keys())

    def add_label(self, label: Label, pattern: Pattern):
        self.mapping[pattern].append(label)

    def combine(self, other):
        combined_mapping = self.mapping.copy()
        patterns = self.get_patterns().union(other.get_patterns())

        for pattern in patterns:
            label = self.get_label(pattern).combine(other.get_label(pattern))
            combined_mapping[pattern] = label
            
        return MultiLabel(combined_mapping)
    
    def to_json(self):
        return {
            "mapping": [
                (pattern.to_json(), label.to_json())
                for pattern, label in self.mapping.items()
            ]
        }        