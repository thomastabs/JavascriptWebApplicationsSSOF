import json

from typing import Dict, Set

from Classes.Label import Label
from Classes.Pattern import Pattern


class MultiLabel:
    """
    Generalizes the Label class in order to be able to represent distinct labels
    corresponding to different patterns.
    """

    def __init__(self, patterns: Set[Pattern]) -> None:
        self.patterns = patterns
        self.mapping = {pattern: Label() for pattern in patterns}

    def get_patterns(self) -> Set[Pattern]:
        return set(self.mapping.keys())

    def get_label(self, pattern: Pattern) -> Label:
        if pattern not in self.mapping:
            return Label()
        return self.mapping[pattern]

    def add_label(self, label: Label, pattern: Pattern) -> None:
        self.mapping[pattern] = label
    
    def combine(self, other: "MultiLabel") -> "MultiLabel":       
        multilabel = MultiLabel(self.patterns)
        for pattern in self.patterns:
            other_label = other.get_label(pattern)
            self_label = self.get_label(pattern)
            combined_label = other_label.combine(self_label)
            multilabel.add_label(combined_label, pattern)

        return multilabel

    def to_json(self) -> Dict:
        return {
            "mapping": [
                (pattern.to_json(), label.to_json())
                for pattern, label in self.mapping.items()
            ]
        }

    def __repr__(self) -> str:
        return json.dumps(self.to_json(), indent=2)
