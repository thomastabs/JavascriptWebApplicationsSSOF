from typing import Dict
from typing import Set
from Classes.MultiLabel import MultiLabel
from Classes.Pattern import Pattern
import Classes.Policy as policy
import json
import copy

class MultiLabelling:
    """
    Represents a mapping from variable names to MultiLabel objects.
    """

    def __init__(self) -> None:
        self.mapping: Dict[str, MultiLabel] = {}

    def get_multilabel(self, var_name: str) -> MultiLabel:
        if not self.has_multi_label(var_name):
            return MultiLabel()
        return self.mapping[var_name]
    
    def get_multilabels(self) -> Set[MultiLabel]:
        return set(self.mapping.values())
    
    def get_patterns(self) -> Set[Pattern]:
        return set.union(
            *[multi_label.get_patterns() for multi_label in self.get_multilabels()]
        )
    
    def has_multi_label(self, var_name: str) -> bool:
        return var_name in self.mapping

    def update_multilabel(self, var_name: str, multilabel: MultiLabel) -> None:
        self.mapping[var_name] = multilabel

    def deep_copy(self) -> "MultiLabelling":
        new_instance = MultiLabelling()
        new_instance.mapping = {name: copy.deepcopy(multilabel) for name, multilabel in self.mapping.items()}
        return new_instance

    def combine(self, other: "MultiLabel") -> "MultiLabel":
        combined_mapping = {}
        patterns = self.get_patterns().union(other.get_patterns())
        for pattern in patterns:
            combined_label = self.get_label(pattern).combine(other.get_label(pattern))
            combined_mapping[pattern] = combined_label
        combined = MultiLabel(combined_mapping)
        print(f"Result of Combination: {combined.mapping}")
        return combined

    
    def to_json(self):
        return {
            "mapping": [
                (name, multilabel.to_json())
                for name, multilabel in self.mapping.items()
            ]
        }

    def __repr__(self) -> str:
        return json.dumps(self.to_json(), indent=2)
