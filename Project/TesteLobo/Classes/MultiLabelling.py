import json

from typing import Dict, Set

from Classes.MultiLabel import MultiLabel
from Classes.Pattern import Pattern
from Classes.Policy import Policy
import copy


class MultiLabelling:
    """
    Maps variables to multilabels.
    """

    def __init__(self, mapping, policy: Policy) -> None:
        if mapping is not None:
            mapping = {}
        self.mapping = {}
        self.policy = policy

    def has_multi_label(self, name: str) -> bool:
        return name in self.mapping

    def get_multilabel(self, var_name):
        if not self.has_multi_label(var_name):
            return MultiLabel(self.policy.get_patterns())
        return self.mapping.get(var_name, MultiLabel(self.policy.get_patterns()))

    def get_multilabels(self) -> Set[MultiLabel]:
        return set(self.mapping.values())
    
    def add_multilabel(self, var_name, multilabel):
        self.mapping[var_name] = multilabel

    def update_multilabel(self, var_name, multilabel):
        self.mapping[var_name] = multilabel
    
    def deep_copy(self):
        return copy.deepcopy(self)

    def combine(self, other: "MultiLabelling") -> "MultiLabelling":
        new_multilabelling = self.deep_copy()
        for var_name, multilabel in other.mapping.items():
            if var_name in new_multilabelling.mapping:
                new_multilabelling.mapping[var_name] = new_multilabelling.mapping[var_name].combine(multilabel)
            else:
                new_multilabelling.mapping[var_name] = multilabel
        return new_multilabelling
    
    def to_json(self) -> Dict:
        return {
            "mapping": [
                (name, multilabel.to_json())
                for name, multilabel in self.mapping.items()
            ]
        }

    def __repr__(self) -> str:
        return json.dumps(self.to_json(), indent=2)
