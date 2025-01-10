import json

from typing import Dict, Set

from Classes.MultiLabel import MultiLabel
from Classes.Pattern import Pattern
import copy


class MultiLabelling:
    """
    Maps variables to multilabels.
    """

    def __init__(self, mapping = None):
        if mapping is not None:
            mapping = {}
        self.mapping = {}

    def has_multi_label(self, name: str) -> bool:
        return name in self.mapping

    def get_multilabel(self, var_name):
        if not self.has_multi_label(var_name):
            return MultiLabel()
        return self.mapping.get(var_name, MultiLabel())

    def get_multilabels(self) -> Set[MultiLabel]:
        return set(self.mapping.values())
    
    def add_multilabel(self, var_name, multilabel):
        self.mapping[var_name] = multilabel

    def update_multilabel(self, var_name, multilabel):
        print(f"Updating multilabel for '{var_name}' with: {multilabel}")
        self.mapping[var_name] = multilabel
    
    def deep_copy(self):
        return copy.deepcopy(self)

    def combine(self, other: "MultiLabelling") -> "MultiLabelling":
        new_multilabelling = self.deep_copy()
        print(f"Combining multilabels: {self.mapping} and {other.mapping}")
        for var_name, multilabel in other.mapping.items():
            if var_name in new_multilabelling.mapping:
                new_label = new_multilabelling.mapping[var_name].combine(multilabel)
                print(f"Combined label for '{var_name}': {new_label}")
                new_multilabelling.mapping[var_name] = new_label
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
