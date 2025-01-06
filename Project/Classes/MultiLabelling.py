from typing import Dict
from MultiLabel import MultiLabel
import json
import copy

class MultiLabelling:
    """
    Represents a mapping from variable names to MultiLabel objects.
    """

    def __init__(self) -> None:
        self.mapping: Dict[str, MultiLabel] = {}

    def get_multilabel(self, var_name: str) -> MultiLabel:
        return self.mapping.get(var_name, MultiLabel())

    def update_multilabel(self, var_name: str, multilabel: MultiLabel) -> None:
        self.mapping[var_name] = multilabel

    def deep_copy(self) -> "MultiLabelling":
        new_instance = MultiLabelling()
        new_instance.mapping = {name: copy.deepcopy(multilabel) for name, multilabel in self.mapping.items()}
        return new_instance

    def combinor(self, other: "MultiLabelling") -> "MultiLabelling":
        new_instance = MultiLabelling()

        # Combine keys from both mappings
        all_keys = set(self.mapping.keys()).union(set(other.mapping.keys()))

        for key in all_keys:
            # Get MultiLabel objects for the current key from both mappings
            self_label = self.get_multilabel(key)
            other_label = other.get_multilabel(key)

            # Combine the MultiLabel objects
            combined_label = self_label.combine_with(other_label)

            # Update the new mapping
            new_instance.update_multilabel(key, combined_label)

        return new_instance
    
    def to_json(self):
        return {
            "mapping": [
                (name, multilabel.to_json())
                for name, multilabel in self.mapping.items()
            ]
        }

    def __repr__(self) -> str:
        return json.dumps(self.to_json(), indent=2)
