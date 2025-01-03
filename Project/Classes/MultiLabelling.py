from typing import Dict
from MultiLabel import MultiLabel
import json

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

    def to_json(self):
        return {
                    "mapping": [
                        (name, multilabel.to_json())
                        for name, multilabel in self.mapping.items()
                    ]
                }

    def __repr__(self) -> str:
        return json.dumps(self.to_json(), indent=2)

