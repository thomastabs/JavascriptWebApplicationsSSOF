import json

from typing import Dict, Set

from Classes.MultiLabel import MultiLabel
from Classes.MultiLabelling import MultiLabelling
from Classes.Pattern import Pattern
from Classes.Policy import Policy
from Classes.FlowProcessor import IllegalFlow


class Vulnerabilities:
    """
    Collects all the illegal information flows discovered during the execution
    of the slice.
    """

    def __init__(self, policy: Policy) -> None:
        self.policy = policy
        self.multilabelling = MultiLabelling()
        self.illegal_flows: Set[IllegalFlow] = set()

    def get_patterns(self) -> Set[Pattern]:
        return self.policy.get_patterns()

    def has_multi_label(self, variable: str) -> bool:
        return self.multilabelling.has_multi_label(variable)

    def get_multi_label(self, variable: str) -> MultiLabel:
        return self.multilabelling.get_multi_label(variable)

    def add_multi_label(self, label: MultiLabel, variable: str) -> None:
        self.multilabelling.add_multi_label(label, variable)

    def add_illegal_flow(self, illegal_flow: IllegalFlow) -> None:
        self.illegal_flows.add(illegal_flow)

    def get_illegal_flows(self) -> Set[IllegalFlow]:
        return self.illegal_flows

    def to_json(self) -> Dict:
        return {
            "policy": self.policy.to_json(),
            "multilabelling": self.multilabelling.to_json(),
            "illegal_flows": [
                illegal_flow.to_json() for illegal_flow in self.illegal_flows
            ],
        }

    def __repr__(self) -> str:
        return json.dumps(self.to_json(), indent=2)
