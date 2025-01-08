import json

from typing import Dict, Set

from Classes.MultiLabel import MultiLabel
from Classes.MultiLabelling import MultiLabelling
from Classes.Pattern import Pattern
from Classes.Policy import Policy
from Classes.Sink import Sink
from Classes.Variable import Variable
from Classes.IllegalFlow import IllegalFlow


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

    def has_multi_label(self, variable: Variable) -> bool:
        return self.multilabelling.has_multi_label(variable)

    def get_multi_label(self, variable: Variable) -> MultiLabel:
        return self.multilabelling.get_multi_label(variable)

    def add_multi_label(self, label: MultiLabel, variable: Variable) -> None:
        self.multilabelling.add_multi_label(label, variable)

    def add_illegal_flow(self, illegal_flow: IllegalFlow) -> None:
        print(f"Adding illegal flow: {illegal_flow}")
        self.illegal_flows.add(illegal_flow)

    def get_illegal_flows(self) -> Set[IllegalFlow]:
        return self.illegal_flows

    def to_json(self):
        return [
            {
                "vulnerability": flow.vulnerability,
                "source": [flow.source, flow.source_lineno],
                "sink": [flow.sink, flow.sink_lineno],
                "unsanitized_flows": "yes" if flow.unsanitized_flows else "no",
                "sanitized_flows": [
                    [sanitizer, lineno] for sanitizer, lineno in flow.sanitized_flows
                ],
                "implicit": "yes" if flow.implicit else "no"
            }
            for flow in self.illegal_flows
        ]


    def __repr__(self) -> str:
        return json.dumps(self.to_json(), indent=2)
