from typing import Dict, List
from MultiLabel import MultiLabel
from Policy import Policy
import json

class Vulnerabilities:
    """
    Represents a collection of illegal flows discovered during the analysis of a program slice.
    Organizes detected illegal flows by vulnerability names.
    """

    def __init__(self, policy: Policy) -> None:
        self.illegal_flows: Dict[str, List[Dict]] = {}

    def report_illegal_flow(self, sink_name: str, multilabel: MultiLabel) -> None:
        for pattern, label in multilabel.mapping.items():
            # Check if the sink is part of the pattern
            if pattern.is_sink(sink_name):
                flow_info = {
                    "pattern": pattern.get_name(),
                    "sources": label.get_sources(),
                    "sanitizers": {
                        source: list(sanitizers)
                        for source, sanitizers in label.get_sanitizers().items()
                    },
                }
                if sink_name not in self.illegal_flows:
                    self.illegal_flows[sink_name] = []
                self.illegal_flows[sink_name].append(flow_info)

    def get_vulnerabilities(self) -> Dict[str, List[Dict]]:
        return self.illegal_flows

    def to_json(self) -> Dict:
        return {
            sink: [
                {
                    "pattern": flow["pattern"],
                    "sources": list(flow["sources"]),
                    "sanitizers": flow["sanitizers"],
                }
                for flow in flows
            ]
            for sink, flows in self.illegal_flows.items()
        }

    def __repr__(self) -> str:
        return json.dumps(self.to_json(), indent=2)



