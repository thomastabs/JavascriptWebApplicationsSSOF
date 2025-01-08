from typing import Dict, List
from Classes.MultiLabel import MultiLabel
from Classes.Policy import Policy
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

    def generate_output(self) -> list:
        output = []
        for sink, flows in self.illegal_flows.items():
            for flow in flows:
                sanitized_flows = [
                    [[sanitizer, line] for sanitizer, line in label.get_sanitizers().items()]
                    for label in flow.get('sanitizers', {}).values()
                ]
                sanitized_flows = sanitized_flows if sanitized_flows else "none"

                output.append({
                    "vulnerability": flow["pattern"],
                    "source": list(flow["sources"])[0],  # Assuming one source per flow
                    "sink": [sink, flow.get("line", "Unknown")],
                    "implicit_flows": "yes" if flow.get("implicit", False) else "no",
                    "unsanitized_flows": "yes" if not sanitized_flows else "no",
                    "sanitized_flows": sanitized_flows
                })
        return output

    def save_output_to_file(self, output_path: str):
        vulnerabilities_output = self.generate_output()
        with open(output_path, "w") as output_file:
            json.dump(vulnerabilities_output, output_file, indent=2)

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



