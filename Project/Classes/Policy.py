from typing import List, Dict, Set
from Classes.MultiLabel import MultiLabel  
from Classes.Label import Label
from Classes.Pattern import Pattern
import json


class Policy:
    """
    Represents an information flow policy using a database of patterns to recognize illegal flows.
    """

    def __init__(self, patterns: List[Pattern]):
        self.patterns = {pattern.get_name(): pattern for pattern in patterns}

    def get_vulnerability_names(self) -> Set[str]:
        return set(self.patterns.keys())

    def get_sources(self, name) -> Set[str]:
        if name in self.patterns:
            return set(self.patterns[name].get_sources())
        return set()

    def get_sanitizers(self, name) -> Set[str]:
        if name in self.patterns:
            return set(self.patterns[name].get_sanitizers())
        return set()

    def get_sinks(self, name) -> Set[str]:
        if name in self.patterns:
            return set(self.patterns[name].get_sinks())
        return set()

    def detect_illegal_flows(self, sink_name, multilabel: MultiLabel) -> MultiLabel:
        print(f"Detecting flows for sink: {sink_name}, MultiLabel: {multilabel.mapping}")
    
        illegal_flows = {}

        for pattern_name, label in multilabel.mapping.items():
            pattern = self.patterns.get(pattern_name)
            if not pattern:
                continue

            # Check if the sink is in the pattern and if there's an illegal flow
            if pattern.is_sink(sink_name):
                illegal_sources = set()
                for source in label.get_sources():
                    if source in pattern.get_sources() and not label.get_sanitizers().get(source):
                        illegal_sources.add(source)

                if illegal_sources:
                    illegal_flows[pattern_name] = Label()
                    illegal_flows[pattern_name].sources = illegal_sources
                    illegal_flows[pattern_name].sanitizers = label.get_sanitizers()

        return MultiLabel(illegal_flows)

    def __repr__(self):
        return json.dumps(self.to_json(), indent=2)


