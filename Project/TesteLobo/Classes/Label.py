
from copy import deepcopy
import json

from typing import Dict, Set, Tuple
from Classes.Flow import Flow

class Label:
    """
    Represents the integrity of information that is carried by a resource.

    Captures the sources that might have influenced a certain piece of
    information, and which sanitizers might have intercepted the information
    since its flow from each source.
    """

    def __init__(self) -> None:
        self.sources: Set[Tuple[str, int]] = set()
        self.flows: Dict[str, Set[Flow]] = dict()


    def get_sources(self) -> Set[Tuple[str, int]]:
        return self.sources

    def add_source(self, source: str, lineno: int):
        print(f"Adding source: {source} at line {lineno}")
        if source in self.sources:
            print(f"Warning: Source '{source}' already exists in the label.")
            return
        self.sources.add((source, lineno))
        if source not in self.flows:
            flow = Flow()
            self.flows[source] = {flow}

    def get_flows_from_source(self, source: str) -> Set[Flow]:
        if source not in self.flows:
            return set()
        return self.flows[source]

    def add_sanitizer(self, sanitizer: str, lineno: int, source: str) -> None:
        if source not in self.flows:
            flow = Flow()
            self.flows[source] = {flow}

        for flow in self.flows[source]:
            flow.add_sanitizer(sanitizer, lineno)

    def combine(self, other: "Label") -> "Label":
        combined_sources = self.sources.union(other.sources)
        combined_flows = {}

        for source, _ in combined_sources:
            self_flows = deepcopy(self.get_flows_from_source(source))
            other_flows = deepcopy(other.get_flows_from_source(source))
            combined_flows[source] = self_flows.union(other_flows)

        label = Label()
        label.sources = combined_sources
        label.flows = combined_flows

        return label

    def to_json(self) -> Dict:
        return {
            "sources": [source for source in self.sources],
            "flows": {
                source: [flow.to_json() for flow in self.flows[source]]
                for source in self.flows
            },
        }

    def __repr__(self) -> str:
        return json.dumps(self.to_json(), indent=2)

    def __eq__(self, other) -> bool:
        return self.sources == other.sources and self.flows == other.flows
