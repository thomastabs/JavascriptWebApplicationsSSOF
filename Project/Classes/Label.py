import json

from typing import Dict, Set, Tuple

class Label:
    """
    Represents the integrity of information carried by a resource, capturing sources and sanitizers.
    """

    def __init__(self):
        """
        Constructor for a Label object.

        :param sources: A set of sources influencing the information (set of str).
        :param sanitizers: A dictionary mapping sources to sets of sanitizers intercepting flows (dict).
        """
        self.sources: Set[Tuple[str, int]] = set() # Initialize with an empty set of tuples (source, lineofcode)
        self.sanitizers: Dict[str, Set[str]] = dict()  # Initialize with an empty dictionary of sources to sanitizers
    
    def get_sources(self):
        return self.sources     
    
    def add_source(self, source, lineofcode):
        if source not in self.sources:
            self.sources.add([source, lineofcode])
            self.sanitizers[source] = set()  # Initialize with an empty sanitizer set

    def add_sanitizer(self, source, sanitizer):
        if source in self.sources:
            self.sanitizers[source].add(sanitizer)

    def get_sanitizers(self):
        return {src: sanitizers.copy() for src, sanitizers in self.sanitizers.items()}

    def combine(self, other):
        combined_sources = self.sources.union(other.sources)
        combined_sanitizers = {}

        for src in combined_sources:
            combined_sanitizers[src] = self.sanitizers.get(src, set()).union(
                other.sanitizers.get(src, set())
            )

        return Label(combined_sources, combined_sanitizers)

    def to_json(self):
        return {
            "sources": list(self.sources),
            "sanitizers": {src: list(sanitizers) for src, sanitizers in self.sanitizers.items()}
        }

    def __repr__(self) -> str:
        return json.dumps(self.to_json(), indent=2)

    def __eq__(self, other) -> bool:
        return self.sources == other.sources and self.flows == other.flows
