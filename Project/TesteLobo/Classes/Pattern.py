import json

from typing import Dict, Set


class Pattern:
    def __init__(
        self,
        name: str,
        sources: Set[str],
        sanitizers: Set[str],
        sinks: Set[str]
    ) -> None:
        self.name = name
        self.sources = sources
        self.sanitizers = sanitizers
        self.sinks = sinks
        self.implicit = False

    def get_vulnerability(self) -> str:
        return self.name

    def get_sources(self) -> Set[str]:
        return self.sources
    
    def get_sanitizers(self) -> Set[str]:
        return self.sanitizers

    def has_source(self, source: str) -> bool:
        return source in self.sources

    def has_sanitizer(self, sanitizer: str) -> bool:
        return sanitizer in self.sanitizers

    def has_sink(self, sink: str) -> bool:
        return sink in self.sinks

    def consider_implicit(self) -> bool:
        return self.implicit

    def test_string(self, string):
        if string in self.sources:
            return "source"
        elif string in self.sanitizers:
            return "sanitizer"
        elif string in self.sinks:
            return "sink"
        else:
            return "none"

    def to_json(self) -> Dict:
        return {
            "vulnerability": self.name,
            "sources": [source for source in self.sources],
            "sanitizers": [sanitizer for sanitizer in self.sanitizers],
            "sinks": [sink for sink in self.sinks],
            "implicit": self.implicit
        }

    def __repr__(self) -> str:
        return json.dumps(self.to_json(), indent=2)
