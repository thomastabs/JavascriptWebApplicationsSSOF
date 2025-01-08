import json

from typing import Dict, Set

from Classes.Sanitizer import Sanitizer
from Classes.Sink import Sink
from Classes.Source import Source
from Classes.Vulnerability import Vulnerability


class Pattern:
    def __init__(
        self,
        vulnerability: Vulnerability,
        sources: Set[Source],
        sanitizers: Set[Sanitizer],
        sinks: Set[Sink],
        implicit: bool,
    ) -> None:
        self.vulnerability = vulnerability
        self.sources = sources
        self.sanitizers = sanitizers
        self.sinks = sinks
        self.implicit = implicit

    def get_vulnerability(self) -> Vulnerability:
        return self.vulnerability

    def get_sources(self) -> Set[Source]:
        return self.sources

    def has_source(self, source: Source) -> bool:
        return source in self.sources

    def has_sanitizer(self, sanitizer: Sanitizer) -> bool:
        return sanitizer in self.sanitizers

    def has_sink(self, sink: Sink) -> bool:
        return sink in self.sinks

    def consider_implicit(self) -> bool:
        return self.implicit

    @classmethod
    def from_json(cls, json_data) -> "Pattern":
        vulnerability = Vulnerability(json_data["vulnerability"])
        sources = {Source(source) for source in json_data["sources"]}
        sinks = {Sink(sink) for sink in json_data["sinks"]}
        sanitizers = {
            Sanitizer(sanitizer) for sanitizer in json_data.get("sanitizers", [])
        }
        implicit = json_data.get("implicit", False)

        return cls(vulnerability, sources, sanitizers, sinks, implicit)

    def to_json(self) -> Dict:
        return {
            "vulnerability": self.vulnerability,
            "sources": [source for source in self.sources],
            "sanitizers": [sanitizer for sanitizer in self.sanitizers],
            "sinks": [sink for sink in self.sinks],
            "implicit": self.implicit,
        }

    def __repr__(self) -> str:
        return json.dumps(self.to_json(), indent=2)
