import json
from typing import List, Dict, Set

class Pattern:
    """
    Represents a vulnerability pattern with its components: sources, sanitizers, sinks and implicit flows.
    """

    def __init__(self, name: str, sources: Set[str], sanitizers: Set[str], sinks: Set[str], implicit: bool):
        """
        Constructor for the Pattern object.

        :param name: The name of the vulnerability pattern (str).
        :param sources: A list of possible source names (list of str).
        :param sanitizers: A list of possible sanitizer names (list of str).
        :param sinks: A list of possible sink names (list of str).
        :param implicit: A boolean flag indicating if the pattern is implicit (bool).
        """
        self.name = name # Name of the Vulnerability Pattern
        self.sources = sources  # Use sets for faster lookup
        self.sanitizers = sanitizers # Use sets for faster lookup
        self.sinks = sinks # Use sets for faster lookup
        self.implicit = implicit # Flag for implicit 

    def get_name(self):
        return self.name

    def get_sources(self):
        return list(self.sources)

    def get_sanitizers(self):
        return list(self.sanitizers)

    def get_sinks(self):
        return list(self.sinks)
    
    def get_implicit(self):
        return self.implicit

    def is_source(self, name):
        return name in self.sources

    def is_sanitizer(self, name):
        return name in self.sanitizers

    def is_sink(self, name):
        return name in self.sinks
    

    @classmethod
    def from_json(cls, json_data):
        name = json_data["name"]
        sources =  {source for source in json_data["sources"]}
        sinks = {sink for sink in json_data["sinks"]}
        sanitizers = {sanitizer for sanitizer in json_data.get("sanitizers", [])}
        implicit = json_data.get("implicit", False)

        return cls(name, sources, sanitizers, sinks, implicit)
    
    def to_json(self):
        return {
            "vulnerability": self.name,
            "source": self.get_sources(),
            "sinks": self.get_sinks(),
            "sanitizers": self.get_sanitizers(),
            "implicit": self.implicit
        }
    
    def __repr__(self):
        return json.dumps(self.to_json(), indent=2)
    