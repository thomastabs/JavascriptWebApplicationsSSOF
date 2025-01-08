import json

from typing import Dict, Set

from Classes.Pattern import Pattern


class Policy:
    def __init__(self, patterns: Set[Pattern]) -> None:
        self.patterns = patterns

    def get_patterns(self) -> Set[Pattern]:
        return self.patterns

    def to_json(self) -> Dict:
        return {"patterns": [pattern.to_json() for pattern in self.patterns]}

    def __repr__(self) -> str:
        return json.dumps(self.to_json(), indent=2)
