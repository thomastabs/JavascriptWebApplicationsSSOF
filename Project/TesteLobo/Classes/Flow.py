import json

from typing import List, Tuple, Dict

from Classes.Sanitizer import Sanitizer


class Flow:
    def __init__(self, flow=None) -> None:
        if flow is None:
            flow = []
        self.flow: List[Tuple[Sanitizer, int]] = flow

    def add_sanitizer(self, sanitizer: Sanitizer, lineno: int) -> None:
        if (sanitizer, lineno) not in self.flow:
            self.flow.append((sanitizer, lineno))

    def is_empty(self) -> bool:
        return len(self.flow) == 0

    def to_json(self) -> List[Dict]:
        print(f"Serializing Flow: {self.flow}")
        return [{"sanitizer": sanitizer, "line": lineno} for sanitizer, lineno in self.flow]

    def __repr__(self) -> str:
        return json.dumps(self.to_json(), indent=2)

    def __eq__(self, other) -> bool:
        if not isinstance(other, Flow):
            return False

        if len(self.flow) != len(other.flow):
            return False

        for i in range(len(self.flow)):
            if self.flow[i] != other.flow[i]:
                return False

        return True

    def __hash__(self) -> int:
        # TODO: performs badly
        return 0
