import json

from typing import Dict, List
from Classes.Flow import Flow


class IllegalFlow:
    def __init__(
        self,
        vulnerability: str,
        source: str,
        source_lineno: int,
        sink: str,
        sink_lineno: int,
        unsanitized_flows: bool,
        sanitized_flows: List[Flow],
        implicit_flow: bool = False
    ) -> None:
        self.vulnerability = vulnerability
        self.source = source
        self.source_lineno = source_lineno
        self.sink = sink
        self.sink_lineno = sink_lineno
        self.unsanitized_flows = unsanitized_flows
        self.sanitized_flows = sanitized_flows
        self.implicit_flow = implicit_flow

    def get_vulnerability(self) -> str:
        return self.vulnerability

    def is_combinable(self, other) -> bool:
        return (
            self.vulnerability == other.vulnerability
            and self.source == other.source
            and self.source_lineno == other.source_lineno
            and self.sink == other.sink
            and self.sink_lineno == other.sink_lineno
        )

    def combine(self, other) -> "IllegalFlow":
        assert self.is_combinable(other)
        return IllegalFlow(
            self.vulnerability,
            self.source,
            self.source_lineno,
            self.sink,
            self.sink_lineno,
            self.unsanitized_flows or other.unsanitized_flows,
            list(set(self.sanitized_flows + other.sanitized_flows)),
        )

    def to_json(self) -> Dict:
        return {
            "vulnerability": str(self.vulnerability),
            "source": [str(self.source), self.source_lineno],
            "sink": [str(self.sink), self.sink_lineno],
            "unsanitized_flows": "yes" if self.unsanitized_flows else "no",
            "sanitized_flows": list(
                map(
                    lambda flow: flow.to_json(),
                    filter(lambda flow: not flow.is_empty(), self.sanitized_flows),
                )
            ),
            "implicit": "yes" if self.implicit_flow else "no",
        }

    def __repr__(self) -> str:
        return json.dumps(self.to_json())

    def __eq__(self, other) -> bool:
        if len(self.sanitized_flows) != len(other.sanitized_flows):
            return False

        for i in range(len(self.sanitized_flows)):
            if self.sanitized_flows[i] != other.sanitized_flows[i]:
                return False

        return (
            self.vulnerability == other.vulnerability
            and self.source == other.source
            and self.source_lineno == other.source_lineno
            and self.sink == other.sink
            and self.sink_lineno == other.sink_lineno
            and self.unsanitized_flows == other.unsanitized_flows
        )

    def __hash__(self) -> int:
        return 0
