import json
from typing import List, Tuple, Dict, Optional


class Flow:
    """
    Represents a flow with associated sanitizers and their line numbers.
    """

    def __init__(self, flow=None) -> None:
        if flow is None:
            flow = []
        self.flow: List[Tuple[str, int]] = flow

    def add_sanitizer(self, sanitizer: str, lineno: int) -> None:
        if (sanitizer, lineno) not in self.flow:
            self.flow.append((sanitizer, lineno))

    def is_empty(self) -> bool:
        return not self.flow

    def to_json(self) -> "Flow":
        return self.flow

    def __repr__(self) -> str:
        return json.dumps(self.to_json(), indent=2)

    def __eq__(self, other) -> bool:
        if isinstance(other, Flow):
            return sorted(self.flow) == sorted(other.flow)
        return False

    def __hash__(self):
        return 0


class IllegalFlow:
    '''
    Represents a flow that violates a security policy.
    '''
    
    def __init__(
        self,
        vulnerability: str,
        source: str,
        source_lineno: int,
        sink: str,
        sink_lineno: int,
        unsanitized_flows: bool,
        sanitized_flows: List[Flow],
        implicit_flow: bool = False,
    ) -> None:
        self.vulnerability = vulnerability
        self.source = source
        self.source_lineno = source_lineno
        self.sink = sink
        self.sink_lineno = sink_lineno
        self.unsanitized_flows = unsanitized_flows
        self.sanitized_flows = sanitized_flows
        self.implicit_flow = implicit_flow

    
    def is_combinable(self, other: "IllegalFlow") -> bool:
        return (
            self.vulnerability == other.vulnerability
            and self.source == other.source
            and self.source_lineno == other.source_lineno
            and self.sink == other.sink
            and self.sink_lineno == other.sink_lineno
        )

    def combine(self, other: "IllegalFlow") -> "IllegalFlow":
        if not self.is_combinable(other):
            raise ValueError("IllegalFlows are not combinable.")
        combined_sanitized_flows = list(set(self.sanitized_flows + other.sanitized_flows))
        return IllegalFlow(
            self.vulnerability,
            self.source,
            self.source_lineno,
            self.sink,
            self.sink_lineno,
            self.unsanitized_flows or other.unsanitized_flows,
            combined_sanitized_flows,
            self.implicit_flow or other.implicit_flow,
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
        if isinstance(other, IllegalFlow):
            return (
                self.vulnerability == other.vulnerability
                and self.source == other.source
                and self.source_lineno == other.source_lineno
                and self.sink == other.sink
                and self.sink_lineno == other.sink_lineno
                and self.unsanitized_flows == other.unsanitized_flows
                and sorted(self.sanitized_flows) == sorted(other.sanitized_flows)
                and self.implicit_flow == other.implicit_flow
            )
        return False

    def __hash__(self):
        return 0