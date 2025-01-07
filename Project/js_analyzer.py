import esprima
import sys
import json
from Classes.Policy import Policy
from Classes.Pattern import Pattern
from Classes.MultiLabelling import MultiLabelling
from Classes.Vulnerabilities import Vulnerabilities
from Classes.MultiLabel import MultiLabel

# Usage: python js_analyzer.py <path_to_program.js> <path_to_patterns.json>

if __name__ == "__main__":
    if len(sys.argv) != 3:
        print(
            "Usage: python3 py-analyser.py <slice>.py <pattern>.json", file=sys.stderr
        )
        sys.exit(1)

    slice_path = sys.argv[1]
    pattern_path = sys.argv[2]

    SLICE_NAME = slice_path.split("/")[-1].split(".")[0]

     # Read Python slice and generate ast
    tree = None
    try:
        with open(slice_path, "r") as f:
            slice = f.read()
            ast = esprima.parseScript(slice, loc=True).toDict()
    except FileNotFoundError:
        print("Slice file not found", file=sys.stderr)
        sys.exit(1)

    # Read patterns and create policy
    policy = None
    try:
        with open(pattern_path, "r") as f:
            patterns_json = json.load(f)
            patterns = set()
            for pattern in patterns_json:
                patterns.add(Pattern.from_json(pattern))
            policy = Policy(patterns)
    except FileNotFoundError:
        print("Pattern file not found", file=sys.stderr)
        sys.exit(1)

        