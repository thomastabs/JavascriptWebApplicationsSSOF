import esprima
import sys
import json
import os

from Classes.Pattern import Pattern
from Classes.Vulnerabilities import Vulnerabilities
from Classes.MultiLabelling import MultiLabelling
from Classes.Policy import Policy
from Classes.ASTProcessor import ASTProcessor
       

def main():
    if len(sys.argv) != 3:
        print(
            "Usage: python3 js_analyzer.py <slice>.js <patterns>.json", file=sys.stderr
        )
        sys.exit(1)

    slice_path = sys.argv[1]
    pattern_path = sys.argv[2]

    # Extract the name of the slice for output file naming
    SLICE_NAME = os.path.basename(slice_path).split(".")[0]
    output_dir = "./output"
    output_path = os.path.join(output_dir, f"{SLICE_NAME}.output.json")

    # Ensure the output directory exists
    os.makedirs(output_dir, exist_ok=True)

    # Read JavaScript slice and generate AST
    try:
        with open(slice_path, "r") as f:
            slice_code = f.read()
            ast_dict = esprima.parseScript(slice_code, loc=True).toDict()
    except FileNotFoundError:
        print(f"Error: Slice file '{slice_path}' not found.", file=sys.stderr)
        sys.exit(1)
    except Exception as e:
        print(f"Error parsing slice file: {e}", file=sys.stderr)
        sys.exit(1)

    # Read patterns and create a Policy object
    try:
        with open(pattern_path, "r") as f:
            patterns_json = json.load(f)
            pattern_objects = [
                Pattern(
                    name=p["vulnerability"],
                    sources=set(p["sources"]),
                    sanitizers=set(p["sanitizers"]),
                    sinks=set(p["sinks"]),
                )
                for p in patterns_json
            ]
            policy = Policy(pattern_objects)
    except FileNotFoundError:
        print(f"Error: Pattern file '{pattern_path}' not found.", file=sys.stderr)
        sys.exit(1)
    except json.JSONDecodeError:
        print(f"Error: Failed to parse the JSON pattern file '{pattern_path}'.", file=sys.stderr)
        sys.exit(1)
    except Exception as e:
        print(f"Error processing pattern file: {e}", file=sys.stderr)
        sys.exit(1)

    # Initialize MultiLabelling and Vulnerabilities
    multilabelling = MultiLabelling()
    vulnerabilities = Vulnerabilities(policy)
    multilabelling = MultiLabelling({})

    ast_processor = ASTProcessor(policy, multilabelling, vulnerabilities)
    ast_processor.traverse_ast(ast_dict)
        
    # Get illegal flows    
    illegal_flows = set()  
    for illegal_flow in vulnerabilities.get_illegal_flows():
        illegal_flows.add(illegal_flow)
    illegal_flows = list(illegal_flows)
        
    # Transform illegal flows to JSON
    for i in range(len(illegal_flows)):
        illegal_flows[i] = illegal_flows[i].to_json()

    # Write illegal flows to output file
    if not os.path.exists("output"):
        os.makedirs("output")
    with open(output_path, "w") as f:
        f.write(json.dumps(illegal_flows, indent=4) + "\n")

if __name__ == "__main__":
    main()
