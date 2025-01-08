from Classes.Policy import Policy
from Classes.Pattern import Pattern
from Classes.MultiLabelling import MultiLabelling
from Classes.Vulnerabilities import Vulnerabilities
from Classes.ASTProcessor import ASTProcessor
import esprima
import sys
import json
import os

# Usage: python js_analyzer.py <path_to_program.js> <path_to_patterns.json>

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
                    vulnerability=p["vulnerability"],
                    sources=set(p["sources"]),
                    sanitizers=set(p["sanitizers"]),
                    sinks=set(p["sinks"]),
                    implicit=p["implicit"] == "yes",
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

    print(policy)

    # Process the AST
    try:
        ast_processor = ASTProcessor(policy, multilabelling, vulnerabilities)
        ast_processor.traverse_ast(ast_dict)
        #ast_processor.traverse_ast_printer(ast_dict)
    except Exception as e:
        print(f"Error processing AST: {e}", file=sys.stderr)
        sys.exit(1)

    # Save the output
    try:
        ast_processor.save_vulnerabilities_to_file(output_path)
        print(f"Vulnerabilities saved to {output_path}")
    except Exception as e:
        print(f"Error saving output: {e}", file=sys.stderr)
        sys.exit(1)

if __name__ == "__main__":
    main()
