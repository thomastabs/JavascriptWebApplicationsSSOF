from Classes.Policy import Policy
from Classes.Pattern import Pattern
from Classes.MultiLabelling import MultiLabelling
from Classes.Vulnerabilities import Vulnerabilities
from Classes.MultiLabel import MultiLabel
from Classes.ASTProcessor import ASTProcessor
import esprima
import sys
import json


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

    # Read Javascript slice and generate ast
    tree = None
    try:
        with open(slice_path, "r") as f:
            slice = f.read()
            ast_dict = esprima.parseScript(slice, loc=True).toDict()
    except FileNotFoundError:
        print("Slice file not found", file=sys.stderr)
        sys.exit(1)

    # Read patterns and create policy
    policy = None
    try:
        with open(pattern_path, "r") as f:
            patterns_json = json.load(f)
            
            # Convert patterns from dicts to Pattern objects
            pattern_objects = []
            for p in patterns_json:
                pattern_objects.append(Pattern(
                    name=p["vulnerability"],
                    sources=set(p["sources"]),
                    sanitizers=set(p["sanitizers"]),
                    sinks=set(p["sinks"]),
                    implicit=p["implicit"] == "yes"
                ))
            policy = Policy(pattern_objects)
    except FileNotFoundError:
        print("Pattern file not found", file=sys.stderr)
        sys.exit(1)

    '''
    # Debugging: Check patterns and their attributes
    print("Patterns Loaded:")
    for pattern in pattern_objects:
        print(f"Pattern: {pattern.name}, Sources: {pattern.sources}, Sinks: {pattern.sinks}")

    print("\n")

    # Debugging: Check patterns and their attributes
    print("Policy Loaded:")
    for pattern in policy.patterns.values():
        print(f"Pattern: {pattern.name}, Sources: {pattern.sources}, Sinks: {pattern.sinks}")
 

    print("AST:")
    ast_json = json.dumps(ast_dict, indent=2)
    print(ast_json)
    '''   
    
    # Process the AST
    multilabelling = MultiLabelling()
    vulnerabilities = Vulnerabilities(policy)

    ast_processor = ASTProcessor(policy, multilabelling, vulnerabilities)
    #ast_processor.traverse_ast(ast_dict)
    ast_processor.traverse_ast_debug(ast_dict)

    # Default Multilabel Initialization
    print("Initializing default labels for uninstantiated variables...")
    for var_name in ["c"]:  # Add other variable names if needed
        if not multilabelling.has_multi_label(var_name):
            default_label = MultiLabel()
            multilabelling.update_multilabel(var_name, default_label)
            print(f"Initialized MultiLabel for {var_name}")

    # Process AST
    for stmt in ast_dict['body']:
        if stmt['type'] == 'ExpressionStatement':
            ast_processor.process_expression_node(stmt['expression'])

    # Generate and save the output
    output_path = "./output/1a-basic-flow.output.json"  
    vulnerabilities.save_output_to_file(output_path)

    #print(f"Vulnerabilities saved to {output_path}")