import ast
import json
import sys
from astexport import export

def main():
    file = sys.argv[1]
    with open(file, 'r') as f:
        file_str = f.read()

    # Parse AST
    tree = ast.parse(file_str)

    # Convert AST into dictionary
    ast_dictionary = export.export_dict(tree)

    # Convert dictionary into JSON
    ast_json = json.dumps(ast_dictionary, indent=2)

    print(ast_json)

    traverse(tree)

def traverse(node):
    try:
        print(f"({node.class.name}, {node.lineno})")
    except AttributeError:
        print(f"{node.class.name} has no lineno")
    for child in ast.iter_child_nodes(node):
        traverse(child)



if name == 'main':
    main()