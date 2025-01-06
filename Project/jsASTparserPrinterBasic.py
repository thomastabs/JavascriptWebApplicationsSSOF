import esprima

# Example program to parse
program = '''
var pos = document.URL.indexOf("name=");
var name = document.URL.substring(pos + 5);
document.write(name);
'''

def traverse_ast(node, indent_level=0):
    # Create an indentation string based on the level
    indent = '  ' * indent_level

    # Check if the node is a dictionary (it should be)
    if isinstance(node, dict) and 'type' in node:
        # Get the node type and line number (default to "Unknown" if not found)
        node_type = node.get('type', 'Unknown')
        # Access the 'loc' field to get line number, default to "Unknown"
        line = node.get('loc', {}).get('start', {}).get('line', 'Unknown')

        # Print node type and line number with indentation
        print(f"{indent}Node Type: {node_type}, Line: {line}")

        # Recursively traverse any child nodes
        for key, value in node.items():
            if isinstance(value, (dict, list)):  # Recurse into dictionaries and lists
                traverse_ast(value, indent_level + 1)

    # If the node is a list, traverse each element
    elif isinstance(node, list):
        for child in node:
            traverse_ast(child, indent_level + 1)


# Example usage with the provided ast_dict
ast_dict = esprima.parseScript(program, loc=True).toDict()

# Call the function to traverse and print the nodes with indentation
traverse_ast(ast_dict)
