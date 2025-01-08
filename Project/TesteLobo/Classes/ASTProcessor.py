from Classes.MultiLabelling import MultiLabelling
from Classes.MultiLabel import MultiLabel
from Classes.Policy import Policy
from Classes.Vulnerabilities import Vulnerabilities
from Classes.Pattern import Pattern
from Classes.Label import Label
from Classes.Variable import Variable
from Classes.IllegalFlow import IllegalFlow
from Classes.Flow import Flow

import json
import sys

class ASTProcessor:
    """
    Class to process an Abstract Syntax Tree (AST) for security analysis.
    """

    def __init__(self, policy: Policy, multilabelling: MultiLabelling, vulnerabilities: Vulnerabilities):
        """
        Initialize the AST Processor with the policy, multilabelling, and vulnerabilities objects.
        """
        self.policy = policy
        self.multilabelling = multilabelling
        self.vulnerabilities = vulnerabilities


    def process_expression_node(self, node) -> MultiLabel:
        """
        Processes an AST expression node, updates multilabelling, and checks for vulnerabilities.

        :param node: AST node representing an expression.
        :return: A Label describing the information flow for the given expression.
        """
        if node['type'] == 'Identifier':
            return self.multilabelling.get_multi_label(node['name'])
        
        elif node['type'] == 'Literal':
            return MultiLabel()

        elif node['type'] == 'BinaryExpression':
            left_label = self.process_expression_node(node['left'])
            right_label = self.process_expression_node(node['right'])
            return left_label.combine(right_label)

        elif node['type'] == 'CallExpression':
            callee = node['callee']
            args = node['arguments']

            combined_multi_label = MultiLabel()
            for arg in args:
                combined_multi_label = combined_multi_label.combine(self.process_expression_node(arg))

            if callee['type'] == 'Identifier':
                function_name = callee['name']
                # Add the source to the MultiLabel
                for pattern in self.policy.get_patterns():
                    if pattern.has_source(function_name):
                        label = Label()
                        label.add_source(function_name, node['loc']['start']['line'])
                        combined_multi_label.add_label(label, pattern)

                    if pattern.has_sink(function_name):
                        print(f"Sink matched: {function_name}")
                        for source, _ in combined_multi_label.get_label(pattern).get_sources():
                            print(f"Checking source: {source}")
                            if pattern.has_source(source):
                                unsanitized = not any(
                                    sanitizer in pattern.sanitizers
                                    for sanitizer in combined_multi_label.get_label(pattern).get_flows_from_source(source)
                                )
                                print(f"Source {source} unsanitized: {unsanitized}")
                                if unsanitized:
                                    illegal_flow = IllegalFlow(
                                        pattern.get_vulnerability(),
                                        source,
                                        node['loc']['start']['line'],
                                        function_name,
                                        node['loc']['end']['line'],
                                        unsanitized,
                                        list(combined_multi_label.get_label(pattern).get_flows_from_source(source))
                                    )
                                    self.vulnerabilities.add_illegal_flow(illegal_flow)

            return combined_multi_label


        elif node['type'] == 'UnaryExpression':
            return self.process_expression_node(node['argument'])

        elif node['type'] == 'MemberExpression':
            object_label = self.process_expression_node(node['object'])
            property_label = self.process_expression_node(node['property'])
            return object_label.combine(property_label)

        elif node['type'] == 'AssignmentExpression':
            variable = node['left']['name']
            value_label = self.process_expression_node(node['right'])
            print(f"Assigning label to {variable}: {value_label}")
            self.multilabelling.add_multi_label(value_label, variable)

        else:
            return MultiLabel()


    '''
    def process_statement_node(self, node):
        """
        Processes an AST statement node, updates multilabelling, and checks for vulnerabilities.

        :param node: AST node representing a statement.
        """
        if node['type'] == 'ExpressionStatement':
            self.process_expression_node(node['expression'])

        elif node['type'] == 'VariableDeclaration':
            for declaration in node['declarations']:
                variable = Variable(declaration['id']['name'])
                init_label = self.process_expression_node(declaration['init'])
                self.multilabelling.add_multi_label(MultiLabel({self.policy: init_label}), variable)

        elif node['type'] == 'IfStatement':
            self.process_expression_node(node['test'])
            self.traverse_ast(node['consequent'])
            if 'alternate' in node and node['alternate']:
                self.traverse_ast(node['alternate'])

        elif node['type'] == 'BlockStatement':
            self.traverse_ast(node)
    '''
            
    def traverse_ast(self, ast):
        for stmt in ast['body']:
            print(f"Processing statement: {stmt}")
            if stmt['type'] == 'ExpressionStatement':
                self.process_expression_node(stmt['expression'])


    def traverse_ast_printer(self, node, indent_level=0):
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
                    self.traverse_ast_printer(value, indent_level + 1)

        # If the node is a list, traverse each element
        elif isinstance(node, list):
            for child in node:
                self.traverse_ast_printer(child, indent_level + 1)


    def save_vulnerabilities_to_file(self, file_path: str):
        try:
            serialized_vulnerabilities = self.vulnerabilities.to_json()
            print(f"Serialized Vulnerabilities: {json.dumps(serialized_vulnerabilities, indent=4)}")
            with open(file_path, 'w') as f:
                json.dump(serialized_vulnerabilities, f, indent=4)
            print(f"Vulnerabilities saved to {file_path}")
        except Exception as e:
            print(f"Error saving vulnerabilities to file: {e}", file=sys.stderr)
            sys.exit(1)
