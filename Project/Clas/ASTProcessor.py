from Classes.MultiLabelling import MultiLabelling
from Classes.MultiLabel import MultiLabel
from Classes.Policy import Policy
from Classes.Vulnerabilities import Vulnerabilities

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
        :return: A MultiLabel describing the information flow for the given expression.
        """
        if node['type'] == 'Identifier':
            return self.multilabelling.get_multilabel(node['name'])
        
        # Literals are considered secure by default (empty multilabel).
        elif node['type'] == 'Literal':
            return MultiLabel()

        elif node['type'] == 'BinaryExpression':
            left_label = self.process_expression_node(node['left'])
            right_label = self.process_expression_node(node['right'])
            return left_label.combine(right_label)
        
        elif node['type'] == 'CallExpression':
            # Process function calls.
            callee = node['callee']
            args = node['arguments']

            # Combine multilabels from all arguments.
            combined_args_label = MultiLabel()
            for arg in args:
                arg_label = self.process_expression_node(arg)
                combined_args_label = combined_args_label.combine(arg_label)

            # Check if the callee is a sink and validate flows.
            if callee['type'] == 'Identifier':
                function_name = callee['name']
                print(f"Processing function: {function_name}")
                for pattern_name in self.policy.get_vulnerability_names():
                    pattern = self.policy.patterns[pattern_name]

                    if pattern.is_sink(function_name):
                        # Check for unsanitized flows to the sink.
                        print(f"Detected sink: {function_name}")
                        illegal_flows = self.policy.detect_illegal_flows(function_name, combined_args_label)
                        if illegal_flows.mapping:
                            self.vulnerabilities.report_illegal_flow(function_name, illegal_flows)
            
            return combined_args_label
        
        elif node['type'] == 'UnaryExpression':
            # Process unary operations (e.g., negations).
            return self.process_expression_node(node['argument'])
        
        elif node['type'] == 'MemberExpression':
            object_label = self.process_expression_node(node['object'])
            property_label = self.process_expression_node(node['property'])
            return object_label.combine(property_label)
        else:
            return MultiLabel()


    def process_statement_node(self, node) -> MultiLabelling:
        """
        Processes an AST statement node, updates multilabelling, and checks for vulnerabilities.

        :param node: AST node representing a statement.
        :return: Updated MultiLabelling object.
        """
        # Implementation for statement processing
        pass

    
    def traverse_ast_debug(self, node, indent=0):
        prefix = " " * indent
        if isinstance(node, dict) and 'type' in node:
            print(f"{prefix}Node Type: {node['type']}")
            for key, value in node.items():
                if isinstance(value, dict):
                    self.traverse_ast_debug(value, indent + 2)
                elif isinstance(value, list):
                    for child in value:
                        if isinstance(child, dict):
                            self.traverse_ast_debug(child, indent + 2)
        elif isinstance(node, list):
            for child in node:
                self.traverse_ast_debug(child, indent)


    def traverse_ast(self, ast):
        for stmt in ast['body']:
            if stmt['type'] == 'ExpressionStatement':
                self.process_expression_node(stmt['expression'])
