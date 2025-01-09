from Classes.MultiLabelling import MultiLabelling
from Classes.MultiLabel import MultiLabel
from Classes.Policy import Policy
from Classes.Vulnerabilities import Vulnerabilities
from Classes.Label import Label
from Classes.FlowProcessor import IllegalFlow


class ASTProcessor:
    """
    Class to process an Abstract Syntax Tree (AST) for security analysis.
    """

    def __init__(self, policy: Policy, multilabelling: MultiLabelling, vulnerabilities: Vulnerabilities):
        self.policy = policy
        self.multilabelling = multilabelling
        self.vulnerabilities = vulnerabilities


    def process_expression_node(self, node) -> MultiLabel:
        """
        Processes an AST expression node, updates multilabelling, and checks for vulnerabilities.

        :param node: AST node representing an expression.
        :return: A Label describing the information flow for the given expression.
        """
        print(f"Processing expression node: {node}")

        if node['type'] == 'Identifier':
            label = self.multilabelling.get_multilabel(node['name'])
            print(f"Identifier '{node['name']}' has label: {label}")
            return label
            
        elif node['type'] == 'Literal':
            print(f"Literal '{node['value']}' encountered. No label assigned.")
            return MultiLabel()

        elif node['type'] == 'BinaryExpression':
            print(f"Processing BinaryExpression: {node}")
            left_label = self.process_expression_node(node['left'])
            right_label = self.process_expression_node(node['right'])
            combined_label = left_label.combine(right_label)
            print(f"Combined labels for BinaryExpression: {left_label}, {right_label} -> {combined_label}")
            return combined_label

        elif node['type'] == 'CallExpression':
            print(f"Processing CallExpression: {node}")
            callee = node['callee']
            args = node['arguments']

            combined_multi_label = MultiLabel()
            for arg in args:
                arg_label = self.process_expression_node(arg)
                combined_multi_label = combined_multi_label.combine(arg_label)

            if callee['type'] == 'Identifier':
                function_name = callee['name']
                for pattern in self.policy.get_patterns():
                    match_type = pattern.test_string(function_name)

                    if match_type == "source":
                        label = Label()
                        label.add_source(function_name, node['loc']['start']['line'])  # Use correct line for source
                        combined_multi_label.add_label(label, pattern)
                        print(f"Source label added for function '{function_name}': {label}")

                    elif match_type == "sink":
                        for source, source_line in combined_multi_label.get_label(pattern).get_sources():
                            if pattern.test_string(source) == "source":
                                flows = combined_multi_label.get_label(pattern).get_flows_from_source(source)
                                unsanitized = not any(sanitizer in pattern.sanitizers for sanitizer in flows)

                                if unsanitized:
                                    illegal_flow = IllegalFlow(
                                        vulnerability=pattern.get_vulnerability(),
                                        source=source,
                                        source_lineno=source_line,
                                        sink=function_name,
                                        sink_lineno=node['callee']['loc']['start']['line'],  # Correct sink line                                        unsanitized_flows=unsanitized,
                                        unsanitized_flows="yes",
                                        sanitized_flows=list(flows)
                                    )
                                    self.vulnerabilities.add_illegal_flow(illegal_flow)
                                    print(f"Illegal flow detected: {illegal_flow}")
            return combined_multi_label


        elif node['type'] == 'UnaryExpression':
            print(f"Processing UnaryExpression: {node}")
            return self.process_expression_node(node['argument'])

        elif node['type'] == 'MemberExpression':
            print(f"Processing MemberExpression: {node}")
            object_label = self.process_expression_node(node['object'])
            property_label = self.process_expression_node(node['property'])
            combined_label = object_label.combine(property_label)
            print(f"Combined labels for MemberExpression: {object_label}, {property_label} -> {combined_label}")
            return combined_label

        elif node['type'] == 'AssignmentExpression':
            print(f"Processing AssignmentExpression: {node}")
            variable = node['left']['name']
            value_label = self.process_expression_node(node['right'])

            # Check if the variable is a sink
            for pattern in self.policy.get_patterns():
                if pattern.has_sink(variable):
                    for source, source_line in value_label.get_label(pattern).get_sources():
                        if pattern.test_string(source) == "source":
                            # Check if the flow from the source is unsanitized
                            flows = value_label.get_label(pattern).get_flows_from_source(source)
                            unsanitized = not any(sanitizer in pattern.sanitizers for sanitizer in flows)

                            if unsanitized:
                                # Create and add an illegal flow
                                illegal_flow = IllegalFlow(
                                    vulnerability=pattern.get_vulnerability(),
                                    source=source,
                                    source_lineno=source_line,
                                    sink=variable,
                                    sink_lineno=node['loc']['start']['line'],  # Ensure the correct line for the sink
                                    unsanitized_flows=unsanitized,
                                    sanitized_flows=list(flows)
                                )
                                self.vulnerabilities.add_illegal_flow(illegal_flow)
                                print(f"Illegal flow detected: {illegal_flow}")

            # Update the label for the assigned variable
            print(f"Assigning label to variable '{variable}': {value_label}")
            self.multilabelling.update_multilabel(variable, value_label)

            # Treat the left-hand side variable as a new potential source
            for pattern in self.policy.get_patterns():
                label = value_label.get_label(pattern)
                if label.get_sources():
                    for source, source_line in list(label.get_sources()):  # Use the correct line number from the source
                        if pattern.test_string(source) == "source":
                            label.add_source(variable, node['left']['loc']['start']['line'])
                    print(f"Added new source '{variable}' at line {node['left']['loc']['start']['line']}")            
            return value_label


        else:
            print(f"Unhandled expression node type: {node['type']}")
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
        """
        Traverse the AST and process each statement.
        """
        print(f"Starting AST traversal for: {ast}")
        for stmt in ast['body']:
            print(f"Visiting statement: {stmt}")
            if stmt['type'] == 'ExpressionStatement':
                self.process_expression_node(stmt['expression'])
                print(f"Processed ExpressionStatement: {stmt}")
            elif stmt['type'] == 'VariableDeclaration':
                for declaration in stmt['declarations']:
                    print(f"Processing VariableDeclaration: {declaration}")
                    if declaration['init']:
                        init_label = self.process_expression_node(declaration['init'])
                        variable_name = declaration['id']['name']
                        self.multilabelling.update_multilabel(variable_name, init_label)
                        print(f"Assigned label to variable '{variable_name}': {init_label}")
            elif stmt['type'] == 'AssignmentExpression':
                print(f"Processing AssignmentExpression: {stmt}")
                self.process_expression_node(stmt)
            else:
                print(f"Unhandled statement type: {stmt['type']}")

    def traverse_ast_printer(self, node, indent_level=0):
        indent = '  ' * indent_level

        if isinstance(node, dict) and 'type' in node:
            node_type = node.get('type', 'Unknown')
            line = node.get('loc', {}).get('start', {}).get('line', 'Unknown')

            print(f"{indent}Node Type: {node_type}, Line: {line}")

            for key, value in node.items():
                if isinstance(value, (dict, list)): 
                    self.traverse_ast_printer(value, indent_level + 1)

        elif isinstance(node, list):
            for child in node:
                self.traverse_ast_printer(child, indent_level + 1)