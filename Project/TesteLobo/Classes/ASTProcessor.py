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
        self.vulnerability_count = 0  # Counter for vulnerabilities

    def _increment_vulnerability_count(self):
        """
        Increment the vulnerability count and return the updated count.
        """
        self.vulnerability_count += 1
        return self.vulnerability_count

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
            left_label = self.process_expression_node(node['left'])
            right_label = self.process_expression_node(node['right'])

            for pattern in self.policy.get_patterns():
                if node['left']['type'] == 'Identifier':
                    if pattern.has_source(node['left']['name']):
                        print(f"Adding source {node['left']['name']} to {pattern.getName()} in left")
                        left_label.get_label(pattern).add_source(node['left']['name'], node['loc']['start']['line'])
                if node['right']['type'] == 'Identifier':
                    if pattern.has_source(node['right']['name']):
                        print(f"Adding source {node['right']['name']} to {pattern.getName()} in right")
                        right_label.get_label(pattern).add_source(node['right']['name'], node['loc']['start']['line'])
            return left_label.combine(right_label)

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
                        label.add_source(function_name, node['loc']['start']['line'])
                        combined_multi_label.add_label(label, pattern)
                        print(f"Source label added for function '{function_name}': {label}")

                    elif match_type == "sink":
                        for source, source_line in combined_multi_label.get_label(pattern).get_sources():
                            if pattern.test_string(source) == "source":
                                flows = combined_multi_label.get_label(pattern).get_flows_from_source(source)
                                unsanitized = not any(sanitizer in pattern.sanitizers for sanitizer in flows)

                                if unsanitized:
                                    illegal_flow = IllegalFlow(
                                        vulnerability=f"{pattern.get_vulnerability()}_{self._increment_vulnerability_count()}",
                                        source=source,
                                        source_lineno=source_line,
                                        sink=function_name,
                                        sink_lineno=node['callee']['loc']['start']['line'],
                                        unsanitized_flows="yes" if unsanitized else "no",
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
            left_variable = node['left']['name']
            if node['right']['type'] == 'Identifier':
                right_variable = node['right']['name']
            else:
                right_variable = None

            # Process left and right sides
            left_label = self.process_expression_node(node['left'])
            right_label = self.process_expression_node(node['right'])
            value_label = left_label.combine(right_label)
            self.multilabelling.update_multilabel(left_variable, value_label)

            for pattern in self.policy.get_patterns():
                # Handle sinks
                if pattern.has_sink(left_variable):
                    for source, source_line in value_label.get_label(pattern).get_sources():
                        if pattern.has_source(source):
                            flows = value_label.get_label(pattern).get_flows_from_source(source)
                            unsanitized = not any(
                                sanitizer in pattern.sanitizers for sanitizer in flows
                            )
                            sanitized_flows = [
                                sanitizer
                                for sanitizer in flows
                                if sanitizer in pattern.sanitizers
                            ]
                            illegal_flow = IllegalFlow(
                                vulnerability=f"{pattern.get_vulnerability()}_{self._increment_vulnerability_count()}",
                                source=source,
                                source_lineno=source_line,
                                sink=left_variable,
                                sink_lineno=node['loc']['start']['line'],
                                unsanitized_flows="yes" if unsanitized else "no",
                                sanitized_flows=sanitized_flows
                            )
                            self.vulnerabilities.add_illegal_flow(illegal_flow)

                # Propagate sources and sanitizers from right to left
                if right_variable is not None and pattern.has_source(right_variable):
                    flows = value_label.get_label(pattern).get_flows_from_source(right_variable)
                    sanitized_flows = [
                        sanitizer for sanitizer in flows if sanitizer in pattern.sanitizers
                    ]
                    unsanitized = not sanitized_flows
                    illegal_flow = IllegalFlow(
                        vulnerability=f"{pattern.get_vulnerability()}_{self._increment_vulnerability_count()}",
                        source=right_variable,
                        source_lineno=node['right']['loc']['start']['line'],
                        sink=left_variable,
                        sink_lineno=node['left']['loc']['start']['line'],
                        unsanitized_flows="yes" if unsanitized else "no",
                        sanitized_flows=sanitized_flows
                    )
                    self.vulnerabilities.add_illegal_flow(illegal_flow)
                    self.multilabelling.get_multilabel(left_variable).get_label(pattern).add_source(right_variable, node['loc']['start']['line'])

            return value_label

        else:
            print(f"Unhandled expression node type: {node['type']}")
            return MultiLabel()

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

    def get_sorted_vulnerabilities(self):
        """
        Returns the vulnerabilities sorted by their numeric suffix in the vulnerability name.
        """
        return sorted(
            self.vulnerabilities.get_illegal_flows(),
            key=lambda v: int(v.to_json()["vulnerability"].split("_")[1])
        )
