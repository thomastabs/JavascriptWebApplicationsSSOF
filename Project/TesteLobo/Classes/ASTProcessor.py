from Classes.MultiLabelling import MultiLabelling
from Classes.MultiLabel import MultiLabel
from Classes.Policy import Policy
from Classes.Vulnerabilities import Vulnerabilities
from Classes.Label import Label
from Classes.FlowProcessor import IllegalFlow
from Classes.Pattern import Pattern
from typing import Dict, List
from Classes.FlowProcessor import Flow

class ASTProcessor:
    """
    Class to process an Abstract Syntax Tree (AST) for security analysis.
    """

    def __init__(self, policy: Policy, multilabelling: MultiLabelling, vulnerabilities: Vulnerabilities):
        self.policy = policy
        self.multilabelling = multilabelling
        self.vulnerabilities = vulnerabilities
        self.vulnerability_count = 0
        self.vulnerability_tracker: List[List[str, int]] = []  # Tracks counts per vulnerability
        self.variables = set()
        self.initialized: Dict[str, int] = {}

    def _increment_vulnerability_count(self, vulnerability_name: str) -> int:
        """
        Increments the count for a specific vulnerability and returns the new count.
        """
        for entry in self.vulnerability_tracker:
            if entry[0] == vulnerability_name:
                entry[1] += 1
                return entry[1]
        # If the vulnerability is not yet tracked, initialize it
        self.vulnerability_tracker.append([vulnerability_name, 1])
        return 1

    def process_expression_node(self, node) -> MultiLabel:
        if node['type'] == 'Identifier':
            print(f"Processing Identifier: {node['name']}")

            if not self.multilabelling.has_multi_label(node['name']):
                multilabel = MultiLabel(self.policy.get_patterns())
                for pattern in self.policy.get_patterns():
                    print(f"Checking pattern {pattern}")
                    label = Label()
                    label.add_source(node['name'], node['loc']['start']['line'])
                    multilabel.add_label(label, pattern)
                self.multilabelling.update_multilabel(node['name'], multilabel)

            for pattern in self.policy.get_patterns():
                if pattern.has_source(node['name']):
                    print(f"Found source in identifier: {node['name']}")
                    print(f"Pattern: {pattern}")
                    self.multilabelling.get_multilabel(node['name']).get_label(pattern).add_source(node['name'], node['loc']['start']['line'])

            return self.multilabelling.get_multilabel(node['name'])

        elif node['type'] == 'Literal':
            print(f"Literal '{node['value']}' encountered. No label assigned.")
            return MultiLabel(self.policy.get_patterns())

        elif node['type'] == 'BinaryExpression':
            left_label = self.process_expression_node(node['left'])
            right_label = self.process_expression_node(node['right'])

            for pattern in self.policy.get_patterns():
                if node['left']['type'] == 'Identifier' and pattern.has_source(node['left']['name']):
                    left_label.get_label(pattern).add_source(node['left']['name'], node['loc']['start']['line'])
                if node['right']['type'] == 'Identifier' and pattern.has_source(node['right']['name']):
                    right_label.get_label(pattern).add_source(node['right']['name'], node['loc']['start']['line'])

            return left_label.combine(right_label)
                
        elif node['type'] == 'CallExpression':
            print(f"Processing CallExpression: {node}")
            combined_multi_label = MultiLabel(self.policy.get_patterns())

            # Process arguments and combine their labels
            for arg in node['arguments']:
                arg_label = self.process_expression_node(arg)
                if not arg_label:
                    arg_label = MultiLabel(self.policy.get_patterns())
                combined_multi_label = combined_multi_label.combine(arg_label)

            if node['callee']['type'] == 'Identifier':
                function_name = node['callee']['name']

                for pattern in self.policy.get_patterns():
                    # Handle sources
                    if pattern.has_source(function_name):
                        label = Label()
                        label.add_source(function_name, node['loc']['start']['line'])
                        combined_multi_label.add_label(label, pattern)

                    # Handle sanitizers
                    if pattern.has_sanitizer(function_name):
                        for source, source_line in combined_multi_label.get_label(pattern).get_sources():
                            combined_multi_label.get_label(pattern).add_sanitizer(
                                function_name, node['loc']['start']['line'], source
                            )

                    # Handle sinks
                    if pattern.has_sink(function_name):
                        for source, source_line in combined_multi_label.get_label(pattern).get_sources():
                            flows = combined_multi_label.get_label(pattern).get_flows_from_source(source)

                            # Determine unsanitized and sanitized flows
                            unsanitized = any(
                                not any(sanitizer[0] in pattern.sanitizers for sanitizer in flow.flow)
                                for flow in flows
                            )
                            sanitized_flows = [
                                Flow(flow=[sanitizer for sanitizer in flow.flow if sanitizer[0] in pattern.sanitizers])
                                for flow in flows
                            ]

                            count = self._increment_vulnerability_count(pattern.get_vulnerability())
                            illegal_flow = IllegalFlow(
                                f"{pattern.get_vulnerability()}_{count}",
                                source,
                                source_line,
                                function_name,
                                node['loc']['start']['line'],
                                unsanitized,
                                sanitized_flows,
                                False  # Implicit flows are not considered here
                            )
                            self.vulnerabilities.add_illegal_flow(illegal_flow)
                            print(f"Recorded illegal flow: {illegal_flow}")

                # Update multilabels for the function
                self.multilabelling.update_multilabel(function_name, combined_multi_label)

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
            left = node['left']['name']
            print(f"Processing AssignmentExpression: {left} = {node['right']}")

            # Process the right-hand side of the assignment
            value_label = self.process_expression_node(node['right'])

            if value_label:
                # Update the multilabel for the left-hand side
                self.multilabelling.update_multilabel(left, value_label)
                print(f"Updated multilabel for {left}: {value_label}")

                # Check for sinks in the left-hand variable
                for pattern in self.policy.get_patterns():
                    if pattern.has_sink(left):
                        print(f"Found sink: {left} for pattern: {pattern.get_vulnerability()}")
                        label = value_label.get_label(pattern)

                        # Process sources and check for unsanitized flows
                        for source, source_line in label.get_sources():
                            print(f"Checking source: {source} for sink: {left}")
                            flows = label.get_flows_from_source(source)

                            # Determine unsanitized and sanitized flows
                            unsanitized = any(
                                not any(sanitizer[0] in pattern.sanitizers for sanitizer in flow.flow)
                                for flow in flows
                            )
                            sanitized_flows = [
                                Flow(flow=[sanitizer for sanitizer in flow.flow if sanitizer[0] in pattern.sanitizers])
                                for flow in flows
                            ]

                            count = self._increment_vulnerability_count(pattern.get_vulnerability())
                            illegal_flow = IllegalFlow(
                                f"{pattern.get_vulnerability()}_{count}",
                                source,
                                source_line,
                                left,
                                node['loc']['start']['line'],
                                unsanitized,
                                sanitized_flows,
                                False  # Explicit flows only for now
                            )
                            self.vulnerabilities.add_illegal_flow(illegal_flow)
                            print(f"Recorded illegal flow: {illegal_flow}")
            else:
                # Handle uninitialized assignments (empty MultiLabel)
                print(f"Right-hand side of {left} is uninitialized.")
                multilabel = MultiLabel(self.policy.get_patterns())
                self.multilabelling.update_multilabel(left, multilabel)
                print(f"Initialized empty MultiLabel for {left}")

                # Check for sinks in the left-hand variable
                for pattern in self.policy.get_patterns():
                    if pattern.has_sink(left):
                        print(f"Sink detected: {left} for pattern: {pattern.get_vulnerability()}")
                        label = multilabel.get_label(pattern)

                        # Process sources and check for unsanitized flows
                        for source, source_line in label.get_sources():
                            print(f"Checking source: {source} for sink: {left}")
                            flows = label.get_flows_from_source(source)

                            # Determine unsanitized and sanitized flows
                            unsanitized = any(
                                not any(sanitizer[0] in pattern.sanitizers for sanitizer in flow.flow)
                                for flow in flows
                            )
                            sanitized_flows = [
                                Flow(flow=[sanitizer for sanitizer in flow.flow if sanitizer[0] in pattern.sanitizers])
                                for flow in flows
                            ]

                            count = self._increment_vulnerability_count(pattern.get_vulnerability())
                            illegal_flow = IllegalFlow(
                                f"{pattern.get_vulnerability()}_{count}",
                                source,
                                source_line,
                                left,
                                node['loc']['start']['line'],
                                unsanitized,
                                sanitized_flows,
                                False
                            )
                            self.vulnerabilities.add_illegal_flow(illegal_flow)
                            print(f"Recorded illegal flow: {illegal_flow}")


        else:
            print(f"Unhandled expression node type: {node['type']}")
            return MultiLabel()

    '''
            
    # Function to process statements
    def process_statement_node(node, policy: Policy, multilabelling: MultiLabelling, vulnerabilities: Vulnerabilities, max_while_iterations=3):
        if node['type'] == 'ExpressionStatement':
            process_expression_node(node['expression'], policy, multilabelling, vulnerabilities)
            return multilabelling
        elif node['type'] == 'VariableDeclaration':
            for decl in node['declarations']:
                if 'init' in decl:
                    var_name = decl['id']['name']
                    label = process_expression_node(decl['init'], policy, multilabelling, vulnerabilities)
                    print(f"Updating MultiLabel for {var_name} with label: {label}")
                    multilabelling.update_multilabel(var_name, label)
            return multilabelling
        elif node['type'] == 'AssignmentExpression':
            left_label = process_expression_node(node['left'], policy, multilabelling, vulnerabilities)
            right_label = process_expression_node(node['right'], policy, multilabelling, vulnerabilities)
            combined_label = right_label.combine(left_label)
            if node['left']['type'] == 'Identifier':
                var_name = node['left']['name']
                print(f"Updating MultiLabel for variable {var_name}")
                multilabelling.update_multilabel(var_name, combined_label)
            return multilabelling
        elif node['type'] == 'BlockStatement':
            for stmt in node['body']:
                multilabelling = process_statement_node(stmt, policy, multilabelling, vulnerabilities)
            return multilabelling
        elif node['type'] == 'IfStatement':
            consequent = process_statement_node(node['consequent'], policy, multilabelling.deep_copy(), vulnerabilities)
            alternate = multilabelling
            if node.get('alternate'):
                alternate = process_statement_node(node['alternate'], policy, multilabelling.deep_copy(), vulnerabilities)
            return consequent.combinor(alternate)
        elif node['type'] == 'WhileStatement':
            loop_label = multilabelling.deep_copy()
            for _ in range(max_while_iterations):
                loop_label = process_statement_node(node['body'], policy, loop_label, vulnerabilities)
                loop_label = multilabelling.combinor(loop_label)
            return loop_label
        else:
            return multilabelling    

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

    def get_sorted_vulnerabilities(self):
        """
        Returns the vulnerabilities sorted alphabetically by their vulnerability name.
        """
        vulnerabilities = self.vulnerabilities.get_illegal_flows()

        return sorted(
            vulnerabilities,
            key=lambda v: v.to_json().get("vulnerability", "")
        )
