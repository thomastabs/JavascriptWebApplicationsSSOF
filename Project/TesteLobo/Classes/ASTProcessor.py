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

    def _process_sources_and_sanitizers(self, combined_multi_label, function_name, node):
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


    def _process_sinks(self, combined_multi_label, var_name, node):
        print(f"Processing sinks for variable: {var_name} at line {node['loc']['start']['line']}")
        for pattern in self.policy.get_patterns():
            if pattern.has_sink(var_name):
                for source, source_line in combined_multi_label.get_label(pattern).get_sources():
                    print(f"Checking source '{source}' for sink '{var_name}'")
                    flows = combined_multi_label.get_label(pattern).get_flows_from_source(source)
                    print(f"Flows for source '{source}': {flows}")

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
                        var_name,
                        node['loc']['start']['line'],
                        unsanitized,
                        sanitized_flows,
                        False
                    )
                    self.vulnerabilities.add_illegal_flow(illegal_flow)
                    print(f"Recorded illegal flow: {illegal_flow}")


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
            callee = node['callee']

            # Process arguments and combine their labels
            for arg in node['arguments']:
                arg_label = self.process_expression_node(arg)
                if not arg_label:
                    arg_label = MultiLabel(self.policy.get_patterns())
                combined_multi_label = combined_multi_label.combine(arg_label)

            if node['callee']['type'] == 'Identifier':
                function_name = node['callee']['name']
                self._process_sources_and_sanitizers(combined_multi_label, function_name, node)
                self._process_sinks(combined_multi_label, function_name, node)
                self.multilabelling.update_multilabel(function_name, combined_multi_label)

            if node['callee']['type'] == 'MemberExpression':
                object = callee['object']['name']
                property = callee['property']['name']
                self._process_sources_and_sanitizers(combined_multi_label, property, node)

                object_label = self.process_expression_node(callee['object'])
                print(f"Object label: {object_label}")
                self.multilabelling.get_multilabel(object).combine(object_label)
                self.multilabelling.get_multilabel(property).combine(combined_multi_label)
                combined_multi_label = combined_multi_label.combine(object_label)

                self._process_sinks(combined_multi_label, object, node)
                self._process_sinks(combined_multi_label, property, node)

            return combined_multi_label

        elif node['type'] == 'UnaryExpression':
            print(f"Processing UnaryExpression: {node}")
            return self.process_expression_node(node['argument'])

        elif node['type'] == 'MemberExpression':
            property_label = self.process_expression_node(node['property'])
            object_label = self.process_expression_node(node['object'])
            object_label.combine(property_label)
            object = node['object']['name']
            property = node['property']['name']

            self._process_sinks(object_label, object, node)
            self._process_sinks(object_label, property, node)

            return object_label

        elif node['type'] == 'AssignmentExpression':
            if node['left']['type'] == 'MemberExpression':
                left = node['left']['object']['name']
            else:
                left = node['left']['name']

            if node['right']['type'] == 'Literal' and node['left']['type'] == "MemberExpression":
                print("Initialized member expression with literal")
                multilabel = MultiLabel(self.policy.get_patterns())
                print(f"Property label {self.multilabelling.get_multilabel(node['left']['property']['name'])}")
                self.multilabelling.update_multilabel(node['left']['property']['name'], multilabel)
                return multilabel

            # Process the right-hand side of the assignment
            value_label = self.process_expression_node(node['right'])

            if value_label:
                # Update the multilabel for the left-hand side
                self.multilabelling.update_multilabel(left, value_label)
                print(f"Updated multilabel for {left}: {value_label}")

                self._process_sinks(value_label, left, node)
            else:
                # Handle uninitialized assignments (empty MultiLabel)
                print(f"Right-hand side of {left} is uninitialized.")
                multilabel = MultiLabel(self.policy.get_patterns())
                self.multilabelling.update_multilabel(left, multilabel)
                print(f"Initialized empty MultiLabel for {left}")

                self._process_sinks(multilabel, left, node)

            if node['left']['type'] == 'MemberExpression':
                property = node['left']['property']['name']
                self.multilabelling.update_multilabel(property, value_label)
                self._process_sinks(value_label, property, node)

            return value_label
        else:
            print(f"Unhandled expression node type: {node['type']}")
            return MultiLabel(self.policy.get_patterns())
        
            
    def process_statement_node(self, node, max_while_iterations=3) -> MultiLabel:
        """
        Processes a single AST statement node and returns a MultiLabel representing its flows.
        """
        if node['type'] == 'ExpressionStatement':
            print(f"Processing ExpressionStatement: {node}")
            stmt_label = self.process_expression_node(node['expression'])

            # Update multilabelling and process sinks
            for var_name, multilabel in stmt_label.mapping.items():
                print(f"Updating multilabelling for variable: {var_name}")
                self.multilabelling.update_multilabel(var_name, multilabel)
                self._process_sinks(multilabel, var_name, node)

            return stmt_label

        elif node['type'] == 'BlockStatement':
            print(f"Processing BlockStatement: {node}")
            combined_label = MultiLabel(self.policy.get_patterns())

            # Process each statement in the block sequentially
            for stmt in node['body']:
                stmt_label = self.process_statement_node(stmt)
                combined_label = combined_label.combine(stmt_label)

            # Update multilabelling and process sinks for combined labels
            for var_name, multilabel in combined_label.mapping.items():
                print(f"Updating multilabelling for block variable: {var_name}")
                self.multilabelling.update_multilabel(var_name, multilabel)
                self._process_sinks(multilabel, var_name, node)

            return combined_label

        elif node['type'] == 'IfStatement':
            print(f"Processing IfStatement: {node}")
            consequent_label = self.process_statement_node(node['consequent'])
            print(f"Consequent label for IfStatement: {consequent_label}")

            alternate_label = MultiLabel(self.policy.get_patterns())
            if node.get('alternate'):
                alternate_label = self.process_statement_node(node['alternate'])
                print(f"Alternate label for IfStatement: {alternate_label}")

            combined_label = consequent_label.combine(alternate_label)
            print(f"Combined label after IfStatement branches: {combined_label}")

            # Ensure shared variables like `a` and `c` are fully updated
            for var_name, multilabel in combined_label.mapping.items():
                print(f"Updating multilabelling for IfStatement variable: {var_name}")
                self.multilabelling.update_multilabel(var_name, multilabel)
                self._process_sinks(multilabel, var_name, node)

            return combined_label


        elif node['type'] == 'WhileStatement':
            print(f"Processing WhileStatement: {node}")
            loop_label = MultiLabel(self.policy.get_patterns())

            # Process the loop body for a fixed number of iterations
            for iteration in range(max_while_iterations):
                print(f"Iteration {iteration + 1} of WhileStatement processing")
                loop_body_label = self.process_statement_node(node['body'])
                loop_label = loop_label.combine(loop_body_label)

            # Update multilabelling and process sinks for loop variables
            for var_name, multilabel in loop_label.mapping.items():
                print(f"Updating multilabelling for WhileStatement variable: {var_name}")
                self.multilabelling.update_multilabel(var_name, multilabel)
                self._process_sinks(multilabel, var_name, node)

            return loop_label

        else:
            print(f"Unhandled statement type: {node['type']}")
            return MultiLabel(self.policy.get_patterns())





    def traverse_ast(self, ast):
        """
        Traverse the AST and process each statement using process_statement_node.
        """
        print(f"Starting AST traversal for: {ast}")

        for stmt in ast['body']:
            print(f"Visiting statement: {stmt}")
            stmt_label = self.process_statement_node(stmt)

            # Update the global multilabelling
            for var_name, multilabel in stmt_label.mapping.items():
                self.multilabelling.update_multilabel(var_name, multilabel)




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