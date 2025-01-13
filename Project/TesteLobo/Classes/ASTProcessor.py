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
        """
        Description: Initializes the ASTProcessor with required components for security analysis.
        Variables:
            - policy (Policy): Defines the security patterns and policies to enforce.
            - multilabelling (MultiLabelling): Tracks variable mappings to multilabels.
            - vulnerabilities (Vulnerabilities): Collects detected illegal information flows.
        Result: An instance of ASTProcessor ready for AST traversal and analysis.
        """
        self.policy = policy
        self.multilabelling = multilabelling
        self.vulnerabilities = vulnerabilities
        self.vulnerability_count = 0
        self.vulnerability_tracker: List[List[str, int]] = []  # Tracks counts per vulnerability
        self.variables = set()
        self.initialized: Dict[str, int] = {}


    def _increment_vulnerability_count(self, vulnerability_name: str) -> int:
        """
        Description: Increments the count for a specific vulnerability and returns the updated count.
        Variables:
            - vulnerability_name (str): The name of the vulnerability to track.
        Result: The updated count of the specified vulnerability.
        """
        for entry in self.vulnerability_tracker:
            if entry[0] == vulnerability_name:
                entry[1] += 1
                return entry[1]
        # If the vulnerability is not yet tracked, initialize it
        self.vulnerability_tracker.append([vulnerability_name, 1])
        return 1


    def _process_sources_and_sanitizers(self, combined_multi_label, function_name, node):
        """
        Description: Processes function calls in the AST to identify sources and sanitizers based on policy patterns.
        Variables:
            - combined_multi_label (MultiLabel): The aggregated label for the node.
            - function_name (str): The name of the function being processed.
            - node (dict): The AST node representing the function call.
        Result: Updates the combined_multi_label with sources and sanitizers if applicable.
        """
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
        """
        Description: Detects illegal flows by analyzing sinks in the AST.
        Variables:
            - combined_multi_label (MultiLabel): The label containing information about sources and sanitizers.
            - var_name (str): The variable name being analyzed as a sink.
            - node (dict): The AST node representing the sink.
        Result: Adds detected illegal flows to the vulnerabilities collection.
        """
        for pattern in self.policy.get_patterns():
            if pattern.has_sink(var_name):
                for source, source_line in combined_multi_label.get_label(pattern).get_sources():
                    flows = combined_multi_label.get_label(pattern).get_flows_from_source(source)

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


    def process_expression_node(self, node) -> MultiLabel:
        """
        Description: Processes an expression node in the AST and retrieves its security label.
        Variables:
            - node (dict): The AST node representing the expression to process.
        Result: A MultiLabel object containing the security labels for the expression.
        """
        if node['type'] == 'Identifier':

            if not self.multilabelling.has_multi_label(node['name']):
                multilabel = MultiLabel(self.policy.get_patterns())
                for pattern in self.policy.get_patterns():
                    label = Label()
                    label.add_source(node['name'], node['loc']['start']['line'])
                    multilabel.add_label(label, pattern)
                self.multilabelling.update_multilabel(node['name'], multilabel)

            for pattern in self.policy.get_patterns():
                if pattern.has_source(node['name']):
                    self.multilabelling.get_multilabel(node['name']).get_label(pattern).add_source(node['name'], node['loc']['start']['line'])

            return self.multilabelling.get_multilabel(node['name'])

        elif node['type'] == 'Literal':
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
                self.multilabelling.get_multilabel(object).combine(object_label)
                self.multilabelling.get_multilabel(property).combine(combined_multi_label)
                combined_multi_label = combined_multi_label.combine(object_label)

                self._process_sinks(combined_multi_label, object, node)
                self._process_sinks(combined_multi_label, property, node)

            return combined_multi_label

        elif node['type'] == 'UnaryExpression':
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
                multilabel = MultiLabel(self.policy.get_patterns())
                self.multilabelling.update_multilabel(node['left']['property']['name'], multilabel)
                return multilabel

            # Process the right-hand side of the assignment
            value_label = self.process_expression_node(node['right'])

            if value_label:
                # Update the multilabel for the left-hand side
                self.multilabelling.update_multilabel(left, value_label)
                self._process_sinks(value_label, left, node)
            else:
                # Handle uninitialized assignments (empty MultiLabel)
                multilabel = MultiLabel(self.policy.get_patterns())
                self.multilabelling.update_multilabel(left, multilabel)
                self._process_sinks(multilabel, left, node)

            if node['left']['type'] == 'MemberExpression':
                property = node['left']['property']['name']
                self.multilabelling.update_multilabel(property, value_label)
                self._process_sinks(value_label, property, node)

            return value_label
        else:
            return MultiLabel(self.policy.get_patterns())
        
            
    def process_statement_node(self, node, max_while_iterations=3) -> MultiLabel:
        """
        Description: Processes a single AST statement node and returns a MultiLabel representing its flows.
        Variables:
            - node (dict): The AST node representing the statement to process.
            - max_while_iterations (int): The maximum number of iterations to process for while loops.
        Result: A MultiLabel object containing the security labels for the statement.
        """
        if node['type'] == 'ExpressionStatement':
            stmt_label = self.process_expression_node(node['expression'])

            # Update multilabelling and process sinks
            for var_name, multilabel in stmt_label.mapping.items():
                self.multilabelling.update_multilabel(var_name, multilabel)
                self._process_sinks(multilabel, var_name, node)

            return stmt_label

        elif node['type'] == 'BlockStatement':
            combined_label = MultiLabel(self.policy.get_patterns())

            # Process each statement in the block sequentially
            for stmt in node['body']:
                stmt_label = self.process_statement_node(stmt)
                combined_label = combined_label.combine(stmt_label)

            # Update multilabelling and process sinks for combined labels
            for var_name, multilabel in combined_label.mapping.items():
                self.multilabelling.update_multilabel(var_name, multilabel)
                self._process_sinks(multilabel, var_name, node)

            return combined_label

        elif node['type'] == 'IfStatement':
            consequent_label = self.process_statement_node(node['consequent'])

            alternate_label = MultiLabel(self.policy.get_patterns())
            if node.get('alternate'):
                alternate_label = self.process_statement_node(node['alternate'])

            combined_label = consequent_label.combine(alternate_label)

            # Ensure shared variables like `a` and `c` are fully updated
            for var_name, multilabel in combined_label.mapping.items():
                self.multilabelling.update_multilabel(var_name, multilabel)
                self._process_sinks(multilabel, var_name, node)

            return combined_label


        elif node['type'] == 'WhileStatement':
            loop_label = MultiLabel(self.policy.get_patterns())

            # Process the loop body for a fixed number of iterations
            for iteration in range(max_while_iterations):
                loop_body_label = self.process_statement_node(node['body'])
                loop_label = loop_label.combine(loop_body_label)

            # Update multilabelling and process sinks for loop variables
            for var_name, multilabel in loop_label.mapping.items():
                self.multilabelling.update_multilabel(var_name, multilabel)
                self._process_sinks(multilabel, var_name, node)

            return loop_label

        else:
            return MultiLabel(self.policy.get_patterns())


    def traverse_ast(self, ast):
        """
        Description: Traverse the AST and process each statement using process_statement_node.
        Variables:
            - ast (dict): The AST to traverse.
        """
        for stmt in ast['body']:
            stmt_label = self.process_statement_node(stmt)

            # Update the global multilabelling
            for var_name, multilabel in stmt_label.mapping.items():
                self.multilabelling.update_multilabel(var_name, multilabel)


    def get_sorted_vulnerabilities(self):
        """
        Description: Returns the vulnerabilities sorted alphabetically by their vulnerability name.
        Variables: None
        Result: A list of sorted vulnerabilities.
        """
        vulnerabilities = self.vulnerabilities.get_illegal_flows()

        return sorted(
            vulnerabilities,
            key=lambda v: v.to_json().get("vulnerability", "")
        )