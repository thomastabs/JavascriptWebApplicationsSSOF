from Classes.MultiLabelling import MultiLabelling
from Classes.MultiLabel import MultiLabel
from Classes.Policy import Policy
from Classes.Vulnerabilities import Vulnerabilities
from Classes.Label import Label
from Classes.FlowProcessor import IllegalFlow
from Classes.Pattern import Pattern
from typing import Dict


class ASTProcessor:
    """
    Class to process an Abstract Syntax Tree (AST) for security analysis.
    """

    def __init__(self, policy: Policy, multilabelling: MultiLabelling, vulnerabilities: Vulnerabilities):
            self.policy = policy
            self.multilabelling = multilabelling
            self.vulnerabilities = vulnerabilities
            self.vulnerability_count = 0

            # Tracking uninitialized variables
            self.variables = set()
            self.initialized: Dict[str, int] = dict()

    def _increment_vulnerability_count(self):
        self.vulnerability_count += 1
        [A,1] 
        return self.vulnerability_count

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
                # Add sources from left and right to patterns
                if node['left']['type'] == 'Identifier' and pattern.has_source(node['left']['name']):
                    left_label.get_label(pattern).add_source(node['left']['name'], node['loc']['start']['line'])
                if node['right']['type'] == 'Identifier' and pattern.has_source(node['right']['name']):
                    right_label.get_label(pattern).add_source(node['right']['name'], node['loc']['start']['line'])

            return left_label.combine(right_label)

        elif node['type'] == 'CallExpression':
            combined_multi_label = MultiLabel(self.policy.get_patterns())
            for arg in node['arguments']:
                multilabel = self.process_expression_node(arg)
                print(f"Multilabel {arg}: {multilabel}")
                if not multilabel:
                    multilabel = MultiLabel(self.policy.get_patterns())
                combined_multi_label = combined_multi_label.combine(multilabel)
                print(f"Combined Multilabel: {combined_multi_label}")
                for pattern in self.policy.get_patterns():
                    if arg['type'] == 'Identifier':
                        if pattern.has_source(arg['name']):
                            print(pattern)
                            combined_multi_label.get_label(pattern).add_source(arg['name'], arg['loc']['start']['line'])

            if node['callee']['type']  == 'Identifier':
                function_name = node['callee']['name']
                # Add the source to the MultiLabel
                for pattern in self.policy.get_patterns():
                    if pattern.has_source(function_name):
                        label = Label()
                        label.add_source(function_name, node['loc']['start']['line'])
                        combined_multi_label.add_label(label, pattern)
                    if pattern.has_sanitizer(function_name):
                        for source, sourceLine in combined_multi_label.get_label(pattern).get_sources():
                            combined_multi_label.get_label(pattern).add_sanitizer(function_name, node['loc']['start']['line'], source)
                
                self.multilabelling.update_multilabel(function_name, combined_multi_label)
                        
                for pattern in self.policy.get_patterns():
                    if pattern.has_sink(function_name):
                        print(f"Sink matched: {function_name}")
                        for source, sourceLine in self.multilabelling.get_multilabel(function_name).get_label(pattern).get_sources():
                            print(f"Checking source: {source}")
                            unsanitized = not any(
                                sanitizer in pattern.sanitizers
                                for sanitizer in combined_multi_label.get_label(pattern).get_flows_from_source(source)
                            )
                            print(f"Source {source} unsanitized: {unsanitized}")
                            if unsanitized:
                                illegal_flow = IllegalFlow(f"{pattern.get_vulnerability()}_{self._increment_vulnerability_count()}", 
                                                           source, 
                                                           sourceLine, 
                                                           function_name, 
                                                           node['loc']['start']['line'], 
                                                           unsanitized, 
                                                           list(combined_multi_label.get_label(pattern).get_flows_from_source(source)), 
                                                           False)
                                self.vulnerabilities.add_illegal_flow(illegal_flow)

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
            
            value_label = self.process_expression_node(node['right'])

            if value_label:
                self.multilabelling.update_multilabel(left, value_label)
            
                for pattern in self.policy.get_patterns():
                    if pattern.has_sink(left):
                        print(f"Found sink: {left}")
                        print(f"Label {value_label.get_label(pattern)}")
                        for source, sourceLine in self.multilabelling.get_multilabel(left).get_label(pattern).get_sources():
                            print(f"Checking source: {source}")
                            unsanitized = not any(
                                sanitizer in pattern.sanitizers
                                for sanitizer in value_label.get_label(pattern).get_flows_from_source(source)
                            )
                            print(f"Source {source} unsanitized: {unsanitized}")
                            if unsanitized:
                                print(f"Adding illegal flow for {left}")
                                illegal_flow = IllegalFlow(f"{pattern.get_vulnerability()}_{self._increment_vulnerability_count()}", 
                                                           source, 
                                                           sourceLine, 
                                                           left, 
                                                           node['loc']['start']['line'], 
                                                           unsanitized, 
                                                           list(value_label.get_label(pattern).get_flows_from_source(source)), 
                                                           False)
                                self.vulnerabilities.add_illegal_flow(illegal_flow)
                                print(self.multilabelling.get_multilabel(left).get_label(pattern).get_sources())
            else:
                multilabel = MultiLabel()
                self.multilabelling.update_multilabel(left, multilabel)

                for pattern in self.policy.get_patterns():
                    if pattern.has_sink(left):
                        for source, sourceLine in self.multilabelling.get_multilabel(left).get_label(pattern).get_sources():
                            print(f"Checking source: {source}")
                            unsanitized = not any(
                                sanitizer in pattern.sanitizers
                                for sanitizer in value_label.get_label(pattern).get_flows_from_source(source)
                            )
                            print(f"Source {source} unsanitized: {unsanitized}")
                            if unsanitized:
                                print(f"Adding illegal flow for {left}")
                                illegal_flow = IllegalFlow(pattern.get_vulnerability(), 
                                                           source, 
                                                           sourceLine, 
                                                           left, 
                                                           node['loc']['start']['line'], 
                                                           unsanitized, 
                                                           list(value_label.get_label(pattern).get_flows_from_source(source)), 
                                                           False)
                                self.vulnerabilities.add_illegal_flow(illegal_flow)
                                print(self.multilabelling.get_multilabel(left).get_label(pattern).get_sources())


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
        vulnerabilities = self.vulnerabilities.get_illegal_flows()

        return sorted(
            vulnerabilities,
            key=lambda v: int(v.to_json().get("vulnerability", "0_0").split("_")[1])  
            if "_" in v.to_json().get("vulnerability", "") else float("inf")  
        )
