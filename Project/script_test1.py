import esprima
from Classes.Policy import Policy
from Classes.MultiLabelling import MultiLabelling
from Classes.Vulnerabilities import Vulnerabilities
from Classes.MultiLabel import MultiLabel
from Classes.Pattern import Pattern

def process_expression_node(node, policy: Policy, multilabelling: MultiLabelling, vulnerabilities: Vulnerabilities):
    """
    Processes an AST expression node to determine the MultiLabel describing the information returned.
    
    :param node: The AST node corresponding to an expression.
    :param policy: A Policy object containing the vulnerability patterns.
    :param multilabelling: A MultiLabelling object mapping variable names to their MultiLabels.
    :param vulnerabilities: A Vulnerabilities object to store detected illegal flows.
    :return: A MultiLabel object representing the information flow for the given expression.
    """
    if node['type'] == 'Identifier':
        # Get the MultiLabel of the variable
        var_name = node['name']
        return multilabelling.get_multilabel(var_name)

    elif node['type'] == 'Literal':
        # A literal has no sources or sanitizers, so return an empty MultiLabel
        return MultiLabel()

    elif node['type'] == 'BinaryExpression':
        # Combine the MultiLabels of the left and right operands
        left_label = process_expression_node(node['left'], policy, multilabelling, vulnerabilities)
        right_label = process_expression_node(node['right'], policy, multilabelling, vulnerabilities)
        return left_label.combine(right_label)

    elif node['type'] == 'CallExpression':
        # Process arguments and combine their MultiLabels
        args_labels = [
            process_expression_node(arg, policy, multilabelling, vulnerabilities)
            for arg in node.get('arguments', [])
        ]
        combined_args_label = args_labels[0] if args_labels else MultiLabel()
        for label in args_labels[1:]:
            combined_args_label = combined_args_label.combine(label)

        # Check if the function being called is a sink
        callee = node['callee']
        if callee['type'] == 'Identifier':
            function_name = callee['name']
            for pattern_name in policy.get_vulnerability_names():
                pattern = policy.patterns[pattern_name]
                if pattern.is_sink(function_name):
                    # Detect illegal flows for this sink
                    illegal_flows = policy.detect_illegal_flows(function_name, combined_args_label)
                    if illegal_flows.mapping:
                        vulnerabilities.report_illegal_flow(function_name, illegal_flows)

        return combined_args_label

    elif node['type'] == 'AssignmentExpression':
        # Update the MultiLabel of the assigned variable
        target_label = process_expression_node(node['right'], policy, multilabelling, vulnerabilities)
        if node['left']['type'] == 'Identifier':
            var_name = node['left']['name']
            multilabelling.update_multilabel(var_name, target_label)
        return target_label

    elif node['type'] == 'MemberExpression':
        # Process the object and property separately
        object_label = process_expression_node(node['object'], policy, multilabelling, vulnerabilities)
        property_label = MultiLabel()  # Properties are typically static
        return object_label.combine(property_label)

    elif node['type'] == 'UnaryExpression':
        # Process the operand
        return process_expression_node(node['argument'], policy, multilabelling, vulnerabilities)

    else:
        # Unsupported node type
        return MultiLabel()


def process_statement_node(node, policy, multilabelling, vulnerabilities, max_while_iterations=3):
    """
    Processes an AST statement node to determine the MultiLabelling after the statement.
    
    :param node: The AST node corresponding to a statement.
    :param policy: A Policy object containing the vulnerability patterns.
    :param multilabelling: A MultiLabelling object mapping variables to their MultiLabels.
    :param vulnerabilities: A Vulnerabilities object to store detected illegal flows.
    :param max_while_iterations: Maximum iterations for approximating while loops.
    :return: A MultiLabelling object representing the resulting variable-to-MultiLabel mapping.
    """
    if node['type'] == 'ExpressionStatement':
        # Process the expression
        process_expression_node(node['expression'], policy, multilabelling, vulnerabilities)
        return multilabelling

    elif node['type'] == 'VariableDeclaration':
        # Process each variable declarator
        for declaration in node.get('declarations', []):
            if declaration['type'] == 'VariableDeclarator':
                var_name = declaration['id']['name']
                if 'init' in declaration:
                    # Assign the MultiLabel of the initializer expression
                    multilabel = process_expression_node(declaration['init'], policy, multilabelling, vulnerabilities)
                    multilabelling.update_multilabel(var_name, multilabel)
        return multilabelling

    elif node['type'] == 'IfStatement':
        # Process the condition
        condition_label = process_expression_node(node['test'], policy, multilabelling, vulnerabilities)

        # Process the 'then' branch
        consequent_labelling = multilabelling.deep_copy()
        consequent_labelling = process_statement_node(node['consequent'], policy, consequent_labelling, vulnerabilities)

        # Process the 'else' branch if it exists
        if 'alternate' in node and node['alternate']:
            alternate_labelling = multilabelling.deep_copy()
            alternate_labelling = process_statement_node(node['alternate'], policy, alternate_labelling, vulnerabilities)
        else:
            alternate_labelling = multilabelling

        # Combine the resulting MultiLabellings
        return consequent_labelling.combinor(alternate_labelling)

    elif node['type'] == 'BlockStatement':
        # Process each statement in the block
        for stmt in node.get('body', []):
            multilabelling = process_statement_node(stmt, policy, multilabelling, vulnerabilities)
        return multilabelling

    elif node['type'] == 'WhileStatement':
        # Process the condition
        condition_label = process_expression_node(node['test'], policy, multilabelling, vulnerabilities)

        # Initialize the loop labelling approximation
        loop_labelling = multilabelling.deep_copy()

        for _ in range(max_while_iterations):
            # Simulate one iteration of the loop
            loop_labelling = process_statement_node(node['body'], policy, loop_labelling, vulnerabilities)

            # Combine with the original labelling to approximate infinite paths
            loop_labelling = multilabelling.combinor(loop_labelling)

        return loop_labelling

    elif node['type'] == 'AssignmentExpression':
        # Use the expression walker to handle assignments
        target_label = process_expression_node(node['right'], policy, multilabelling, vulnerabilities)
        if node['left']['type'] == 'Identifier':
            var_name = node['left']['name']
            multilabelling.update_multilabel(var_name, target_label)
        return multilabelling

    else:
        # Unsupported node type; return current labelling unchanged
        return multilabelling


# Test the function
if __name__ == "__main__":
    program = '''
    a = "";
    b = c();
    d(a);
    e(b);
    '''

    patterns = [
    {
        "vulnerability": "A",
        "sources": [
            "c"
        ],
        "sanitizers": [],
        "sinks": [
            "d",
            "e"
        ],
        "implicit": "no"
    }
    ]


    # Convert patterns from dicts to Pattern objects
    pattern_objects = []
    for p in patterns:
        pattern_objects.append(Pattern(
            name=p["vulnerability"],
            sources=set(p["sources"]),
            sanitizers=set(p["sanitizers"]),
            sinks=set(p["sinks"]),
            implicit=p["implicit"] == "yes"
        ))

    ast = esprima.parseScript(program, loc=True).toDict()

    # Debugging: Check patterns and their attributes
    print("Patterns Loaded:")
    for pattern in pattern_objects:
        print(f"Pattern: {pattern.name}, Sources: {pattern.sources}, Sinks: {pattern.sinks}")

    policy = Policy(pattern_objects)
    multilabelling = MultiLabelling()
    vulnerabilities = Vulnerabilities(policy)

    # Process the AST
    for stmt in ast['body']:
        if stmt['type'] == 'ExpressionStatement':
            process_statement_node(stmt['expression'], policy, multilabelling, vulnerabilities)

    # Output the results
    print("Detected Vulnerabilities:", vulnerabilities.get_vulnerabilities())
