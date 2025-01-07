import esprima
from Classes.Policy import Policy
from Classes.MultiLabelling import MultiLabelling
from Classes.Vulnerabilities import Vulnerabilities
from Classes.MultiLabel import MultiLabel
from Classes.Pattern import Pattern

def process_expression_node(node, policy: Policy, multilabelling: MultiLabelling, vulnerabilities: Vulnerabilities, pc_level: MultiLabel):
    """
    Processes an AST expression node to determine the MultiLabel describing the information returned.
    Includes pc_level for implicit flows.
    """
    if node['type'] == 'Identifier':
        var_name = node['name']
        return multilabelling.get_multilabel(var_name).combine(pc_level)

    elif node['type'] == 'Literal':
        return MultiLabel()  # Literals have no sources or sanitizers

    elif node['type'] == 'BinaryExpression':
        left_label = process_expression_node(node['left'], policy, multilabelling, vulnerabilities, pc_level)
        right_label = process_expression_node(node['right'], policy, multilabelling, vulnerabilities, pc_level)
        return left_label.combine(right_label)

    elif node['type'] == 'CallExpression':
        args_labels = [
            process_expression_node(arg, policy, multilabelling, vulnerabilities, pc_level)
            for arg in node.get('arguments', [])
        ]
        combined_args_label = MultiLabel()
        for label in args_labels:
            combined_args_label = combined_args_label.combine(label)

        # Check for sinks
        callee = node['callee']
        if callee['type'] == 'Identifier':
            function_name = callee['name']
            for pattern_name in policy.get_vulnerability_names():
                pattern = policy.patterns[pattern_name]
                if pattern.is_sink(function_name):
                    illegal_flows = policy.detect_illegal_flows(function_name, combined_args_label)
                    if illegal_flows.mapping:
                        vulnerabilities.report_illegal_flow(function_name, illegal_flows)

        return combined_args_label

    elif node['type'] == 'AssignmentExpression':
        target_label = process_expression_node(node['right'], policy, multilabelling, vulnerabilities, pc_level)
        if node['left']['type'] == 'Identifier':
            var_name = node['left']['name']
            multilabelling.update_multilabel(var_name, target_label)
        return target_label

    elif node['type'] == 'MemberExpression':
        object_label = process_expression_node(node['object'], policy, multilabelling, vulnerabilities, pc_level)
        return object_label  # Simplified; property is usually static

    elif node['type'] == 'UnaryExpression':
        return process_expression_node(node['argument'], policy, multilabelling, vulnerabilities, pc_level)

    else:
        return MultiLabel()

def process_statement_node(node, policy: Policy, multilabelling: MultiLabelling, vulnerabilities: Vulnerabilities, pc_level=None, max_while_iterations=3):
    """
    Processes an AST statement node considering pc_level for implicit flows.
    """
    if pc_level is None:
        pc_level = MultiLabel()

    if node['type'] == 'ExpressionStatement':
        process_expression_node(node['expression'], policy, multilabelling, vulnerabilities, pc_level)
        return multilabelling

    elif node['type'] == 'VariableDeclaration':
        for declaration in node.get('declarations', []):
            if declaration['type'] == 'VariableDeclarator':
                var_name = declaration['id']['name']
                if 'init' in declaration:
                    multilabel = process_expression_node(declaration['init'], policy, multilabelling, vulnerabilities, pc_level)
                    multilabelling.update_multilabel(var_name, multilabel)
        return multilabelling

    elif node['type'] == 'IfStatement':
        condition_label = process_expression_node(node['test'], policy, multilabelling, vulnerabilities, pc_level)
        condition_pc_level = pc_level.combine(condition_label)

        consequent_labelling = process_statement_node(
            node['consequent'], policy, multilabelling.deep_copy(), vulnerabilities, condition_pc_level
        )

        if 'alternate' in node and node['alternate']:
            alternate_labelling = process_statement_node(
                node['alternate'], policy, multilabelling.deep_copy(), vulnerabilities, condition_pc_level
            )
        else:
            alternate_labelling = multilabelling

        return consequent_labelling.combine(alternate_labelling)

    elif node['type'] == 'WhileStatement':
        condition_label = process_expression_node(node['test'], policy, multilabelling, vulnerabilities, pc_level)
        condition_pc_level = pc_level.combine(condition_label)

        loop_labelling = multilabelling.deep_copy()
        for _ in range(max_while_iterations):
            loop_labelling = process_statement_node(
                node['body'], policy, loop_labelling, vulnerabilities, condition_pc_level
            )
            loop_labelling = multilabelling.combinor(loop_labelling)

        return loop_labelling

    elif node['type'] == 'BlockStatement':
        for stmt in node.get('body', []):
            multilabelling = process_statement_node(stmt, policy, multilabelling, vulnerabilities, pc_level)
        return multilabelling

    elif node['type'] == 'AssignmentExpression':
        target_label = process_expression_node(node['right'], policy, multilabelling, vulnerabilities, pc_level)
        if node['left']['type'] == 'Identifier':
            var_name = node['left']['name']
            multilabelling.update_multilabel(var_name, target_label)
        return multilabelling

    else:
        return multilabelling


if __name__ == "__main__":
    program = '''
    var a = "";
    var b = c();
    if (a) {
        d(a);
    } else {
        e(b);
    }
    '''

    patterns = [
        {
            "vulnerability": "A",
            "sources": ["c"],
            "sanitizers": [],
            "sinks": ["d", "e"],
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

    ast = esprima.parseScript(program, loc=True).toDict()
    for stmt in ast['body']:
        process_statement_node(stmt, policy, multilabelling, vulnerabilities)

    print("Detected Vulnerabilities:", vulnerabilities.get_vulnerabilities())
