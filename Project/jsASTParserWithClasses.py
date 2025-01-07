import esprima
from Classes.Policy import Policy
from Classes.MultiLabelling import MultiLabelling
from Classes.Vulnerabilities import Vulnerabilities
from Classes.MultiLabel import MultiLabel
from Classes.Pattern import Pattern

# Function to process expressions
def process_expression_node(node, policy: Policy, multilabelling: MultiLabelling, vulnerabilities: Vulnerabilities):
    if node['type'] == 'Identifier':
        return multilabelling.get_multilabel(node['name'])
    elif node['type'] == 'Literal':
        return MultiLabel()
    elif node['type'] == 'BinaryExpression':
        left = process_expression_node(node['left'], policy, multilabelling, vulnerabilities)
        right = process_expression_node(node['right'], policy, multilabelling, vulnerabilities)
        combined = left.combine(right)
        print(f"Combined MultiLabels for BinaryExpression: {combined}")
        return combined
    elif node['type'] == 'CallExpression':
        print(f"Processing CallExpression: {node}")
        args = [process_expression_node(arg, policy, multilabelling, vulnerabilities) for arg in node['arguments']]
        combined_args = MultiLabel()
        for arg in args:
            combined_args = combined_args.combine(arg)
        callee = node['callee']
        if callee['type'] == 'Identifier':
            function_name = callee['name']
            print(f"Checking function: {function_name}")
            for pattern_name in policy.get_vulnerability_names():
                pattern = policy.patterns[pattern_name]
                print(f"Checking sink for pattern: {pattern_name}, Sinks: {pattern.get_sinks()}")
                if pattern.is_sink(function_name):
                    print(f"Detected sink match for function: {function_name}")
                    illegal_flows = policy.detect_illegal_flows(function_name, combined_args)
                    vulnerabilities.report_illegal_flow(function_name, illegal_flows)
        return combined_args
    else:
        return MultiLabel()

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

# Test the functions
if __name__ == "__main__":
    program = '''
    var a = 5;
    var b = a + 10;
    if (b > 15) {
        b = b + 1;
    } else {
        b = b - 1;
    }
    while (b > 0) {
        b = b - 1;
    }
    exec(b);
    '''

    patterns = [
        {
            "vulnerability": "Arithmetic Overflows",
            "sources": ["a", "b"],
            "sanitizers": [],
            "sinks": ["b > 15", "b > 0"],
            "implicit": "no"
        },
        {
            "vulnerability": "Command Injection",
            "sources": ["a", "b"],
            "sanitizers": ["shell-escape"],
            "sinks": ["exec"],
            "implicit": "yes"
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

    # Debugging: Initial MultiLabelling state
    print("Initial MultiLabelling:", multilabelling.mapping)

    # Process the AST
    for stmt in ast['body']:
        if stmt['type'] == 'ExpressionStatement':
            process_expression_node(stmt['expression'], policy, multilabelling, vulnerabilities)


