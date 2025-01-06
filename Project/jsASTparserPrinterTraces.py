def traverse_ast_traces(node, trace, max_while_iterations=3, indent_level=0):
    indent = '  ' * indent_level

    if isinstance(node, dict) and 'type' in node:
        node_type = node['type']

        # Print the current node type and line
        if 'loc' in node and 'start' in node['loc']:
            trace.append(f"{indent}{node_type} (Line {node['loc']['start']['line']})")
        else:
            trace.append(f"{indent}{node_type}")

        # Recursively process children based on node type
        if node_type == 'Program':
            for stmt in node.get('body', []):
                traverse_ast_traces(stmt, trace, max_while_iterations, indent_level + 1)

        elif node_type == 'VariableDeclaration':
            for declaration in node.get('declarations', []):
                traverse_ast_traces(declaration, trace, max_while_iterations, indent_level + 1)

        elif node_type == 'VariableDeclarator':
            traverse_ast_traces(node.get('id'), trace, max_while_iterations, indent_level + 1)
            traverse_ast_traces(node.get('init'), trace, max_while_iterations, indent_level + 1)

        elif node_type == 'ExpressionStatement':
            traverse_ast_traces(node.get('expression'), trace, max_while_iterations, indent_level + 1)

        elif node_type == 'WhileStatement':
            condition = node.get('test')
            body = node.get('body')

            # Simulate loop iterations up to max_while_iterations
            for i in range(max_while_iterations):
                trace.append(f"{indent}While loop iteration {i + 1} (Condition at line {condition['loc']['start']['line']})")
                traverse_ast_traces(body, trace, max_while_iterations, indent_level + 1)

        elif node_type == 'IfStatement':
            test = node.get('test')
            consequent = node.get('consequent')
            alternate = node.get('alternate')

            trace.append(f"{indent}If condition at line {test['loc']['start']['line']}")
            traverse_ast_traces(test, trace, max_while_iterations, indent_level + 1)

            trace.append(f"{indent}Then branch:")
            traverse_ast_traces(consequent, trace, max_while_iterations, indent_level + 1)

            if alternate:
                trace.append(f"{indent}Else branch:")
                traverse_ast_traces(alternate, trace, max_while_iterations, indent_level + 1)

        elif node_type == 'UnaryExpression':
            trace.append(f"{indent}Unary operation: {node['operator']} (Line {node['loc']['start']['line']})")
            traverse_ast_traces(node.get('argument'), trace, max_while_iterations, indent_level + 1)

        elif node_type == 'BlockStatement':
            for stmt in node.get('body', []):
                traverse_ast_traces(stmt, trace, max_while_iterations, indent_level + 1)

        elif node_type == 'CallExpression':
            traverse_ast_traces(node.get('callee'), trace, max_while_iterations, indent_level + 1)
            for arg in node.get('arguments', []):
                traverse_ast_traces(arg, trace, max_while_iterations, indent_level + 1)

        elif node_type == 'AssignmentExpression':
            traverse_ast_traces(node.get('left'), trace, max_while_iterations, indent_level + 1)
            traverse_ast_traces(node.get('right'), trace, max_while_iterations, indent_level + 1)

        elif node_type == 'MemberExpression':
            traverse_ast_traces(node.get('object'), trace, max_while_iterations, indent_level + 1)
            traverse_ast_traces(node.get('property'), trace, max_while_iterations, indent_level + 1)

        elif node_type == 'BinaryExpression':
            traverse_ast_traces(node.get('left'), trace, max_while_iterations, indent_level + 1)
            traverse_ast_traces(node.get('right'), trace, max_while_iterations, indent_level + 1)

        elif node_type == 'Identifier':
            trace.append(f"{indent}Identifier: {node['name']} (Line {node['loc']['start']['line']})")

        elif node_type == 'Literal':
            trace.append(f"{indent}Literal: {node['value']} (Line {node['loc']['start']['line']})")

    elif isinstance(node, list):
        for child in node:
            traverse_ast_traces(child, trace, max_while_iterations, indent_level)

# Example program
program = '''
var pos = document.URL.indexOf("name=");
var name = document.URL.substring(pos + 5);
while (name) {
  document.write(name);
  name = name.substring(0, name.length - 1);
}
document.write("done");
'''

import esprima
ast_dict = esprima.parseScript(program, loc=True).toDict()

# Initialize and print the trace
initial_trace = []
traverse_ast_traces(ast_dict, initial_trace)

for line in initial_trace:
    print(line)
