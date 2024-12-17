import esprima
import sys
import json

# Usage: python js_analyzer.py <path_to_program.js> <path_to_patterns.json>

#with open(sys.argv[1], 'r') as f:
#    program = f.read().strip()

#with open(sys.argv[2], 'r') as f:
#    patterns = json.loads(f.read().strip())

#program = open("foo/slice_1.js", "r").read()
#patterns = json.loads(open("bar/my_patterns.json", "r").read())

program = """
alert("Hello World!");
"""

patterns = [
    {
        "vulnerability": "DOM XSS",
        "sources": ["document.referrer", "document.URL", "document.location"],
        "sanitizers": ["DOMPurify.sanitize", "escapeHTML"],
        "sinks": ["document.write", "innerHTML", "outerHTML", "setAttribute"],
        "implicit": "yes"
    },
    {
        "vulnerability": "Stored/Reflected XSS",
        "sources": ["req.query", "req.body", "req.params", "req.headers"],
        "sanitizers": ["sanitizeInput", "escapeHTML"],
        "sinks": ["res.send", "res.write", "res.end", "setAttribute"],
        "implicit": "yes"
    },
    {
        "vulnerability": "SQL Injection",
        "sources": ["req.query", "req.body", "req.params"],
        "sanitizers": ["escape", "mysql.escape", "sequelize.escape"],
        "sinks": ["db.query", "db.execute", "sequelize.query", "connection.query"],
        "implicit": "no"
    },
    {
        "vulnerability": "Command Injection",
        "sources": ["req.query", "req.body", "req.params", "req.headers", "readFile"],
        "sanitizers": ["shell-escape"],
        "sinks": ["exec", "execSync", "spawn", "spawnSync", "execFile", "execFileSync"],
        "implicit": "no"
    },
    {
        "vulnerability": "Path Traversal",
        "sources": ["req.query", "req.body", "req.params", "req.headers"],
        "sanitizers": ["path.normalize", "sanitizePath"],
        "sinks": ["fs.readFile", "fs.readFileSync", "fs.createReadStream"],
        "implicit": "no"
    },
    {
        "vulnerability": "Insecure Deserialization",
        "sources": ["req.body", "req.query", "req.params"],
        "sanitizers": ["safeParse", "JSON.parseSafe"],
        "sinks": ["eval", "Function", "vm.runInContext", "vm.runInNewContext"],
        "implicit": "no"
    },
    {
        "vulnerability": "Open Redirect",
        "sources": ["req.query", "req.body", "req.params"],
        "sanitizers": ["validateURL", "url.parse"],
        "sinks": ["res.redirect", "location.assign", "window.location"],
        "implicit": "no"
    },
    {
        "vulnerability": "File Upload Vulnerability",
        "sources": ["req.files", "req.body.file", "req.body.image"],
        "sanitizers": ["validateFileType", "fileTypeCheck"],
        "sinks": ["fs.writeFile", "fs.writeFileSync", "fs.createWriteStream"],
        "implicit": "no"
    },
    {
        "vulnerability": "Server-Side Request Forgery (SSRF)",
        "sources": ["req.query", "req.body", "req.params"],
        "sanitizers": ["validateURL", "sanitizeInput"],
        "sinks": ["http.request", "https.request", "axios", "fetch"],
        "implicit": "no"
    },
    {
        "vulnerability": "Prototype Pollution",
        "sources": ["req.body", "req.query", "req.params"],
        "sanitizers": ["safeAssign", "deepClone"],
        "sinks": ["Object.assign", "Object.setPrototypeOf", "_.merge", "_.set"],
        "implicit": "no"
    },
    {
        "vulnerability": "NoSQL Injection",
        "sources": ["req.query", "req.body", "req.params"],
        "sanitizers": ["mongoSanitize", "validateInput"],
        "sinks": ["db.find", "db.findOne", "db.update", "db.delete"],
        "implicit": "no"
    }
]


ast_dict = esprima.parseScript(program, loc = True).toDict()

print(ast_dict)

taint_set = {
    "variables": set(),  # Tainted variable names
    "flows": list(),     # Tracked flows (source -> sink)
    "sanitizers": dict() # Maps variables to sanitizers applied
}


# Add initial sources to taint_set
def initialize_taint_set(ast_dict, patterns):
    for vulnerability in patterns:
        sources = vulnerability["sources"]
        collect_sources(ast_dict, sources)


def handle_literal(node, sources):
    if "value" in node and node["value"] in sources:
        taint_set["variables"].add(node["value"])
        print(f"Source detected (Literal): {node['value']}")


def handle_identifier(node, sources):
    if "name" in node and node["name"] in sources:
        taint_set["variables"].add(node["name"])
        print(f"Source detected (Identifier): {node['name']}")


def handle_unary_expression(node, sources):
    if "argument" in node and node["argument"]["type"] == "Identifier" and node["argument"]["name"] in sources:
        taint_set["variables"].add(node["argument"]["name"])
        print(f"Source detected (UnaryExpression): {node['argument']['name']}")


def handle_binary_expression(node, sources):
    if "left" in node and node["left"]["type"] == "Identifier" and node["left"]["name"] in sources:
        taint_set["variables"].add(node["left"]["name"])
        print(f"Source detected (BinaryExpression - Left): {node['left']['name']}")
    if "right" in node and node["right"]["type"] == "Identifier" and node["right"]["name"] in sources:
        taint_set["variables"].add(node["right"]["name"])
        print(f"Source detected (BinaryExpression - Right): {node['right']['name']}")


def handle_call_expression(node, sources):
    if "callee" in node:
        if node["callee"]["type"] == "MemberExpression":
            obj = node["callee"]["object"]
            prop = node["callee"]["property"]
            if obj["type"] == "Identifier" and obj["name"] == "document":
                if prop["type"] == "Identifier" and prop["name"] in sources:
                    taint_set["variables"].add(prop["name"])
                    print(f"Source detected (CallExpression - MemberExpression): {prop['name']}")
        elif node["callee"]["type"] == "Identifier" and node["callee"]["name"] in sources:
            taint_set["variables"].add(node["callee"]["name"])
            print(f"Source detected (CallExpression): {node['callee']['name']}")
    if "arguments" in node:
        for arg in node["arguments"]:
            collect_sources(arg, sources)


def handle_member_expression(node, sources):
    if "object" in node and "property" in node:
        if node["object"]["type"] == "Identifier" and node["object"]["name"] == "document":
            if node["property"]["type"] == "Identifier" and node["property"]["name"] in sources:
                taint_set["variables"].add(node["property"]["name"])
                print(f"Source detected (MemberExpression): {node['property']['name']}")


def handle_assignment_expression(node, sources):
    if "right" in node and node["right"]["type"] == "Identifier" and node["right"]["name"] in sources:
        taint_set["variables"].add(node["right"]["name"])
        print(f"Source detected (AssignmentExpression): {node['right']['name']}")


def handle_block_statement(node, sources):
    if "body" in node:
        for stmt in node["body"]:
            collect_sources(stmt, sources)


def handle_expression_statement(node, sources):
    if "expression" in node:
        collect_sources(node["expression"], sources)


def handle_if_statement(node, sources):
    if "test" in node and node["test"]["type"] == "Identifier" and node["test"]["name"] in sources:
        taint_set["variables"].add(node["test"]["name"])
        print(f"Source detected (IfStatement): {node['test']['name']}")
    if "consequent" in node:
        collect_sources(node["consequent"], sources)
    if "alternate" in node and node["alternate"]:
        collect_sources(node["alternate"], sources)


def handle_while_statement(node, sources):
    if "test" in node and node["test"]["type"] == "Identifier" and node["test"]["name"] in sources:
        taint_set["variables"].add(node["test"]["name"])
        print(f"Source detected (WhileStatement): {node['test']['name']}")
    if "body" in node:
        collect_sources(node["body"], sources)


def collect_sources(node, sources):
    """Main function to dispatch handling based on node type."""
    if isinstance(node, dict) and "type" in node:
        match node["type"]:
            case "Literal":
                handle_literal(node, sources)
            case "Identifier":
                handle_identifier(node, sources)
            case "UnaryExpression":
                handle_unary_expression(node, sources)
            case "BinaryExpression":
                handle_binary_expression(node, sources)
            case "CallExpression":
                handle_call_expression(node, sources)
            case "MemberExpression":
                handle_member_expression(node, sources)
            case "AssignmentExpression":
                handle_assignment_expression(node, sources)
            case "BlockStatement":
                handle_block_statement(node, sources)
            case "ExpressionStatement":
                handle_expression_statement(node, sources)
            case "IfStatement":
                handle_if_statement(node, sources)
            case "WhileStatement":
                handle_while_statement(node, sources)

    # Traverse all children of the current node
    for key, value in node.items():
        if isinstance(value, dict):
            collect_sources(value, sources)
        elif isinstance(value, list):
            for child in value:
                if isinstance(child, dict):
                    collect_sources(child, sources)





'''
# Update sanitization logic
def handle_assignment(node, patterns):
    lhs = node["left"]["name"]
    rhs = node["right"]

    # Check if RHS is tainted and apply sanitization
    if rhs["type"] == "Identifier" and rhs["name"] in taint_set["variables"]:
        taint_set["variables"].add(lhs)
        print(f"Tainted variable: {lhs}")  # Debugging line

    # Check if sanitizer is applied to a variable
    if rhs["type"] == "CallExpression" and rhs["callee"]["name"] in taint_set["sanitizers"]:
        for arg in rhs["arguments"]:
            if arg["type"] == "Identifier" and arg["name"] in taint_set["variables"]:
                # Sanitize the variable
                taint_set["variables"].remove(arg["name"])
                print(f"Sanitized variable: {arg['name']}")  # Debugging line



def handle_call(node, patterns):
    if "callee" in node and "name" in node["callee"]:
        func_name = node["callee"]["name"]
    else:
        func_name = None

    if func_name:
        for vulnerability in patterns:
            if func_name in vulnerability["sinks"]:
                # Check if arguments are tainted
                for arg in node["arguments"]:
                    if arg["type"] == "Identifier" and arg["name"] in taint_set["variables"]:
                        taint_set["flows"].append({
                            "vulnerability": vulnerability["vulnerability"],
                            "source": arg["name"],
                            "sink": func_name,
                            "sanitized": False
                        })
                        print(f"Flow detected: {arg['name']} -> {func_name}")  # Debugging line




# Handle if statements
def handle_if(node, patterns):
    condition = node["test"]

    # If the condition variable is tainted, propagate to the block
    if condition["type"] == "Identifier" and condition["name"] in taint_set["variables"]:
        for stmt in node["consequent"]["body"]:
            traverse_ast(stmt, patterns)
        if "alternate" in node and node["alternate"]:
            for stmt in node["alternate"]["body"]:
                traverse_ast(stmt, patterns)


# Traverse the AST and analyze taint flows
def traverse_ast(node, patterns):
    if isinstance(node, dict) and "type" in node:  # Ensure the node is a dict with "type" key
        if node["type"] == "AssignmentExpression":
            handle_assignment(node, patterns)
        elif node["type"] == "CallExpression":
            handle_call(node, patterns)
        elif node["type"] == "IfStatement":
            handle_if(node, patterns)
        elif node["type"] == "BlockStatement":
            for stmt in node["body"]:
                traverse_ast(stmt, patterns)
        # Handle other constructs as needed

        # Recursively process child nodes
        for key, value in node.items():
            if isinstance(value, dict):
                traverse_ast(value, patterns)
            elif isinstance(value, list):
                for child in value:
                    if isinstance(child, dict):
                        traverse_ast(child, patterns)



# Generate the output
def generate_results():
    output = []
    for flow in taint_set["flows"]:
        sanitized_flows = []
        unsanitized_flows = "no"
        source = flow["source"]
        sink = flow["sink"]

        if source in taint_set["sanitizers"]:
            sanitized_flows.append([taint_set["sanitizers"][source]])
        else:
            unsanitized_flows = "yes"

        output.append({
            "vulnerability": flow["vulnerability"],
            "source": [source, -1],  # Line numbers can be added if available
            "sink": [sink, -1],
            "implicit_flows": "no",  # Update if implicit flows are found
            "unsanitized_flows": unsanitized_flows,
            "sanitized_flows": sanitized_flows if sanitized_flows else "none"
        })

        print(output)


    # Write output to file
    #output_file = f"./output/{sys.argv[1].split('/')[-1].replace('.js', '.output.json')}"
    #with open(output_file, "w") as f:
    #    json.dump(output, f, indent=4)

    '''

# Add initial sources to taint_set
initialize_taint_set(ast_dict, patterns)

# Traverse the AST and analyze taint flows
# traverse_ast(ast_dict, patterns)

# Generate the output
# generate_results()
