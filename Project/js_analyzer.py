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
var pos = document.URL.indexOf("name=");
var name = document.URL.substring(pos + 5);
document.write(name);
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
    if "callee" in node and "arguments" in node:
        callee = node["callee"]
        args = node["arguments"]

        # Handle sources like document.URL.substring
        if callee["type"] == "MemberExpression":
            obj = callee["object"]
            prop = callee["property"]
            if obj["type"] == "Identifier" and obj["name"] == "document":
                if prop["type"] == "Identifier" and prop["name"] in sources:
                    # Propagate taint to the arguments of the call
                    for arg in args:
                        if arg["type"] == "Identifier":
                            taint_set["variables"].add(arg["name"])
                            print(f"Taint added to variable (CallExpression): {arg['name']}")
                        traverse_ast(arg, sources)
        elif callee["type"] == "Identifier" and callee["name"] in sources:
            # Propagate taint directly
            for arg in args:
                if arg["type"] == "Identifier":
                    taint_set["variables"].add(arg["name"])
                    print(f"Source detected in CallExpression: {callee['name']} -> {arg['name']}")
                traverse_ast(arg, sources)


def handle_member_expression(node, sources):
    if "object" in node and "property" in node:
        if node["object"]["type"] == "Identifier" and node["object"]["name"] == "document":
            if node["property"]["type"] == "Identifier" and node["property"]["name"] in sources:
                taint_set["variables"].add(node["property"]["name"])
                print(f"Source detected (MemberExpression): {node['property']['name']}")
        
def handle_assignment_expression(node, sources):
    if "right" in node:
        rhs = node["right"]
        lhs = node["left"]["name"] if "left" in node and "name" in node["left"] else None

        if rhs["type"] == "MemberExpression" and "object" in rhs and "property" in rhs:
            # Handle cases like var pos = document.URL.indexOf("name=");
            obj = rhs["object"]
            prop = rhs["property"]
            if obj["type"] == "Identifier" and obj["name"] == "document":
                if prop["type"] == "Identifier" and prop["name"] in sources:
                    taint_set["variables"].add(lhs)
                    print(f"Source detected in AssignmentExpression: {lhs}")

        elif rhs["type"] == "Identifier" and rhs["name"] in taint_set["variables"]:
            # Propagate taint from RHS to LHS
            taint_set["variables"].add(lhs)
            print(f"Taint propagated from {rhs['name']} to {lhs}")

        elif rhs["type"] == "CallExpression":
            # Analyze the call expression for taint propagation
            handle_call_expression(rhs, sources)


def handle_block_statement(node, sources):
    if "body" in node:
        for stmt in node["body"]:
            traverse_ast(stmt, sources)

def handle_expression_statement(node, sources):
    if "expression" in node:
        traverse_ast(node["expression"], sources)

def handle_return_statement(node, sources):
    if "argument" in node:
        traverse_ast(node["argument"], sources)

def handle_if_statement(node, sources):
    if "test" in node and node["test"]["type"] == "Identifier" and node["test"]["name"] in sources:
        taint_set["variables"].add(node["test"]["name"])
        print(f"Source detected (IfStatement): {node['test']['name']}")
    if "consequent" in node:
        traverse_ast(node["consequent"], sources)
    if "alternate" in node and node["alternate"]:
        traverse_ast(node["alternate"], sources)

def handle_while_statement(node, sources):
    if "test" in node and node["test"]["type"] == "Identifier" and node["test"]["name"] in sources:
        taint_set["variables"].add(node["test"]["name"])
        print(f"Source detected (WhileStatement): {node['test']['name']}")
    if "body" in node:
        traverse_ast(node["body"], sources)

def handle_sink(node, patterns):
    if "callee" in node and "arguments" in node:
        callee = node["callee"]
        args = node["arguments"]

        for vulnerability in patterns:
            if callee["type"] == "MemberExpression":
                # Check if sink matches
                if callee["property"]["name"] in vulnerability["sinks"]:
                    for arg in args:
                        if arg["type"] == "Identifier" and arg["name"] in taint_set["variables"]:
                            taint_set["flows"].append({
                                "vulnerability": vulnerability["vulnerability"],
                                "source": arg["name"],
                                "sink": callee["property"]["name"],
                                "sanitized": arg["name"] in taint_set["sanitizers"]
                            })
                            print(f"Flow detected: {arg['name']} -> {callee['property']['name']}")
            elif callee["type"] == "Identifier" and callee["name"] in vulnerability["sinks"]:
                for arg in args:
                    if arg["type"] == "Identifier" and arg["name"] in taint_set["variables"]:
                        taint_set["flows"].append({
                            "vulnerability": vulnerability["vulnerability"],
                            "source": arg["name"],
                            "sink": callee["name"],
                            "sanitized": arg["name"] in taint_set["sanitizers"]
                        })
                        print(f"Flow detected: {arg['name']} -> {callee['name']}")

     

def initialize_taint_set(ast_dict, patterns):
    for vulnerability in patterns:
        sources = vulnerability["sources"]
        traverse_ast(ast_dict, sources)


def print_taint_set():
    print("Tainted variables:")
    print(taint_set["variables"])
    print("\nTracked flows:")
    print(taint_set["flows"])
    print("\nSanitizers applied:")
    print(taint_set["sanitizers"])



# Traverse the AST and analyze taint flows
def traverse_ast(node, sources):
    if isinstance(node, dict) and "type" in node:  # Ensure the node is a dict with "type" key
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
                handle_sink(node, patterns)  # Detect sinks in calls
            case "MemberExpression":
                handle_member_expression(node, sources)
                handle_sink(node, patterns)  # Detect sinks in member access
            case "AssignmentExpression":
                handle_assignment_expression(node, sources)
                handle_sink(node, patterns)  # Detect sinks in assignments
            case "BlockStatement":
                handle_block_statement(node, sources)
            case "ExpressionStatement":
                handle_expression_statement(node, sources)
                handle_sink(node, patterns)  # Detect sinks in direct expressions
            case "ReturnStatement":
                handle_return_statement(node, sources)
                handle_sink(node, patterns)  # Detect sinks in returned values
            case "IfStatement":
                handle_if_statement(node, sources)
            case "WhileStatement":
                handle_while_statement(node, sources)

        for key, value in node.items():
            if isinstance(value, dict):
                traverse_ast(value, sources)
            elif isinstance(value, list):
                for item in value:
                    if isinstance(item, dict):
                        traverse_ast(item, sources)   


# Add initial sources to taint_set
initialize_taint_set(ast_dict, patterns)
print_taint_set()
