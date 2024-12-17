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
var sanitizedName = DOMPurify.sanitize(name);
document.write(sanitizedName);
"""

patterns = [
    {
      "vulnerability": "Command Injection",
      "sources": ["req.headers", "readFile"],
      "sanitizers": ["shell-escape"],
      "sinks": ["exec", "execSync", "spawnSync", "execFileSync"],
      "implicit": "no"
    },
    {
      "vulnerability": "DOM XSS",
      "sources": ["document.referrer", "document.URL", "document.location"],
      "sanitizers": ["DOMPurify.sanitize"],
      "sinks": ["document.write", "innerHTML", "setAttribute"],
      "implicit": "yes"
    }
  ]


ast_dict = esprima.parseScript(program, loc = True).toDict()

##print(ast_dict)

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


def collect_sources(node, sources):
    if isinstance(node, dict):
        # Check if it's an Identifier
        if "type" in node and node["type"] == "Identifier":
            if node["name"] in sources:
                taint_set["variables"].add(node["name"])
                print(f"Source detected (Identifier): {node['name']}")
        
        # Check if it's a Property (e.g., document.URL)
        elif "type" in node and node["type"] == "MemberExpression":
            if node["object"]["type"] == "Identifier" and node["object"]["name"] == "document":
                if node["property"]["type"] == "Identifier" and node["property"]["name"] in sources:
                    taint_set["variables"].add(node["property"]["name"])
                    print(f"Source detected (Property): {node['property']['name']}")

        # Traverse child nodes
        for key, value in node.items():
            if isinstance(value, dict):
                collect_sources(value, sources)
            elif isinstance(value, list):
                for child in value:
                    if isinstance(child, dict):
                        collect_sources(child, sources)


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
        for vulnerability in patterns["vulnerabilities"]:
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


# Add initial sources to taint_set
initialize_taint_set(ast_dict, patterns)

# Traverse the AST and analyze taint flows
traverse_ast(ast_dict, patterns)

# Generate the output
generate_results()
