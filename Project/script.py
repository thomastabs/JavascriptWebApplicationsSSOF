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


def analyze_ast(ast_dict, patterns):
    results = []
    # Perform static analysis logic
    for pattern in patterns:
        vulnerability = pattern["vulnerability"]
        sources = pattern["sources"]
        sinks = pattern["sinks"]
        sanitizers = pattern["sanitizers"]
        implicit_flag = pattern["implicit"]
        
        # Traverse AST to find matches
        # Example logic for source-to-sink detection
        for source in sources:
            for sink in sinks:
                # Check flow and sanitization here
                # Append results to 'results'
                pass
    return results



# Load inputs
ast_dict = esprima.parseScript(program, loc = True).toDict()
ast_json = json.dumps(ast_dict, indent=2)


# Analyze AST
results = analyze_ast(ast_dict, patterns)






