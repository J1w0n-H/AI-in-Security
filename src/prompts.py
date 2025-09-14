API_LABELLING_SYSTEM_PROMPT = """\
You are a security expert. \
You are given a list of APIs to be labeled as potential taint sources, sinks, or APIs that propagate taints. \
Taint sources are values that an attacker can use for unauthorized and malicious operations when interacting with the system. \
Taint source APIs usually return strings or custom object types. Setter methods are typically NOT taint sources. \
Taint sinks are program points that can use tainted data in an unsafe way, which directly exposes vulnerability under attack. \
Taint propagators carry tainted information from input to the output without sanitization, and typically have non-primitive input and outputs. \
Return the result as a json list with each object in the format:

{ "package": <package name>,
  "class": <class name>,
  "method": <method name>,
  "signature": <signature of the method>,
  "sink_args": <list of arguments or `this`; empty if the API is not sink>,
  "type": <"source", "sink", or "taint-propagator"> }

DO NOT OUTPUT ANYTHING OTHER THAN JSON.\
"""

API_LABELLING_USER_PROMPT = """\
{cwe_long_description}

Some example source/sink/taint-propagator methods are:
{cwe_examples}

Among the following methods, \
assuming that the arguments passed to the given function is malicious, \
what are the functions that are potential source, sink, or taint-propagators to {cwe_description} attack (CWE-{cwe_id})?

Package,Class,Method,Signature
{methods}
"""
# 추가된 부분 from here
API_LABELLING_USER_PROMPT_WITH_ENV = """\
{cwe_long_description}

Some example source/sink/taint-propagator methods are:
{cwe_examples}

ENVIRONMENT-SPECIFIC ANALYSIS EXAMPLES:
{environment_examples}

CURRENT ANALYSIS TASK:
Environment: {env_os} ({env_distro}), {env_java}, Security: SELinux={env_selinux}, AppArmor={env_apparmor}

Based on the examples above, analyze the following methods considering the {env_os} environment:

Package,Class,Method,Signature
{methods}

Provide your analysis following the same format as the examples, considering:
1. {env_os}-specific file system behavior
2. Security mechanisms and their protective effects
3. Runtime-specific considerations
4. Platform-specific attack vectors
"""

# 2단계: 환경 인지형 LLM 판정 프롬프트 추가
ENVIRONMENT_AWARE_VULNERABILITY_PROMPT = """\
You are a security expert analyzing a potential vulnerability in a specific environment.

[CODE SUMMARY]:
Source: {source_location}
Sink: {sink_location}
Flow: {flow_summary}
Intermediate Functions: {intermediate_functions}
Sanitizers Applied: {sanitizers_applied}

[ENVIRONMENT SUMMARY]:
Operating System: {env_os} ({env_distro})
Runtime: {env_runtime}
Build Tools: {env_build_tools}
Database: {env_database}
Security Policies: {env_security_policies}
File System: {env_filesystem}
Containerized: {env_containerized}

[ANALYSIS QUESTIONS]:
1) Is this SINK actually dangerous in this specific environment? (e.g., shell metacharacter interpretation, symlink/UNC/ADS handling, autoescape version compatibility)
2) Are the SANITIZERS effective in this environment? (version/policy-based neutralization)
3) What is the exploitability considering the environment context?

[REQUIRED OUTPUT FORMAT]:
Label: {VULNERABLE_CONFIRMED, ENVIRONMENT_SAFE, UNCERTAIN_NEEDS_TESTING}
Confidence: {HIGH, MEDIUM, LOW}
Reasoning: [Brief explanation of why this label was chosen based on environment context]
Environment Factors: [Specific environment aspects that influenced the decision]
Rule IDs: [If any environment rules apply, list them]

Analyze the vulnerability considering the specific environment context provided above.
"""
# Few-Shot Learning 예시 데이터
ENVIRONMENT_FEW_SHOT_EXAMPLES = {
    "windows_path_traversal": """
EXAMPLE 1 - Windows Path Traversal Analysis:
Environment: Windows 10, NTFS, Java 11
Vulnerability: Path Traversal (CWE-022)
Method: java.io.File(String pathname)

Analysis:
- Windows uses backslash (\) as path separator
- NTFS supports Alternate Data Streams (ADS) which can bypass simple path validation
- UNC paths (\\server\share) can access remote resources
- Windows security policies may not protect against all traversal attacks

Conclusion: HIGH RISK on Windows due to ADS and UNC path support
""",
    
    "linux_path_traversal": """
EXAMPLE 2 - Linux Path Traversal Analysis:
Environment: Ubuntu 22.04, ext4, Java 11, AppArmor enabled
Vulnerability: Path Traversal (CWE-022)
Method: java.io.File(String pathname)

Analysis:
- Linux uses forward slash (/) as path separator
- Symbolic links can be used for directory traversal
- AppArmor provides additional protection against file access
- ext4 file system has different behavior than NTFS

Conclusion: MEDIUM RISK on Linux due to AppArmor protection but symlink risks remain
""",
    
    "windows_command_injection": """
EXAMPLE 3 - Windows Command Injection Analysis:
Environment: Windows 10, cmd.exe, Java 11
Vulnerability: Command Injection (CWE-078)
Method: Runtime.exec(String command)

Analysis:
- Windows cmd.exe interprets &, |, <, > as command separators
- PowerShell has different syntax and security model
- Windows process creation is different from Unix fork/exec
- UseShellExecute parameter affects security

Conclusion: HIGH RISK on Windows due to shell interpretation
""",
    
    "linux_command_injection": """
EXAMPLE 4 - Linux Command Injection Analysis:
Environment: Ubuntu 22.04, bash, Java 11, AppArmor enabled
Vulnerability: Command Injection (CWE-078)
Method: Runtime.exec(String command)

Analysis:
- Linux bash interprets $, `, |, & as special characters
- AppArmor can restrict command execution
- Process isolation and containerization provide protection
- Different shell behaviors (bash vs sh)

Conclusion: MEDIUM RISK on Linux due to AppArmor but shell interpretation risks remain
"""
}

def get_relevant_examples(env_os, vulnerability_type):
    """Get relevant few-shot examples for the given environment and vulnerability type."""
    examples = []
    
    # Path traversal examples
    if "path" in vulnerability_type.lower() or "traversal" in vulnerability_type.lower():
        if env_os.lower() == "windows":
            examples.append(ENVIRONMENT_FEW_SHOT_EXAMPLES["windows_path_traversal"])
        else:
            examples.append(ENVIRONMENT_FEW_SHOT_EXAMPLES["linux_path_traversal"])
    
    # Command injection examples
    if "command" in vulnerability_type.lower() or "injection" in vulnerability_type.lower():
        if env_os.lower() == "windows":
            examples.append(ENVIRONMENT_FEW_SHOT_EXAMPLES["windows_command_injection"])
        else:
            examples.append(ENVIRONMENT_FEW_SHOT_EXAMPLES["linux_command_injection"])
    
    return "\n".join(examples)

# 추가된 부분 to here
FUNC_PARAM_LABELLING_SYSTEM_PROMPT = """\
You are a security expert. \
You are given a list of APIs implemented in established Java libraries, \
and you need to identify whether some of these APIs could be potentially invoked by downstream libraries with malicious end-user (not programmer) inputs. \
For instance, functions that deserialize or parse inputs might be used by downstream libraries and would need to add sanitization for malicious user inputs. \
On the other hand, functions like HTTP request handlers are typically final and won't be called by a downstream package. \
Utility functions that are not related to the primary purpose of the package should also be ignored. \
Return the result as a json list with each object in the format:

{ "package": <package name>,
  "class": <class name>,
  "method": <method name>,
  "signature": <signature>,
  "tainted_input": <a list of argument names that are potentially tainted> }

In the result list, only keep the functions that might be used by downstream libraries and is potentially invoked with malicious end-user inputs. \
Do not output anything other than JSON.\
"""

FUNC_PARAM_LABELLING_USER_PROMPT = """\
You are analyzing the Java package {project_username}/{project_name}. \
Here is the package summary:

{project_readme_summary}

Please look at the following public methods in the library and their documentations (if present). \
What are the most important functions that look like can be invoked by a downstream Java package that is dependent on {project_name}, \
and that the function can be called with potentially malicious end-user inputs? \
If the package does not seem to be a library, just return empty list as the result. \
Utility functions that are not related to the primary purpose of the package should also be ignored

Package,Class,Method,Doc
{methods}
"""

POSTHOC_FILTER_SYSTEM_PROMPT = """\
You are an expert in detecting security vulnerabilities. \
You are given the starting point (source) and the ending point (sink) of a dataflow path in a Java project that may be a potential vulnerability. \
Analyze the given taint source and sink and predict whether the given dataflow can be part of a vulnerability or not, and store it as a boolean in "is_vulnerable". \
Note that, the source must be either a) the formal parameter of a public library function which might be invoked by a downstream package, or b) the result of a function call that returns tainted input from end-user. \
If the given source or sink do not satisfy the above criteria, mark the result as NOT VULNERABLE. \
Please provide a very short explanation associated with the verdict. \
Assume that the intermediate path has no sanitizer.

Answer in JSON object with the following format:

{ "explanation": <YOUR EXPLANATION>,
  "source_is_false_positive": <true or false>,
  "sink_is_false_positive": <true or false>,
  "is_vulnerable": <true or false> }

Do not include anything else in the response.\
"""

POSTHOC_FILTER_USER_PROMPT = """\
Analyze the following dataflow path in a Java project and predict whether it contains a {cwe_description} vulnerability ({cwe_id}), or a relevant vulnerability.
{hint}

Source ({source_msg}):
```
{source}
```

Steps:
{intermediate_steps}

Sink ({sink_msg}):
```
{sink}
```\
"""

POSTHOC_FILTER_USER_PROMPT_W_CONTEXT = """\
Analyze the following dataflow path in a Java project and predict whether it contains a {cwe_description} vulnerability ({cwe_id}), or a relevant vulnerability.
{hint}

Source ({source_msg}):
```
{source}
```

Steps:
{intermediate_steps}

Sink ({sink_msg}):
```
{sink}
```

{context}\
"""
# The key should be the CWE number without any string prefixes.
# The value should be sentences describing more specific details for detecting the CWE.
POSTHOC_FILTER_HINTS = {
    "022": "Note: please be careful about defensing against absolute paths and \"..\" paths. Just canonicalizing paths might not be sufficient for the defense.",
    "078": "Note that other than typical Runtime.exec which is directly executing command, using Java Reflection to create dynamic objects with unsanitized inputs might also cause OS Command injection vulnerability. This includes deserializing objects from untrusted strings and similar functionalities. Writing to config files about library data may also induce unwanted execution of OS commands.",
    "079": "Please be careful about reading possibly tainted HTML input. During sanitization, do not assume the sanitization to be sufficient.",
    "094": "Please note that dubious error messages can sometimes be handled by downstream code for execution, resulting in CWE-094 vulnerability. Injection of malicious values might lead to arbitrary code execution as well.",
    "089": "Please be careful about reading possibly tainted SQL input. Look for SQL queries that are constructed using string concatenation or similar methods without proper sanitization.",
    "918": "Server-Side Request Forgery occurs when untrusted input controls the target of an outgoing HTTP or other protocol request. Watch for user input flowing into URL constructors, HTTP client execute/connect methods, or SSRF-related libraries without validation.",
    "502": "Be cautious of calls to deserialization methods like `readObject()` or `deserialize()` when passed data from untrusted sources. Attackers may craft malicious object graphs or gadget chains to trigger unexpected behavior or even remote code execution. Check if class allowlisting or validation is in place. Avoid deserializing directly from network input or unvalidated byte arrays.",
    "807": "Pay special attention to cases where user-controlled input is directly used in permission checks (e.g., permission strings or resource identifiers). Focus on whether permission checks (such as Subject.isPermitted or similar APIs) rely on tainted or untrusted data, which may allow privilege escalation or unauthorized access.",
    "352": "Check if the JSONP callback parameter is validated or restricted. Unchecked callback parameters may allow attackers to inject arbitrary JavaScript, leading to CSRF or data theft."
}

SNIPPET_CONTEXT_SIZE = 4
