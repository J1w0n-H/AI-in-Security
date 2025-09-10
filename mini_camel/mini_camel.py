# mini_camel.py - Stage 1 Minimal Implementation
"""
Stage 1 implementation of CaMeL paper's core concepts, maximally simplified

Core ideas:
- Attach metadata to all data
- Metadata-based security policies
- Sandboxed execution environment
"""

from dataclasses import dataclass
from enum import Enum
from typing import Any, Dict

# 1. Metadata System (Paper: Complex frozenset-based capabilities → Simple enums)
class Source(Enum):
    """Data source: USER (untrusted), CAMEL (trusted), TOOL (generated)"""
    USER = "user"      # User input - untrusted
    CAMEL = "camel"    # System generated - trusted  
    TOOL = "tool"      # Tool output - trusted

class Reader(Enum):
    """Data access permissions: PUBLIC (accessible), PRIVATE (restricted)"""
    PUBLIC = "public"    # Can be used in operations
    PRIVATE = "private"  # Restricted access

@dataclass
class Capabilities:
    """Metadata attached to all data (Paper: complex frozenset → Simple enums)"""
    source: Source      # Where data came from
    reader: Reader      # Access permission level
    
    def is_public(self) -> bool:
        """Check if data is publicly accessible"""
        return self.reader == Reader.PUBLIC
    
    def is_trusted(self) -> bool:
        """Check if data is from trusted source (CAMEL system)"""
        return self.source == Source.CAMEL

@dataclass
class CaMeLValue:
    """All values carry metadata (Paper: complex CaMeLValue → Simple wrapper)"""
    value: Any                    # Actual data
    capabilities: Capabilities    # Metadata (source + permissions)
    
    def __repr__(self):
        return f"CaMeLValue({self.value!r}, {self.capabilities})"
    

# 2. Security Policy (Paper: Domain-specific policies → Single trust-based policy)
class SecurityPolicy:
    """Trust-based security policy (Paper: banking/workspace/slack → Single policy)"""
    
    def check_access(self, tool_name: str, args: Dict[str, CaMeLValue]) -> bool:
        """Block dangerous operations with untrusted data"""
        if tool_name in ["write", "delete", "email"]:  # Dangerous tools
            for arg in args.values():
                if not arg.capabilities.is_trusted():  # Untrusted data
                    return False  # Block!
        return True
    

# 3. Tools (Paper: 100+ AgentDojo tools → 4 essential tools)
def safe_print(data: CaMeLValue) -> CaMeLValue:
    """Safe output tool (all data allowed)"""
    return CaMeLValue(
        f"Output: {data.value}",
        Capabilities(Source.CAMEL, Reader.PUBLIC)
    )

def dangerous_write(data: CaMeLValue) -> CaMeLValue:
    """Dangerous write tool (trusted data only)"""
    return CaMeLValue(
        f"Write complete: {data.value}",
        Capabilities(Source.CAMEL, Reader.PUBLIC)
    )

def delete_file(filename: CaMeLValue) -> CaMeLValue:
    """File deletion tool (trusted data only)"""
    return CaMeLValue(
        f"File deleted: {filename.value}",
        Capabilities(Source.CAMEL, Reader.PUBLIC)
    )

def send_email(recipient: CaMeLValue, content: CaMeLValue) -> CaMeLValue:
    """Email sending tool (trusted data only)"""
    return CaMeLValue(
        f"Email sent: {recipient.value} - {content.value}",
        Capabilities(Source.CAMEL, Reader.PUBLIC)
    )

# 4. Interpreter (Paper: 25,000+ line AST parser → Simple operation dispatch)
class MiniCaMeLInterpreter:
    """Mini CaMeL interpreter (Paper: Full Python AST parsing → Simple dispatch)"""
    
    def __init__(self):
        self.security_policy = SecurityPolicy()
        self.tools = {
            'print': safe_print,
            'write': dangerous_write,
            'delete': delete_file,
            'email': send_email
        }
    
    def execute_operation(self, operation: str, *args: CaMeLValue) -> CaMeLValue:
        """Execute operation with security check"""
        if operation not in self.tools:
            return CaMeLValue(
                f"Unknown operation: {operation}",
                Capabilities(Source.CAMEL, Reader.PUBLIC)
            )
        
        # Security policy check (Paper: Complex policy engine → Simple trust check)
        args_dict = {f"arg_{i}": arg for i, arg in enumerate(args)}
        if not self.security_policy.check_access(operation, args_dict):
            return CaMeLValue(
                f"Security policy violation: {operation}",
                Capabilities(Source.CAMEL, Reader.PUBLIC)
            )
        
        # Tool execution (Paper: Real API calls → Simulated responses)
        try:
            return self.tools[operation](*args)
        except Exception as e:
            return CaMeLValue(
                f"Execution error: {e}",
                Capabilities(Source.CAMEL, Reader.PUBLIC)
            )
    
    def create_value(self, value: Any, source: Source = Source.USER, 
                    reader: Reader = Reader.PUBLIC) -> CaMeLValue:
        """CaMeLValue creation helper"""
        return CaMeLValue(value, Capabilities(source, reader))

# 5. Test and examples
def main():
    """Main test function"""
    print("=== Mini CaMeL Stage 1 Test ===\n")
    
    interpreter = MiniCaMeLInterpreter()
    
    # Trusted data (generated by CaMeL system)
    trusted_data = interpreter.create_value("safe data", Source.CAMEL, Reader.PUBLIC)
    
    # Untrusted data (user input)
    untrusted_data = interpreter.create_value("user input", Source.USER, Reader.PUBLIC)
    
    print("1. Safe operations test (all data allowed)")
    print(f"   print(trusted): {interpreter.execute_operation('print', trusted_data)}")
    print(f"   print(untrusted): {interpreter.execute_operation('print', untrusted_data)}")
    
    print("\n2. Dangerous operations test (trusted data only)")
    print(f"   write(trusted): {interpreter.execute_operation('write', trusted_data)}")
    print(f"   write(untrusted): {interpreter.execute_operation('write', untrusted_data)}")
    
    print("\n3. File deletion test")
    filename = interpreter.create_value("important.txt", Source.USER, Reader.PUBLIC)
    print(f"   delete(user_file): {interpreter.execute_operation('delete', filename)}")
    
    trusted_filename = interpreter.create_value("system.log", Source.CAMEL, Reader.PUBLIC)
    print(f"   delete(trusted_file): {interpreter.execute_operation('delete', trusted_filename)}")
    
    print("\n4. Email sending test")
    recipient = interpreter.create_value("admin@company.com", Source.USER, Reader.PUBLIC)
    content = interpreter.create_value("important message", Source.USER, Reader.PUBLIC)
    print(f"   email(user_data): {interpreter.execute_operation('email', recipient, content)}")
    
    trusted_recipient = interpreter.create_value("support@company.com", Source.CAMEL, Reader.PUBLIC)
    trusted_content = interpreter.create_value("system notification", Source.CAMEL, Reader.PUBLIC)
    print(f"   email(trusted_data): {interpreter.execute_operation('email', trusted_recipient, trusted_content)}")
    
    print("\n5. Unknown operation test")
    print(f"   unknown_op: {interpreter.execute_operation('unknown_operation', trusted_data)}")
    
    print("\n=== Test Complete ===")

if __name__ == "__main__":
    main()
