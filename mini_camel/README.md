# Mini CaMeL - Stage 1 Implementation

A simplified Stage 1 implementation of the core concepts from the CaMeL paper.

## 🎯 Core Concepts

- **Metadata-based Security**: Attach source and permission info to all data
- **Sandboxed Execution**: Safe Python code execution
- **Basic Security Policy**: Public/private data distinction

## 🚀 Installation & Execution

```bash
# Run without dependencies
python mini_camel.py

# Or run tests
python test_mini_camel.py
```

## 📁 Structure

```
mini_camel/
├── mini_camel.py      # Core implementation (180 lines)
├── test_mini_camel.py # Test code (190 lines)
└── README.md          # This file
```

## 🔬 Execution Results

```
=== Mini CaMeL Stage 1 Test ===

1. Safe operations test (all data allowed)
   print(trusted): CaMeLValue('Output: safe data', ...)
   print(untrusted): CaMeLValue('Output: user input', ...)

2. Dangerous operations test (trusted data only)
   write(trusted): CaMeLValue('Write complete: safe data', ...)
   write(untrusted): CaMeLValue('Security policy violation: write', ...)

3. File deletion test
   delete(user_file): CaMeLValue('Security policy violation: delete', ...)
   delete(trusted_file): CaMeLValue('File deleted: system.log', ...)

4. Email sending test
   email(user_data): CaMeLValue('Security policy violation: email', ...)
   email(trusted_data): CaMeLValue('Email sent: support@company.com - system notification', ...)

5. Unknown operation test
   unknown_op: CaMeLValue('Unknown operation: unknown_operation', ...)

=== Test Complete ===
```

## ✅ Test Results

```
=== Mini CaMeL Test Started ===
Ran 13 tests in 0.001s
OK

=== Test Results ===
Tests run: 13
Failures: 0
Errors: 0
```

## 🔗 Core Ideas & Simplified Implementation

### 📖 Core Idea
**Metadata-based Security**: Attach source and permission info to all data to block dangerous operations with untrusted data

### 🔧 Paper → Implementation Mapping

| Paper Concept | Paper Implementation | → | Our Implementation | How We Simplified |
|---------------|---------------------|---|-------------------|-------------------|
| **Metadata System** | Complex `CaMeLValue` class | → | `Capabilities` + `CaMeLValue` (25 lines) | **Complex frozenset-based capabilities** → **Simple Source + Reader enums** |
| **Security Policy** | Domain-specific policy engines | → | `SecurityPolicy` class (10 lines) | **Banking/workspace/slack policies** → **Single trust-based policy** |
| **Python Interpreter** | 25,000+ line AST parser | → | `MiniCaMeLInterpreter` (35 lines) | **Full Python AST parsing** → **Simple operation dispatch** |
| **Tool Integration** | AgentDojo benchmark | → | 4 tools: `print`, `write`, `delete`, `email` | **100+ AgentDojo tools** → **4 essential tools** |
| **LLM Integration** | Real AI model calls | → | Mock execution (simulation) | **Real API calls** → **Simulated responses** |

*See code comments for detailed implementation explanations*

**Core**: Untrusted data attempting dangerous operations → Blocked!



## 🎓 Learning Points

1. **Importance of Metadata**: Track source of all data
2. **Effectiveness of Security Policy**: Block dangerous operations with untrusted data
3. **Sandboxed Execution**: Constraints for safe code execution
4. **Test-driven Development**: Verification of all functionality
5. **Code Optimization**: Remove redundancy while maintaining functionality
