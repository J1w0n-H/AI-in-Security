# test_mini_camel.py - Mini CaMeL test code
"""
Test code for Mini CaMeL's core functionality
"""

import unittest
from mini_camel import (
    Source, Reader, Capabilities, CaMeLValue, 
    SecurityPolicy, MiniCaMeLInterpreter
)

class TestCaMeLValue(unittest.TestCase):
    """CaMeLValue class tests"""
    
    def test_create_value(self):
        """Value creation test"""
        value = CaMeLValue("test", Capabilities(Source.USER, Reader.PUBLIC))
        self.assertEqual(value.value, "test")
        self.assertEqual(value.capabilities.source, Source.USER)
        self.assertEqual(value.capabilities.reader, Reader.PUBLIC)
    
    def test_capabilities_access(self):
        """Capabilities access test"""
        public_value = CaMeLValue("public", Capabilities(Source.USER, Reader.PUBLIC))
        private_value = CaMeLValue("private", Capabilities(Source.USER, Reader.PRIVATE))
        trusted_value = CaMeLValue("trusted", Capabilities(Source.CAMEL, Reader.PUBLIC))
        untrusted_value = CaMeLValue("untrusted", Capabilities(Source.USER, Reader.PUBLIC))
        
        # Test public/private access
        self.assertTrue(public_value.capabilities.is_public())
        self.assertFalse(private_value.capabilities.is_public())
        
        # Test trusted/untrusted access
        self.assertTrue(trusted_value.capabilities.is_trusted())
        self.assertFalse(untrusted_value.capabilities.is_trusted())

class TestSecurityPolicy(unittest.TestCase):
    """Security policy tests"""
    
    def setUp(self):
        self.policy = SecurityPolicy()
    
    def test_safe_operation_allowed(self):
        """Safe operation allowed test"""
        safe_data = CaMeLValue("data", Capabilities(Source.USER, Reader.PUBLIC))
        result = self.policy.check_access("print", {"arg_0": safe_data})
        self.assertTrue(result)
    
    def test_dangerous_operation_with_trusted_data(self):
        """Dangerous operation with trusted data allowed test"""
        trusted_data = CaMeLValue("data", Capabilities(Source.CAMEL, Reader.PUBLIC))
        result = self.policy.check_access("write", {"arg_0": trusted_data})
        self.assertTrue(result)
    
    def test_dangerous_operation_with_untrusted_data(self):
        """Dangerous operation with untrusted data blocked test"""
        untrusted_data = CaMeLValue("data", Capabilities(Source.USER, Reader.PUBLIC))
        result = self.policy.check_access("write", {"arg_0": untrusted_data})
        self.assertFalse(result)
    

class TestMiniCaMeLInterpreter(unittest.TestCase):
    """MiniCaMeLInterpreter tests"""
    
    def setUp(self):
        self.interpreter = MiniCaMeLInterpreter()
    
    def test_create_value(self):
        """Value creation helper test"""
        value = self.interpreter.create_value("test", Source.USER, Reader.PUBLIC)
        self.assertEqual(value.value, "test")
        self.assertEqual(value.capabilities.source, Source.USER)
        self.assertEqual(value.capabilities.reader, Reader.PUBLIC)
    
    def test_safe_operation_execution(self):
        """Safe operation execution test"""
        data = self.interpreter.create_value("hello", Source.USER, Reader.PUBLIC)
        result = self.interpreter.execute_operation("print", data)
        
        self.assertIn("Output: hello", result.value)
        self.assertEqual(result.capabilities.source, Source.CAMEL)
    
    def test_dangerous_operation_with_trusted_data(self):
        """Dangerous operation with trusted data execution test"""
        trusted_data = self.interpreter.create_value("secret", Source.CAMEL, Reader.PUBLIC)
        result = self.interpreter.execute_operation("write", trusted_data)
        
        self.assertIn("Write complete: secret", result.value)
        self.assertEqual(result.capabilities.source, Source.CAMEL)
    
    def test_dangerous_operation_with_untrusted_data(self):
        """Dangerous operation with untrusted data blocked test"""
        untrusted_data = self.interpreter.create_value("user_data", Source.USER, Reader.PUBLIC)
        result = self.interpreter.execute_operation("write", untrusted_data)
        
        self.assertIn("Security policy violation", result.value)
        self.assertEqual(result.capabilities.source, Source.CAMEL)
    
    def test_unknown_operation(self):
        """Unknown operation test"""
        data = self.interpreter.create_value("test", Source.USER, Reader.PUBLIC)
        result = self.interpreter.execute_operation("unknown_op", data)
        
        self.assertIn("Unknown operation: unknown_op", result.value)
        self.assertEqual(result.capabilities.source, Source.CAMEL)
    
    def test_file_operations(self):
        """File operations test"""
        # Attempt to delete untrusted file (blocked)
        user_file = self.interpreter.create_value("user_file.txt", Source.USER, Reader.PUBLIC)
        result1 = self.interpreter.execute_operation("delete", user_file)
        self.assertIn("Security policy violation", result1.value)
        
        # Delete trusted file (allowed)
        trusted_file = self.interpreter.create_value("system.log", Source.CAMEL, Reader.PUBLIC)
        result2 = self.interpreter.execute_operation("delete", trusted_file)
        self.assertIn("File deleted: system.log", result2.value)
    
    def test_email_operations(self):
        """Email operations test"""
        recipient = self.interpreter.create_value("user@example.com", Source.USER, Reader.PUBLIC)
        content = self.interpreter.create_value("user message", Source.USER, Reader.PUBLIC)
        
        # Attempt to send email with user data (blocked)
        result = self.interpreter.execute_operation("email", recipient, content)
        self.assertIn("Security policy violation", result.value)
        
        # Send email with trusted data (allowed)
        trusted_recipient = self.interpreter.create_value("admin@company.com", Source.CAMEL, Reader.PUBLIC)
        trusted_content = self.interpreter.create_value("system notification", Source.CAMEL, Reader.PUBLIC)
        result2 = self.interpreter.execute_operation("email", trusted_recipient, trusted_content)
        self.assertIn("Email sent: admin@company.com - system notification", result2.value)

class TestIntegration(unittest.TestCase):
    """Integration tests"""
    
    def test_complete_workflow(self):
        """Complete workflow test"""
        interpreter = MiniCaMeLInterpreter()
        
        # 1. Create user data
        user_data = interpreter.create_value("user request", Source.USER, Reader.PUBLIC)
        
        # 2. Execute safe operation (allowed)
        print_result = interpreter.execute_operation("print", user_data)
        self.assertIn("Output: user request", print_result.value)
        
        # 3. Execute dangerous operation (blocked)
        write_result = interpreter.execute_operation("write", user_data)
        self.assertIn("Security policy violation", write_result.value)
        
        # 4. Execute dangerous operation with trusted data (allowed)
        trusted_data = interpreter.create_value("system data", Source.CAMEL, Reader.PUBLIC)
        trusted_write_result = interpreter.execute_operation("write", trusted_data)
        self.assertIn("Write complete: system data", trusted_write_result.value)

def run_tests():
    """Run tests"""
    print("=== Mini CaMeL Test Started ===\n")
    
    # Create test suite
    test_suite = unittest.TestSuite()
    
    # Add test classes
    test_classes = [
        TestCaMeLValue,
        TestSecurityPolicy,
        TestMiniCaMeLInterpreter,
        TestIntegration
    ]
    
    for test_class in test_classes:
        tests = unittest.TestLoader().loadTestsFromTestCase(test_class)
        test_suite.addTests(tests)
    
    # Run tests
    runner = unittest.TextTestRunner(verbosity=2)
    result = runner.run(test_suite)
    
    print(f"\n=== Test Results ===")
    print(f"Tests run: {result.testsRun}")
    print(f"Failures: {len(result.failures)}")
    print(f"Errors: {len(result.errors)}")
    
    if result.failures:
        print("\nFailed tests:")
        for test, traceback in result.failures:
            print(f"  - {test}: {traceback}")
    
    if result.errors:
        print("\nTests with errors:")
        for test, traceback in result.errors:
            print(f"  - {test}: {traceback}")
    
    return result.wasSuccessful()

if __name__ == "__main__":
    success = run_tests()
    exit(0 if success else 1)
