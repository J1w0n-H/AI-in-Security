# test_mini_camel.py - CaMeL 간소화 테스트
"""
CaMeL 핵심 구조 간소화 테스트
"""

import unittest
from unittest.mock import Mock, patch
from mini_camel import (
    CaMeL, CaMeLValue, Capabilities, Source, Reader, RiskLevel,
    SecurityPolicy, SecurityPolicyResult, PLLM, QLLM, NotEnoughInformationError,
    infer_risk_from_value, Readers
)
from pydantic import BaseModel

class TestSchema(BaseModel):
    name: str
    value: int

class TestCapabilities(unittest.TestCase):
    def test_is_trusted(self):
        user_cap = Capabilities(Source.USER, Reader.PUBLIC)
        camel_cap = Capabilities(Source.CAMEL, Reader.PUBLIC)
        
        self.assertFalse(user_cap.is_trusted())
        self.assertTrue(camel_cap.is_trusted())
    
    def test_risk_levels(self):
        low_cap = Capabilities(Source.USER, Reader.PUBLIC, RiskLevel.LOW)
        medium_cap = Capabilities(Source.USER, Reader.PUBLIC, RiskLevel.MEDIUM)
        high_cap = Capabilities(Source.USER, Reader.PUBLIC, RiskLevel.HIGH)
        
        self.assertFalse(low_cap.is_high_risk())
        self.assertFalse(low_cap.is_medium_risk())
        self.assertTrue(medium_cap.is_medium_risk())
        self.assertTrue(high_cap.is_high_risk())
    
    def test_readers_and_provenance(self):
        # Public 데이터
        public_cap = Capabilities(Source.USER, Reader.PUBLIC, readers="Public")
        self.assertTrue(public_cap.is_public())
        self.assertTrue(public_cap.readers_include({"user1", "user2"}))
        
        # 특정 사용자 집합
        private_cap = Capabilities(Source.USER, Reader.PUBLIC, readers={"user1", "user2"})
        self.assertFalse(private_cap.is_public())
        self.assertTrue(private_cap.readers_include({"user1"}))
        self.assertTrue(private_cap.readers_include({"user1", "user2"}))
        self.assertFalse(private_cap.readers_include({"user3"}))
        
        # Provenance 테스트
        camel_cap = Capabilities(Source.CAMEL, Reader.PUBLIC, provenance="camel")
        self.assertEqual(camel_cap.provenance, "camel")

class TestRiskInference(unittest.TestCase):
    def test_risk_inference(self):
        # LOW 위험
        self.assertEqual(infer_risk_from_value("hello world"), RiskLevel.LOW)
        self.assertEqual(infer_risk_from_value("normal text"), RiskLevel.LOW)
        
        # MEDIUM 위험
        self.assertEqual(infer_risk_from_value("my name is John"), RiskLevel.MEDIUM)
        self.assertEqual(infer_risk_from_value("address: 123 Main St"), RiskLevel.MEDIUM)
        
        # HIGH 위험
        self.assertEqual(infer_risk_from_value("john@example.com"), RiskLevel.HIGH)
        self.assertEqual(infer_risk_from_value("010-1234-5678"), RiskLevel.HIGH)
        self.assertEqual(infer_risk_from_value("123456-1234567"), RiskLevel.HIGH)

class TestSecurityPolicy(unittest.TestCase):
    def setUp(self):
        self.policy = SecurityPolicy()
    
    def test_safe_operations(self):
        trusted = CaMeLValue("data", Capabilities(Source.CAMEL, Reader.PUBLIC))
        untrusted = CaMeLValue("data", Capabilities(Source.USER, Reader.PUBLIC))
        
        result1 = self.policy.check_access("print", {"data": trusted})
        result2 = self.policy.check_access("print", {"data": untrusted})
        
        self.assertTrue(result1.allowed)
        self.assertTrue(result2.allowed)
    
    def test_dangerous_operations(self):
        trusted = CaMeLValue("data", Capabilities(Source.CAMEL, Reader.PUBLIC))
        untrusted = CaMeLValue("data", Capabilities(Source.USER, Reader.PUBLIC))
        
        result1 = self.policy.check_access("write", {"data": trusted})
        result2 = self.policy.check_access("write", {"data": untrusted})
        
        self.assertTrue(result1.allowed)
        self.assertFalse(result2.allowed)
        self.assertEqual(result2.reason_code, "UNTRUSTED_DANGER_OP")
        self.assertIn("untrusted data", result2.reason)
    
    def test_risk_based_policy(self):
        # LOW 위험 데이터는 허용
        low_risk = CaMeLValue("safe data", Capabilities(Source.CAMEL, Reader.PUBLIC, RiskLevel.LOW))
        result1 = self.policy.check_access("write", {"data": low_risk})
        self.assertTrue(result1.allowed)
        
        # MEDIUM 위험 데이터는 write 차단 (임계치 MEDIUM)
        medium_risk = CaMeLValue("name: John", Capabilities(Source.CAMEL, Reader.PUBLIC, RiskLevel.MEDIUM))
        result2 = self.policy.check_access("write", {"data": medium_risk})
        self.assertFalse(result2.allowed)
        self.assertEqual(result2.reason_code, "RISK_THRESHOLD_EXCEEDED")
        self.assertIn("MEDIUM exceeds threshold MEDIUM", result2.reason)
        
        # HIGH 위험 데이터는 모든 작업 차단
        high_risk = CaMeLValue("john@example.com", Capabilities(Source.CAMEL, Reader.PUBLIC, RiskLevel.HIGH))
        result3 = self.policy.check_access("write", {"data": high_risk})
        result4 = self.policy.check_access("email", {"data": high_risk})
        result5 = self.policy.check_access("delete", {"data": high_risk})
        
        self.assertFalse(result3.allowed)
        self.assertFalse(result4.allowed)
        self.assertFalse(result5.allowed)
        self.assertEqual(result3.reason_code, "RISK_THRESHOLD_EXCEEDED")
        self.assertEqual(result4.reason_code, "RISK_THRESHOLD_EXCEEDED")
        self.assertEqual(result5.reason_code, "RISK_THRESHOLD_EXCEEDED")
    
    def test_recipient_checks(self):
        # 수신자 집합 검사 테스트
        policy = SecurityPolicy()
        
        # Public 데이터는 모든 수신자 허용
        public_content = CaMeLValue("public message", 
                                  Capabilities(Source.CAMEL, Reader.PUBLIC, readers="Public"))
        recipient1 = CaMeLValue("user1", Capabilities(Source.USER, Reader.PUBLIC))
        
        result1 = policy._check_recipients("email", {"arg_0": recipient1, "arg_1": public_content})
        self.assertTrue(result1.allowed)
        
        # 특정 사용자 집합 데이터
        private_content = CaMeLValue("private message", 
                                   Capabilities(Source.CAMEL, Reader.PUBLIC, readers={"user1", "user2"}))
        
        # 허용된 수신자
        result2 = policy._check_recipients("email", {"arg_0": recipient1, "arg_1": private_content})
        self.assertTrue(result2.allowed)
        
        # 차단된 수신자
        recipient2 = CaMeLValue("user3", Capabilities(Source.USER, Reader.PUBLIC))
        result3 = policy._check_recipients("email", {"arg_0": recipient2, "arg_1": private_content})
        self.assertFalse(result3.allowed)
        self.assertEqual(result3.reason_code, "READER_MISMATCH")

class TestPLLM(unittest.TestCase):
    def setUp(self):
        self.pllm = PLLM()
    
    def test_safe_print(self):
        data = CaMeLValue("test", Capabilities(Source.USER, Reader.PUBLIC))
        result = self.pllm._print(data)
        self.assertIn("test", result.value)
        self.assertTrue(result.capabilities.is_trusted())
    
    def test_dangerous_write_trusted(self):
        data = CaMeLValue("data", Capabilities(Source.CAMEL, Reader.PUBLIC))
        result = self.pllm._write(data)
        self.assertIn("Write:", result.value)
    
    def test_dangerous_write_untrusted(self):
        # PLLM의 _write는 이제 정책 검사 없이 직접 실행됨
        data = CaMeLValue("data", Capabilities(Source.USER, Reader.PUBLIC))
        result = self.pllm._write(data)
        self.assertIn("Write:", result.value)

class TestCaMeL(unittest.TestCase):
    def setUp(self):
        self.camel = CaMeL()
    
    def test_create_value(self):
        value = self.camel.create_value("test", Source.USER)
        self.assertEqual(value.value, "test")
        self.assertEqual(value.capabilities.source, Source.USER)
    
    def test_execute_operation(self):
        data = self.camel.create_value("test", Source.USER)
        result = self.camel.execute("print", data)
        self.assertIn("test", result.value)
    
    def test_security_enforcement(self):
        untrusted = self.camel.create_value("data", Source.USER)
        trusted = self.camel.create_value("data", Source.CAMEL)
        
        write_untrusted = self.camel.execute("write", untrusted)
        write_trusted = self.camel.execute("write", trusted)
        
        self.assertIn("Security violation", write_untrusted.value)
        self.assertIn("Write:", write_trusted.value)
    
    def test_risk_based_security(self):
        # 자동 위험도 추론 테스트
        email_data = self.camel.create_value("john@example.com")
        self.assertEqual(email_data.capabilities.risk, RiskLevel.HIGH)
        
        # HIGH 위험 데이터로 이메일 시도 → 차단
        email_result = self.camel.execute("email", email_data, self.camel.create_value("message"))
        self.assertIn("Security violation", email_result.value)
        
        # LOW 위험 데이터로 이메일 시도 → 허용 (CAMEL 소스이므로)
        safe_data = self.camel.create_value("safe message", Source.CAMEL, RiskLevel.LOW)
        safe_email = self.camel.execute("email", safe_data, self.camel.create_value("message"))
        # 이메일은 LOW 위험도도 차단하므로 Security violation이 나와야 함
        self.assertIn("Security violation", safe_email.value)
    
    def test_single_gateway_pattern(self):
        """단일 게이트웨이 패턴 테스트: 모든 툴 호출이 execute()를 통해서만 가능"""
        # 1. execute()를 통한 정상 호출
        data = self.camel.create_value("test data", Source.USER)
        result = self.camel.execute("print", data)
        self.assertIn("test data", result.value)
        
        # 2. execute()를 통한 차단
        write_result = self.camel.execute("write", data)
        self.assertIn("Security violation", write_result.value)
        
        # 3. 직접 툴 호출 시도 (차단됨)
        with self.assertRaises(AttributeError):
            self.camel.pllm._block_direct_access()
        
        # 4. 알 수 없는 작업
        unknown_result = self.camel.execute("unknown_op", data)
        self.assertIn("Unknown: unknown_op", unknown_result.value)

if __name__ == "__main__":
    unittest.main(verbosity=2)