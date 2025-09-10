# mini_camel.py - CaMeL 핵심 구조 간소화 버전
"""
CaMeL 논문의 핵심만 구현:
- PLLM (Privileged LLM)
- QLLM (Quarantined LLM) 
- Security Policies
- Capabilities
"""

from dataclasses import dataclass
from enum import Enum
from typing import Any, Dict, Type, Optional
import json
import ollama
import re
from pydantic import BaseModel, Field

# ============================================================================
# Capabilities (메타데이터)
# ============================================================================

class Source(Enum):
    USER = "user"      # 신뢰할 수 없음
    CAMEL = "camel"    # 신뢰할 수 있음

class Reader(Enum):
    PUBLIC = "public"
    PRIVATE = "private"

class RiskLevel(Enum):
    LOW = 1      # 안전한 데이터 (기본값)
    MEDIUM = 3   # 중간 위험 데이터
    HIGH = 5     # 높은 위험 데이터

@dataclass
class Capabilities:
    source: Source
    reader: Reader
    risk: RiskLevel = RiskLevel.LOW  # 기본값은 LOW
    
    def is_trusted(self) -> bool:
        return self.source == Source.CAMEL
    
    def is_high_risk(self) -> bool:
        return self.risk == RiskLevel.HIGH
    
    def is_medium_risk(self) -> bool:
        return self.risk == RiskLevel.MEDIUM

@dataclass
class CaMeLValue:
    value: Any
    capabilities: Capabilities

# ============================================================================
# 위험도 추론 함수
# ============================================================================

def infer_risk_from_value(value: Any) -> RiskLevel:
    """값의 내용을 분석하여 위험도를 추론"""
    if not isinstance(value, str):
        return RiskLevel.LOW
    
    value_str = str(value).lower()
    
    # HIGH 위험 패턴 (민감한 개인정보)
    high_risk_patterns = [
        r'\d{6}-\d{7}',  # 주민등록번호 (6자리-7자리)
        r'\d{3}-\d{4}-\d{4}',  # 전화번호 (3-4-4)
        r'\d{2,3}-\d{3,4}-\d{4}',  # 전화번호 변형
        r'\b\d{4}-\d{2}-\d{2}\b',  # 생년월일 (YYYY-MM-DD)
        r'\b\d{2}/\d{2}/\d{4}\b',  # 생년월일 (MM/DD/YYYY)
        r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}',  # 이메일
        r'\b\d{4}\s?\d{4}\s?\d{4}\s?\d{4}\b',  # 신용카드 번호
        r'password|passwd|pwd',  # 패스워드 관련
        r'secret|private|confidential',  # 기밀 정보
    ]
    
    # MEDIUM 위험 패턴 (중간 민감도)
    medium_risk_patterns = [
        r'\b\d{3}-\d{2}-\d{5}\b',  # 사업자등록번호
        r'\b\d{2}-\d{2}-\d{6}\b',  # 운전면허번호
        r'address|주소',  # 주소 정보
        r'name|이름',  # 이름 정보
        r'phone|전화',  # 전화 관련
    ]
    
    # HIGH 위험 패턴 검사
    for pattern in high_risk_patterns:
        if re.search(pattern, value_str):
            return RiskLevel.HIGH
    
    # MEDIUM 위험 패턴 검사
    for pattern in medium_risk_patterns:
        if re.search(pattern, value_str):
            return RiskLevel.MEDIUM
    
    return RiskLevel.LOW

# ============================================================================
# Security Policy
# ============================================================================

@dataclass
class SecurityPolicyResult:
    allowed: bool
    reason_code: str
    reason: str
    
    @classmethod
    def allow(cls) -> 'SecurityPolicyResult':
        return cls(True, "ALLOWED", "Operation allowed")
    
    @classmethod
    def deny(cls, reason_code: str, reason: str) -> 'SecurityPolicyResult':
        return cls(False, reason_code, reason)

class SecurityPolicy:
    def __init__(self):
        self.dangerous_ops = {"write", "delete", "email"}
        # 위험도 임계치 설정
        self.risk_thresholds = {
            "write": RiskLevel.MEDIUM,    # MEDIUM 이상 위험 데이터로 쓰기 차단
            "delete": RiskLevel.LOW,      # LOW 이상 위험 데이터로 삭제 차단
            "email": RiskLevel.LOW,       # LOW 이상 위험 데이터로 이메일 차단
        }
    
    def check_access(self, operation: str, args: Dict[str, CaMeLValue]) -> SecurityPolicyResult:
        # 1. 위험한 작업에 신뢰할 수 없는 데이터 사용 시 하드 차단
        if operation in self.dangerous_ops:
            for arg_name, arg in args.items():
                if not arg.capabilities.is_trusted():
                    return SecurityPolicyResult.deny(
                        "UNTRUSTED_DANGER_OP",
                        f"Operation '{operation}' blocked: untrusted data in '{arg_name}'"
                    )
        
        # 2. 위험도 임계치 기반 차단
        if operation in self.risk_thresholds:
            threshold = self.risk_thresholds[operation]
            for arg_name, arg in args.items():
                if arg.capabilities.risk.value >= threshold.value:
                    return SecurityPolicyResult.deny(
                        "RISK_THRESHOLD_EXCEEDED",
                        f"Operation '{operation}' blocked: risk level {arg.capabilities.risk.name} exceeds threshold {threshold.name} for '{arg_name}'"
                    )
        
        return SecurityPolicyResult.allow()

# ============================================================================
# QLLM (Quarantined LLM)
# ============================================================================

class NotEnoughInformationError(Exception):
    pass

class QLLM:
    def __init__(self, model: str = "llama3.2:3b"):
        self.model = model
        self.client = ollama.Client()
    
    def parse_data(self, query: str, output_schema: Type[BaseModel]) -> BaseModel:
        try:
            prompt = f"Parse: {query}\nOutput JSON matching: {output_schema.model_fields}"
            response = self.client.generate(model=self.model, prompt=prompt)
            result_data = json.loads(response['response'])
            return output_schema(**result_data)
        except:
            raise NotEnoughInformationError()

# ============================================================================
# PLLM (Privileged LLM)
# ============================================================================

class PLLM:
    def __init__(self, model: str = "llama3.2:3b"):
        self.model = model
        self.client = ollama.Client()
        self.qllm = QLLM(model)
        self.policy = SecurityPolicy()
        self.tools = {
            "print": self._print,
            "write": self._write,
            "delete": self._delete,
            "email": self._email,
            "query_ai_assistant": self._query_ai
        }
    
    def process_query(self, query: str) -> CaMeLValue:
        # 간단한 코드 생성 시뮬레이션
        if "print" in query.lower():
            return self._print(CaMeLValue("Hello World", Capabilities(Source.CAMEL, Reader.PUBLIC)))
        elif "write" in query.lower():
            return self._write(CaMeLValue("data", Capabilities(Source.USER, Reader.PUBLIC)))
        else:
            return CaMeLValue(f"Processed: {query}", Capabilities(Source.CAMEL, Reader.PUBLIC))
    
    def _print(self, data: CaMeLValue) -> CaMeLValue:
        return CaMeLValue(f"Output: {data.value}", 
                         Capabilities(Source.CAMEL, Reader.PUBLIC, RiskLevel.LOW))
    
    def _write(self, data: CaMeLValue) -> CaMeLValue:
        result = self.policy.check_access("write", {"data": data})
        if not result.allowed:
            return CaMeLValue(f"Security violation: {result.reason}", 
                             Capabilities(Source.CAMEL, Reader.PUBLIC, RiskLevel.LOW))
        return CaMeLValue(f"Write: {data.value}", 
                         Capabilities(Source.CAMEL, Reader.PUBLIC, RiskLevel.LOW))
    
    def _delete(self, filename: CaMeLValue) -> CaMeLValue:
        result = self.policy.check_access("delete", {"filename": filename})
        if not result.allowed:
            return CaMeLValue(f"Security violation: {result.reason}", 
                             Capabilities(Source.CAMEL, Reader.PUBLIC, RiskLevel.LOW))
        return CaMeLValue(f"Deleted: {filename.value}", 
                         Capabilities(Source.CAMEL, Reader.PUBLIC, RiskLevel.LOW))
    
    def _email(self, recipient: CaMeLValue, content: CaMeLValue) -> CaMeLValue:
        result = self.policy.check_access("email", {"recipient": recipient, "content": content})
        if not result.allowed:
            return CaMeLValue(f"Security violation: {result.reason}", 
                             Capabilities(Source.CAMEL, Reader.PUBLIC, RiskLevel.LOW))
        return CaMeLValue(f"Email sent: {recipient.value}", 
                         Capabilities(Source.CAMEL, Reader.PUBLIC, RiskLevel.LOW))
    
    def _query_ai(self, query: str, output_schema: Type[BaseModel]) -> BaseModel:
        return self.qllm.parse_data(query, output_schema)

# ============================================================================
# CaMeL System
# ============================================================================

class CaMeL:
    def __init__(self):
        self.pllm = PLLM()
    
    def process(self, query: str) -> CaMeLValue:
        return self.pllm.process_query(query)
    
    def create_value(self, value: Any, source: Source = Source.USER, 
                    risk: Optional[RiskLevel] = None) -> CaMeLValue:
        # 위험도가 지정되지 않으면 자동 추론
        if risk is None:
            risk = infer_risk_from_value(value)
        
        return CaMeLValue(value, Capabilities(source, Reader.PUBLIC, risk))
    
    def execute(self, operation: str, *args: CaMeLValue) -> CaMeLValue:
        if operation in self.pllm.tools:
            return self.pllm.tools[operation](*args)
        return CaMeLValue(f"Unknown: {operation}", Capabilities(Source.CAMEL, Reader.PUBLIC))

# ============================================================================
# Test and examples
# ============================================================================

def main():
    """Main test function"""
    print("=" * 50)
    print("CaMeL Simple Demo")
    print("=" * 50)
    
    camel = CaMeL()
    
    # 1. Capabilities 테스트
    print("\n1. Capabilities")
    trusted = camel.create_value("safe data", Source.CAMEL)
    untrusted = camel.create_value("user data", Source.USER)
    
    print(f"Trusted: {trusted.capabilities.is_trusted()}")
    print(f"Untrusted: {untrusted.capabilities.is_trusted()}")
    
    # 2. 위험도 자동 추론 테스트
    print("\n2. Risk Level Auto-Detection")
    safe_data = camel.create_value("hello world")
    email_data = camel.create_value("john@example.com")
    phone_data = camel.create_value("010-1234-5678")
    ssn_data = camel.create_value("123456-1234567")
    
    print(f"Safe data risk: {safe_data.capabilities.risk}")
    print(f"Email data risk: {email_data.capabilities.risk}")
    print(f"Phone data risk: {phone_data.capabilities.risk}")
    print(f"SSN data risk: {ssn_data.capabilities.risk}")
    
    # 3. 보안 정책 테스트 (기존)
    print("\n3. Security Policy (Basic)")
    print_result = camel.execute("print", untrusted)
    write_result = camel.execute("write", untrusted)
    
    print(f"Print: {print_result.value}")
    print(f"Write: {write_result.value}")
    
    # 4. 위험도 기반 보안 정책 테스트
    print("\n4. Risk-Based Security Policy")
    
    # USER 데이터 + email → 하드룰 차단
    user_email = camel.create_value("user@example.com", Source.USER)
    email_result = camel.execute("email", user_email, camel.create_value("message"))
    print(f"USER email blocked: {email_result.value}")
    
    # CAMEL 데이터 HIGH + email → 임계치 맞춰 차단
    camel_high_risk = camel.create_value("123456-1234567", Source.CAMEL, RiskLevel.HIGH)
    high_risk_email = camel.execute("email", camel_high_risk, camel.create_value("message"))
    print(f"CAMEL HIGH risk email blocked: {high_risk_email.value}")
    
    # CAMEL 데이터 LOW + email → 허용
    camel_low_risk = camel.create_value("safe data", Source.CAMEL, RiskLevel.LOW)
    low_risk_email = camel.execute("email", camel_low_risk, camel.create_value("message"))
    print(f"CAMEL LOW risk email allowed: {low_risk_email.value}")
    
    # 5. 정책 결과 상세 테스트
    print("\n5. Detailed Policy Results")
    policy = camel.pllm.policy
    
    # 직접 정책 호출하여 상세 결과 확인
    test_data = camel.create_value("sensitive@email.com", Source.USER)
    policy_result = policy.check_access("email", {"recipient": test_data, "content": camel.create_value("msg")})
    print(f"Policy result: {policy_result.reason_code} - {policy_result.reason}")
    
    # 위험도 기반 차단 테스트
    high_risk_data = camel.create_value("john@example.com", Source.CAMEL, RiskLevel.HIGH)
    risk_result = policy.check_access("write", {"data": high_risk_data})
    print(f"Risk-based result: {risk_result.reason_code} - {risk_result.reason}")
    
    # 6. PLLM 처리
    print("\n6. PLLM Processing")
    result1 = camel.process("Print hello world")
    result2 = camel.process("Write some data")
    
    print(f"Query 1: {result1.value}")
    print(f"Query 2: {result2.value}")
    
    # 7. QLLM 시뮬레이션
    print("\n7. QLLM Simulation")
    print("QLLM would parse: 'John Doe, john@example.com'")
    print("Into: UserInfo(name='John Doe', email='john@example.com')")
    
    print("\n" + "=" * 50)
    print("Demo Complete")
    print("=" * 50)

if __name__ == "__main__":
    main()
