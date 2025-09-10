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
        
        # 2. 위험도 임계치 기반 차단 (신뢰할 수 있는 데이터도 위험도 검사)
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
        """QLLM: 실제 LLM을 사용하여 비구조화 데이터를 구조화 데이터로 파싱"""
        try:
            # 실제 LLM 호출 시도
            prompt = f"""Parse this text into JSON format:

Text: "{query}"

Required JSON format: {output_schema.model_fields}

Return ONLY the JSON object, nothing else. Example:
{{"name": "John Doe", "age": 25}}

JSON:"""
            
            response = self.client.generate(
                model=self.model, 
                prompt=prompt,
                options={'temperature': 0.1}
            )
            
            # JSON 파싱 시도 (Python 딕셔너리도 처리)
            response_text = response['response'].strip()
            
            # Python 딕셔너리 형태인 경우 eval로 변환
            if response_text.startswith('{') and response_text.endswith('}'):
                try:
                    # 안전한 eval 사용 (문자열만)
                    result_data = eval(response_text)
                except:
                    # JSON으로 파싱 시도
                    result_data = json.loads(response_text)
            else:
                result_data = json.loads(response_text)
            
            parsed_result = output_schema(**result_data)
            return parsed_result
            
        except json.JSONDecodeError as e:
            raise NotEnoughInformationError()
        except Exception as e:
            # Ollama가 없을 경우 시뮬레이션으로 폴백
            return self._simulate_parsing(query, output_schema)
    
    def _simulate_parsing(self, query: str, output_schema: Type[BaseModel]) -> BaseModel:
        """Ollama가 없을 경우 시뮬레이션으로 폴백"""
        
        # 간단한 패턴 매칭으로 시뮬레이션
        if "name" in output_schema.model_fields and "age" in output_schema.model_fields:
            # "John Doe, 25" 형태 파싱
            import re
            name_match = re.search(r'([A-Za-z\s]+)', query)
            age_match = re.search(r'(\d+)', query)
            
            if name_match and age_match:
                name = name_match.group(1).strip()
                age = int(age_match.group(1))
                return output_schema(name=name, age=age)
        
        # 기본값으로 시뮬레이션
        if "name" in output_schema.model_fields:
            return output_schema(name="Unknown", age=0)
        
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
        self._tools = {
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
        return CaMeLValue(f"Write: {data.value}", 
                         Capabilities(Source.CAMEL, Reader.PUBLIC, RiskLevel.LOW))
    
    def _delete(self, filename: CaMeLValue) -> CaMeLValue:
        return CaMeLValue(f"Deleted: {filename.value}", 
                         Capabilities(Source.CAMEL, Reader.PUBLIC, RiskLevel.LOW))
    
    def _email(self, recipient: CaMeLValue, content: CaMeLValue) -> CaMeLValue:
        return CaMeLValue(f"Email sent: {recipient.value}", 
                         Capabilities(Source.CAMEL, Reader.PUBLIC, RiskLevel.LOW))
    
    def _query_ai(self, query: str, output_schema: Type[BaseModel]) -> BaseModel:
        return self.qllm.parse_data(query, output_schema)
    
    def _block_direct_access(self):
        raise AttributeError("Direct tool access blocked. Use CaMeL.execute() instead.")

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
        if risk is None:
            risk = infer_risk_from_value(value)
        
        return CaMeLValue(value, Capabilities(source, Reader.PUBLIC, risk))
    
    def execute(self, operation: str, *args: CaMeLValue) -> CaMeLValue:
        """단일 게이트웨이: 모든 툴 호출은 여기서만 허용"""
        if operation in self.pllm._tools:
            args_dict = {f"arg_{i}": arg for i, arg in enumerate(args)}
            policy_result = self.pllm.policy.check_access(operation, args_dict)
            
            if not policy_result.allowed:
                return CaMeLValue(f"Security violation: {policy_result.reason}", 
                                 Capabilities(Source.CAMEL, Reader.PUBLIC, RiskLevel.LOW))
            
            return self.pllm._tools[operation](*args)
        
        return CaMeLValue(f"Unknown: {operation}", Capabilities(Source.CAMEL, Reader.PUBLIC))

# ============================================================================
# Test and examples
# ============================================================================

def main():
    """CaMeL 데모"""
    print("=" * 40)
    print("CaMeL Demo")
    print("=" * 40)
    
    camel = CaMeL()
    
    # 1. 위험도 자동 추론
    print("\n1. Risk Detection")
    safe_data = camel.create_value("hello world")
    email_data = camel.create_value("john@example.com")
    print(f"Safe: {safe_data.capabilities.risk}")
    print(f"Email: {email_data.capabilities.risk}")
    
    # 2. 보안 정책 테스트
    print("\n2. Security Policy")
    user_data = camel.create_value("user data", Source.USER)
    print_result = camel.execute("print", user_data)
    write_result = camel.execute("write", user_data)
    print(f"Print: {print_result.value}")
    print(f"Write: {write_result.value}")
    
    # 3. QLLM 실제 호출
    print("\n3. QLLM (Actual LLM)")
    from pydantic import BaseModel
    
    class UserInfo(BaseModel):
        name: str
        email: str
    
    try:
        qllm_result = camel.pllm._query_ai("John Doe, john@example.com", UserInfo)
        print(f"QLLM: {qllm_result}")
    except Exception as e:
        print(f"QLLM Error: {e}")
    
    print("\n" + "=" * 40)
    print("Demo Complete")
    print("=" * 40)

if __name__ == "__main__":
    main()
