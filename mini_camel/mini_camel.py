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
<<<<<<< HEAD
from typing import Any, Dict, Optional, Union, Set, Type, List
import json
import ollama
import re
from pydantic import BaseModel, Field
from datetime import datetime

# ============================================================================
# Trace Logging (감사/재현)
# ============================================================================

@dataclass
class ToolCall:
    """툴 호출 정보"""
    name: str
    args: Dict[str, Any]
    timestamp: datetime

@dataclass
class TraceEntry:
    """트레이스 로그 엔트리"""
    call: ToolCall
    memstep: Dict[str, Any]  # 메모리 상태 스냅샷
    result: str  # "Allowed" 또는 "Denied"
    reason: str  # 상세한 이유
    timestamp: datetime

class TraceLogger:
    """트레이스 로거: 감사 및 재현을 위한 로그 관리"""
    
    def __init__(self):
        self.entries: List[TraceEntry] = []
    
    def log_tool_call(self, operation: str, args: Dict[str, 'CaMeLValue'], 
                     result: str, reason: str, memstep: Optional[Dict[str, Any]] = None):
        """툴 호출 로그 기록"""
        # PII 마스킹된 args 생성
        masked_args = self._mask_pii_in_args(args)
        
        # 메모리 상태 스냅샷 (간단한 버전)
        if memstep is None:
            memstep = {"operation": operation, "timestamp": datetime.now().isoformat()}
        
        # 툴 호출 정보
        tool_call = ToolCall(
            name=operation,
            args=masked_args,
            timestamp=datetime.now()
        )
        
        # 트레이스 엔트리 생성
        entry = TraceEntry(
            call=tool_call,
            memstep=memstep,
            result=result,
            reason=reason,
            timestamp=datetime.now()
        )
        
        self.entries.append(entry)
    
    def _mask_pii_in_args(self, args: Dict[str, 'CaMeLValue']) -> Dict[str, Any]:
        """PII 마스킹: Public이 아닌 데이터는 <REDACTED>로 마스킹"""
        masked = {}
        for key, value in args.items():
            if value.capabilities.is_public():
                # Public 데이터는 그대로 표시
                masked[key] = str(value.value)
            else:
                # Private 데이터는 마스킹
                masked[key] = "<REDACTED>"
        return masked
    
    def get_trace_summary(self) -> Dict[str, Any]:
        """트레이스 요약 정보 반환"""
        total_calls = len(self.entries)
        allowed_calls = sum(1 for entry in self.entries if entry.result == "Allowed")
        denied_calls = total_calls - allowed_calls
        
        return {
            "total_calls": total_calls,
            "allowed_calls": allowed_calls,
            "denied_calls": denied_calls,
            "denial_rate": f"{(denied_calls/total_calls*100):.1f}%" if total_calls > 0 else "0%",
            "recent_entries": self.entries[-5:] if self.entries else []
        }
    
    def get_entries_by_operation(self, operation: str) -> List[TraceEntry]:
        """특정 작업의 트레이스 엔트리 반환"""
        return [entry for entry in self.entries if entry.call.name == operation]
    
    def clear_trace(self):
        """트레이스 로그 초기화"""
        self.entries.clear()

# ============================================================================
# Capabilities (메타데이터)
# ============================================================================
=======
from typing import Any, Dict
>>>>>>> 8c4ca537ff73d47d0ecbe7df21b577bba6fddae2

# 1. Metadata System (Paper: Complex frozenset-based capabilities → Simple enums)
class Source(Enum):
    """Data source: USER (untrusted), CAMEL (trusted), TOOL (generated)"""
    USER = "user"      # User input - untrusted
    CAMEL = "camel"    # System generated - trusted  
    TOOL = "tool"      # Tool output - trusted

<<<<<<< HEAD

# Readers는 "Public" 문자열 또는 구체적인 사용자 ID 집합
Readers = Union[str, Set[str]]

class RiskLevel(Enum):
    LOW = 1      # 안전한 데이터 (기본값)
    MEDIUM = 3   # 중간 위험 데이터
    HIGH = 5     # 높은 위험 데이터

@dataclass
class Capabilities:
    source: Source
    risk: RiskLevel = RiskLevel.LOW
    readers: Readers = "Public"  # "Public" 또는 구체적인 사용자 ID 집합
    provenance: str = "user"  # "user", "camel", "tool_id", "qllm"
    inner_source: Optional[str] = None  # 내부 소스 정보
=======
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
>>>>>>> 8c4ca537ff73d47d0ecbe7df21b577bba6fddae2
    
    def is_trusted(self) -> bool:
        """Check if data is from trusted source (CAMEL system)"""
        return self.source == Source.CAMEL
<<<<<<< HEAD
    
    
    def is_public(self) -> bool:
        """데이터가 공개 데이터인지 확인"""
        return self.readers == "Public"
    
    def readers_include(self, principals: Set[str]) -> bool:
        """지정된 사용자들이 읽기 권한을 가지는지 확인"""
        if self.is_public():
            return True
        if isinstance(self.readers, set):
            return principals.issubset(self.readers)
        return False
=======
>>>>>>> 8c4ca537ff73d47d0ecbe7df21b577bba6fddae2

@dataclass
class CaMeLValue:
    """All values carry metadata (Paper: complex CaMeLValue → Simple wrapper)"""
    value: Any                    # Actual data
    capabilities: Capabilities    # Metadata (source + permissions)
    
    def __repr__(self):
        return f"CaMeLValue({self.value!r}, {self.capabilities})"
    

<<<<<<< HEAD
# 정책 함수 타입 정의
PolicyFunction = callable

class PolicyRegistry:
    """정책 레지스트리: 정책 충돌 처리 및 우선순위 관리"""
    
    def __init__(self):
        # 정책 우선순위: 명시 Deny > 명시 Allow > 글로벌 > 기본 Allow
        self.global_checks: list[PolicyFunction] = []
        self.tool_checks: Dict[str, list[PolicyFunction]] = {}
        self.explicit_allows: Dict[str, set[str]] = {}  # operation -> {arg_name}
        self.explicit_denies: Dict[str, set[str]] = {}  # operation -> {arg_name}
    
    def add_global_policy(self, policy_func: PolicyFunction):
        """글로벌 정책 추가"""
        self.global_checks.append(policy_func)
    
    def add_tool_policy(self, operation: str, policy_func: PolicyFunction):
        """특정 툴 정책 추가"""
        if operation not in self.tool_checks:
            self.tool_checks[operation] = []
        self.tool_checks[operation].append(policy_func)
    
    def add_explicit_allow(self, operation: str, arg_name: str):
        """명시적 허용 추가"""
        if operation not in self.explicit_allows:
            self.explicit_allows[operation] = set()
        self.explicit_allows[operation].add(arg_name)
    
    def add_explicit_deny(self, operation: str, arg_name: str):
        """명시적 차단 추가"""
        if operation not in self.explicit_denies:
            self.explicit_denies[operation] = set()
        self.explicit_denies[operation].add(arg_name)
    
    def check(self, operation: str, args: Dict[str, CaMeLValue]) -> SecurityPolicyResult:
        """정책 체크: 결정적 순서로 실행"""
        
        # 1. 명시적 차단 (최고 우선순위)
        if operation in self.explicit_denies:
            for arg_name in self.explicit_denies[operation]:
                if arg_name in args:
                    return SecurityPolicyResult.deny(
                        "EXPLICIT_DENY",
                        f"Operation '{operation}' explicitly denied for '{arg_name}'"
                    )
        
        # 2. 명시적 허용 (차단보다 우선)
        if operation in self.explicit_allows:
            for arg_name in self.explicit_allows[operation]:
                if arg_name in args:
                    return SecurityPolicyResult.allow()
        
        # 3. 툴별 정책 (글로벌보다 우선)
        if operation in self.tool_checks:
            for policy_func in self.tool_checks[operation]:
                result = policy_func(operation, args)
                if not result.allowed:
                    return result
        
        # 4. 글로벌 정책
        for policy_func in self.global_checks:
            result = policy_func(operation, args)
            if not result.allowed:
                return result
        
        # 5. 기본 허용
        return SecurityPolicyResult.allow()

# ============================================================================
# 공통 헬퍼 정책들
# ============================================================================

def create_untrusted_danger_op_policy(dangerous_ops: set[str]):
    """비신뢰 데이터 + 위험한 작업 차단 정책"""
    def policy(operation: str, args: Dict[str, CaMeLValue]) -> SecurityPolicyResult:
        if operation in dangerous_ops:
            for arg_name, arg in args.items():
                if not arg.capabilities.is_trusted():
                    return SecurityPolicyResult.deny(
                        "UNTRUSTED_DANGER_OP",
                        f"Operation '{operation}' blocked: untrusted data in '{arg_name}'"
                    )
        return SecurityPolicyResult.allow()
    return policy

def create_risk_threshold_policy(risk_thresholds: Dict[str, RiskLevel]):
    """위험도 임계치 기반 차단 정책"""
    def policy(operation: str, args: Dict[str, CaMeLValue]) -> SecurityPolicyResult:
        if operation in risk_thresholds:
            threshold = risk_thresholds[operation]
            for arg_name, arg in args.items():
                if arg.capabilities.risk.value >= threshold.value:
                    return SecurityPolicyResult.deny(
                        "RISK_THRESHOLD_EXCEEDED",
                        f"Operation '{operation}' blocked: risk level {arg.capabilities.risk.name} exceeds threshold {threshold.name} for '{arg_name}'"
                    )
        return SecurityPolicyResult.allow()
    return policy

def create_reader_mismatch_policy(recipient_ops: set[str]):
    """수신자 권한 불일치 차단 정책"""
    def policy(operation: str, args: Dict[str, CaMeLValue]) -> SecurityPolicyResult:
        if operation in recipient_ops:
            if operation == "email":
                recipient = args.get("arg_0")
                content = args.get("arg_1")
                
                if recipient and content:
                    if not content.capabilities.readers_include({recipient.value}):
                        return SecurityPolicyResult.deny(
                            "READER_MISMATCH",
                            f"Email recipient '{recipient.value}' not in content readers"
                        )
        return SecurityPolicyResult.allow()
    return policy


class SecurityPolicy:
    def __init__(self):
        # 정책 레지스트리 초기화
        self.registry = PolicyRegistry()
        
        # 정책 설정
        self.dangerous_ops = {"write", "delete", "email"}
        self.risk_thresholds = {
            "write": RiskLevel.MEDIUM,    # MEDIUM 이상 위험 데이터로 쓰기 차단
            "delete": RiskLevel.LOW,      # LOW 이상 위험 데이터로 삭제 차단
            "email": RiskLevel.MEDIUM,    # MEDIUM 이상 위험 데이터로 이메일 차단 (LOW 허용)
        }
        self.recipient_ops = {"email", "event"}
        
        # 정책 등록
        self._register_policies()
    
    def _register_policies(self):
        """정책들을 레지스트리에 등록"""
        
        # 1. 비신뢰 데이터 + 위험한 작업 차단 (글로벌)
        self.registry.add_global_policy(
            create_untrusted_danger_op_policy(self.dangerous_ops)
        )
        
        # 2. 위험도 임계치 기반 차단 (글로벌)
        self.registry.add_global_policy(
            create_risk_threshold_policy(self.risk_thresholds)
        )
        
        # 3. 수신자 권한 불일치 차단 (글로벌)
        self.registry.add_global_policy(
            create_reader_mismatch_policy(self.recipient_ops)
        )
        
        # 4. 툴별 특수 정책 예시
        self.registry.add_tool_policy("email", self._email_specific_policy)
        self.registry.add_tool_policy("write", self._write_specific_policy)
    
    def _email_specific_policy(self, operation: str, args: Dict[str, CaMeLValue]) -> SecurityPolicyResult:
        """이메일 특수 정책: 추가 검증 로직"""
        if operation == "email":
            recipient = args.get("arg_0")
            content = args.get("arg_1")
            
            # 이메일 주소 형식 검증
            if recipient and "@" not in str(recipient.value):
                return SecurityPolicyResult.deny(
                    "INVALID_EMAIL",
                    f"Invalid email address format: {recipient.value}"
                )
            
            # 내용 길이 제한
            if content and len(str(content.value)) > 1000:
                return SecurityPolicyResult.deny(
                    "EMAIL_TOO_LONG",
                    f"Email content too long: {len(str(content.value))} characters"
                )
        
        return SecurityPolicyResult.allow()
    
    def _write_specific_policy(self, operation: str, args: Dict[str, CaMeLValue]) -> SecurityPolicyResult:
        """쓰기 특수 정책: 파일명 검증"""
        if operation == "write":
            data = args.get("arg_0")
            
            # 파일명에 위험한 문자 차단
            if data and any(char in str(data.value) for char in ['..', '/', '\\', '<', '>', '|']):
                return SecurityPolicyResult.deny(
                    "DANGEROUS_FILENAME",
                    f"Dangerous characters in filename: {data.value}"
                )
        
        return SecurityPolicyResult.allow()
    
    def check_access(self, operation: str, args: Dict[str, CaMeLValue]) -> SecurityPolicyResult:
        """정책 체크: 레지스트리를 통한 통합 검사"""
        return self.registry.check(operation, args)
    
    def add_explicit_allow(self, operation: str, arg_name: str):
        """명시적 허용 추가"""
        self.registry.add_explicit_allow(operation, arg_name)
    
    def add_explicit_deny(self, operation: str, arg_name: str):
        """명시적 차단 추가"""
        self.registry.add_explicit_deny(operation, arg_name)
    
    def add_custom_policy(self, operation: str, policy_func: PolicyFunction):
        """커스텀 정책 추가"""
        self.registry.add_tool_policy(operation, policy_func)

# ============================================================================
# QLLM (Quarantined LLM)
# ============================================================================

class NotEnoughInformationError(Exception):
    """QLLM이 충분한 정보를 얻지 못했을 때 발생하는 예외"""
    def __init__(self, message: str, missing_fields: Optional[list] = None):
        super().__init__(message)
        self.message = message
        self.missing_fields = missing_fields or []

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

Rules:
1. Extract only the information that is clearly present
2. Use null/None for missing fields
3. Include "have_enough_information": true/false based on whether you have sufficient data
4. Return ONLY the JSON object, nothing else

Example:
{{"name": "John Doe", "age": 25, "have_enough_information": true}}

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
            
            # have_enough_information 필드 확인
            have_enough = result_data.get('have_enough_information', True)
            if not have_enough:
                missing_fields = [field for field in output_schema.model_fields.keys() 
                                if field not in result_data or result_data[field] is None]
                raise NotEnoughInformationError(
                    f"Insufficient information to parse data. Missing fields: {missing_fields}",
                    missing_fields
                )
            
            # have_enough_information 필드 제거 후 스키마 생성
            result_data.pop('have_enough_information', None)
            parsed_result = output_schema(**result_data)
            return parsed_result
            
        except NotEnoughInformationError:
            # 정보 부족 예외는 그대로 전파
            raise
        except (json.JSONDecodeError, Exception) as e:
            # JSON 파싱 실패나 기타 오류 시 시뮬레이션으로 폴백
            print(f"QLLM parsing failed: {e}, using simulation")
            return self._simulate_parsing(query, output_schema)
    
    def _simulate_parsing(self, query: str, output_schema: Type[BaseModel]) -> BaseModel:
        """Ollama가 없을 경우 시뮬레이션으로 폴백"""
        
        # 스키마 필드에 맞는 기본값 생성
        field_values = {}
        
        for field_name, field_info in output_schema.model_fields.items():
            if field_name == "name":
                # 이름 추출 시도
                name_match = re.search(r'([A-Za-z\s]+)', query)
                field_values[field_name] = name_match.group(1).strip().lower() if name_match else "unknown"
            elif field_name == "email":
                # 이메일 추출 시도
                email_match = re.search(r'([a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,})', query)
                field_values[field_name] = email_match.group(1) if email_match else "unknown@example.com"
            elif field_name == "age":
                # 나이 추출 시도
                age_match = re.search(r'(\d+)', query)
                field_values[field_name] = int(age_match.group(1)) if age_match else 0
            elif field_name == "phone":
                field_values[field_name] = "000-0000-0000"
            elif field_name == "address":
                field_values[field_name] = "Unknown Address"
            else:
                # 기타 필드는 기본값
                if field_info.annotation == str:
                    field_values[field_name] = "Unknown"
                elif field_info.annotation == int:
                    field_values[field_name] = 0
                else:
                    field_values[field_name] = None
        
        return output_schema(**field_values)

# ============================================================================
# Tool Adapter (자동 Capabilities 부착)
# ============================================================================

def tool_adapter(tool_name: str):
    """툴 어댑터 데코레이터: 자동으로 Capabilities 부착"""
    def decorator(func):
        def wrapper(self, *args, **kwargs):
            # 입력 검증: self를 제외한 모든 인자가 CaMeLValue인지 확인
            for i, arg in enumerate(args):
                if not isinstance(arg, CaMeLValue):
                    raise TypeError(f"Tool '{tool_name}' argument {i} must be CaMeLValue, got {type(arg)}")
            
            # 툴 실행
            result = func(self, *args, **kwargs)
            
            # 결과가 CaMeLValue가 아니면 변환
            if not isinstance(result, CaMeLValue):
                result = CaMeLValue(result, Capabilities(
                    source=Source.CAMEL,
                    risk=RiskLevel.LOW,
                    readers="Public",
                    provenance=f"tool.{tool_name}",
                    inner_source=f"tool.{tool_name}.output"
                ))
            else:
                # 기존 CaMeLValue의 Capabilities 업데이트
                result.capabilities.provenance = f"tool.{tool_name}"
                result.capabilities.inner_source = f"tool.{tool_name}.output"
            
            return result
        return wrapper
    return decorator

# ============================================================================
# PLLM (Privileged LLM)
# ============================================================================

class PLLM:
    def __init__(self, model: str = "llama3.2:3b"):
        self.model = model
        self.client = ollama.Client()
        self.qllm = QLLM(model)
        self.policy = SecurityPolicy()
    
    @property
    def _tools(self):
        """데코레이터가 적용된 툴 메서드들을 반환"""
        return {
            "print": self._print,
            "write": self._write,
            "delete": self._delete,
            "email": self._email,
            "query_ai_assistant": self._query_ai
        }
    
    def process_query(self, query: str) -> CaMeLValue:
        # 간단한 코드 생성 시뮬레이션
        if "print" in query.lower():
            return self._print(CaMeLValue("Hello World", Capabilities(Source.CAMEL)))
        elif "write" in query.lower():
            return self._write(CaMeLValue("data", Capabilities(Source.USER)))
        else:
            return CaMeLValue(f"Processed: {query}", Capabilities(Source.CAMEL))
    
    @tool_adapter("print")
    def _print(self, data: CaMeLValue) -> CaMeLValue:
        return f"Output: {data.value}"
    
    @tool_adapter("write")
    def _write(self, data: CaMeLValue) -> CaMeLValue:
        return f"Write: {data.value}"
    
    @tool_adapter("delete")
    def _delete(self, filename: CaMeLValue) -> CaMeLValue:
        return f"Deleted: {filename.value}"
    
    @tool_adapter("email")
    def _email(self, recipient: CaMeLValue, content: CaMeLValue) -> CaMeLValue:
        return f"Email sent: {recipient.value}"
    
    def _query_ai(self, query: str, output_schema: Type[BaseModel], max_retries: int = 3) -> BaseModel:
        """QLLM을 사용하여 AI 쿼리 처리 (재시도 루프 포함)"""
        for attempt in range(max_retries):
            try:
                return self.qllm.parse_data(query, output_schema)
            except NotEnoughInformationError as e:
                if attempt == max_retries - 1:
                    # 최종 시도 실패 시 명확한 이유 출력
                    raise NotEnoughInformationError(
                        f"Failed to parse data after {max_retries} attempts. "
                        f"Missing fields: {e.missing_fields}. "
                        f"Original query: '{query}'"
                    )
                else:
                    # 재시도 전에 프롬프트 개선 (간단한 버전)
                    print(f"QLLM attempt {attempt + 1} failed: {e.message}. Retrying...")
                    # 실제로는 더 정교한 프롬프트 개선이 필요하지만, 
                    # 여기서는 간단히 재시도만 함
                    continue
    

# ============================================================================
# CaMeL System
# ============================================================================

class CaMeL:
    def __init__(self):
        self.pllm = PLLM()
        self.trace_logger = TraceLogger()
    
    def process(self, query: str) -> CaMeLValue:
        return self.pllm.process_query(query)
    
    def create_value(self, value: Any, source: Source = Source.USER, 
                    risk: Optional[RiskLevel] = None, readers: Readers = "Public",
                    provenance: str = "user", inner_source: Optional[str] = None) -> CaMeLValue:
        if risk is None:
            risk = infer_risk_from_value(value)
        
        # CAMEL 소스인 경우 자동으로 provenance 설정
        if source == Source.CAMEL:
            provenance = "camel"
        
        return CaMeLValue(value, Capabilities(
            source=source, 
            risk=risk,
            readers=readers,
            provenance=provenance,
            inner_source=inner_source
        ))
    
    def execute(self, operation: str, *args: CaMeLValue) -> CaMeLValue:
        """단일 게이트웨이: 모든 툴 호출은 여기서만 허용"""
        if operation in self.pllm._tools:
            args_dict = {f"arg_{i}": arg for i, arg in enumerate(args)}
            policy_result = self.pllm.policy.check_access(operation, args_dict)
            
            if not policy_result.allowed:
                # 차단된 경우 트레이스 로그 기록
                self.trace_logger.log_tool_call(
                    operation=operation,
                    args=args_dict,
                    result="Denied",
                    reason=policy_result.reason,
                    memstep={"policy_result": policy_result.reason_code}
                )
                return CaMeLValue(f"Security violation: {policy_result.reason}", 
                                 Capabilities(Source.CAMEL, RiskLevel.LOW))
            
            # 허용된 경우 툴 실행
            result = self.pllm._tools[operation](*args)
            
            # 성공한 경우 트레이스 로그 기록
            self.trace_logger.log_tool_call(
                operation=operation,
                args=args_dict,
                result="Allowed",
                reason="Operation executed successfully",
                memstep={"result_type": type(result).__name__}
            )
            
            return result
        
        # 알 수 없는 작업
        self.trace_logger.log_tool_call(
            operation=operation,
            args={},
            result="Denied",
            reason=f"Unknown operation: {operation}",
            memstep={"error": "unknown_operation"}
        )
        return CaMeLValue(f"Unknown: {operation}", Capabilities(Source.CAMEL))

=======
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
>>>>>>> 8c4ca537ff73d47d0ecbe7df21b577bba6fddae2
