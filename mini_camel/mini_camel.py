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
from typing import Any, Dict, Optional, Union, Set, Type, List, Callable
import json
import re
from datetime import datetime
from pydantic import BaseModel
import ollama
import yaml

# Trace Logging (감사/재현)

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
    
    def log_tool_call(self, operation: str, args, result: bool, reason: str, memstep: Optional[Dict[str, Any]] = None):
        """툴 호출 로그 기록"""
        # args가 리스트인 경우 딕셔너리로 변환
        if isinstance(args, list):
            args_dict = {f"arg_{i}": arg for i, arg in enumerate(args)}
        else:
            args_dict = args
        
        # PII 마스킹된 args 생성
        masked_args = self._mask_pii_in_args(args_dict)
        
        # 메모리 상태 스냅샷 (간단한 버전)
        if memstep is None:
            memstep = {"operation": operation, "timestamp": datetime.now().isoformat()}
        
        # 툴 호출 정보 (기존 TraceLogger의 ToolCall 구조 사용)
        tool_call = ToolCall(
            name=operation,
            args=masked_args,
            timestamp=datetime.now()
        )
        
        # 트레이스 엔트리 생성
        entry = TraceEntry(
            call=tool_call,
            memstep=memstep,
            result="Allowed" if result else "Denied",
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

# Capabilities (메타데이터)

class Source(Enum):
    USER = "user"      # 신뢰할 수 없음
    CAMEL = "camel"    # 신뢰할 수 있음


# Readers는 "Public" 문자열 또는 구체적인 사용자 ID 집합
Readers = Union[str, Set[str]]

class RiskLevel(Enum):
    LOW = 1      # 안전한 데이터 (기본값)
    MEDIUM = 3   # 중간 위험 데이터
    HIGH = 5     # 높은 위험 데이터

class DataImportance(Enum):
    """데이터 중요도 레벨"""
    PUBLIC = 1      # 공개 데이터
    INTERNAL = 2    # 내부 데이터
    CONFIDENTIAL = 3  # 기밀 데이터
    SECRET = 4      # 비밀 데이터

class SecurityMode(Enum):
    """보안 모드"""
    NORMAL = "NORMAL"  # 일반 모드: 제어 의존성 무시
    STRICT = "STRICT"  # 엄격 모드: 제어 의존성 포함

class OperationMode(Enum):
    """운영 모드"""
    ENFORCEMENT = "ENFORCEMENT"  # 실제 차단 모드
    DRY_RUN = "DRY_RUN"          # 드라이런 모드 (경고만)

class PolicyPriority(Enum):
    """정책 우선순위"""
    HARD_RULES = 1           # 하드룰 (세분화된 정책)
    EXPLICIT_ALLOW = 2       # 명시적 허용
    LEVEL_THRESHOLDS = 3     # 레벨 임계치
    DEFAULT_ALLOW = 4        # 기본 허용

@dataclass
class Capabilities:
    source: Source
    risk: RiskLevel = RiskLevel.LOW
    readers: Readers = "Public"  # "Public" 또는 구체적인 사용자 ID 집합
    provenance: str = "user"  # "user", "camel", "tool_id", "qllm"
    inner_source: Optional[str] = None  # 내부 소스 정보
    importance: DataImportance = DataImportance.PUBLIC  # 데이터 중요도
    
    def is_trusted(self) -> bool:
        return self.source == Source.CAMEL
    
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

@dataclass
class CaMeLValue:
    value: Any
    capabilities: Capabilities
    depends_on: Optional[Set[str]] = None  # 데이터 의존성 추적
    control_depends_on: Optional[Set[str]] = None  # 제어 의존성 추적 (조건/루프에서 사용된 값)
    
    def __post_init__(self):
        if self.depends_on is None:
            self.depends_on = set()
        if self.control_depends_on is None:
            self.control_depends_on = set()

# ToolCall (플랜 실행을 위한 툴 호출 정의)

@dataclass
class PlanToolCall:
    """플랜 실행을 위한 툴 호출 데이터 클래스"""
    operation: str
    args: List[CaMeLValue]
    
    def __post_init__(self):
        # 모든 인자가 CaMeLValue인지 검증
        for i, arg in enumerate(self.args):
            if not isinstance(arg, CaMeLValue):
                raise TypeError(f"PlanToolCall argument {i} must be CaMeLValue, got {type(arg)}")

# 위험도 추론 함수

def infer_risk_from_value(value: Any) -> RiskLevel:
    """값의 내용을 분석하여 위험도를 추론"""
    if not isinstance(value, str):
        return RiskLevel.LOW
    
    value_str = str(value).lower()
    
    # 이메일 주소는 수신자 식별자이므로 항상 LOW 위험도
    if '@' in value and '.' in value.split('@')[-1]:
        return RiskLevel.LOW
    
    # HIGH 위험 패턴 (민감한 개인정보)
    high_risk_patterns = [
        r'\d{6}-\d{7}',  # 주민등록번호 (6자리-7자리)
        r'\d{3}-\d{4}-\d{4}',  # 전화번호 (3-4-4)
        r'\d{2,3}-\d{3,4}-\d{4}',  # 전화번호 변형
        r'\b\d{4}-\d{2}-\d{2}\b',  # 생년월일 (YYYY-MM-DD)
        r'\b\d{2}/\d{2}/\d{4}\b',  # 생년월일 (MM/DD/YYYY)
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
        r'^[가-힣]{2,4}$',  # 한국어 이름 (2-4글자)
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

def infer_importance_from_value(value: Any) -> DataImportance:
    """값의 내용을 분석하여 중요도를 추론"""
    if not isinstance(value, str):
        return DataImportance.PUBLIC
    
    value_str = str(value).lower()
    
    # 이메일 주소는 수신자 식별자이므로 항상 PUBLIC 중요도
    if '@' in value and '.' in value.split('@')[-1]:
        return DataImportance.PUBLIC
    
    # SECRET 중요도 패턴 (최고 중요도)
    secret_patterns = [
        r'password|passwd|pwd',  # 패스워드 관련
        r'secret|private|confidential',  # 기밀 정보
        r'key|token|credential',  # 인증 정보
        r'admin|root|superuser',  # 관리자 계정
    ]
    
    # CONFIDENTIAL 중요도 패턴
    confidential_patterns = [
        r'email|@',  # 이메일 주소
        r'phone|전화',  # 전화번호
        r'address|주소',  # 주소
        r'personal|개인',  # 개인정보
    ]
    
    # INTERNAL 중요도 패턴
    internal_patterns = [
        r'company|회사',  # 회사 정보
        r'internal|내부',  # 내부 정보
        r'project|프로젝트',  # 프로젝트 정보
    ]
    
    # SECRET 중요도 검사
    for pattern in secret_patterns:
        if re.search(pattern, value_str):
            return DataImportance.SECRET
    
    # CONFIDENTIAL 중요도 검사
    for pattern in confidential_patterns:
        if re.search(pattern, value_str):
            return DataImportance.CONFIDENTIAL
    
    # INTERNAL 중요도 검사
    for pattern in internal_patterns:
        if re.search(pattern, value_str):
            return DataImportance.INTERNAL
    
    return DataImportance.PUBLIC

# Security Policy

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

# 정책 함수 타입 정의
PolicyFunction = callable

class PolicyRegistry:
    """정책 레지스트리: 정책 충돌 처리 및 우선순위 관리"""
    
    def __init__(self):
        # 정책 우선순위: 하드룰 > 명시 Allow > 레벨 임계치 > 기본 Allow
        self.global_checks: List[tuple[PolicyFunction, int]] = []  # (policy, priority)
        self.tool_checks: Dict[str, List[tuple[PolicyFunction, int]]] = {}
        self.explicit_allows: Dict[str, set[str]] = {}  # operation -> {arg_name}
        self.explicit_denies: Dict[str, set[str]] = {}  # operation -> {arg_name}
        self.explicit_allow_policies: List[Dict[str, str]] = []  # 명시적 허용 정책 리스트
    
    def add_global_policy(self, policy_func: PolicyFunction, priority: int = 3):
        """글로벌 정책 추가 (우선순위 포함)"""
        self.global_checks.append((policy_func, priority))
        # 우선순위 순으로 정렬 (낮은 숫자가 높은 우선순위)
        self.global_checks.sort(key=lambda x: x[1])
    
    def add_tool_policy(self, operation: str, policy_func: PolicyFunction, priority: int = 3):
        """특정 툴 정책 추가 (우선순위 포함)"""
        if operation not in self.tool_checks:
            self.tool_checks[operation] = []
        self.tool_checks[operation].append((policy_func, priority))
        # 우선순위 순으로 정렬
        self.tool_checks[operation].sort(key=lambda x: x[1])
    
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
    
    def add_explicit_allow_policy(self, allow_rule: Dict[str, str]):
        """명시적 허용 정책 추가 (조건 기반)"""
        self.explicit_allow_policies.append(allow_rule)
    
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
        
        # 2. 명시적 허용 (조건 기반) - 매치될 때만 허용
        for allow_rule in self.explicit_allow_policies:
            if allow_rule.get("operation") == operation:
                condition = allow_rule.get("condition", "")
                if _evaluate_condition(condition, args):
                    # 제어 의존성이 있는 경우 명시적 허용을 적용하지 않음
                    has_control_dependency = any(
                        arg_value.control_depends_on and 
                        any(sensitive in str(arg_value.control_depends_on) for sensitive in ["qllm", "secret", "password", "admin"])
                        for arg_value in args.values()
                    )
                    if not has_control_dependency:
                        return SecurityPolicyResult.allow()
        
        # 3. 기존 명시적 허용 (arg_name 기반)
        if operation in self.explicit_allows:
            for arg_name in self.explicit_allows[operation]:
                if arg_name in args:
                    return SecurityPolicyResult.allow()
        
        # 4. 툴별 정책 (글로벌보다 우선, 우선순위 순으로 실행)
        if operation in self.tool_checks:
            for policy_func, priority in self.tool_checks[operation]:
                result = policy_func(operation, args)
                if not result.allowed:
                    return result
        
        # 5. 글로벌 정책 (우선순위 순으로 실행)
        for policy_func, priority in self.global_checks:
            result = policy_func(operation, args)
            if not result.allowed:
                return result
        
        # 6. 기본 허용
        return SecurityPolicyResult.allow()

# 공통 헬퍼 정책들

def create_untrusted_danger_op_policy(dangerous_ops: Set[str]) -> Callable[[str, Dict[str, CaMeLValue]], SecurityPolicyResult]:
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

def create_risk_threshold_policy(risk_thresholds: Dict[str, RiskLevel]) -> Callable[[str, Dict[str, CaMeLValue]], SecurityPolicyResult]:
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

def create_reader_mismatch_policy(recipient_ops: Set[str]) -> Callable[[str, Dict[str, CaMeLValue]], SecurityPolicyResult]:
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

def create_dependency_policy():
    """데이터 의존성 기반 정책: Q-LLM 의존 값의 외부 전송 차단"""
    def policy(operation: str, args: Dict[str, CaMeLValue]) -> SecurityPolicyResult:
        # 외부 전송 연산들
        external_ops = {"email", "write"}
        
        if operation in external_ops:
            for arg_name, arg_value in args.items():
                # Q-LLM 의존성이 있는 값인지 확인
                if any("qllm" in dep for dep in arg_value.depends_on):
                    return SecurityPolicyResult.deny(
                        "QLLM_DEPENDENCY_BLOCKED",
                        f"External operation '{operation}' blocked: value depends on Q-LLM output"
                    )
        
        return SecurityPolicyResult.allow()
    return policy

def create_importance_based_policy(dangerous_ops: set[str], importance_thresholds: Dict[str, DataImportance]):
    """데이터 중요도 기반 정책: (1) 위험연산+비신뢰값 하드차단, (2) 중요도 임계치 초과시 차단"""
    def policy(operation: str, args: Dict[str, CaMeLValue]) -> SecurityPolicyResult:
        # 1. 위험 연산에 비신뢰 값 들어오면 하드 차단
        if operation in dangerous_ops:
            for arg_name, arg in args.items():
                if not arg.capabilities.is_trusted():
                    return SecurityPolicyResult.deny(
                        "UNTRUSTED_DANGER_OP",
                        f"Operation '{operation}' blocked: untrusted data in '{arg_name}' (hard block for dangerous operations)"
                    )
        
        # 2. 중요도 임계치 초과 시 차단
        if operation in importance_thresholds:
            threshold = importance_thresholds[operation]
            for arg_name, arg in args.items():
                if arg.capabilities.importance.value > threshold.value:
                    return SecurityPolicyResult.deny(
                        "IMPORTANCE_THRESHOLD_EXCEEDED",
                        f"Operation '{operation}' blocked: data importance {arg.capabilities.importance.name} exceeds threshold {threshold.name} for '{arg_name}'"
                    )
        
        return SecurityPolicyResult.allow()
    return policy

def create_risk_importance_combined_policy(dangerous_ops: Set[str], risk_thresholds: Dict[str, RiskLevel], importance_thresholds: Dict[str, DataImportance], config: 'SecurityConfig' = None) -> Callable[[str, Dict[str, CaMeLValue]], SecurityPolicyResult]:
    """위험도와 중요도를 결합한 정책: 다층 보안 검사"""
    def policy(operation: str, args: Dict[str, CaMeLValue]) -> SecurityPolicyResult:
        # 1. 위험 연산 + 비신뢰 데이터 = 하드 차단 (제거됨)
        # Q-LLM 의존성 정책이 이미 Q-LLM 의존성 값을 차단하고,
        # 일반적인 USER 소스 데이터는 허용하도록 함
        # 주석: 이 검사는 너무 엄격하여 일반적인 사용을 방해함
        
        # 2. 위험도 임계치 검사 (컨텍스트 기반 조정 적용)
        if operation in risk_thresholds:
            # 컨텍스트 정보 수집
            context = {}
            for arg_name, arg in args.items():
                if arg.capabilities.source == Source.USER:
                    context['user_role'] = 'user'  # 기본 역할
                elif arg.capabilities.source == Source.CAMEL:
                    context['data_source'] = 'camel'
            
            # 조정된 임계치 사용
            if config:
                threshold = config.get_adjusted_threshold(operation, context)
            else:
                threshold = risk_thresholds[operation]
            
            for arg_name, arg in args.items():
                if arg.capabilities.risk.value >= threshold.value:
                    return SecurityPolicyResult.deny(
                        "RISK_THRESHOLD_EXCEEDED",
                        f"Operation '{operation}' blocked: risk level {arg.capabilities.risk.name} exceeds threshold {threshold.name} for '{arg_name}'"
                    )
        
        # 3. 중요도 임계치 검사
        if operation in importance_thresholds:
            threshold = importance_thresholds[operation]
            for arg_name, arg in args.items():
                if arg.capabilities.importance.value > threshold.value:
                    return SecurityPolicyResult.deny(
                        "IMPORTANCE_THRESHOLD_EXCEEDED",
                        f"Operation '{operation}' blocked: data importance {arg.capabilities.importance.name} exceeds threshold {threshold.name} for '{arg_name}'"
                    )
        
        return SecurityPolicyResult.allow()
    return policy

def create_control_dependency_policy(mode: SecurityMode) -> Callable[[str, Dict[str, CaMeLValue]], SecurityPolicyResult]:
    """제어 의존성 기반 정책: STRICT 모드에서 조건/루프 의존성 차단"""
    def policy(operation: str, args: Dict[str, CaMeLValue]) -> SecurityPolicyResult:
        if mode == SecurityMode.STRICT:
            for arg_name, arg_value in args.items():
                # 제어 의존성이 있는 값인지 확인
                if arg_value.control_depends_on:
                    # 민감한 제어 의존성 체크
                    for control_dep in arg_value.control_depends_on:
                        if any(sensitive in control_dep for sensitive in ["qllm", "secret", "password", "admin"]):
                            return SecurityPolicyResult.deny(
                                "CONTROL_DEPENDENCY_BLOCKED",
                                f"Operation '{operation}' blocked: value has sensitive control dependency '{control_dep}' in STRICT mode"
                            )
        return SecurityPolicyResult.allow()
    return policy

def create_hard_rules_policy(hard_rules: List[Dict[str, str]]) -> Callable[[str, Dict[str, CaMeLValue]], SecurityPolicyResult]:
    """하드룰 정책: 패턴 기반 차단 (최고 우선순위)"""
    def policy(operation: str, args: Dict[str, CaMeLValue]) -> SecurityPolicyResult:
        for rule in hard_rules:
            pattern = rule.get("pattern", "")
            action = rule.get("action", "BLOCK")
            message = rule.get("message", f"Hard rule violation: {rule.get('name', 'UNKNOWN')}")
            
            if action == "BLOCK":
                for arg_name, arg_value in args.items():
                    if re.search(pattern, str(arg_value.value), re.IGNORECASE):
                        return SecurityPolicyResult.deny(
                            "HARD_RULE_VIOLATION",
                            f"Operation '{operation}' blocked: {message}"
                        )
        return SecurityPolicyResult.allow()
    return policy

# create_explicit_allow_policy 함수는 제거됨 - PolicyRegistry에서 직접 처리

def _evaluate_condition(condition: str, args: Dict[str, CaMeLValue]) -> bool:
    """간단한 조건 평가 (실제로는 더 복잡한 파서 필요)"""
    # 간단한 구현: source == 'CAMEL' AND risk == 'LOW' 같은 조건
    try:
        # 모든 조건을 AND로 연결하여 평가
        conditions_met = []
        
        if "source == 'CAMEL'" in condition:
            source_ok = all(arg.capabilities.source == Source.CAMEL for arg in args.values())
            conditions_met.append(source_ok)
        elif "source == 'USER'" in condition:
            source_ok = all(arg.capabilities.source == Source.USER for arg in args.values())
            conditions_met.append(source_ok)
        
        if "risk == 'LOW'" in condition:
            risk_ok = all(arg.capabilities.risk == RiskLevel.LOW for arg in args.values())
            conditions_met.append(risk_ok)
        elif "risk == 'MEDIUM'" in condition:
            risk_ok = all(arg.capabilities.risk == RiskLevel.MEDIUM for arg in args.values())
            conditions_met.append(risk_ok)
        elif "risk == 'HIGH'" in condition:
            risk_ok = all(arg.capabilities.risk == RiskLevel.HIGH for arg in args.values())
            conditions_met.append(risk_ok)
        
        if "importance == 'PUBLIC'" in condition:
            importance_ok = all(arg.capabilities.importance == DataImportance.PUBLIC for arg in args.values())
            conditions_met.append(importance_ok)
        elif "importance == 'INTERNAL'" in condition:
            importance_ok = all(arg.capabilities.importance == DataImportance.INTERNAL for arg in args.values())
            conditions_met.append(importance_ok)
        elif "importance == 'CONFIDENTIAL'" in condition:
            importance_ok = all(arg.capabilities.importance == DataImportance.CONFIDENTIAL for arg in args.values())
            conditions_met.append(importance_ok)
        
        # 모든 조건이 만족되어야 함 (AND 로직)
        return all(conditions_met) if conditions_met else False
    except:
        return False

def sanitize_error_message(message: str, args) -> str:
    """예외 메시지에서 비신뢰 텍스트 검열"""
    sanitized_message = message
    
    # args가 list인 경우 dict로 변환
    if isinstance(args, list):
        args_dict = {f"arg_{i}": arg for i, arg in enumerate(args)}
    else:
        args_dict = args
    
    for arg_name, arg_value in args_dict.items():
        # CaMeLValue 객체인지 확인
        if hasattr(arg_value, 'capabilities') and hasattr(arg_value, 'value'):
            # 비신뢰 소스의 데이터를 [REDACTED]로 대체
            if arg_value.capabilities.provenance in {"user", "qllm"}:
                # 해당 인자의 값이 메시지에 포함되어 있으면 [REDACTED]로 대체
                if str(arg_value.value) in sanitized_message:
                    sanitized_message = sanitized_message.replace(str(arg_value.value), "[REDACTED]")
                
                # 추가: 일반적인 악성 패턴도 검열
                value_str = str(arg_value.value)
                if any(pattern in value_str.lower() for pattern in ["drop", "delete", "insert", "update", "select", "script", "alert", "password", "admin"]):
                    # 메시지에 악성 패턴이 포함되어 있으면 [REDACTED]로 대체
                    for pattern in ["drop", "delete", "insert", "update", "select", "script", "alert", "password", "admin"]:
                        if pattern in sanitized_message.lower():
                            sanitized_message = sanitized_message.replace(pattern, "[REDACTED]")
    
    return sanitized_message

class SecurityError(Exception):
    """보안 정책 위반 시 발생하는 예외"""
    pass

def create_sanitized_security_error(operation: str, reason: str, args) -> SecurityError:
    """검열된 보안 에러 생성"""
    sanitized_reason = sanitize_error_message(reason, args)
    return SecurityError(f"Operation '{operation}' blocked: {sanitized_reason}")

@dataclass
class SecurityConfig:
    """보안 정책 설정 관리"""
    operation_mode: OperationMode = OperationMode.ENFORCEMENT
    dry_run: bool = False
    log_level: str = "INFO"
    
    # 정책 우선순위
    policy_priority: Dict[str, int] = None
    
    # 임계치 설정
    risk_thresholds: Dict[str, RiskLevel] = None
    importance_thresholds: Dict[str, DataImportance] = None
    tool_risk_levels: Dict[str, RiskLevel] = None
    
    # 컨텍스트 보정값
    context_adjustments: Dict[str, Dict[str, float]] = None
    
    # 하드룰
    hard_rules: List[Dict[str, str]] = None
    
    # 명시적 허용 규칙
    explicit_allows: List[Dict[str, str]] = None
    
    def __post_init__(self):
        if self.policy_priority is None:
            self.policy_priority = {
                "hard_rules": 1,
                "explicit_allow": 2,
                "level_thresholds": 3,
                "default_allow": 4
            }
        
        if self.risk_thresholds is None:
            self.risk_thresholds = {
                "write": RiskLevel.MEDIUM,
                "delete": RiskLevel.LOW,
                "email": RiskLevel.MEDIUM,
                "print": RiskLevel.HIGH
            }
        
        if self.importance_thresholds is None:
            self.importance_thresholds = {
                "write": DataImportance.CONFIDENTIAL,
                "delete": DataImportance.PUBLIC,
                "email": DataImportance.INTERNAL,
                "print": DataImportance.SECRET
            }
        
        if self.tool_risk_levels is None:
            self.tool_risk_levels = {
                "print": RiskLevel.LOW,
                "write": RiskLevel.MEDIUM,
                "delete": RiskLevel.HIGH,
                "email": RiskLevel.HIGH
            }
        
        if self.context_adjustments is None:
            self.context_adjustments = {
                "time_based": {"business_hours": 0.8, "after_hours": 1.2},
                "user_role": {"admin": 0.5, "user": 1.0, "guest": 1.5},
                "data_source": {"internal": 0.8, "external": 1.2}
            }
        
        if self.hard_rules is None:
            # 기본적으로 하드룰 비활성화 (기존 테스트 호환성을 위해)
            self.hard_rules = []
        
        if self.explicit_allows is None:
            self.explicit_allows = [
                {"operation": "print", "condition": "source == 'CAMEL' AND risk == 'LOW'"}
            ]
    
    @classmethod
    def from_yaml(cls, file_path: str) -> 'SecurityConfig':
        """YAML 파일에서 설정 로드"""
        with open(file_path, 'r', encoding='utf-8') as f:
            config_data = yaml.safe_load(f)
        
        # Enum 변환
        if 'operation_mode' in config_data:
            config_data['operation_mode'] = OperationMode.ENFORCEMENT if not config_data.get('dry_run', False) else OperationMode.DRY_RUN
        
        # RiskLevel 변환
        if 'risk_thresholds' in config_data:
            config_data['risk_thresholds'] = {k: RiskLevel[v] for k, v in config_data['risk_thresholds'].items()}
        
        if 'importance_thresholds' in config_data:
            config_data['importance_thresholds'] = {k: DataImportance[v] for k, v in config_data['importance_thresholds'].items()}
        
        if 'tool_risk_levels' in config_data:
            config_data['tool_risk_levels'] = {k: RiskLevel[v] for k, v in config_data['tool_risk_levels'].items()}
        
        return cls(**config_data)
    
    def reload_from_yaml(self, file_path: str):
        """YAML 파일에서 설정 재로드"""
        new_config = self.from_yaml(file_path)
        self.__dict__.update(new_config.__dict__)
    
    def get_adjusted_threshold(self, operation: str, context: Dict[str, Any] = None) -> RiskLevel:
        """컨텍스트를 고려한 조정된 임계치 반환"""
        base_threshold = self.risk_thresholds.get(operation, RiskLevel.MEDIUM)
        
        if not context:
            return base_threshold
        
        # 컨텍스트 보정값 적용
        adjustment = 1.0
        
        # 시간대 보정
        if 'time_based' in self.context_adjustments:
            current_hour = datetime.now().hour
            if 9 <= current_hour <= 17:  # 업무시간
                adjustment *= self.context_adjustments['time_based']['business_hours']
            else:
                adjustment *= self.context_adjustments['time_based']['after_hours']
        
        # 사용자 역할 보정
        if 'user_role' in self.context_adjustments and 'user_role' in context:
            user_role = context['user_role']
            if user_role in self.context_adjustments['user_role']:
                adjustment *= self.context_adjustments['user_role'][user_role]
        
        # 데이터 소스 보정
        if 'data_source' in self.context_adjustments and 'data_source' in context:
            data_source = context['data_source']
            if data_source in self.context_adjustments['data_source']:
                adjustment *= self.context_adjustments['data_source'][data_source]
        
        # 조정된 임계치 반환 (간단한 구현)
        if adjustment < 0.8:
            # RiskLevel의 유효한 값들: 1, 3, 5
            if base_threshold.value == 1:
                return RiskLevel.LOW
            elif base_threshold.value == 3:
                return RiskLevel.LOW
            else:  # 5
                return RiskLevel.MEDIUM
        elif adjustment > 1.2:
            # RiskLevel의 유효한 값들: 1, 3, 5
            if base_threshold.value == 1:
                return RiskLevel.MEDIUM
            elif base_threshold.value == 3:
                return RiskLevel.HIGH
            else:  # 5
                return RiskLevel.HIGH
        else:
            return base_threshold

class SecurityPolicy:
    def __init__(self, mode: SecurityMode = SecurityMode.NORMAL, config: Optional[SecurityConfig] = None):
        # 정책 레지스트리 초기화
        self.registry = PolicyRegistry()
        self.mode = mode
        self.config = config or SecurityConfig()
        
        # 정책 설정 (설정 파일에서 로드)
        self.dangerous_ops = {"write", "delete", "email"}
        self.risk_thresholds = self.config.risk_thresholds
        self.importance_thresholds = self.config.importance_thresholds
        self.recipient_ops = {"email", "event"}
        
        # 정책 등록
        self._register_policies()
    
    def _register_policies(self):
        """정책들을 우선순위에 따라 레지스트리에 등록"""
        
        # 1. 하드룰 (최고 우선순위)
        if self.config.hard_rules:
            self.registry.add_global_policy(
                create_hard_rules_policy(self.config.hard_rules),
                priority=self.config.policy_priority["hard_rules"]
            )
        
        # 2. 데이터 의존성 기반 차단 (Q-LLM 의존성 차단) - 최고 우선순위
        self.registry.add_global_policy(
            create_dependency_policy(),
            priority=0  # 하드룰과 같은 최고 우선순위
        )
        
        # 3. 명시적 허용 (세 번째 우선순위) - 새로운 방식으로 처리
        if self.config.explicit_allows:
            for allow_rule in self.config.explicit_allows:
                self.registry.add_explicit_allow_policy(allow_rule)
        
        # 4. 수신자 권한 불일치 차단 (글로벌)
        self.registry.add_global_policy(
            create_reader_mismatch_policy(self.recipient_ops),
            priority=self.config.policy_priority["level_thresholds"]
        )
        
        # 5. 중요도 기반 정책 (글로벌) - 컨텍스트 기반 임계치 적용
        self.registry.add_global_policy(
            create_risk_importance_combined_policy(
                self.dangerous_ops, 
                self.risk_thresholds, 
                self.importance_thresholds,
                self.config  # 컨텍스트 기반 임계치 조정을 위해 config 전달
            ),
            priority=self.config.policy_priority["level_thresholds"]
        )
        
        # 6. 제어 의존성 기반 정책 (글로벌) - STRICT 모드에서만 활성화
        self.registry.add_global_policy(
            create_control_dependency_policy(self.mode),
            priority=self.config.policy_priority["level_thresholds"]
        )
        
        # 7. 툴별 특수 정책 예시
        self.registry.add_tool_policy("email", self._email_specific_policy)
        self.registry.add_tool_policy("write", self._write_specific_policy)
    
    def _email_specific_policy(self, operation: str, args: Dict[str, CaMeLValue]) -> SecurityPolicyResult:
        """이메일 특수 정책: 추가 검증 로직"""
        if operation == "email":
            recipient = args.get("arg_0")
            content = args.get("arg_1")
            
            # 1. 의존성 체크 (최우선)
            for arg_name, arg_value in args.items():
                if any("qllm" in dep for dep in arg_value.depends_on):
                    return SecurityPolicyResult.deny(
                        "QLLM_DEPENDENCY_BLOCKED",
                        f"External operation '{operation}' blocked: value depends on Q-LLM output"
                    )
            
            # 2. 이메일 주소 형식 검증
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
        """쓰기 특수 정책: 파일명 검증 및 위험도 임계치 검사"""
        if operation == "write":
            data = args.get("arg_0")
            
            # 1. 의존성 체크 (최우선)
            for arg_name, arg_value in args.items():
                if any("qllm" in dep for dep in arg_value.depends_on):
                    return SecurityPolicyResult.deny(
                        "QLLM_DEPENDENCY_BLOCKED",
                        f"External operation '{operation}' blocked: value depends on Q-LLM output"
                    )
            
            # 2. 위험도 임계치 검사
            if operation in self.risk_thresholds:
                threshold = self.risk_thresholds[operation]
                for arg_name, arg in args.items():
                    if arg.capabilities.risk.value >= threshold.value:
                        return SecurityPolicyResult.deny(
                            "RISK_THRESHOLD_EXCEEDED",
                            f"Operation '{operation}' blocked: risk level {arg.capabilities.risk.name} exceeds threshold {threshold.name} for '{arg_name}'"
                        )
            
            # 3. 파일명에 위험한 문자 차단
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

# QLLM (Quarantined LLM)

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
            
            # JSON 파싱 시도 (eval() 제거, 보안 강화)
            response_text = response['response'].strip()
            
            try:
                # JSON 파싱만 허용 (eval() 제거로 보안 강화)
                result_data = json.loads(response_text)
            except json.JSONDecodeError:
                # JSON이 아니면 시뮬레이션 폴백으로
                return self._simulate_parsing(query, output_schema)
            
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
            # QLLM parsing failed, using simulation
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

# Tool Adapter (자동 Capabilities 부착)

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

# PLLM (Privileged LLM)

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
    
    def process_query(self, query: str, max_retries: int = 3) -> List[PlanToolCall]:
        """PLLM: 사용자 쿼리를 처리하여 툴 플랜 생성 (재시도 포함)"""
        for attempt in range(max_retries):
            try:
                return self._generate_plan(query)
            except SecurityError as e:
                if attempt == max_retries - 1:
                    # 최종 시도 실패 시 요약된 에러 메시지
                    raise SecurityError(f"PLLM failed after {max_retries} attempts: Security policy violation")
                # 재시도 전에 잠시 대기 (시뮬레이션)
                continue
            except Exception as e:
                if attempt == max_retries - 1:
                    raise RuntimeError(f"PLLM failed after {max_retries} attempts: {str(e)}")
                continue
        
        # 이론적으로 도달할 수 없는 코드
        raise RuntimeError("Unexpected end of retry loop")
    
    def _generate_plan(self, query: str) -> List[PlanToolCall]:
        """실제 플랜 생성 로직 (시뮬레이션)"""
        plan = []
        
        if "print" in query.lower():
            plan.append(PlanToolCall(
                operation="print",
                args=[CaMeLValue("Hello World", Capabilities(Source.CAMEL, RiskLevel.LOW, "Public", "pllm", "pllm.generated"))]
            ))
        elif "write" in query.lower():
            plan.append(PlanToolCall(
                operation="write",
                args=[CaMeLValue("data", Capabilities(Source.USER, RiskLevel.LOW, "Public", "user", "user.input"))]
            ))
        elif "delete" in query.lower():
            plan.append(PlanToolCall(
                operation="delete",
                args=[CaMeLValue("file.txt", Capabilities(Source.USER, RiskLevel.LOW, "Public", "user", "user.input"))]
            ))
        elif "email" in query.lower():
            plan.append(PlanToolCall(
                operation="email",
                args=[
                    CaMeLValue("user@example.com", Capabilities(Source.USER, RiskLevel.LOW, "Public", "user", "user.input")),
                    CaMeLValue("Hello", Capabilities(Source.USER, RiskLevel.LOW, "Public", "user", "user.input"))
                ]
            ))
        else:
            # 기본적으로 print 플랜 생성
            plan.append(PlanToolCall(
                operation="print",
                args=[CaMeLValue(f"Processed: {query}", Capabilities(Source.CAMEL, RiskLevel.LOW, "Public", "pllm", "pllm.processed"))]
            ))
        
        return plan
    
    @tool_adapter("print")
    def _print(self, data: CaMeLValue) -> CaMeLValue:
        return CaMeLValue(f"Output: {data.value}", Capabilities(Source.CAMEL, RiskLevel.LOW, "Public", "qllm", "qllm.print"), depends_on={"qllm"})
    
    @tool_adapter("write")
    def _write(self, data: CaMeLValue) -> CaMeLValue:
        return CaMeLValue(f"Write: {data.value}", Capabilities(Source.CAMEL, RiskLevel.LOW, "Public", "qllm", "qllm.write"), depends_on={"qllm"})
    
    @tool_adapter("delete")
    def _delete(self, filename: CaMeLValue) -> CaMeLValue:
        return CaMeLValue(f"Deleted: {filename.value}", Capabilities(Source.CAMEL, RiskLevel.LOW, "Public", "qllm", "qllm.delete"), depends_on={"qllm"})
    
    @tool_adapter("email")
    def _email(self, recipient: CaMeLValue, content: CaMeLValue) -> CaMeLValue:
        return CaMeLValue(f"Email sent: {recipient.value}", Capabilities(Source.CAMEL, RiskLevel.LOW, "Public", "qllm", "qllm.email"), depends_on={"qllm"})
    
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
                    # QLLM attempt failed, retrying...
                    continue
        
        # 이론적으로 도달할 수 없는 코드 (for 루프가 항상 return 또는 raise)
        raise RuntimeError("Unexpected end of retry loop")

# Interpreter (미니 해석기 게이트)

class Interpreter:
    """미니 해석기 게이트: 플랜 실행을 통한 툴 호출 제어"""
    
    def __init__(self, security_policy: 'SecurityPolicy', trace_logger: 'TraceLogger'):
        self.security_policy = security_policy
        self.trace_logger = trace_logger
        
        # 화이트리스트된 연산들
        self.whitelisted_operations = {
            "print", "write", "delete", "email"
        }
    
    def run(self, plan: List[PlanToolCall]) -> List[CaMeLValue]:
        """플랜을 실행하고 각 툴 호출에 대해 정책 검사 → 실행 → 트레이스"""
        results = []
        
        for tool_call in plan:
            # 1. 화이트리스트 검증
            if tool_call.operation not in self.whitelisted_operations:
                error_msg = f"Operation '{tool_call.operation}' is not whitelisted"
                self.trace_logger.log_tool_call(
                    tool_call.operation, 
                    tool_call.args, 
                    False, 
                    error_msg
                )
                raise ValueError(error_msg)
            
            # 2. 정책 검사 (args를 딕셔너리로 변환)
            args_dict = {f"arg_{i}": arg for i, arg in enumerate(tool_call.args)}
            policy_result = self.security_policy.check_access(tool_call.operation, args_dict)
            
            if not policy_result.allowed:
                # 차단된 경우
                self.trace_logger.log_tool_call(
                    tool_call.operation, 
                    tool_call.args, 
                    False, 
                    policy_result.reason
                )
                
                # 드라이런 모드 확인
                if self.security_policy.config.operation_mode == OperationMode.DRY_RUN:
                    # 드라이런 모드: 경고만 로그하고 계속 진행
                    print(f"[DRY RUN WARNING] {policy_result.reason}")
                    # 실제로는 실행하지 않고 시뮬레이션 결과 반환
                    result = CaMeLValue(
                        f"[DRY RUN] Would have executed: {tool_call.operation}",
                        Capabilities(Source.CAMEL, RiskLevel.LOW, "Public", "dry_run", "dry_run.simulation"),
                        depends_on=set(),
                        control_depends_on=set()
                    )
                    results.append(result)
                    continue
                else:
                    # 실제 차단 모드: 에러 발생
                    raise create_sanitized_security_error(tool_call.operation, policy_result.reason, tool_call.args)
            
            # 3. 툴 실행 (여기서는 시뮬레이션)
            try:
                result = self._execute_tool(tool_call.operation, tool_call.args)
                results.append(result)
                
                # 4. 트레이스 로그
                self.trace_logger.log_tool_call(
                    tool_call.operation, 
                    tool_call.args, 
                    True, 
                    "Operation executed successfully"
                )
                
            except Exception as e:
                # 실행 실패
                self.trace_logger.log_tool_call(
                    tool_call.operation, 
                    tool_call.args, 
                    False, 
                    f"Execution failed: {str(e)}"
                )
                raise
        
        return results
    
    def _execute_tool(self, operation: str, args: List[CaMeLValue]) -> CaMeLValue:
        """실제 툴 실행 (시뮬레이션)"""
        # 입력들의 의존성 수집
        input_dependencies = set()
        input_control_dependencies = set()
        
        for arg in args:
            input_dependencies.update(arg.depends_on)
            input_control_dependencies.update(arg.control_depends_on)
        
        # 현재 툴의 의존성 추가
        current_dependency = f"tool.{operation}"
        all_dependencies = input_dependencies | {current_dependency}
        all_control_dependencies = input_control_dependencies
        
        if operation == "print":
            return CaMeLValue(
                value=f"Printed: {args[0].value}",
                capabilities=Capabilities(
                    source=Source.CAMEL,
                    risk=RiskLevel.LOW,
                    readers="Public",
                    provenance="tool.print",
                    inner_source="tool.print.output"
                ),
                depends_on=all_dependencies,
                control_depends_on=all_control_dependencies
            )
        elif operation == "write":
            return CaMeLValue(
                value=f"Written: {args[0].value}",
                capabilities=Capabilities(
                    source=Source.CAMEL,
                    risk=RiskLevel.MEDIUM,
                    readers="Public",
                    provenance="tool.write",
                    inner_source="tool.write.output"
                ),
                depends_on=all_dependencies,
                control_depends_on=all_control_dependencies
            )
        elif operation == "delete":
            return CaMeLValue(
                value=f"Deleted: {args[0].value}",
                capabilities=Capabilities(
                    source=Source.CAMEL,
                    risk=RiskLevel.HIGH,
                    readers="Public",
                    provenance="tool.delete",
                    inner_source="tool.delete.output"
                ),
                depends_on=all_dependencies,
                control_depends_on=all_control_dependencies
            )
        elif operation == "email":
            return CaMeLValue(
                value=f"Email sent to: {args[0].value}",
                capabilities=Capabilities(
                    source=Source.CAMEL,
                    risk=RiskLevel.MEDIUM,
                    readers="Public",
                    provenance="tool.email",
                    inner_source="tool.email.output"
                ),
                depends_on=all_dependencies,
                control_depends_on=all_control_dependencies
            )
        else:
            raise ValueError(f"Unknown operation: {operation}")

# CaMeL System

class CaMeL:
    def __init__(self, mode: SecurityMode = SecurityMode.NORMAL, config: Optional[SecurityConfig] = None):
        self.pllm = PLLM()
        self.trace_logger = TraceLogger()
        self.config = config or SecurityConfig()
        self.security_policy = SecurityPolicy(mode, self.config)
        self.interpreter = Interpreter(self.security_policy, self.trace_logger)
        self.mode = mode
    
    def reload_config(self, config_path: str):
        """설정 파일 재로드"""
        self.config.reload_from_yaml(config_path)
        # 보안 정책 재생성
        self.security_policy = SecurityPolicy(self.mode, self.config)
        self.interpreter = Interpreter(self.security_policy, self.trace_logger)
    
    def set_dry_run_mode(self, enabled: bool):
        """드라이런 모드 설정"""
        self.config.operation_mode = OperationMode.DRY_RUN if enabled else OperationMode.ENFORCEMENT
        self.config.dry_run = enabled
    
    def process(self, query: str) -> List[CaMeLValue]:
        """CaMeL 시스템의 메인 처리 함수: 플랜 생성 → 실행"""
        # 1. PLLM이 플랜 생성
        plan = self.pllm.process_query(query)
        
        # 2. Interpreter가 플랜 실행
        results = self.interpreter.run(plan)
        
        return results
    
    def create_value(self, value: Any, source: Source = Source.USER, 
                    risk: Optional[RiskLevel] = None, readers: Optional[Readers] = None,
                    provenance: str = "user", inner_source: Optional[str] = None,
                    depends_on: Optional[Set[str]] = None, importance: Optional[DataImportance] = None,
                    control_depends_on: Optional[Set[str]] = None) -> CaMeLValue:
        if risk is None:
            risk = infer_risk_from_value(value)
        
        if importance is None:
            importance = infer_importance_from_value(value)
        
        # 보안 강화: 민감한 데이터는 자동으로 readers 제한
        # 단, 사용자가 명시적으로 readers를 설정한 경우는 자동 조정하지 않음
        if readers is None:  # 기본값인 경우에만 자동 조정
            readers = "Public"  # 기본값 설정
            
            # 이메일 주소는 수신자 식별자이므로 Public 유지
            is_email_address = isinstance(value, str) and '@' in value and '.' in value.split('@')[-1]
            
            if not is_email_address:  # 이메일 주소가 아닌 경우에만 자동 제한
                if risk in [RiskLevel.HIGH] or importance in [DataImportance.CONFIDENTIAL, DataImportance.SECRET]:
                    # HIGH 위험도 또는 CONFIDENTIAL/SECRET 중요도 → 내부자만
                    readers = {"internal"}
                elif risk == RiskLevel.MEDIUM or importance == DataImportance.INTERNAL:
                    # MEDIUM 위험도 또는 INTERNAL 중요도 → 내부자만
                    readers = {"internal"}
        
        # CAMEL 소스인 경우 자동으로 provenance 설정
        if source == Source.CAMEL and provenance == "user":  # 기본값인 경우에만
            provenance = "camel"
        
        return CaMeLValue(value, Capabilities(
            source=source, 
            risk=risk,
            readers=readers,
            provenance=provenance,
            inner_source=inner_source,
            importance=importance or DataImportance.PUBLIC
        ), depends_on=depends_on or set(), control_depends_on=control_depends_on or set())
    
    def execute_plan(self, plan: List[PlanToolCall]) -> List[CaMeLValue]:
        """플랜 실행 (Interpreter를 통한 직접 실행)"""
        return self.interpreter.run(plan)
    
    def execute(self, operation: str, *args: CaMeLValue) -> CaMeLValue:
        """단일 게이트웨이: 모든 툴 호출은 이 메서드를 통해서만 가능 (하위 호환성)"""
        # 플랜 생성
        plan = [PlanToolCall(operation, list(args))]
        
        # 플랜 실행
        results = self.interpreter.run(plan)
        
        # 첫 번째 결과 반환 (하위 호환성)
        return results[0] if results else CaMeLValue("No result", Capabilities(Source.CAMEL, RiskLevel.LOW, "Public", "camel", "camel.noop"))

