# Mini CaMeL - CaMeL 핵심 구조 간소화 버전

CaMeL 논문의 핵심 구조를 최대한 간소화한 버전입니다.

## 🎯 핵심 구조

- **PLLM**: 사용자 쿼리 → Python 코드 생성 (시뮬레이션)
- **QLLM**: 비구조화 데이터 → 구조화 데이터 파싱 (Ollama LLM 호출)
- **Security Policy**: 정책 레지스트리 기반 다층 보안 제어
- **Capabilities**: 소스, 읽기권한, 위험도, 출처 추적 메타데이터
- **Risk Level**: 데이터 민감도 자동 추론 (LOW/MEDIUM/HIGH)
- **Tool Adapter**: 자동 Capabilities 부착 및 타입 검증
- **Trace Logging**: 감사 및 재현을 위한 완전한 로그 추적

## 🚀 사용법

```bash
# 의존성 설치
pip install -r requirements.txt

# 데모 실행
python demo.py

# 테스트 실행  
python test_mini_camel.py
```

## 💻 코드 예제

```python
from mini_camel import CaMeL, Source, RiskLevel

# CaMeL 시스템 초기화
camel = CaMeL()

# 데이터 생성 (자동 위험도 추론)
safe_data = camel.create_value("hello world")  # RiskLevel.LOW
email_data = camel.create_value("john@example.com")  # RiskLevel.HIGH (자동 감지)
phone_data = camel.create_value("010-1234-5678")  # RiskLevel.HIGH (자동 감지)

# 작업 실행
print_result = camel.execute("print", email_data)  # 허용
write_result = camel.execute("write", email_data)  # 차단 (HIGH 위험도)

print(print_result.value)  # "Output: john@example.com"
print(write_result.value)  # "Security violation: Operation 'write' blocked: risk level HIGH exceeds threshold MEDIUM for 'data'"

# 정책 결과 상세 확인
policy = camel.pllm.policy
result = policy.check_access("email", {"recipient": email_data})
print(f"Reason: {result.reason_code} - {result.reason}")
```

## 🔧 간소화

| 논문 구성요소 | 원래 논문 구현 | 간소화 구현 |
|---------------|----------------|-------------|
| **PLLM (Privileged LLM)** | 복잡한 코드 생성 엔진<br/>- Python AST 파싱<br/>- 복잡한 프롬프트 엔지니어링<br/>- 다단계 코드 검증 | `PLLM` 클래스 (30 라인)<br/>- 간단한 시뮬레이션<br/>- 툴 어댑터 데코레이터<br/>- 자동 Capabilities 부착 |
| **QLLM (Quarantined LLM)** | 격리된 환경에서 실행<br/>- Pydantic 스키마 검증<br/>- 복잡한 에러 핸들링<br/>- 재시도 메커니즘 | `QLLM` 클래스 (40 라인)<br/>- Ollama 직접 호출<br/>- Pydantic 스키마 검증<br/>- JSON 파싱 및 폴백 |
| **Security Policies** | 도메인별 정책 엔진<br/>- Banking/Workspace/Slack/Travel<br/>- 복잡한 권한 매트릭스<br/>- 세밀한 접근 제어 | `SecurityPolicy` + `PolicyRegistry` (120 라인)<br/>- 정책 레지스트리 시스템<br/>- 우선순위 기반 충돌 해결<br/>- 상세한 차단 이유 반환 |
| **Capabilities** | 복잡한 frozenset 기반<br/>- 다중 소스 추적<br/>- 세밀한 권한 제어<br/>- 동적 권한 계산 | `Capabilities` 클래스 (25 라인)<br/>- Source + RiskLevel + Readers<br/>- 자동 위험도 추론<br/>- 완전한 출처 추적 |
| **CaMeL Interpreter** | 25,000+ 라인 AST 파서<br/>- 완전한 Python 파싱<br/>- 복잡한 네임스페이스 관리<br/>- 고급 메모리 관리 | `CaMeL` 클래스 (25 라인)<br/>- 단일 게이트웨이 패턴<br/>- 정책 검사 후 실행<br/>- 툴 어댑터 통합 |
| **Tool Integration** | 100+ AgentDojo 도구<br/>- 실제 시스템 호출<br/>- 복잡한 도구 체인<br/>- 고급 에러 복구 | 4개 핵심 도구 + 어댑터<br/>- 자동 Capabilities 부착<br/>- 타입 안전성 검증<br/>- Silent failure 방지 |
| **LLM Integration** | 실제 API 호출<br/>- OpenAI/Google/Anthropic<br/>- 복잡한 클라이언트 관리<br/>- 고급 프롬프트 엔지니어링 | QLLM만 Ollama 통합<br/>- PLLM은 시뮬레이션<br/>- 프롬프트 엔지니어링<br/>- JSON 응답 파싱 |

## 🚀 개선

| 새로운 기능 | 설명 | 구현 |
|-------------|------|------|
| **데이터 의존성 그래프 (DFG)** | 데이터 출처 추적 및 의존성 전파 | `CaMeLValue.depends_on` 필드<br/>- 의존성 누적 및 전파<br/>- Q-LLM 의존성 차단 정책 |
| **데이터 중요도 기반 정책** | 데이터 중요도에 따른 차단 정책 | `DataImportance` 열거형 (PUBLIC/INTERNAL/CONFIDENTIAL/SECRET)<br/>- 위험 연산 + 비신뢰 값 = 하드 차단<br/>- 중요도 임계치 초과 시 차단 |
| **STRICT 모드 (제어 의존성)** | 조건문/반복문의 제어 의존성 추적 | `SecurityMode.NORMAL/STRICT`<br/>- `CaMeLValue.control_depends_on` 필드<br/>- 민감한 제어 의존성 차단 |
| **예외 처리: 메시지 검열 & 재시도** | 보안을 위한 에러 메시지 검열 | 비신뢰 텍스트 `[REDACTED]` 대체<br/>- P-LLM 재시도 메커니즘 (최대 3회)<br/>- 악성 문자열 차단 |
| **레벨링 + 우선순위 운영화** | 정책 우선순위 및 설정 외부화 | 정책 우선순위: 하드룰 > 명시적 허용 > 레벨 임계치 > 기본 허용<br/>- YAML 설정 파일 외부화<br/>- 드라이런 모드 (경고 + 시뮬레이션)<br/>- 컨텍스트 보정값 (시간대, 사용자 역할, 데이터 소스) |
