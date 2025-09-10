# Mini CaMeL - CaMeL 핵심 구조 간소화 버전

CaMeL 논문의 핵심 구조를 최대한 간소화한 버전입니다.

## 🎯 핵심 구조

- **PLLM**: 사용자 쿼리 → Python 코드 생성
- **QLLM**: 비구조화 데이터 → 구조화 데이터 파싱  
- **Security Policy**: 신뢰성 + 위험도 기반 작업 제어
- **Capabilities**: 소스, 읽기권한, 위험도 메타데이터 첨부
- **Risk Level**: 데이터 민감도 자동 추론 (LOW/MEDIUM/HIGH)

## 🚀 사용법

```bash
# 의존성 설치
pip install -r requirements.txt

# 데모 실행
python mini_camel.py

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

## 🛡️ 보안 기능

### 위험도 자동 추론
- **LOW**: 일반 텍스트, 안전한 데이터
- **MEDIUM**: 이름, 주소, 사업자등록번호 등
- **HIGH**: 이메일, 전화번호, 주민등록번호, 신용카드 등

### 정책 기반 제어
- **신뢰성 검사**: USER 소스 데이터로 위험한 작업 차단
- **위험도 임계치**: 작업별 위험도 임계치 초과 시 차단
- **상세한 차단 이유**: `reason_code`와 `reason`으로 명확한 차단 사유 제공

### 지원 작업
- `print`: 안전한 출력 (항상 허용)
- `write`: 파일 쓰기 (MEDIUM 이상 위험도 차단)
- `delete`: 파일 삭제 (LOW 이상 위험도 차단)  
- `email`: 이메일 전송 (LOW 이상 위험도 차단)

## 🔧 논문 구성요소 간소화 구현

| 논문 구성요소 | 원래 논문 구현 | 간소화 구현 |
|---------------|----------------|-------------|
| **PLLM (Privileged LLM)** | 복잡한 코드 생성 엔진<br/>- Python AST 파싱<br/>- 복잡한 프롬프트 엔지니어링<br/>- 다단계 코드 검증 | `PLLM` 클래스 (30 라인)<br/>- 간단한 쿼리 매칭<br/>- 직접적인 도구 호출<br/>- 시뮬레이션 기반 처리 |
| **QLLM (Quarantined LLM)** | 격리된 환경에서 실행<br/>- Pydantic 스키마 검증<br/>- 복잡한 에러 핸들링<br/>- 재시도 메커니즘 | `QLLM` 클래스 (15 라인)<br/>- 기본 JSON 파싱<br/>- 간단한 예외 처리<br/>- Ollama 직접 호출 |
| **Security Policies** | 도메인별 정책 엔진<br/>- Banking/Workspace/Slack/Travel<br/>- 복잡한 권한 매트릭스<br/>- 세밀한 접근 제어 | `SecurityPolicy` 클래스 (25 라인)<br/>- 신뢰성 + 위험도 기반 정책<br/>- 위험도 임계치 설정<br/>- 상세한 차단 이유 반환 |
| **Capabilities** | 복잡한 frozenset 기반<br/>- 다중 소스 추적<br/>- 세밀한 권한 제어<br/>- 동적 권한 계산 | `Capabilities` 클래스 (15 라인)<br/>- Source + Reader + RiskLevel<br/>- 자동 위험도 추론<br/>- 위험도 기반 권한 체크 |
| **CaMeL Interpreter** | 25,000+ 라인 AST 파서<br/>- 완전한 Python 파싱<br/>- 복잡한 네임스페이스 관리<br/>- 고급 메모리 관리 | `CaMeL` 클래스 (15 라인)<br/>- 간단한 도구 디스패치<br/>- 직접적인 함수 호출<br/>- 최소한의 상태 관리 |
| **Tool Integration** | 100+ AgentDojo 도구<br/>- 실제 시스템 호출<br/>- 복잡한 도구 체인<br/>- 고급 에러 복구 | 4개 핵심 도구<br/>- 시뮬레이션 응답<br/>- 직접적인 도구 호출<br/>- 간단한 에러 처리 |
| **LLM Integration** | 실제 API 호출<br/>- OpenAI/Google/Anthropic<br/>- 복잡한 클라이언트 관리<br/>- 고급 프롬프트 엔지니어링 | 로컬 Ollama<br/>- 단순한 클라이언트<br/>- 기본 프롬프트<br/>- 간단한 응답 처리 |

