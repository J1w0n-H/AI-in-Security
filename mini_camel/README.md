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

## 🛡️ 보안 기능

### 1. 데이터 위험도 레벨화
- **LOW**: 일반 텍스트, 안전한 데이터
- **MEDIUM**: 이름, 주소, 사업자등록번호 등
- **HIGH**: 이메일, 전화번호, 주민등록번호, 신용카드 등
- **자동 추론**: RegEx 패턴으로 데이터 내용 분석하여 자동 위험도 할당

### 2. 정책 결과 표준화 & 단일 게이트웨이
- **SecurityPolicyResult**: `allowed`, `reason_code`, `reason` 상세 정보 제공
- **단일 진입점**: 모든 툴 호출은 `CaMeL.execute()`를 통해서만 가능
- **우회 방지**: 직접 툴 호출 차단으로 보안 정책 우회 불가

### 3. Readers/Provenance 확장
- **세분화된 읽기 권한**: `"Public"` 또는 구체적인 사용자 ID 집합
- **완전한 출처 추적**: `provenance`와 `inner_source`로 데이터 흐름 추적
- **수신자 검증**: 이메일/이벤트 시 수신자가 읽기 권한을 가지는지 확인

### 4. 툴 어댑터 자동부착
- **자동 Capabilities 부착**: 모든 툴 출력에 자동으로 메타데이터 첨부
- **타입 안전성**: 원시값 전달 시 `TypeError` 예외 발생
- **실패 방지**: 태깅 누락으로 인한 Silent failure 완전 차단

### 5. 정책 레지스트리 & 합성
- **정책 우선순위**: 명시 Deny > 명시 Allow > 글로벌 > 기본 Allow
- **충돌 해결**: 정책 간 충돌 시 결정적 순서로 처리
- **확장성**: 커스텀 정책 쉽게 추가 가능

### 6. 트레이스 로그 (감사/재현)
- **완전한 로그 추적**: 모든 툴 호출의 성공/차단 기록
- **PII 마스킹**: Private 데이터는 `<REDACTED>`로 자동 마스킹
- **재현 가능**: 연속 툴 호출 시 순서/사유 정확히 기록
- **감사 지원**: 요약 정보 및 작업별 필터링 기능

### 7. Q-LLM 스키마 & 정보부족 루프
- **정보 충분성 검증**: QLLM 출력에 `have_enough_information` 필드 포함
- **자동 재시도**: 정보 부족 시 PLLM 재시도 N회 (프롬프트 개선)
- **격리 유지**: QLLM → PLLM 직접 커뮤니케이션 금지
- **명확한 실패**: 최종 실패 시 누락된 필드와 원인 상세 출력

### 지원 작업
- `print`: 안전한 출력 (항상 허용)
- `write`: 파일 쓰기 (MEDIUM 이상 위험도 차단)
- `delete`: 파일 삭제 (LOW 이상 위험도 차단)  
- `email`: 이메일 전송 (MEDIUM 이상 위험도 차단)

## 🔧 논문 구성요소 간소화 구현

| 논문 구성요소 | 원래 논문 구현 | 간소화 구현 |
|---------------|----------------|-------------|
| **PLLM (Privileged LLM)** | 복잡한 코드 생성 엔진<br/>- Python AST 파싱<br/>- 복잡한 프롬프트 엔지니어링<br/>- 다단계 코드 검증 | `PLLM` 클래스 (30 라인)<br/>- 간단한 시뮬레이션<br/>- 툴 어댑터 데코레이터<br/>- 자동 Capabilities 부착 |
| **QLLM (Quarantined LLM)** | 격리된 환경에서 실행<br/>- Pydantic 스키마 검증<br/>- 복잡한 에러 핸들링<br/>- 재시도 메커니즘 | `QLLM` 클래스 (40 라인)<br/>- Ollama 직접 호출<br/>- Pydantic 스키마 검증<br/>- JSON 파싱 및 폴백 |
| **Security Policies** | 도메인별 정책 엔진<br/>- Banking/Workspace/Slack/Travel<br/>- 복잡한 권한 매트릭스<br/>- 세밀한 접근 제어 | `SecurityPolicy` + `PolicyRegistry` (120 라인)<br/>- 정책 레지스트리 시스템<br/>- 우선순위 기반 충돌 해결<br/>- 상세한 차단 이유 반환 |
| **Capabilities** | 복잡한 frozenset 기반<br/>- 다중 소스 추적<br/>- 세밀한 권한 제어<br/>- 동적 권한 계산 | `Capabilities` 클래스 (25 라인)<br/>- Source + RiskLevel + Readers<br/>- 자동 위험도 추론<br/>- 완전한 출처 추적 |
| **CaMeL Interpreter** | 25,000+ 라인 AST 파서<br/>- 완전한 Python 파싱<br/>- 복잡한 네임스페이스 관리<br/>- 고급 메모리 관리 | `CaMeL` 클래스 (25 라인)<br/>- 단일 게이트웨이 패턴<br/>- 정책 검사 후 실행<br/>- 툴 어댑터 통합 |
| **Tool Integration** | 100+ AgentDojo 도구<br/>- 실제 시스템 호출<br/>- 복잡한 도구 체인<br/>- 고급 에러 복구 | 4개 핵심 도구 + 어댑터<br/>- 자동 Capabilities 부착<br/>- 타입 안전성 검증<br/>- Silent failure 방지 |
| **LLM Integration** | 실제 API 호출<br/>- OpenAI/Google/Anthropic<br/>- 복잡한 클라이언트 관리<br/>- 고급 프롬프트 엔지니어링 | QLLM만 Ollama 통합<br/>- PLLM은 시뮬레이션<br/>- 프롬프트 엔지니어링<br/>- JSON 응답 파싱 |

## 🚀 주요 개선사항

### 7가지 핵심 보안 기능 구현
1. **데이터 위험도 레벨화**: RegEx 기반 자동 위험도 추론
2. **정책 결과 표준화**: 상세한 차단 이유 및 단일 게이트웨이
3. **Readers/Provenance 확장**: 세분화된 권한 및 완전한 출처 추적
4. **툴 어댑터 자동부착**: 자동 메타데이터 부착 및 타입 안전성
5. **정책 레지스트리 & 합성**: 우선순위 기반 정책 충돌 해결
6. **트레이스 로그 (감사/재현)**: 완전한 로그 추적 및 PII 마스킹
7. **Q-LLM 스키마 & 정보부족 루프**: 정보 충분성 검증 및 자동 재시도

### 코드 품질 개선
- **간소화**: 639줄 → 541줄 (-15%)
- **불필요한 코드 제거**: 사용되지 않는 enum, 메서드, 변수 정리
- **모듈화**: 데모 코드를 별도 파일로 분리
- **테스트 커버리지**: 38개 테스트 모두 통과

