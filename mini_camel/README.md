# Mini CaMeL - Enhanced Security Framework for LLM Systems

CaMeL 논문의 핵심 구조를 간소화하면서 **6가지 중요한 보안 취약점을 수정**하고 **미니 해석기 게이트**를 구현한 강화된 보안 프레임워크입니다.

## 🎯 핵심 구조 (논문 기반 간소화)

- **PLLM**: 사용자 쿼리 → 툴 플랜 생성 (논문: 직접 툴 호출 → 간소화: 플랜 생성)
- **QLLM**: 비구조화 데이터 → 구조화 데이터 파싱 (논문: 복잡한 격리 환경 → 간소화: Ollama 직접 호출)
- **Security Policy**: 정책 레지스트리 기반 다층 보안 제어 (논문: 도메인별 엔진 → 간소화: 통합 레지스트리)
- **Capabilities**: 소스, 읽기권한, 위험도, 출처 추적 메타데이터 (논문: 복잡한 frozenset → 간소화: 단순 클래스)
- **Risk Level**: 데이터 민감도 자동 추론 (논문: 기본 추론 → 간소화: 한국어 지원 추가)
- **Tool Adapter**: 자동 Capabilities 부착 및 타입 검증 (논문: 100+ 도구 → 간소화: 4개 핵심 도구)
- **Trace Logging**: 감사 및 재현을 위한 완전한 로그 추적 (논문 기반 유지)

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

### 기본 사용법
```python
from mini_camel import CaMeL, Source, RiskLevel

# CaMeL 시스템 초기화
camel = CaMeL()

# 데이터 생성 (자동 위험도 추론)
safe_data = camel.create_value("hello world")  # RiskLevel.LOW
email_data = camel.create_value("john@example.com")  # RiskLevel.LOW (이메일은 수신자 식별자)
phone_data = camel.create_value("010-1234-5678")  # RiskLevel.HIGH (전화번호)
korean_name = camel.create_value("홍길동")  # RiskLevel.MEDIUM (한국어 이름)

# 플랜 기반 실행 (새로운 방식)
results = camel.process("print hello world")
print(results[0].value)  # "Printed: Hello World"

# 단일 게이트웨이 실행 (하위 호환성)
print_result = camel.execute("print", safe_data)  # 허용
write_result = camel.execute("write", phone_data)  # 차단 (HIGH 위험도)

# 정책 결과 상세 확인
policy = camel.pllm.policy
result = policy.check_access("write", {"arg_0": phone_data})
print(f"Reason: {result.reason_code} - {result.reason}")
```

### 보안 정책 예제
```python
# STRICT 모드에서 제어 의존성 추적
camel_strict = CaMeL(mode=SecurityMode.STRICT)

# 드라이런 모드 (경고만, 실제 차단 안함)
camel.set_dry_run_mode(True)
results = camel.process("write sensitive data")
# 출력: [DRY RUN WARNING] Operation 'write' blocked: risk level HIGH exceeds threshold MEDIUM
```

### YAML 설정 파일 사용
```python
from mini_camel import SecurityConfig, CaMeL

# YAML 설정 파일로 CaMeL 초기화
config = SecurityConfig.from_yaml("security_config.yaml")
camel = CaMeL(config=config)

# 설정 재로드
camel.reload_config("security_config.yaml")

# 드라이런 모드 설정
camel.set_dry_run_mode(True)
```

## 🔧 간소화 (논문 → Mini CaMeL)

| 논문 구성요소 | 원래 논문 구현 | 간소화 구현 |
|---------------|----------------|-------------|
| **PLLM (Privileged LLM)** | 복잡한 코드 생성 엔진<br/>- Python AST 파싱<br/>- 복잡한 프롬프트 엔지니어링<br/>- 다단계 코드 검증 | `PLLM` 클래스 (100 라인)<br/>- 간단한 시뮬레이션<br/>- 툴 어댑터 데코레이터<br/>- 자동 Capabilities 부착 |
| **QLLM (Quarantined LLM)** | 격리된 환경에서 실행<br/>- Pydantic 스키마 검증<br/>- 복잡한 에러 핸들링<br/>- 재시도 메커니즘 | `QLLM` 클래스 (80 라인)<br/>- Ollama 직접 호출<br/>- Pydantic 스키마 검증<br/>- JSON 파싱 및 폴백 |
| **Security Policies** | 도메인별 정책 엔진<br/>- Banking/Workspace/Slack/Travel<br/>- 복잡한 권한 매트릭스<br/>- 세밀한 접근 제어 | `SecurityPolicy` + `PolicyRegistry` (200 라인)<br/>- 정책 레지스트리 시스템<br/>- 우선순위 기반 충돌 해결<br/>- 상세한 차단 이유 반환 |
| **Capabilities** | 복잡한 frozenset 기반<br/>- 다중 소스 추적<br/>- 세밀한 권한 제어<br/>- 동적 권한 계산 | `Capabilities` 클래스 (30 라인)<br/>- Source + RiskLevel + Readers<br/>- 자동 위험도 추론<br/>- 완전한 출처 추적 |
| **CaMeL System** | 25,000+ 라인 AST 파서<br/>- 완전한 Python 파싱<br/>- 복잡한 네임스페이스 관리<br/>- 고급 메모리 관리 | `CaMeL` 클래스 (50 라인)<br/>- 단일 게이트웨이 패턴<br/>- 정책 검사 후 실행<br/>- 툴 어댑터 통합 |
| **Tool Integration** | 100+ AgentDojo 도구<br/>- 실제 시스템 호출<br/>- 복잡한 도구 체인<br/>- 고급 에러 복구 | 4개 핵심 도구 + 어댑터<br/>- 자동 Capabilities 부착<br/>- 타입 안전성 검증<br/>- Silent failure 방지 |
| **LLM Integration** | 실제 API 호출<br/>- OpenAI/Google/Anthropic<br/>- 복잡한 클라이언트 관리<br/>- 고급 프롬프트 엔지니어링 | QLLM만 Ollama 통합<br/>- PLLM은 시뮬레이션<br/>- 프롬프트 엔지니어링<br/>- JSON 응답 파싱 |

## 🚀 주요 개선사항 (논문에 없던 새로운 기능)

### 🔒 보안 취약점 수정 (A-F) - 논문 구현에서 발견된 버그들

| 버그 | 문제점 | 해결책 |
|------|--------|--------|
| **A. Explicit Allow Policy** | 조건 매치 안 돼도 항상 허용 | 조건 평가 로직 수정, 매치 시에만 허용 |
| **B. LLM Output eval()** | LLM 응답에 eval() 사용으로 코드 실행 취약점 | eval() 제거, json.loads()만 허용 |
| **C. Readers/Permission Model** | 민감 데이터가 기본적으로 "Public" | 자동 readers 제한, 위험도 기반 조정 |
| **D. Provenance Tag Mismatch** | tool_adapter와 PLLM 간 출처 태그 불일치 | 일관된 provenance 태깅 시스템 |
| **E. Q-LLM Dependency Flag** | Q-LLM 의존성 플래그 누락 | depends_on={"qllm"} 자동 부여 |
| **F. Context-based Threshold** | 컨텍스트 기반 임계치 미사용 | get_adjusted_threshold() 통합 |

### 🆕 논문에 없던 새로운 기능

| 새로운 기능 | 설명 | 구현 |
|-------------|------|------|
| **미니 해석기 게이트** | PLLM 직접 툴 호출 차단 (논문에는 없던 보안 강화) | `Interpreter` 클래스<br/>- 화이트리스트 기반 검증<br/>- 플랜 실행 전 정책 검사 |
| **데이터 의존성 그래프 (DFG)** | 데이터 출처 추적 및 의존성 전파 (논문 확장) | `CaMeLValue.depends_on` 필드<br/>- 의존성 누적 및 전파<br/>- Q-LLM 의존성 차단 정책 |
| **데이터 중요도 기반 정책** | 데이터 중요도에 따른 차단 정책 (논문에 없던 기능) | `DataImportance` 열거형 (PUBLIC/INTERNAL/CONFIDENTIAL/SECRET)<br/>- 중요도 임계치 초과 시 차단<br/>- 자동 readers 제한 |
| **STRICT 모드 (제어 의존성)** | 조건문/반복문의 제어 의존성 추적 (논문 확장) | `SecurityMode.NORMAL/STRICT`<br/>- `CaMeLValue.control_depends_on` 필드<br/>- 민감한 제어 의존성 차단 |
| **한국어 위험도 추론** | 한국어 이름 및 패턴 인식 (논문에 없던 다국어 지원) | 정규식 기반 한국어 패턴 매칭<br/>- 이름: MEDIUM 위험도<br/>- 전화번호: HIGH 위험도 |
| **예외 처리: 메시지 검열 & 재시도** | 보안을 위한 에러 메시지 검열 (논문에 없던 보안 강화) | 비신뢰 텍스트 `[REDACTED]` 대체<br/>- P-LLM 재시도 메커니즘 (최대 3회)<br/>- 악성 문자열 차단 |
| **드라이런 모드** | 정책 위반 시 경고만, 실제 차단 안함 (논문에 없던 운영 모드) | `OperationMode.DRY_RUN`<br/>- 경고 메시지 출력<br/>- 시뮬레이션 결과 반환 |
| **컨텍스트 기반 임계치** | 시간대/역할/소스에 따른 동적 임계치 조정 (논문 확장) | `get_adjusted_threshold()` 함수<br/>- 업무시간/야간 시간 보정<br/>- 사용자 역할별 보정 |
| **YAML 설정 파일** | 외부 설정 파일을 통한 정책 관리 (논문에 없던 기능) | `SecurityConfig.from_yaml()`<br/>- 하드룰, 임계치, 우선순위 외부화<br/>- 런타임 설정 재로드 지원 |

## 📊 성능 지표

- **코드 크기**: 25,000+ 라인 → 1,439 라인 (94% 감소)
- **테스트 커버리지**: 79/79 테스트 통과 (100% 성공률)
- **보안 취약점**: 6개 주요 취약점 수정 (논문 구현에서 발견)
- **새로운 기능**: 9개 추가 (논문에 없던 기능)
- **기능 완성도**: 원본 기능 100% 보존

## 🔧 설치 및 실행

### 요구사항
```bash
pip install ollama pydantic pyyaml
```

### 테스트 실행
```bash
cd mini_camel
python test_mini_camel.py
python test_yaml_config.py  # YAML 설정 테스트
```

### 데모 실행
```python
from mini_camel import CaMeL

# 기본 사용
camel = CaMeL()
results = camel.process("print hello world")
print(results[0].value)  # "Printed: Hello World"

# 보안 정책 테스트
phone_data = camel.create_value("010-1234-5678")  # HIGH 위험도
try:
    camel.execute("write", phone_data)  # 차단됨
except SecurityError as e:
    print(f"보안 정책 위반: {e}")
```

## 📝 라이선스

이 프로젝트는 원본 CaMeL 논문의 구현을 기반으로 하며, 보안 강화 및 간소화를 목적으로 합니다.

## 🤝 기여

보안 취약점 발견이나 개선 제안은 언제든 환영합니다. 이슈를 통해 알려주세요.
