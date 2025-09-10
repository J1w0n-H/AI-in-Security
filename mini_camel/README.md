# Mini CaMeL - Stage 1 Implementation

A simplified Stage 1 implementation of the core concepts from the CaMeL paper.

## 🎯 Core Concepts

- **PLLM**: 사용자 쿼리 → Python 코드 생성 (시뮬레이션)
- **QLLM**: 비구조화 데이터 → 구조화 데이터 파싱 (Ollama LLM 호출)
- **Security Policy**: 정책 레지스트리 기반 다층 보안 제어
- **Capabilities**: 소스, 읽기권한, 위험도, 출처 추적 메타데이터
- **Risk Level**: 데이터 민감도 자동 추론 (LOW/MEDIUM/HIGH)
- **Tool Adapter**: 자동 Capabilities 부착 및 타입 검증
- **Trace Logging**: 감사 및 재현을 위한 완전한 로그 추적

## 🚀 Installation & Execution

```bash
# 의존성 설치
pip install -r requirements.txt

# 데모 실행
python demo.py

# 또는 테스트 실행
python test_mini_camel.py
```

## 📁 Structure

```
mini_camel/
├── mini_camel.py      # Core implementation (180 lines)
├── test_mini_camel.py # Test code (190 lines)
└── README.md          # This file
```

## 🔬 Core Features

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

## 📊 Test Results

```
=== Mini CaMeL Stage 1 Test ===

1. Safe operations test (all data allowed)
   print(trusted): CaMeLValue('Output: safe data', ...)
   print(untrusted): CaMeLValue('Output: user input', ...)

2. Dangerous operations test (trusted data only)
   write(trusted): CaMeLValue('Write complete: safe data', ...)
   write(untrusted): CaMeLValue('Security policy violation: write', ...)

3. File deletion test
   delete(user_file): CaMeLValue('Security policy violation: delete', ...)
   delete(trusted_file): CaMeLValue('File deleted: system.log', ...)

4. Email sending test
   email(user_data): CaMeLValue('Security policy violation: email', ...)
   email(trusted_data): CaMeLValue('Email sent: support@company.com - system notification', ...)

5. Unknown operation test
   unknown_op: CaMeLValue('Unknown operation: unknown_operation', ...)

=== Test Complete ===
```

## ✅ Test Results

```
=== Mini CaMeL Test Started ===
Ran 13 tests in 0.001s
OK

=== Test Results ===
Tests run: 13
Failures: 0
Errors: 0
```

## 🔗 Implementation Details

### 📖 Core Idea
**Metadata-based Security**: Attach source and permission info to all data to block dangerous operations with untrusted data

### 🔧 Paper → Implementation Mapping

| Paper Concept | Paper Implementation | → | Our Implementation | How We Simplified |
|---------------|---------------------|---|-------------------|-------------------|
| **Metadata System** | Complex `CaMeLValue` class | → | `Capabilities` + `CaMeLValue` (25 lines) | **Complex frozenset-based capabilities** → **Simple Source + Reader enums** |
| **Security Policy** | Domain-specific policy engines | → | `SecurityPolicy` class (10 lines) | **Banking/workspace/slack policies** → **Single trust-based policy** |
| **Python Interpreter** | 25,000+ line AST parser | → | `MiniCaMeLInterpreter` (35 lines) | **Full Python AST parsing** → **Simple operation dispatch** |
| **Tool Integration** | AgentDojo benchmark | → | 4 tools: `print`, `write`, `delete`, `email` | **100+ AgentDojo tools** → **4 essential tools** |
| **LLM Integration** | Real AI model calls | → | Mock execution (simulation) | **Real API calls** → **Simulated responses** |

**Core**: Untrusted data attempting dangerous operations → Blocked!

## 🎓 Key Learnings

1. **Importance of Metadata**: Track source of all data
2. **Effectiveness of Security Policy**: Block dangerous operations with untrusted data
3. **Sandboxed Execution**: Constraints for safe code execution
4. **Test-driven Development**: Verification of all functionality
5. **Code Optimization**: Remove redundancy while maintaining functionality
