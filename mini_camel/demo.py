#!/usr/bin/env python3
"""
CaMeL 데모 스크립트
"""

from mini_camel import CaMeL, Source, RiskLevel
from pydantic import BaseModel

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
    
    # 3. Readers/Provenance 테스트
    print("\n3. Readers/Provenance")
    
    # Public 데이터
    public_data = camel.create_value("public info", readers="Public")
    print(f"Public data: {public_data.capabilities.is_public()}")
    
    # Private 데이터 (특정 사용자만)
    private_data = camel.create_value("private info", readers={"user1", "user2"})
    print(f"Private data readers: {private_data.capabilities.readers}")
    print(f"User1 can read: {private_data.capabilities.readers_include({'user1'})}")
    print(f"User3 can read: {private_data.capabilities.readers_include({'user3'})}")
    
    # 4. 툴 어댑터 자동 태깅
    print("\n4. Tool Adapter Auto-Tagging")
    
    test_data = camel.create_value("test data", Source.USER)
    result = camel.execute("print", test_data)
    
    print(f"Tool result: {result.value}")
    print(f"Provenance: {result.capabilities.provenance}")
    print(f"Inner source: {result.capabilities.inner_source}")
    
    # 5. QLLM 스키마 & 정보부족 루프
    print("\n5. QLLM Schema & Information Loop")
    
    class UserInfo(BaseModel):
        name: str
        email: str
    
    class ComplexInfo(BaseModel):
        name: str
        email: str
        phone: str
        address: str
    
    # 충분한 정보가 있는 경우
    try:
        qllm_result = camel.pllm._query_ai("John Doe, john@example.com", UserInfo)
        print(f"QLLM (sufficient): {qllm_result}")
    except Exception as e:
        print(f"QLLM Error: {e}")
    
    # 정보가 부족한 경우 (재시도 루프)
    try:
        qllm_result2 = camel.pllm._query_ai("John", ComplexInfo, max_retries=2)
        print(f"QLLM (insufficient): {qllm_result2}")
    except Exception as e:
        print(f"QLLM Retry Error: {e}")
    
    # 6. 트레이스 로그 (감사/재현)
    print("\n6. Trace Logging (Audit/Replay)")
    
    # 트레이스 요약 정보
    summary = camel.trace_logger.get_trace_summary()
    print(f"Total calls: {summary['total_calls']}")
    print(f"Allowed: {summary['allowed_calls']}")
    print(f"Denied: {summary['denied_calls']}")
    print(f"Denial rate: {summary['denial_rate']}")
    
    # 최근 트레이스 엔트리
    print("\nRecent trace entries:")
    for i, entry in enumerate(summary['recent_entries'][-3:], 1):
        print(f"  {i}. {entry.call.name}: {entry.result} - {entry.reason}")
        print(f"     Args: {entry.call.args}")
    
    # 특정 작업의 트레이스
    print_entries = camel.trace_logger.get_entries_by_operation("print")
    print(f"\nPrint operations: {len(print_entries)}")
    
    print("\n" + "=" * 40)
    print("Demo Complete")
    print("=" * 40)

if __name__ == "__main__":
    main()
