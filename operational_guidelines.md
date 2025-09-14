# IRIS Environment-Aware Analysis - Operational Guidelines

## 6단계: 운영 수칙 & 안전 가드

### 환경 전제 기재

**중요**: 모든 취약점 판정은 `env.json` 기준입니다. 환경 변경 시 재평가가 필요합니다.

#### 환경 변경 감지
- `environment.yml`, `pom.xml`, `build.gradle` 등 의존성 파일 변경 시
- Docker 이미지 업데이트 시
- OS 버전 업그레이드 시
- 보안 정책 변경 시

### 룰과 테스트의 동기화

#### 룰 추가 시 체크리스트
1. **환경 지식베이스 업데이트** (`environment_knowledge_base.yaml`)
   - 새로운 룰 추가
   - 기존 룰 수정
   - 환경별 적용 조건 명시

2. **동적 검증 테스트 추가** (`dynamic_verification.py`)
   - 룰에 대응하는 테스트 케이스 작성
   - 환경별 테스트 시나리오 구현
   - 회귀 방지를 위한 테스트 케이스

3. **점수 모델 업데이트** (`vulnerability_ranker.py`)
   - 새로운 룰에 대한 가중치 설정
   - 환경별 점수 조정 규칙 추가

### 변경 감지 및 자동 재평가

#### 자동 재평가 트리거
```yaml
# .github/workflows/iris-reanalysis.yml
name: IRIS Reanalysis
on:
  push:
    paths:
      - 'environment.yml'
      - 'pom.xml'
      - 'build.gradle'
      - 'Dockerfile'
      - 'environment_knowledge_base.yaml'
  schedule:
    - cron: '0 2 * * 1'  # Weekly reanalysis

jobs:
  reanalysis:
    runs-on: ubuntu-latest
    steps:
      - name: Checkout
        uses: actions/checkout@v3
      
      - name: Detect Changes
        id: changes
        run: |
          echo "changed_files=$(git diff --name-only HEAD~1 HEAD)" >> $GITHUB_OUTPUT
      
      - name: Trigger Reanalysis
        if: steps.changes.outputs.changed_files != ''
        run: |
          python scripts/trigger_reanalysis.py --changed-files "${{ steps.changes.outputs.changed_files }}"
```

#### 수동 재평가 명령어
```bash
# 환경 변경 후 수동 재평가
python scripts/trigger_reanalysis.py --reason "environment_update"

# 특정 프로젝트 재평가
python scripts/trigger_reanalysis.py --project "apache__camel" --reason "dependency_update"

# 전체 재평가
python scripts/trigger_reanalysis.py --reason "full_reanalysis"
```

### 실무용 체크리스트

#### CI/CD 통합
- [ ] `env.json` 자동 생성 확인
- [ ] 환경 인지형 LLM 판정 활성화
- [ ] 미니 E-KB 룰 3도메인 적용 (명령/경로/템플릿)
- [ ] "불확실" 라벨 동적 검증 실행
- [ ] 점수화 우선순위 재정렬
- [ ] 근거(룰ID/테스트결과) 포함 리포트 생성

#### 환경별 특수 고려사항

##### Windows 환경
- [ ] NTFS ADS 우회 가능성 검토
- [ ] UNC 경로 처리 확인
- [ ] PowerShell vs CMD 차이점 고려
- [ ] CreateProcessW vs shell 실행 차이점

##### Linux 환경
- [ ] Symlink 처리 확인
- [ ] Shell 메타문자 해석 확인
- [ ] SELinux 정책 영향 검토
- [ ] AppArmor 프로파일 확인

##### 컨테이너 환경
- [ ] 베이스 이미지 보안 정책 확인
- [ ] 컨테이너 내부 vs 호스트 차이점
- [ ] 네트워크 격리 영향 검토
- [ ] 볼륨 마운트 보안 고려

### 성능 모니터링

#### 메트릭 수집
```python
# 성능 메트릭 수집 예시
metrics = {
    "analysis_time": {
        "environment_collection": env_collection_time,
        "kb_rule_evaluation": kb_evaluation_time,
        "dynamic_verification": dynamic_verification_time,
        "ranking": ranking_time
    },
    "accuracy_metrics": {
        "false_positive_reduction": fp_reduction_rate,
        "false_negative_reduction": fn_reduction_rate,
        "environment_aware_accuracy": env_aware_accuracy
    },
    "coverage_metrics": {
        "rules_applied": rules_applied_count,
        "dynamic_tests_run": dynamic_tests_count,
        "environment_factors_considered": env_factors_count
    }
}
```

#### 알림 설정
- 환경 변경 감지 시 알림
- 룰 적용 실패 시 알림
- 동적 검증 실패 시 알림
- 성능 저하 감지 시 알림

### 보안 고려사항

#### 동적 검증 보안
- 테스트 페이로드는 격리된 환경에서만 실행
- 실제 시스템에 영향을 주지 않는 안전한 테스트만 수행
- 테스트 후 정리 작업 자동화

#### 환경 메타데이터 보안
- 민감한 정보는 마스킹 처리
- 환경 메타데이터 접근 권한 제한
- 로그에서 민감한 정보 제거

### 문제 해결 가이드

#### 일반적인 문제
1. **환경 메타데이터 수집 실패**
   - `env_collector_config.yaml` 설정 확인
   - 필요한 도구 설치 확인
   - 권한 문제 해결

2. **룰 적용 실패**
   - `environment_knowledge_base.yaml` 문법 확인
   - 환경 조건 매칭 확인
   - 로그에서 상세 오류 확인

3. **동적 검증 실패**
   - 테스트 환경 격리 확인
   - 테스트 페이로드 안전성 확인
   - 타임아웃 설정 조정

#### 디버깅 명령어
```bash
# 환경 메타데이터 수집 디버깅
python -m src.modules.env_collector --debug --project-path /path/to/project

# 룰 적용 디버깅
python -m src.modules.environment_knowledge_base --debug --rule-id "command.exec"

# 동적 검증 디버깅
python -m src.modules.dynamic_verification --debug --vuln-type "command_injection"
```

### 업데이트 및 유지보수

#### 정기 업데이트
- 월간: 환경 지식베이스 룰 검토
- 분기별: 동적 검증 테스트 케이스 업데이트
- 연간: 전체 시스템 성능 및 정확도 검토

#### 버전 관리
- 환경 지식베이스 버전 관리
- 룰 변경 이력 추적
- 테스트 케이스 버전 관리
- 호환성 매트릭스 유지

### 기대 효과 (ROI)

#### 1-2단계 도입 효과
- 거짓 경보(FP) 즉시 감소: 20-30%
- 환경 인식 정확도 향상: 15-25%
- 설정 외부화로 유지보수성 향상

#### 3-4단계 도입 효과
- 환경 특수 이슈 미탐(FN) 감소: 10-20%
- 룰 기반 일관성 있는 판정
- 동적 검증으로 실제 환경 검증

#### 5단계 도입 효과
- Triage 시간 단축: 30-50%
- 현실적 위험 중심 대응 가능
- 우선순위 기반 리소스 배분

### 연락처 및 지원

- 기술 지원: [GitHub Issues](https://github.com/iris-sast/iris/issues)
- 문서: [IRIS Documentation](https://iris-sast.github.io/iris/)
- 커뮤니티: [IRIS Discussions](https://github.com/iris-sast/iris/discussions)
