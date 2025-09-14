# Environment Metadata Collector

IRIS의 환경 메타 자동 수집 기능을 사용하여 정적 분석과 LLM 판정에 실제 배포 환경 요약을 자동 주입할 수 있습니다.

## 기능 개요

이 기능은 다음 정보를 자동으로 수집합니다:

- **시스템 정보**: OS, 배포판, 컨테이너 여부, 파일시스템, 셸
- **런타임 정보**: Python, Java, Node.js 버전
- **프레임워크 정보**: Maven, Gradle, Ant 버전
- **데이터베이스 정보**: 프로젝트에서 사용하는 DB 드라이버
- **보안 정책**: SELinux, AppArmor, 방화벽 상태
- **프로젝트별 정보**: JDK 버전, 빌드 도구, 의존성

## 설정 파일

`env_collector_config.yaml` 파일을 통해 수집할 정보와 동작을 제어할 수 있습니다.

### 기본 설정

```yaml
# 환경 수집 활성화/비활성화
enabled: true

# 수집할 정보 설정
collection:
  system:
    enabled: true
    collect_distro: true
    collect_container_info: true
    collect_filesystem: true
    collect_shell: true
  
  runtime:
    enabled: true
    collect_python: true
    collect_java: true
    collect_node: true
  
  frameworks:
    enabled: true
    collect_maven: true
    collect_gradle: true
    collect_ant: true
  
  database:
    enabled: true
    detect_drivers: true
    driver_patterns:
      - "mysql-connector"
      - "postgresql"
      - "h2"
      - "sqlite"
      - "oracle"
      - "mssql"
  
  security:
    enabled: true
    collect_selinux: true
    collect_apparmor: true
    collect_firewall: true
  
  project:
    enabled: true
    detect_jdk_version: true
    detect_build_tool: true
    extract_dependencies: true

# 출력 설정
output:
  filename: "env.json"
  include_in_results: true
  include_in_prompts: true
  verbose: false

# LLM 프롬프트 설정
prompt:
  use_env_context: true
  context_format: "detailed"  # "simple" or "detailed"
  include_fields:
    - "os"
    - "distro"
    - "runtime"
    - "frameworks"
    - "db"
    - "policies"

# 성능 설정
performance:
  subprocess_timeout: 30
  max_file_size: 1048576  # 1MB
  skip_large_projects: false
  large_project_threshold: 1000
```

## 사용 방법

### 1. 기본 사용법

기존 IRIS 워크플로우를 그대로 사용하면 환경 정보가 자동으로 수집됩니다:

```bash
# 프로젝트 빌드 (환경 정보 자동 수집)
python scripts/fetch_and_build.py --filter apache__camel

# IRIS 분석 (환경 정보가 LLM 프롬프트에 자동 주입)
python src/iris.py --query cwe-022wLLM --run-id test apache__camel_CVE-2018-8041_2.20.3
```

### 2. 설정 커스터마이징

`env_collector_config.yaml` 파일을 수정하여 수집할 정보를 제어할 수 있습니다:

```yaml
# 특정 정보만 수집
collection:
  system:
    enabled: true
  runtime:
    enabled: true
  frameworks:
    enabled: false  # 프레임워크 정보 수집 비활성화
  database:
    enabled: false  # DB 드라이버 감지 비활성화
  security:
    enabled: false  # 보안 정책 수집 비활성화
  project:
    enabled: true

# 간단한 환경 컨텍스트만 사용
prompt:
  use_env_context: true
  context_format: "simple"
  include_fields:
    - "os"
    - "runtime"
```

### 3. 테스트

환경 수집 기능을 테스트하려면:

```bash
python test_env_collector.py
```

## 생성되는 파일

### env.json

각 프로젝트의 `data/project-sources/{project}/env.json`에 환경 메타데이터가 저장됩니다:

```json
{
  "os": "linux",
  "distro": "ubuntu",
  "containerized": true,
  "shell": "bash",
  "runtime": {
    "python": "3.10.12",
    "java": "17.0.7",
    "node": null
  },
  "frameworks": {
    "maven": "3.9.8",
    "gradle": "8.9",
    "ant": null
  },
  "db": {
    "driver": "mysql-connector, h2",
    "version": "unknown"
  },
  "fs": "ext4",
  "policies": {
    "selinux": "disabled",
    "apparmor": "disabled",
    "firewall": "unknown"
  },
  "project_specific": {
    "jdk_version": "8",
    "build_tool": "maven",
    "build_tool_version": "3.5.0",
    "project_slug": "apache__camel_CVE-2018-8041_2.20.3",
    "dependencies": {
      "maven_deps": [...],
      "gradle_deps": [...],
      "jar_files": [...]
    }
  },
  "config": {
    // 수집 시 사용된 설정 정보
  }
}
```

## LLM 프롬프트에 환경 정보 주입

환경 정보가 LLM 프롬프트에 자동으로 주입되어 더 정확한 보안 취약점 분석을 제공합니다:

```
Environment Context:
- Operating System: linux (ubuntu)
- Runtime: Python 3.10, Java 17
- Build Tools: maven 3.5.0
- Database Drivers: mysql-connector, h2
- Security Policies: SELinux disabled, AppArmor disabled

Among the following methods, assuming that the arguments passed to the given function is malicious, what are the functions that are potential source, sink, or taint-propagators to path traversal attack (CWE-22)?
```

## 성능 고려사항

- **파일 크기 제한**: 기본적으로 1MB 이상의 파일은 스캔하지 않습니다
- **대용량 프로젝트**: 의존성이 많은 프로젝트는 건너뛸 수 있습니다
- **타임아웃**: 서브프로세스 호출에 30초 타임아웃이 적용됩니다

## 문제 해결

### 환경 정보가 수집되지 않는 경우

1. `env_collector_config.yaml`에서 `enabled: true`인지 확인
2. 해당 수집 모듈이 활성화되어 있는지 확인
3. 로그에서 오류 메시지 확인

### LLM 프롬프트에 환경 정보가 포함되지 않는 경우

1. `prompt.use_env_context: true`인지 확인
2. `prompt.include_fields`에 원하는 필드가 포함되어 있는지 확인
3. `env.json` 파일이 올바르게 생성되었는지 확인

### 성능 문제

1. `performance.max_file_size`를 줄여서 스캔할 파일 크기 제한
2. `performance.skip_large_projects: true`로 설정하여 대용량 프로젝트 건너뛰기
3. 불필요한 수집 모듈 비활성화

## 확장

새로운 환경 정보를 수집하려면:

1. `EnvironmentCollector` 클래스에 새로운 수집 메서드 추가
2. `collect_all()` 메서드에서 새 메서드 호출 추가
3. 설정 파일에 새로운 옵션 추가
4. LLM 프롬프트에 새로운 필드 포함
