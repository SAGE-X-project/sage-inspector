# 배포 레지스트리 관측 증거 계약

0.10.0의 REG-05/REG-06을 위한 **Inspector 증거 입력 계약**이다. Go/Rust의
`Source` 구현, 전체 레코드/PoP 검증기, 실제 RPC 수집기나 배포 인증이 아니다.
기존 코어의 `Snapshot.Validated`/`Finalized`를 원격 JSON 플래그로 채우지 않는다.
이 도구는 입력을 코어 Snapshot으로 변환하거나 메시지 처리를 승인하지 않는다.

## 신뢰 경계와 실행 결과

배포 자료는 운영자가 신뢰하는 별도 관측기가 수집해야 한다. 관측기는 노드/해석기의
신원, 네트워크, 배포 코드, ABI, 업그레이드 정책과 readiness/finality 정책을 실제로
검증하고 전체 레코드·서명키 PoP·KEM endorsement를 확인해야 한다. Inspector는
관측기의 선언과 첨부 원문의 구조·해시·시간 순서·상호 일관성만 검사한다.
원문 해시가 일치해도 내용의 진실성이나 합의 증명이 검증되는 것은 아니다.

- 입력 부재: `NOT_RUN`, CLI 종료 3. 알려지지 않은 지연은 `null`이다.
- 일관성 검사 성공: `EVIDENCE_VALIDATED`, 종료 0. 체인 적합성 PASS가 아니다.
- 잘못된 입력/증거: `FAIL`, 종료 1. 실제 체인의 실패를 관측했다는 뜻은 아니다.
- 출력 디렉터리 재사용 등 실행 오류: 종료 2. 기존 증거를 덮어쓰지 않는다.
- 모든 결과에 `conformance: NOT_ESTABLISHED`, `actual_core_execution: false`,
  `live_chain_verification: NOT_RUN`을 유지한다. `environment: deployed` 선언만으로
  실제 체인 검증 판정을 승격하지 않는다.

현재 실행은 합성 자료와 로컬 CLI만 사용한다. 실제 네트워크·레지스트리 배포와
신뢰할 관측기 바인딩은 지정되지 않았다. 기존 배포 주소나 ABI를 추정하지 않는다.
스펙 원본 및 과거 FAIL/UNSUPPORTED/NOT_RUN 증거는 수정하지 않는다.

## 배포 설정

`vectors/0.10.0/registry-source-binding.json`은 실행 가능한 배포 정보가 아닌
**synthetic 예제**다. JSON은 닫힌 스키마이며 중복 멤버·비유한 수·범위 초과를 거부한다.

| 필드 | 계약 |
|---|---|
| `schema_version`, `protocol_version` | 정수 1, 문자열 0.10.0 |
| `environment` | synthetic 또는 deployed; 신뢰 증명이 아닌 선언 |
| `source`, `trust_model` | 로컬 설정 신원; self-validated-node 또는 explicitly-trusted-resolver |
| `chain_id`, `registry_address` | eip155 양의 십진수 32자리 이내, 소문자 20바이트 0x 주소 |
| `code_hash` | 체인 프로파일에서 정한 배포 코드 해시의 소문자 hex 32바이트; SHA-256로 대체 계산하지 않음 |
| `read_abi_sha256`, `write_abi_sha256` | 리뷰된 ABI 바이트의 SHA-256 식별자; 이 도구는 ABI 의미를 검증하지 않음 |
| `upgrade_policy`, `operator_scopes`, `transaction_authorization` | 필수 운영자 선언; 구현·정책 리뷰는 별도 |
| `readiness_policy`, `finality_policy` | 신뢰할 관측기가 실제로 집행해야 하는 정책 식별/설명 |
| `readiness_max_age_ms` | 1–60000, 이 Inspector 계약의 로컬 상한; 프로토콜의 새로운 합의 규칙이 아님 |
| `observer_revision`, `observer_sha256` | 별도 관측기 revision 및 실행물 SHA-256 식별자; 실제 실행 입증은 별도 |

일반 설명 문자열은 printable ASCII 1–256바이트다. 임의 RPC URL을 받아 호출하지
않으며, URL·Card endpoint를 fetch하거나 트랜잭션을 전송하는 기능이 없다.

## 관측 입력

`registry-source-observations.json`의 최상위 멤버는 `schema_version`,
`binding_sha256`, `observer_sha256`, `artifacts`, `observations`다.
`binding_sha256`은 설정 파일 **원문**의 SHA-256이다. 관측기 해시는 설정과 같아야 한다.

`artifacts`는 SHA-256 → 원문 바이트의 소문자 hex 매핑이다. 1–512개, 각각 최대
65536바이트이며 모든 항목은 관측에서 참조해야 한다. 전체 입력은 4 MiB 이하,
관측은 1–128개다. 외부 파일 경로나 네트워크 참조를 따라가지 않는다.

각 관측은 아래 필드를 모두 갖는다. 입력 순서는 하나의 관측기가 완료한 **직렬
작업 순서**다. 겹치는 병렬 작업은 이 계약의 지원 범위가 아니므로 거부한다.

| 필드 | 검사 |
|---|---|
| `operation_id`, `epoch`, `epoch_started_ms` | 작업 ID는 bundle 내 유일, epoch는 연속 구간만 사용하고 재사용 금지 |
| `source`, `chain_id`, `registry_address`, `code_hash` | 배포 설정과 정확히 일치 |
| `readiness_ms`, `start_ms`, `acquired_ms`, `gate_ms` | 같은 epoch의 신뢰된 단조 시계 밀리초 |
| `utc_ms` | gate 시점 신뢰된 UTC 밀리초, 재시작을 넘어 역행 금지 |
| `block_height`, `block_hash`, `keys_block_hash` | 확정 높이 후퇴·동일 높이 해시 충돌·키의 다른 블록 혼합 금지 |
| `finalized`, `conflicting` | true, false여야 함; 관측기 선언이지 원격 RPC 플래그를 신뢰하는 API가 아님 |
| `did`, `version`, `record_digest`, `state` | 해당 registry DID, uint64 양의 십진 문자열, 전체 원문 SHA-256, created/active/deactivated |
| `readiness_evidence`, `finality_evidence`, `record_evidence` | 원문 artifact 참조; record_evidence는 record_digest와 일치 |
| `publication` | null 또는 epoch/submitted_ms/finalized_ms/evidence |

readiness는 매 epoch 시작 이후 다시 취득해야 한다. 작업 시작 이후 관측을
취득하고 gate까지 5000ms 이하이어야 한다. readiness도 설정된 수명을 넘길 수 없다.
UTC·블록·DID별 version/digest/terminal 상태는 bundle 내 재시작을 넘어 비교한다.
동일 블록의 동일 DID가 달라지거나, 같은 버전의 내용/상태가 달라지거나,
최종 deactivated 레코드가 변경되면 거부한다.

이 비교 상태는 **bundle 내부 검증용 메모리**다. 별개 CLI 실행 사이의 영속 watermark나
세션 replay 저장소를 대체하지 않는다. 전체 record의 JCS/PoP 검증 또한 별도다.
`record_digest`와 원문 해시를 연결해도 합성 예제의 레코드가 규범 레코드가 되지 않는다.

## 지연 측정

작업별 `read_ms = acquired_ms - start_ms`,
`observation_age_ms = gate_ms - acquired_ms`를 기록한다.
`publication`이 있으면 같은 epoch에서
`epoch_started_ms <= submitted_ms <= finalized_ms <= acquired_ms`를 요구하고,
`publication_to_finality_ms = finalized_ms - submitted_ms`를 기록한다.
이 값은 관측기가 선언한 측정이며 `publication_measurement: DECLARED`다.
없으면 `null`과 `NOT_RUN`으로 남긴다. 블록 타임스탬프를 로컬 발행 시각으로
대체하거나 다른 프로세스의 단조 시계를 빼서 지연을 계산하지 않는다.

발행은 관측기 로컬에서 제출을 관측한 시점이며, 확정은 정책을 만족한 블록을
관측한 시점이다. 네트워크/폴링 지연을 포함하므로 순수 합의 시간이라고 주장하지 않는다.

## 실행과 검증

```sh
python3 scripts/inspect_registry_source010.py --output /tmp/registry-not-run
# exit 3: no configured deployment
python3 scripts/inspect_registry_source010.py \
  --binding vectors/0.10.0/registry-source-binding.json \
  --observations vectors/0.10.0/registry-source-observations.json \
  --output /tmp/registry-synthetic-evidence
python3 scripts/test_registry_source010.py
python3 scripts/test_registry_source_runtime.py
```

출력은 새 디렉터리에 report.json과 입력 원문 복사본·SHA-256을 보존한다.
검증 실패에도 읽은 입력 원문과 실패 원인을 남긴다. 유닛 테스트는 경계와 잘못된
증거를 검증한다. 런타임은 7개 입력 경로와 각각의 재실행 거부를 실제 로컬 CLI
프로세스로 확인한다. `run_verification_tests.py`와 CI가 두 테스트의 로그·소스 해시를
기존 Inspector 시험 보고서에 기록한다. 코어 실행 시험으로 집계하지 않는다.

## 남은 배포 작업

신뢰할 네트워크/주소/배포 코드·ABI·업그레이드/권한 정책·노드 또는 해석기와
관측기 실행 바인딩을 확정해야 실제 Source 구현과 런타임 검증을 진행할 수 있다.
그다음 전체 레코드/PoP 검증, 신뢰된 단일 확정 블록 조회, 재시작 readiness,
실제 발행/폐기 지연 수집을 연결한다. 이 계약 검증 완료를 실제 배포 검증 완료로
표시하지 않는다. 별도 execution ledger 복구와 호스트 집행도 계속 남아 있다.
