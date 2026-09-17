# 요청별 레지스트리 관측과 고정 키 검증

두 코어의 `registry010`은 매 작업의 새 권위 관측, 정확한 서명 키 선택,
ASCII 이름 순서의 X25519 선택, 선택 당시 키의 재검증과 영속 거부 상태를 제공한다.
이 구현은 신뢰된 조회 소스와 시계를 사용하는 경계다. 네트워크 resolver,
전체 레코드·PoP 검증기 또는 인증 세션 관리자가 아니다.

## 구현 경계

- 관측은 해당 작업 시작 이후 취득해야 하며, 영속 저장이 끝난 최종 관측 시점까지
  5초를 넘으면 거부한다. 시계 오류·역행, 조회 실패, 준비되지 않은 소스, 잘못된
  source/registry/network, 미확정·충돌 상태와 혼합 블록도 거부한다.
- 이전 `active`/`accepted` 결과를 다음 작업의 권한으로 재사용하지 않는다.
  지연된 최종 인가에는 새 조회가 필요하다. 마지막 시계 표본이 이 모듈의 관측
  선형화 지점이며, 호출자는 실제 dispatch 시점의 인가 연결을 책임진다.
- 정확한 Ed25519 DID URL만 선택한다. KEM이 필요한 경우 첫 번째 사용 가능한
  X25519 키를 선택한다. 서명만 필요한 요청은 KEM 없이 처리할 수 있다.
- 고정 키의 이름·알고리즘·바이트·만료는 변경할 수 없다. 무관한 레코드 갱신이나
  새 키 추가는 기존 키를 대체하지 않는다. 매 작업에서 원래 키를 재검증한다.
  실패 시 세션 종료는 이후 세션 소유자 연결에서 구현해야 한다.
- 확정 버전과 전체 레코드 digest를 registry/DID별로 영속화한다. 버전 역행,
  동일 버전의 내용 변경, 확정 폐기 이후 활성화를 거부한다. 미확정 폐기는
  현재 작업을 거부하지만 영구 tombstone을 남기지 않는다.

전체 레코드의 닫힌 스키마·암호·PoP·신원·최종성·readiness 검증은 **신뢰된 Source의
선행 의무**다. 원격 JSON의 `validated`·`finalized` 플래그를 신뢰하라는 계약이 아니다.
테스트 입력은 이 Source와 Clock을 로컬에서 주입하며, digest는 테스트용 키/상태
projection을 대상으로 한다. 실제 전체 레코드 proof를 실행했다고 집계하지 않는다.
지원 키 알고리즘은 Ed25519/X25519로 한정한다.

## 저장과 재시작

Go와 Rust는 `sage-registry-watermarks|0.10.0` 헤더의 JSON Lines 저널을 사용한다.
버전은 정수 uint64, scope는 registry/DID이고 digest와 terminal 플래그를 함께 기록한다.
append와 fsync가 성공하기 전에는 저장 성공을 반환하지 않는다. 용량은 64 MiB,
레코드 수는 4096으로 제한되며 초과 시 거부한다.

신규 생성은 명시적 초기화에서만 허용한다. 일반 재시작은 기존의 완전한 저널을
열어야 한다. 누락·잘린 행·빈 행은 거부한다. 단일 writer가 `.lock`을 소유하며
정상 종료에서만 해제한다. 비정상 종료 후에는 운영자가 배타 소유권을 확인하고
복구해야 한다. 자동 crash recovery나 악의적인 디스크 rollback 방지는 제공하지
않는다. 신뢰된 경로와 영속 저장 보호는 배포 전제다.

## 유닛 테스트와 실제 프로세스 테스트

| 검증 | 이번 실행 범위 |
|---|---|
| 코어 단위 테스트 | 동일한 39개 시나리오, 코어별 107단계 및 저널 거부 테스트 |
| 코어 CLI 실행 | 두 코어 합계 78개 시나리오, 214단계 |
| 프로세스 재시작 | Go→Go, Go→Rust, Rust→Go, Rust→Rust 각각 버전 역행·영구 폐기, 총 8조합 |
| 런타임 제어 | 동시 writer 거부, 정상 재열기, 누락·손상·빈 행, 잘못된 입력, 관리 기능 미지원 등 22개 |
| Go 검사 | 새 코어와 어댑터의 단위 테스트, race detector, 코어 vet |
| Rust 검사 | 새 코어와 어댑터의 단위 테스트, 코어 all-targets/all-features clippy, fmt |

고정된 기존 레지스트리 시나리오 16개의 관측 부분을 투영하고 키 선택·만료·버전·
지연 등의 사례를 추가했다. 원본 파일 해시는 새 벡터에 보존한다. REG-03 mutation
시나리오는 포함하지 않으며 기존 관리 상태·부수 효과를 어댑터에서 흉내 내지 않는다.
어댑터의 `mutate`는 `UNSUPPORTED`다.

`generate_registry010.py --check`로 벡터를 재현하고, 코어 두 곳의 단위 테스트
fixture가 동일한 바이트인지 실행 전에 검사한다. `test_registry010.py`는 고정 core
revision과 추적 파일의 변경 여부를 확인한다. 별도 프로세스는 실제 Gate와 Journal을
호출하며 Inspector가 버전·폐기·키 선택 정책을 대신 구현하지 않는다.

CLI는 신뢰된 로컬 journal 경로와 `create`/`reopen` 인자를 받고,
`{"id":"0","request":{...}}` JSON Lines를 최대 128개, 행당 최대 1 MiB 처리한다.
`observe`, `select`, `check`, `inspect`, `restart`를 지원한다. Source/Clock 제어값은
로컬 테스트 입력이다. 기대값은 CLI에 전달하지 않는다. 잘못된 제어 입력은 종료 코드
2, 코어 거부는 `REJECT`, 미지원 관리는 `UNSUPPORTED`로 구분한다.

```sh
(cd adapters/go && go test -race ./cmd/sage-registry010 && go build -o /tmp/sage-registry010-go ./cmd/sage-registry010)
cargo test --locked --manifest-path adapters/rust/Cargo.toml --bin registry010
cargo build --locked --manifest-path adapters/rust/Cargo.toml --bin registry010
python3 scripts/generate_registry010.py --check
python3 scripts/test_registry010.py --go /tmp/sage-registry010-go --rust adapters/rust/target/debug/registry010 --output /tmp/new-registry010-results
```

결과 디렉터리는 새 경로여야 한다. `report.json`은 모든 입력·stdout·stderr·종료 코드,
고정 revision·실행 파일/fixture 해시와 실패 원문을 보존한다. CI의 Record API bindings
artifact 아래 `registry010/`에서 동일한 보고서를 보존한다. 이전 실패 증거와 frozen
catalog는 갱신하지 않는다.

## 남은 연결

실제 validating Source, 배포된 체인의 최종성·발행 지연·관측 지연 측정, 여러 DID에
의존하는 인증 tuple, 고정 키와 transcript 연결, 실패 시 세션 종료 및 dispatch gate는
아직 통합되지 않았다. 다음 작업은 인증 tuple 및 서명된 완료 메시지·pending 수명을
이 경계에 연결하는 것이다. 이번 결과는 REG-05의 코어 경계 검증이며 REG-05 배포
검증이나 전체 프로토콜 적합성 완료를 의미하지 않는다. 전체 판정은
`NOT_ESTABLISHED`로 유지한다.
