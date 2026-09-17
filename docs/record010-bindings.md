# 0.10.0 레코드 API 연결

Go `e36cb2476e900ac6d3421aee42d3bff43dbc82da`와 Rust
`89949e89083c5f7dc7d0948ccda65d9810f52a10`의 RecordSession010을 연결했다.
이 문서는 새 API의 제한된 로컬 검증을 설명한다. 과거 코어 보고서와 source lock은
그 실행 당시의 증거이므로 변경하지 않는다.

## 어댑터 계약

schema 1 / primitive-foundation에 다음 별도 연산을 추가한다.

| 연산 | 입력 | 수락 출력 |
|---|---|---|
| sage.session.record010.open | seed_hex, th_hex, direction, caller_aad_hex, record_hex | plaintext_hex |
| sage.session.record010.seal | seed_hex, th_hex, direction, caller_aad_hex, plaintext | record_sha256, record_bytes |
| sage.session.record010.export | seal과 같음 | seal 출력과 record_hex, session_id |

seed/th는 각각 32바이트이며 direction은 c2s 또는 s2c다. plaintext는 공개 테스트
바이트의 반복을 표현하는 `{byte, length}`다. 송신 시작 seq는 0이며 각 요청은
새 코어 인스턴스를 사용한다. 코어가 직접 키·nonce·AAD·sid를 생성하고 레코드를
검증한다. 어댑터는 요청·결과 변환과 보고용 해시만 처리한다.

sid는 입력으로 받지 않는다. 인증 envelope의 session_id 일치 여부는 이 저수준
API의 기능이 아니므로 어댑터에서 대신 검사하지 않는다. 추가 입력 멤버는 오류다.
잘못된 제어 타입·hex·direction은 비정상 종료이고, 코어의 레코드 거부만 REJECT다.
테스트 자원 상한으로 callerAAD는 4034바이트까지, plaintext recipe는 8 MiB-35까지
전달할 수 있다. 각각 규범 상한보다 1바이트 큰 값은 코어가 거부하는지 검사한다.
더 큰 제어는 어댑터 오류로 처리하며 코어의 거부 증거로 사용하지 않는다.

기존 `sage.session.record.*`는 legacy 동작을 유지한다. 기존 교환 도구의
`open.bound` 미지원도 그대로 두며 새 테스트에서 legacy 송신/정상 대조군과
record010 수신을 혼용하지 않는다. 내부 파생 키를 반환하는 공개 코어 API가
없으므로 기존 key 연산의 미지원도 어댑터 자체 HKDF로 대체하지 않는다.

## 검증 범위

`scripts/test_record010_adapters.py`는 실행 파일 세 개와 새 출력 경로를 요구한다.

- 독립 session-records.json의 55개 중 키 조회 18개를 제외한 37개를 코어별로
  실제 sage-conformance CLI에서 실행한다. 테스트 메모리에서 연산명과 sid 입력만
  투영한다. 기대 레코드·평문·해시 및 원본 벡터 파일은 변경하지 않는다.
- Go→Rust·Rust→Go의 c2s/s2c 네 조합에서 export로 생성한 실제 바이트를 전달한다.
  같은 record010.open의 정상 평문 수락을 확인한 뒤 th만 바꾼 거부를 확인한다.
  정상 대조군 실패 시 이후 거부 검사를 진행하지 않고 전체 테스트를 실패시킨다.
- 송신 결과의 길이·해시와 transcript에서 독립 계산한 sid를 확인한다.
- 코어별 7개, 총 14개의 잘못된 제어가 정상 REJECT로 숨겨지지 않는지 검사한다.

공개 고정 입력을 사용하는 로컬 프로세스 테스트이며 네트워크, 호스트 실행,
경합 진단 또는 우회 프로그램을 실행하지 않는다. 새 코어의 실제 레코드 연산을
검사하지만 세션 상태를 여러 요청에 걸쳐 유지하는 어댑터를 구현한 것은 아니다.
따라서 재전송·만료·재시작·registry·인증 tuple·HPKE·HTTP/WS·Guard 적합성 결과로
확장하지 않는다. 기존 전체 적합성은 NOT_ESTABLISHED다.

## 실행과 CI

```sh
go build -o /tmp/sage-record010-runner ./cmd/sage-conformance
(cd adapters/go && go build -o /tmp/sage-record010-go .)
cargo build --locked --manifest-path adapters/rust/Cargo.toml --target-dir /tmp/sage-record010-rust
python3 scripts/test_record010_adapters.py --go /tmp/sage-record010-go --rust /tmp/sage-record010-rust/debug/sage-inspector-rust-adapter --runner /tmp/sage-record010-runner --output /tmp/sage-record010-results-new
```

CI는 두 코어를 위 revision으로 checkout하여 별도 `Record API bindings` 작업에서
빌드·실행한다. `record010-bindings-<revision>` artifact에는 두 CLI 원시 보고서와
report.json을 보존한다. report.json은 주체 revision·실행 파일 해시·벡터 해시와
교환 요청·관측을 기록한다. 실패 시 가능한 부분 결과와 오류를 남기고 비정상
종료한다. git revision과 실행 파일 해시 자체가 독립적인 빌드 인증은 아니며 CI의
고정 소스 빌드와 함께 추적한다. 출력은 기존 경로를 덮어쓰거나 docs/evidence에
생성할 수 없다. 과거 카탈로그의 386개 계획 사례 상태를 이번 결과로 승격하지 않는다.

다음은 새 레코드 API의 상태 유지 어댑터와 관측 계약을 연결하는 작업이다.
키/tuple·레지스트리·HPKE 확인 등의 추가 코어 계약은 별도로 준비해야 한다.
