# Guard commitments 및 서명 메시지 검증

두 코어의 `guard010` API에 원본·manifest·정책 commitment, 엄격 JSON 제한과
Ed25519 intent/result 검증을 구현하고 Inspector primitive 어댑터에 연결했다.
실제 실행 대상 revision은 `scripts/test_record010_adapters.py`의 PINS와 CI
checkout에 고정한다. 과거 [준비 상태 계약](guard-binding-handoff.md)과
`docs/evidence/guard` 결과는 해당 revision의 이력으로 보존한다.

## 검증 경계

코어는 전체 envelope의 중복 decoded key·UTF-8·surrogate·크기·깊이·member 제한을
서명 검증 전에 검사한다. 음의 0과 음의 underflow를 거부하고 protocol timestamp는
binary64 반올림 전에 정확한 안전 정수인지 검사한다. 독립 manifest는 4096파일까지,
정책과 envelope는 aggregate object member 4096까지라는 서로 다른 상한을 적용한다.

서명은 intent/result별 domain과 JCS를 사용한다. 수신자, keyid/issuer, 원본,
승인 정책 및 manifest commitment와 최종 인자를 검사한다. 성공 결과는 proof까지
포함한 전체 canonical envelope를 소유한다. Go accessor는 복사본, Rust는 immutable
borrow를 반환한다. 불투명 raw bytes를 authenticated receipt로 승격하는 생성자는 없다.
Go receipt의 zero value도 인증된 값이 아니다.

clock, 요청별 활성 키 관측, issuer/request_id에 대한 보호된 원본·정책·manifest 조회,
닫힌 tool schema와 최종 인자 평가, outstanding invocation은 **신뢰된 호스트 서비스**다.
어댑터의 active_key/policy_allow/outstanding은 고정 테스트를 위한 seam이며 운영 wire
권한 형식이 아니다. 범용 policy 언어나 실제 registry Source를 구현했다고 주장하지 않는다.

result 검증은 기존 수락된 invocation의 정확한 intent envelope와 request/call ID,
양측 identity, 현재 결과 키 및 freshness를 검사한다. 이미 수락한 호출의 intent가
만료된 뒤에도 fresh result를 받을 수 있으며, 만료 후 새 invocation 허용과 구분한다.
이 API 자체는 terminal 소비의 영속 상태를 갱신하지 않는다.

## 검사 결과와 재현

고정 102개 중 코어별 **86 PASS, 16 UNSUPPORTED, 0 FAIL**이다. 86개는 새 Guard
primitive 78개와 기존 signature/JCS projection 8개다. MCP result mapping 16개는
UNSUPPORTED이고, stateful scenario 37개/297단계는 NOT_RUN으로 유지한다.
전체 Guard inspection은 INCOMPLETE, 전체 프로토콜 적합성은 NOT_ESTABLISHED다.
검사 harness의 PASS는 이 정확한 부분 지원 결과가 관측되었다는 뜻이다.

- 코어 유닛 테스트: 독립 78개, Unicode/decoded 중복 키, 음의 0·underflow,
  정확한 timestamp와 crypto 이전 거부, manifest 4096/4097 경계.
- Go 추가 테스트: 반환 바이트 변경이 receipt를 바꾸지 않음, 취소·nil authority 거부.
- 안전한 런타임: 실제 Go/Rust 어댑터 프로세스에서 고정 102개씩 실행.
- 별도 Node 검산: 102개/37개 fixture의 해시·서명·기대값을 독립 확인.
- 보고서 유닛 테스트: 잘못된 값, 누락, MCP/상태 시나리오의 허위 PASS 승격 거부.

```sh
python3 scripts/test_guard_primitive_reports.py
python3 scripts/test_guard_primitive_adapters.py \
  --go /path/to/go-adapter --rust /path/to/rust-adapter \
  --runner /path/to/sage-conformance --output /tmp/new-guard-primitives
```

코어는 PINS revision에서 빌드해야 한다. 출력은 새 디렉터리에만 생성하며 adapter,
runner, fixture와 summary 해시 및 raw primitive 보고서를 남긴다. CI artifact
`guard-primitive-bindings-*`는 기존 readiness·record evidence와 별도로 보존한다.

다음 작업은 private verified intent에서 ledger Entry를 유도하는 bridge, 동일
호출·nonce의 원자 예약 및 재조회, 정책 retirement·instance·최종 dispatch gate 연결이다.
MCP mapping, 결과의 한 번만 소비하기, 배포 Source·scope 복구·호스트 isolation도 남아 있다.
현재 API 성공만으로 도구 실행을 허용하면 안 된다.
