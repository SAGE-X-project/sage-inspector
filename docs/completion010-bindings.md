# 인증된 완료와 pending 수명 연결

Go와 Rust에 별도 completion API를 추가했다. 실제 서명된 요청을 보관하고 응답의
요청 해시·서명, 완료 payload의 별도 서명, 모든 반향 필드, 현재 고정 키와 ACK를
검증한 뒤에만 인증된 tuple/seed 소유 객체를 만든다. 외부에서 `authenticated: true`
또는 seed를 입력하여 이 객체를 생성할 수 없다.

## 지원하는 경계

- Ed25519 서명과 X25519 KEM을 사용하며, 양쪽 DID는 같은 설정된 registry Gate에서
  조회한다. 선택된 로컬 공개 키와 실제 로컬 개인 키의 대응도 검사한다.
- 이번 carriage는 metadata/task_id가 없는 `plain` 핸드셰이크와 명시적 context/role
  필드를 지원한다. 일반 envelope의 모든 선택 필드, role/context 생략, 오류 응답,
  HTTP 서명 및 session encoding을 지원하는 범용 WireTransport 구현은 아니다.
- 요청의 반환 시점을 로컬 emission 경계로 사용한다. 보낸 요청 원본을 복사해
  보관하며, 지연 전송하려면 새 핸드셰이크가 필요하다. 새 context/nonce/id와 독립
  HPKE/E2E 임시 키를 생성하고, peer가 제공한 파생 문자열은 사용하지 않는다.
- 응답자는 요청의 닫힌 payload와 sender/recipient/key/context/nonce, 서명을 검사한다.
  응답은 원본 signed request 전체의 JCS 해시와 message_id에 바인딩한다.
- initiator는 응답·완료의 두 서명, 고정 initiation의 모든 반향 값, 현재 두 서명 키와
  KEM, th 기반 ACK를 검사한다. 실패하면 pending 암호 재료를 폐기하고 결과를 만들지
  않는다. 같은 pending의 두 번째 완료는 거부한다.
- pending은 300초 단조 시각 상한과 initiation expires 중 빠른 경계에서 만료한다.
  responder는 completion expires도 적용한다. equality와 시계 오류·역행은 거부하며
  재전송으로 수명을 연장하지 않는다.
- 최종 관측 시각의 5초 제한과 **고정 키 자체의 만료**를 모두 검사한다. 특히 영속
  replay 예약을 기다리는 동안 키가 만료되면 결과를 만들지 않는다. 이미 커밋된
  replay 항목은 거부 상태로 남으며 다시 사용할 수 있는 허가가 되지 않는다.

payload는 resolution/암호 작업 전에 최대 16 KiB, 이 핸드셰이크 envelope는 최대
32 KiB로 제한한다. 중복·미지·null 필드, 잘못된 바이너리 인코딩과 trailing JSON을
거부한다. 완료 payload 자체도 JCS 정규 바이트여야 한다.

## 소유권과 남은 통합

인증 결과는 public tuple의 사본만 제공한다. seed를 export하지 않으며, 외부에서
동일 seed로 새 결과를 구성할 수 없다. Go는 명시적 Close와 복사 금지 소유 규칙을
따르고, Rust는 소유 객체와 zeroizing 버퍼를 사용한다. 물리적 메모리 소거 증명으로
해석하지 않는다. restart/abandon 시 pending·결과와 endpoint 키 복사본을 각각 폐기해야
하며 복원 API가 없다.

initiator 결과는 이 핸드셰이크 경계에서 `ESTABLISHED`, responder 결과는
`RESPONSE_SENT`다. **두 결과 모두 application send/dispatch API를 제공하지 않는다.**
응답자 첫 레코드의 tuple·서명·AEAD 검증과 transport replay/sequence 예약·확정의 원자적
연결은 다음 작업이다. responder의 단순 Check는 상태를 확정하지 않는다.
현재 키 검증 실패·폐기·만료·재료 변경은 결과를 닫고, 무관한 키 추가는 원래 선택을
유지한다. Check는 트래픽이 아니므로 idle 수명을 갱신하지 않는다.

검증된 전체 레코드·PoP·chain readiness/finality를 제공하는 Source와 신뢰된 Clock은
선행 의무다. ReplayStore도 필수 인터페이스이며 ID/nonce의 원자적 예약, expires+30
보존, sender별 initiation context 재사용 방지, 영속 복구 또는 재시작 quarantine을
구현해야 한다. 운영용 메모리 fallback은 없다. 테스트의 제한된 replay 저장소와
고장 주입은 이 호출 경계를 검증하며 운영 환경의 영속성·quarantine 증거가 아니다.
실제 HTTP/TLS, 배포 registry, 영속 transport replay와 호스트 강제 경로는 남아 있다.

## 유닛·런타임 검증

| 종류 | 실행 범위 |
|---|---|
| 코어별 단위 시나리오 | 공통 36개 완료 시나리오 |
| 추가 코어 수명 시나리오 | 8개: 요청 재사용, 고정 키 검사, provisional 만료/종료, 저장 도중 키 만료 |
| 실제 프로세스 완료 검사 | Go→Go, Go→Rust, Rust→Go, Rust→Rust 각각 36개, 총 144개 |
| 실제 프로세스 수명 검사 | 네 조합 × 8개, 총 32개 |
| 잘못된 어댑터 입력 | 코어별 4개, 총 8개, 종료 코드 2 |
| 독립 암호 검증 | 완료 사례마다 Node로 요청·외부 응답·내부 완료 서명 3개 검증 |
| 독립 public binding | Python으로 request_hash, JCS(T)의 th와 sid 재계산 |
| 임시 상태 관측 | 코어의 State/Check/Close를 호출; 임의 성공 boolean으로 대체하지 않음 |

원본 HPKE 상태 시나리오 6개의 해시를 공통 fixture에 보존한다. 기존 고정 임시 개인 키를
운영 API에 주입하지 않고 새 CSPRNG 교환을 사용한다. 따라서 원본의 boolean 기반
효과 카운터를 이번 결과로 덮어쓰지 않는다. 기대 결과는 스펙에서 분리해 정의했으며,
Node는 공개된 테스트 seed 1/2의 Ed25519 키를 사용한다. 네트워크 대상이나 운영 키,
호스트 우회·취약점 재현 기능은 없다.

`generate_completion010.py --check`는 독립 Node 공개 키와 fixture를 재현한다.
코어 단위 fixture와 Inspector fixture의 바이트가 같은지도 실행 전에 검사한다.
런타임은 검토한 core revision과 추적 파일 무변경 상태를 요구한다.

```sh
(cd adapters/go && go test -race ./cmd/sage-completion010 && go build -o /tmp/sage-completion010-go ./cmd/sage-completion010)
cargo test --locked --manifest-path adapters/rust/Cargo.toml --bin completion010
cargo build --locked --manifest-path adapters/rust/Cargo.toml --bin completion010
python3 scripts/generate_completion010.py --check
python3 scripts/test_completion010.py --go /tmp/sage-completion010-go --rust adapters/rust/target/debug/completion010 --output /tmp/new-completion010-results
```

각 CLI는 테스트 role과 새 로컬 journal 경로를 인자로 받는다. JSON Lines에 action,
시간·고장 제어, 필요한 wire_hex를 전달하며 최대 128단계·행당 256 KiB로 제한한다.
`start/respond/complete/check/inspect/close`를 실제 코어에 연결한다. `dispatch`는
`UNSUPPORTED`이고, 검증 실패는 `REJECT`와 빈 출력이다. 비밀 seed나 임시 개인 키는
반환하지 않는다.

새 결과 디렉터리의 `report.json`에는 상태·revision·실행 파일/fixture 해시를,
`raw.jsonl`에는 모든 입력·출력·프로세스 종료·stderr를 보존한다. 실패해도 원문을
남긴다. CI의 Record API bindings artifact 아래 `completion010/`에 동일한 결과를
보존한다. 기존 실패·고정 catalog·NOT_RUN은 그대로이며 전체 적합성은
`NOT_ESTABLISHED`로 유지한다.
