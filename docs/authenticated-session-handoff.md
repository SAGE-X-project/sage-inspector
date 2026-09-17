# 인증 세션과 권위 관측 연결 검토

검토 기준: Go `e36cb2476e900ac6d3421aee42d3bff43dbc82da`, Rust
`89949e89083c5f7dc7d0948ccda65d9810f52a10`의 아래 호출 경로와
[고정 스펙 기준선](spec-baseline.md). 이 문서는 소스 검토와 구현 인계이며
새 코어 실행 보고서나 전체 보안 적합성 판정이 아니다.

## 결론과 지원 경계

새 RecordSession010은 인증된 핸드셰이크 결과를 소비할 하위 레코드 계층이다.
현재 어댑터의 seed/th 테스트 입력을 실제 인증 완료의 증거로 사용할 수 없다.
기존 HPKE 흐름을 이 레코드 API에 연결하는 것만으로 0.10.0이 완성되지 않는다.

| 경계 | Go에서 확인한 경로 | Rust에서 확인한 경로 | 연결 판단 |
|---|---|---|---|
| 레코드 암호·순서·종료 | `pkg/agent/session/record010.go` | `src/session/record010.rs` | 새 API와 제한된 실제 상태 검증 제공 |
| HPKE 파생·완료 | `pkg/agent/hpke/{types,common,client,server}.go` | `src/hpke/{types,common,client,server}.rs` | v1 도메인·완료 형식 사용. 0.10.0 전체 파생/완료 바인딩 미지원 |
| 인증 tuple | RecordSession010 생성 입력은 seed/th/역할 | RecordSession010 생성 입력은 seed/th/역할 | 고정 DID·키 URL·키 재료와 외부 envelope의 일치 검사는 별도 코어 계약 필요 |
| 권위 관측 | `pkg/agent/did/resolver.go`, `types.go` | `src/hpke/types.rs`, `resolver.rs` | 검토한 반환형만으로 REG-05 요청별 관측·확정 버전·최종 gate를 보장할 수 없음 |
| 임시 응답자 확인 | 서버가 legacy manager에 세션을 생성·바인딩 | 서버가 envelope/seed/kid/session_id를 반환 | 첫 레코드 검증과 예약·확인 전환을 함께 commit하는 0.10.0 계약 필요 |

Go의 `createSessionAndBindKid`는 `EnsureSessionFromExporterWithRole`에
`sage/hpke+e2e v1`을 전달한다. Rust의 `SESSION_LABEL`도 같은 v1 값이다.
두 코어의 기존 combiner는 `SAGE-HPKE+E2E-Combiner`를 사용하므로
HPKE-03의 `sage-hpke-combiner|0.10.0` 및 th 바인딩과 구별해야 한다.
기존 서명·ACK·DH 검사가 없는 것은 아니다. 이 검토는 해당 검사가 새 스펙의
형식과 상태 전이를 충족한다는 근거가 아직 없다는 판단이다.

Go Resolver는 DID 기반 metadata/공개 키/KEM 키를 반환하고 AgentMetadata에
Keys도 존재한다. Rust의 HPKE signing/KEM resolver는 DID로 키를 반환하며,
DID 문서 기반 KEM resolver는 X25519 방법을 선택한다. 이 경로에는 요청 시작,
최종 인가 시각, 동일 확정 블록 및 선택된 전체 키 URL을 함께 검증하는 반환 계약이
없다. 다른 모듈의 모든 기능이 부재하다는 주장이나 배포된 체인 검증 결과는 아니다.

## 코어가 제공할 연결 계약

아래는 구현 인계 제안이다. 규범은 [HPKE](../../sage-spec/spec/04-hpke.md),
[Session](../../sage-spec/spec/05-session.md),
[Registry](../../sage-spec/spec/09-registry.md)를 따른다. API 이름은 확정하지 않는다.

1. **권위 관측과 키 선택.** 코어가 신뢰된 resolver/clock을 통해 요청 시작 후
   관측을 획득하고 최종 인가 시점까지 최대 5초인지 검사한다. 대기 중 초과하면
   다시 조회한다. source/registry/network/readiness, 레코드와 키의 동일 확정
   블록, 버전, 선택된 키 URL·알고리즘·바이트·상태를 함께 검사한다. 단순히
   응답에 `trusted: true`가 있거나 RPC가 latest를 반환하는 것으로 대체하지 않는다.
   최고 확정 버전과 확정 tombstone은 유지하고 재시작 시 readiness를 재검사한다.
   미확정 폐기는 현재 요청을 거부하되 영구 tombstone으로 승격하지 않는다.
2. **핸드셰이크 결과와 tuple.** 코어가 닫힌 0.10.0 payload, 정확한 B/T/JCS,
   info/exportCtx, 두 DH의 0 결과 거부, th 기반 seed/ACK 파생, 내부·외부 서명과
   pending 일치를 검증한다. 성공 결과가 tuple
   `(v,ctx,initDid,respDid,initKid,respKid,kemKid,suite,combiner,kid,th,sid)`와
   고정 키 재료·역할을 소유한다. 호출자가 검증 여부 boolean을 지정해 인증된
   세션을 만들 수 있는 운영 API로 설계하지 않는다. 하위 RecordSession010의
   직접 생성은 암호 계층 사용이며 인증된 세션 생성과 구별한다.
3. **레코드 인가.** 모든 레코드에서 반대 역할, envelope did/recipient/kid,
   version/context/session id와 고정 tuple을 검사하고 선택된 두 서명 키와 KEM
   키를 REG-05에 따라 재검증한다. 선택 키의 폐기·만료·조회 불가·재료 변경은
   세션을 닫는다. 같은 DID의 다른 유효 키로 자동 교체하지 않는다. 관계없는
   키 추가나 service 갱신만으로 세션을 닫지 않는다.
4. **임시 세션 commit.** 응답자는 첫 레코드의 schema/tuple/키/서명/AEAD를
   검사한 뒤 transport id/nonce와 레코드 seq 예약 및 ESTABLISHED 전환을 원자적으로
   수행해야 한다. commit 시 종료와 pending deadline을 다시 검사한다. 기존
   Open 호출 뒤 어댑터에서 나머지를 검사하면 이미 seq가 소비될 수 있으므로
   그것을 원자적 프로토콜 수신으로 취급하지 않는다. 유효 첫 seq는 0만으로
   제한하지 않는다. 암호 수락 후 애플리케이션 인가가 거부되어도 확인·재전송
   예약은 유지하고 보호된 효과는 0이어야 한다.
5. **실패와 관측.** pending은 300초 단조 시각 제한과 해당 UTC 만료 중 이른
   경계를 적용하고 equality에서 만료한다. 잘못된 완료 메시지는 pending을 파기하고 세션을
   생성하지 않는다. 실제 생성·파기·예약·전환·보호 효과를 코어 경계에서
   관측할 수 있어야 한다. 논리적 파기 카운터를 물리적 메모리 소거 증명으로
   해석하지 않는다. 운영 오류에는 비밀·키·평문을 노출하지 않는다.

권위 관측은 그 관측 시점의 판단이며 미래 폐기를 예측하거나 이미 끝난 효과를
취소하는 보장이 아니다. 이 계약도 장악된 프로세스가 검증 코드와 신뢰 입력을
모두 변경하는 상황에 대한 독립 실행 무결성을 제공하지 않는다. 호스트 강제
gate와 신뢰 경계 검증은 별도 배포 작업으로 남는다.

## 구현 순서와 완료 조건

| 순서 | 작업 | 완료를 판단할 증거 |
|---|---|---|
| 1 | 두 코어에 별도의 0.10.0 HPKE 파생 API 제공 | 고정 독립 중간값·음성 벡터를 코어 단위 테스트와 실제 로컬 CLI로 검증. v1 결과를 정규화하지 않음 |
| 2 | 권위 관측·고정 키 선택 및 tuple 생성 경계 구현 | registry 17개 상태 시나리오를 실제 코어 seam으로 연결하고 재시작·확정/미확정·5초 경계 확인 |
| 3 | 인증된 완료와 pending 수명 연결 | HPKE 6개 상태 시나리오에서 실제 생성/파기 관측. 외부 envelope 검증의 독립 근거도 연결 |
| 4 | tuple 수신 및 응답자 첫 레코드 commit 연결 | session 37개 시나리오 중 실제 지원 항목을 연결. 부분 실패의 예약·효과를 단위 테스트로 확인 |
| 5 | 양방향 HTTP/WS 및 호스트 검증 범위 확정 | 지원되는 안전한 런타임 경로와 아직 미지정인 호스트 경계를 따로 보고 |

다음 실행 단위는 **1번의 두 코어 0.10.0 파생 API와 Inspector 연결**이다.
파생 성공은 인증된 완료·권위 관측·전체 핸드셰이크 성공을 뜻하지 않는다.
원자성 실패 순서와 시간 경계는 명시적인 단위 테스트 제어로 검증하며 공격 재현
프로그램이나 실제 호스트 우회 도구는 만들지 않는다.

[HPKE 기존 계약](hpke-inspection.md)의 67개 사례,
[Registry 계약](registry-inspection.md)의 17개 상태 시나리오,
[Session 계약](session-inspection.md)의 37개 상태 시나리오를 재사용한다.
기존 trusted harness boolean은 고정 테스트 입력이다. 실제 연결에서는 해당
검증 결과를 코어의 신뢰된 seam에서 얻어야 하며 peer wire flag로 받지 않는다.
필수 관측을 제공할 수 없으면 UNSUPPORTED와 후속 NOT_RUN을 유지한다.

이번 검토는 [상태 유지 레코드 결과](record010-state-bindings.md)를 확장한
실행 증거가 아니다. 과거 FAIL·원시 보고서·고정 source lock은 그대로 보존한다.
386개 규범 계획 사례의 NOT_RUN과 전체 `NOT_ESTABLISHED`도 변경하지 않는다.

후속 구현 기록: 위 표는 초기 검토 시점의 지원 상태다. 이후
[전체 암호 파생](hpke-derivation010.md)과
[요청별 관측·고정 키·영속 버전 경계](registry010-bindings.md)를 별도 API로 구현했다.
레지스트리 원본 17개 중 관리 mutation을 제외한 16개의 관측 부분을 투영했으며,
새 경계의 39개 시나리오로 검증한다. tuple 생성·인증된 완료·pending 및 dispatch
통합은 아직 남아 있다. 다음 실행 단위는 이 인증 세션 연결이다.
