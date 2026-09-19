# Guard 배포 통합 계약 검토

이 문서는 0.10.0의 기존 규범을 현재 코어 API에 연결하는 **구현 인계 계약**이다.
새 wire 형식·프로토콜 버전·배포 인증을 정의하지 않는다. 검토 범위는 아래 고정
revision이며, 소스 해시 일치는 코드 식별 증거이고 실행·보안성 증명이 아니다.

| 코어 | 검토 revision | 연결 가능한 API |
|---|---|---|
| Go | `cd9e84232de197b477802837bc39b36f49618d37` | registry010.Source/Gate, guard010.Authority/IntentPolicy/Component, MCPWireSender/MCPEndpoint/Client |
| Rust | `8d3b29b5b1157f8792654591c13ae9d26cd6bd21` | registry010::Source/Gate, guard010::Authority/IntentPolicy/Component, MCPWireSender/MCPEndpoint/Client |

소스 파일과 규범 해시는 [검토 계약](../verification/0.10.0/guard-integration-contract.json)에
고정했다. 기존 [RPC 검증](guard-rpc010.md)의 실제 IPC·서명 결과는 유효하지만
고정 키·inert sink·로컬 pipe를 운영 Source·보호 전송·호스트 격리로 승격하지 않는다.
과거 [인계 보고서](guard-binding-handoff.md)는 당시 revision의 이력으로 보존한다.
전체 lifecycle 37개는 `NOT_RUN`, 전체 적합성은 `NOT_ESTABLISHED`다.

## 경계별 책임과 완료 증거

| 경계 / 소유자 | 현재 지원과 부족한 연결 | 완료에 필요한 증거 |
|---|---|---|
| Source / 배포 | Gate는 신뢰된 Snapshot의 freshness·동일 블록·키·영속 version을 검사한다. 실제 노드/해석기, 완전한 record·PoP·endorsement 검증은 Source의 책임이다. | 네트워크·registry·배포 코드·ABI·업그레이드 권한과 source 신원 고정, 동일 확정 블록 원문, 완전한 record 검증, 재시작 readiness, 발행·관측 지연 |
| Authority / 코어 어댑터 | Guard는 정확한 현재 Ed25519 키와 신뢰된 시각을 요구한다. registry Gate를 Guard Authority로 잇는 운영 바인딩은 이번 검토에서 확립하지 않았다. | 매 결정의 정확한 issuer/keyid 선택, 이전 양성 결과 재사용 금지, 단일 로컬 시계, 최종 gate의 유효한 관측 |
| 원본·정책·서명 / 호스트 | 원본·policy·manifest commitments와 IntentPolicy API가 있다. 승인 매핑의 설치·보호, evaluator, signer 권한은 신뢰 의존성이다. | 확장 전 원본 캡처 경로, 최종 arguments의 closed schema 검사, 승인 epoch와 baseline의 영속 관리, exact intent에 한정된 서명 권한 |
| 전송 / 어댑터 | RPC는 구조·UUID·응답 상관관계를 검사한다. MCPWireSender와 endpoint 입력은 이미 인증된 연결을 가정한다. | 인증된 initialize/version과 peer, 전체 바이트·invocation ID 결합, outer/inner 신원 일치, 별도 outer replay 및 연결 수명 |
| 복구 / 호스트 | durable ledger·단일 terminal·로컬 retire가 있다. 여러 worker/receiver의 소유권과 관리 복구는 별도다. | 공유 scope의 독점성, 재시작·lost-ledger 조정, baseline/policy rollout, UNKNOWN 재실행 금지, 이미 commit된 효과의 보존 |
| 실행 통제 / 호스트 | Component.Check/Commit은 신뢰된 instance 인계 지점이다. 라이브러리가 임의 호스트의 파일·네트워크·하위 프로세스 권한을 차단하지 않는다. | 호스트/로더 revision, 모든 보호 효과 경로 목록, plugin과 gate의 capability 분리, 동일 불변 instance와 의존성, bounded commitment |

위 항목은 모두 `INTEGRATION_NOT_VERIFIED`다. 이 표현은 코어 API가 없다는 뜻이
아니며, 선정된 운영 배포에서 결합된 경계의 증거가 없다는 뜻이다.

## Source → Authority 연결

[REG-05](../verification/0.10.0/snapshot/spec/09-registry.md)의 관측은 작업 시작 후,
최종 인가 gate 전 5초 이내의 신뢰된 단조 시각이어야 한다. 5초는 양성 cache TTL이
아니다. readiness는 재시작 후 다시 수립하고, record와 키는 같은 확정 블록에서
얻는다. 원격 `validated/finalized/ready` 플래그를 Source 검증으로 대체하지 않는다.
기존 [관측 증거 검사기](registry-source010.md)는 원문의 일관성만 검사한다.

어댑터는 `Gate.Select`/`select`로 정확한 issuer/keyid를 새로 선택하고, accepted·
active·unexpired Ed25519 material을 복사해 반환해야 한다. 세션에 고정한 키는
`CheckPinned`/`check_pinned`로 다시 읽어 확인하며 다른 키로 자동 대체하지 않는다.
Source와 Guard는 일관된 신뢰 시각을 사용하고 rollback·timeout·source 실패를
양성 응답이나 이전 키로 바꾸지 않는다. 저장 지연 후에도 freshness가 유지되어야 한다.

현재 Authority 반환값은 키 바이트이며 관측 시각이나 portable authorization token이
아니다. `ActiveKey`가 성공했다는 사실만으로 임의의 이후 실행을 허용할 수 없다.
실제 어댑터는 Guard의 재검사와 최종 인계 사이의 지연까지 유효성을 보장하거나
재관측/거부해야 한다. 이 결합은 controlled clock·느린 저장 seam 유닛 테스트와
실제 로컬 바인딩 실행으로 확인한 뒤 지원을 선언한다.

Go callback은 context를, Rust callback은 동기 Result를 사용한다. 인터페이스
호출만으로 강제 deadline이 생기지 않는다. 신뢰된 구현의 bounded I/O·취소·종료
계약과 lock 순서가 필요하며, 무한 callback을 그대로 둔 채 반환 후 시간을 검사하는
것은 timeout 집행이 아니다. gate 안에서 재진입하거나 untrusted tool을 장시간 실행하지 않는다.

## 전송 연결과 HTTP 경로의 구분

[EXEC-03/08](../verification/0.10.0/snapshot/profiles/agent-mcp-security.md)에 따라
transport 인증과 intent 인가는 별개다. endpoint의 expected UUID는 검증된 invocation
문맥에서 얻어야 하며, 수신 JSON의 id를 그대로 복사해서 인증했다고 할 수 없다.
외부 sender/recipient는 내부 issuer/recipient와 일치해야 한다. outer nonce/sequence,
inner Guard nonce, RPC ID를 같은 replay 공간으로 취급하지 않는다.

- 비HTTP MCP: `tools/call` → `sage_secure_call` → `arguments.envelope`의 exact intent를
  검증하고 인증된 peer·전체 RPC 바이트·UUID를 결합한다. 이 경로는 그 자체로 chapter 08
  WireTransport 적합성을 주장하지 않는다.
- HTTP carriage: chapter 08 인증 봉투의 decoded payload는 서명된 intent envelope다.
  현재 MCP RPC 전체를 이 payload로 바로 넣는 것으로 연결을 끝낼 수 없다. RPC ID,
  outer message ID, 본문과 응답을 연결하는 어댑터 매핑을 명시하고 기존 HTTP/Guard
  검증을 모두 유지해야 한다. 새로운 wire 필드가 필요하면 Inspector에서 발명하지 않고
  명세 검토로 되돌린다. 이번 문서는 그 매핑을 확정하거나 구현하지 않는다.

지원 MCP 버전은 현재 바인딩의 `2025-06-18`이며, 인증된 협상 결과를 사용한다.
한 세션의 endpoint를 새로 만들어 1024회 시도 이력을 초기화하지 않는다. reconnect와
재시작에는 outer replay 복구가 필요하고, Guard ledger는 같은 call의 재실행을 막는다.
pending은 invocation의 유일한 응답이며 새 ID poll도 기존 exact intent를 유지한다.
전송 오류를 authenticated rejected/completed로 변환하지 않는다.

## 호스트 집행과 침해 경계

원본은 untrusted 확장 전에 보호 영역에 캡처하고 승인한 policy/manifest만 설치한다.
요청이 제시한 digest는 승인 권한이 아니다. 해시는 비교할 바이트의 동일성을 검사하지만
승인 baseline 자체의 신뢰, 측정 이후 로딩 대상, 실제 실행 중인 코드를 증명하지 않는다.
측정한 불변 artifact instance와 전이 의존성을 실제 Commit까지 연결해야 한다.

hook·SDK middleware·proxy는 구현 선택이다. 어떤 선택이든 모델의 호출 여부와 무관하게
모든 보호 효과를 중재해야 한다. hook 누락·예외·disconnect·timeout·판정 부재는 거부하고,
전체 중재가 불가능한 호스트는 Execution Guard를 unsupported로 표시한다. confirmation을
끄는 설정이 verifier를 끄거나 보호 요청을 비보호 경로로 조용히 전환해서는 안 된다.

등록 이후 plugin/MCP가 변조되는 경우에도 보호된 원본·승인 baseline·gate·키 권한이
유지되는 범위에서 탐지·거부를 설계한다. 공격자가 이 신뢰 영역까지 모두 바꿀 수 있다면
서명이나 사전 등록만으로 원본 진실성을 복구할 수 없다. 최초 등록 이전 침해의 제외와
별개로 이 런타임 신뢰 경계도 명시한다. 이는 EXEC-09의 whole-host compromise 및
remote attestation 비보장과 일치하며, 사용자 승인을 매번 요구하는 해결책으로 대체하지 않는다.

## 검사와 후속 순서

```sh
python3 scripts/test_guard_integration.py
python3 scripts/test_guard_integration_runtime.py
python3 scripts/inspect_guard_integration.py --go-root ../sage --rust-root ../rs-sage-core \
  --output /tmp/new-guard-integration-review
# exit 3: contract PASS, deployment integration INCOMPLETE
```

core root를 생략하면 source identity는 `NOT_CHECKED`다. 제공하면 HEAD와 검토 파일의
원문 해시를 대조해 `SOURCE_IDENTITY_VERIFIED`로 기록한다. 이것은 core runtime PASS가
아니다. 잘못된 계약·해시·revision·출력 재사용은 종료 2이며, 기존 증거를 덮지 않는다.
새 디렉터리에 contract 원문과 report를 보존한다. CI는 pinned checkout으로 실행하고
별도 artifact를 보존한다. 유닛 테스트는 누락·중복·의존성·허위 승격을 거부하고,
CLI 런타임 테스트는 실제 로컬 프로세스의 종료·출력 보존만 검증한다.

다음 구현은 **registry Gate와 Guard Authority의 제한된 연결 및 freshness 검사**다.
신뢰된 test Source로 실제 코어 경로를 실행하되 live registry 인증으로 세지 않는다.
이후 선택한 MCP 전송의 신원/바이트/ID 연결, 보호된 capture/policy/loader, 복구와
전체 중재를 각각 구현·검증한다. 실제 배포 검증에는 선정된 네트워크·registry·신뢰할
source·호스트 버전·보호 경로 목록이 필요하다. 공격용 우회 프로그램은 만들지 않고,
부정 경로는 유닛 seam으로, 안전한 정상 서명 교환·복구는 로컬 런타임으로 검사한다.
37개 lifecycle은 해당 사례의 실제 연결·관측 증거가 생길 때만 개별 판정을 갱신한다.
