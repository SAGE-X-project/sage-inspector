# Guard 서명 메시지와 실행 ledger 연결 계약

상태: **구현 인계 및 준비 상태 검사 완료**. 실제 Guard 코어 연결은 아직
`NOT_RUN`이며 전체 적합성은 `NOT_ESTABLISHED`다. 이 문서는 새 규범을 만들지
않으며 고정된 [Execution Guard 프로파일](../verification/0.10.0/snapshot/profiles/agent-mcp-security.md)
EXEC-02..08의 구현 경계를 정리한다.

## 소스 검토와 현재 지원 범위

| 코어 | 검토 revision | 확인한 API |
|---|---|---|
| Go | `6c46fadf5df748801c1868b94444327199225ed4` | `pkg/agent/execution010/ledger.go`: Open, Commit, Lookup, Close |
| Rust | `9fc5f044589929fc00b430219b1887af0946c7a4` | `src/execution010/mod.rs`: open, commit, lookup, close |

두 저장소의 Entry는 issuer, recipient, call_id, nonce, expires를 호출자가 공급하고,
intent_hex/result_hex는 크기·인코딩만 검사하는 opaque bytes다. Commit의 changed=true는
저장 성공이며 서명·인가·도구 실행 허가가 아니다. Lookup도 인증된 결과 조회가 아니다.
기존 completion010의 서명·registry gate는 핸드셰이크와 세션용이다. 그것을 그대로
사용했다는 이유로 다른 domain/schema인 Guard intent/result를 검증한 것으로 세지 않는다.
검토 파일의 해시는 [기계 판독 계약](../verification/0.10.0/guard-binding-contract.json)에
기록했다. 이 자료는 해당 revision의 소스 검토이며 현재 배포 코드나 런타임 증거가 아니다.

[기존 ledger 테스트](execution-ledger010.md)의 저장·복구 증거는 유효하다.
그 합성 바이트를 서명된 Guard 메시지의 검증 증거로 승격하지 않는다.

## 연결 순서와 소유 경계

아래 이름은 구현 역할이며 확정된 공개 API 이름이나 새 wire 필드가 아니다.

1. **Commitments와 신뢰 입력.** 원본 캡처, manifest, 정책 descriptor를 기존
   domain과 정확한 바이트로 검증한다. issuer/policy_digest 승인 매핑은 신뢰된
   관리자가 설치한다. 요청의 descriptor나 `approved=true`로 설치할 수 없다.
   시계, 요청별 활성 키 관측, 닫힌 tool schema, 정책 evaluator, 실제 로드 instance,
   signer와 ledger는 호스트가 제공하는 필수 신뢰 의존성이다. 누락·예외·시간 초과는 거부한다.
2. **Intent 검증.** 원시 입력의 UTF-8·중복 키·1 MiB/depth32/member4096 제한과
   닫힌 schema를 crypto 전에 확인한다. domain-separated JCS 서명, 활성 keyid/issuer,
   정확한 recipient, original/policy/manifest, tool 및 최종 arguments를 검사한다.
   created<=now+30, now<expires, expires-created<=300이며 equality에 유예가 없다.
   성공 결과는 exact JCS 전체 envelope와 해시·identity projection·arguments를
   불변으로 소유한다. 호출자가 직접 생성하거나 검증 이후 mutable map을 바꿔
   사용할 수 없게 한다. raw bytes/verified boolean을 받은 ledger wrapper로 대체하지 않는다.
3. **예약과 복구.** 저장 Entry의 identity와 intent_hex는 위 성공 결과에서만
   파생한다. `(issuer, call_id)`와 `(issuer, recipient, nonce)`를 기존 하나의 durable
   transaction으로 예약한다. proof까지 포함한 전체 JCS 바이트가 같아야 재조회다.
   다른 proof·인자·nonce를 새로 서명했어도 기존 호출을 교체하지 못한다.
   changed=false인 재시도는 dispatch로 내려가지 않는다. 재시작 UNKNOWN은 실행하거나
   COMPLETED로 바꾸지 않으며, lost ledger를 빈 ledger로 재생성하지 않는다.
4. **Dispatch gate.** 승인 정책의 retirement, component baseline 교체, 현재 identity,
   시각/expiry, 동일 immutable instance, 취소와 dispatch의 순서를 같은 gate에서
   결정한다. 긴 crypto/registry 호출 뒤 lock만 잡는 것으로 충분하지 않다. 최종 gate에서
   관측의 유효성과 정책 세대를 다시 검사하고 stale이면 다시 검증하거나 거부한다.
   실행할 arguments는 불변 소유 객체의 복사 또는 read-only view이며 unsigned defaults를
   추가하지 않는다. EXECUTING을 durable 저장한 뒤 정확히 한 번 effect 경계로 넘긴다.
   코어가 받는 dispatcher는 신뢰된 integration seam이며 문자열을 shell로 실행하지 않는다.
5. **결과와 Client.** 결과 서명은 result domain을 사용한다. intent_digest는 proof를
   포함한 전체 intent envelope의 JCS 해시다. status와 저장 상태가 일치해야 한다.
   첫 terminal envelope를 durable 저장한 후에만 응답하고 이후 byte-for-byte 재사용한다.
   Client는 outstanding invocation, executor/key, 시간, request/call ID와 intent_digest를
   검사한 뒤 한 번만 terminal을 소비한다. 늦은 pending은 이미 끝난 호출을 다시 열지 않는다.

이 순서는 구현 선행 관계다. 이미 저장된 결과를 읽는 호출도 현재 인증·정책과 intent
만료 검사를 먼저 거쳐야 한다. transport 인증·nonce와 Guard 인증·nonce는 별도 경계다.

## 반환 상태와 장애 처리

| 상황 | 필요한 동작 |
|---|---|
| malformed/서명 실패/현재 키 불가 | ledger 변경·dispatch·출력 소비 0; 인증되지 않은 실패 |
| absent이고 인증은 성공했으나 정책 거부 | signed rejected를 게시하려면 nonce와 REJECTED를 원자 저장; 실패하면 unverified failure |
| 기존 RESERVED/EXECUTING | 동일 envelope와 현재 접근 허가 확인 후 pending; 재예약·재실행 없음 |
| pending | 그 invocation의 유일한 응답, output={}; 완료를 두 번째 응답으로 push하지 않음 |
| 저장된 terminal이 만료되거나 키가 폐기됨 | 조회 실패; 재서명·시간 연장·상태 덮어쓰기 없음 |
| 이전에 수락한 invocation에서 intent 만료 후 결과 완성 | 독립 result freshness 검사; 만료 후 새 조회 허가와 구분 |
| signer 성공 뒤 storage 실패 | completed를 게시하지 않음; 외부 효과를 롤백했다고 주장하지 않음 |
| 복구 UNKNOWN에 서명 없음 | 도구 실행 없이 첫 unknown 결과만 저장; 나중에 completed로 교체 금지 |
| retire 먼저 / dispatch 먼저 | 전자는 효과 0; 후자는 이미 commit된 효과 보존, rollback 보장 없음 |
| lost ledger | scope 전체 retirement·새 durable mapping의 관리 증거 전까지 fail-closed |

최종 gate의 lock은 untrusted tool의 무제한 실행 동안 유지하는 설계가 아니다.
인가와 effect commitment의 선형화 지점 및 capability 수명은 호스트와 코어의 통합
계약에서 명시해야 한다. ledger와 외부 tool 사이의 crash window는 UNKNOWN으로
처리하며 외부 효과의 exactly-once를 약속하지 않는다.

## 고정 자료와 자동 준비 상태 보고

계약은 기존 102개 primitive와 37개/297단계 scenario를 선행 구현 역할에 한 번씩
배정한다. 배정은 주된 구현 소유자를 뜻하며 해당 case가 그 역할 전체를 증명하거나
다른 선행 검사를 생략할 수 있다는 뜻이 아니다. 기존 primitive의 부분 PASS도
새 Guard 연결의 PASS로 합산하지 않는다.

```sh
python3 scripts/test_guard_binding.py
python3 scripts/inspect_guard_binding.py --output /tmp/new-guard-binding-readiness
# exit 3: 계약 검사는 PASS, 실제 바인딩은 INCOMPLETE/NOT_RUN
```

검사기는 고정 profile/record/manifest/scenario 해시, 전체 사례 배정, 중복·누락,
선행 관계와 허위 runtime/PASS 승격을 검사한다. 보고서의 reviewed_cores는 소스
검토 이력이며 source hash를 실행 증거로 바꾸지 않는다. 실행 파일을 호출하거나
호스트 hook을 바꾸거나 도구를 실행하지 않는다. CLI 런타임 테스트 역시 이 검사기의
실제 실행·오류·출력 보존만 증명한다. 새 출력 디렉터리만 허용하며 과거 증거를 덮지 않는다.
CI는 검사 결과를 별도 artifact로 보존하고 INCOMPLETE 종료를 명시적으로 확인한다.

## 다음 실제 구현과 완료 기준

다음 구현 단위는 **두 코어의 Guard commitments 및 closed signed intent/result
검증 API와 Inspector primitive 연결**이다. 기존 `sage.guard.*` 사례 중 지원되는
연산을 실제 코어 호출로 바꾸고, 미지원은 그대로 남긴다. 그 다음 private verified
intent에서 ledger Entry를 만드는 bridge와 상태·정책·instance를 직렬화하는 gate를
연결한다. 안전한 로컬 dispatcher는 정확한 인자·instance·호출 수만 기록하는 test sink로
검증하며, 그것을 실제 MCP/Agent 호스트의 capability isolation으로 집계하지 않는다.

- 양성·재서명된 잘못된 binding·필드 누락/중복/범위·서명 실패와 시간 경계 검사
- 동일 호출·nonce 경쟁, policy retirement 순서, terminal 저장 장애는 제어된 unit seam
- 유효 서명 교환과 저장/재시작은 임시 파일·자신이 만든 프로세스의 실제 runtime
- snapshot 입력에 있는 active_key/policy_allow 플래그는 테스트 seam이며 운영 wire 권한이 아님
- malformed 입력과 우회 시나리오는 오프라인 unit 수준; 공격용 host bypass 실행 코드 제외

실제 validating Source 배포와 scope 복구 관리 절차, MCP/Agent의 완전한 경로 중재는
여전히 별도 의존성이다. 이번 인계 완료가 INS-11 전체 완료나 Guard 인증을 의미하지 않는다.
