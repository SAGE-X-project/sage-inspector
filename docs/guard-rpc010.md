# MCP RPC boundary bindings

두 코어의 MCP 도구 입력·RPC 경계를 기존 dispatch/client API와 연결했다.
도구 descriptor의 이름은 `sage_secure_call`이고 입력은 필수 `envelope` 한 개,
`additionalProperties: false`다. 내부 intent와 proof도 closed object 구조다.
JSON Schema만으로 인가하지 않고 기존 서명·현재 키·정책·component 검사를 수행한다.

## 지원 계약

- 지원 협상 버전은 `2025-06-18`이다. 지원하지 않는 endpoint/sender 설정은 거부한다.
- 이 구현은 기존 durable client ID와 동일한 **UUID 문자열 JSON-RPC ID 부분집합**을
  지원한다. 숫자 ID나 일반 MCP의 다른 method까지 구현했다는 의미는 아니다.
- 호스트는 보호된 transport invocation에서 얻은 expected ID를 전달한다. 문서의
  ID를 무조건 복사해 전달하면 그 연결을 증명할 수 없다.
- `tools/call` → `sage_secure_call` → 단일 `envelope` 구조만 허용한다. 실제 대상
  도구·인자는 signed intent에서 얻는다. 알림·배치·직접 도구 호출·추가 필드·ID 불일치와
  recursive wrapping을 거부한다.
- endpoint는 실패를 포함해 세션 내 시도 ID를 소비한다. 1024개 이후에는 종료가
  필요하다. 같은 세션에서 객체를 새로 만들어 이력을 초기화하면 안 된다.
- 같은 call을 새 RPC ID로 조회해도 ledger는 그대로 사용하므로 새 실행이 발생하지 않는다.
- receipt는 endpoint·RPC ID와 기존 단일 응답 permit에 묶인다. pending 이후 같은
  invocation으로 terminal을 push하지 않는다. 새 client poll로만 조회한다.
- client sender는 실제 handoff 안에서 원본 intent를 RPC로 직렬화한다. 응답 ID 불일치,
  JSON-RPC error, 형식·서명 실패는 해당 invocation을 소비한 미인증 실패로 처리한다.
- wrapper 제한은 요청 2 MiB·응답 9 MiB이며 내부 Guard/MCP 제한은 원본 바이트에서
  별도로 적용한다. unsigned metadata는 소비하지 않고 거부한다.

## 검증

`guard-rpc.json`은 공개 독립 fixture로부터 요청 27개·응답 22개를 생성한다.
양 코어 유닛 테스트가 이를 실행하고, 동시 동일 ID·session 용량·foreign receipt·
단일 응답·close·protected sender handoff를 검사한다.

`scripts/test_guard_rpc010.py`는 실제 프로세스 **106개**를 실행한다.

- 두 코어에서 요청 사례 54개: invalid request의 도구 효과 0, 같은 ID 재사용 거부
- 두 코어에서 응답 사례 44개: 일치하는 호출에만 output 1회, 실패 후 토큰 재사용 거부
- 네 언어 조합의 client/server 프로세스 8개: 실제 RPC 요청 → pending → 완료 후
  새 ID poll → 단일 terminal 소비, 전체 도구 인계 1회

프로세스는 bounded JSONL IPC와 inert sink만 사용한다. 원본 입출력·종료 코드와
양쪽 journal을 **214개 파일**로 해시와 함께 보존한다. Node/OpenSSL로 실제 발행된
응답 및 저장된 terminal 서명 **16개**를 독립 검산한다. 오프라인 보고서 검사 6개는
잘못된 ID·도구·인자·매핑·미인증 출력·중복 전달·실제 전송 누락을 거부한다.

## 보증하지 않는 범위와 다음 작업

기존 primitive 및 lifecycle 보고서는 변경하지 않는다. 전체 lifecycle 37개는
NOT_RUN, 전체 적합성은 NOT_ESTABLISHED다. 이 보고서의 PASS는 위 API/IPC 검증
범위에만 해당한다.

호스트의 authenticated MCP initialize 협상·연결 수명 관리, 실제 보호 transport,
세션 간/재시작 replay 차단, 최신 registry Source와 승인 baseline, 모든 alternate
호출 경로의 차단과 불변 component 로더는 별도 통합 경계다. 이 라이브러리만으로
production MCP server나 host isolation을 인증하지 않는다.
다음은 **실제 Source·보호 transport·호스트 집행에 필요한 통합 계약과 지원 가능성
검토**, 이어서 검증 가능한 연결부터 lifecycle 실행 증거를 구축하는 작업이다.
