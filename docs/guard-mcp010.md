# Guard MCP result verification

두 코어가 명세의 MCP 결과 표현과 상태 매핑을 구현한다. 지원하는 협상 버전은
`2025-06-18`이며 미래 버전을 날짜 비교만으로 허용하지 않는다. 실제 협상의
인증·설정 단계 거부는 배포 호스트의 책임이다.

`structuredContent`와 단일 text block의 canonical JSON이 동일해야 한다.
중복 필드, 추가 블록·주석, 잘못된 `isError`, 지원하지 않는 버전을 거부한다.
wrapper는 JSON 문자열 이스케이프를 위해 8 MiB를 허용하지만 내부 envelope는
기존 1 MiB·depth 32·4096 members 제한을 그대로 적용한다. 원본 정수 검사를
canonicalization 전에 수행해 소수 반올림으로 timestamp 검사를 우회하지 못한다.

파싱 API는 인증되지 않은 바이트만 반환한다. 현재 키·시간·원래 intent와
outstanding invocation을 확인한 뒤에만 결과를 사용한다. client의 MCP acceptance는
형식·버전·서명 실패에도 해당 invocation을 소비하며, 첫 terminal 저장 후 output을
한 번만 전달한다. 인증된 snapshot은 재서명 없이 MCP 표현을 만들 수 있으나,
발행자의 응답 permit이나 수신자의 새로운 인증·소비를 대신하지 않는다.

| 상태 | isError | chapter 08 success | error |
|---|---|---|---|
| completed | false | true | 없음 |
| pending | true | false | unavailable |
| unknown | true | false | operation_failed |
| rejected | true | false | policy_denied |

오류 코드만으로 polling이나 실행을 승인하지 않는다.

## 실행 증거

`vectors/0.10.0/guard-mcp.json`은 기존 공개 독립 서명 fixture에서 구성한 32개
wire-level 사례다. 두 코어 유닛 테스트와 실제 Inspector adapter가 각각 실행한다.
크기 경계, client 소비 및 기존 16개 MCP 표현 벡터도 코어 유닛 테스트로 검사한다.
`scripts/test_guard_mcp010.py`는 실제 프로세스 88개를 실행한다:

- 두 코어 × 32개 인증/거부 사례: 64개
- 네 언어 조합 × 네 상태의 직렬화 결과 교환: 16개
- 두 코어 × 정상·표현 불일치·버전 거부·키 폐기 client 소비: 8개

원본 입력·출력·종료 코드와 client journal을 해시와 함께 새 디렉터리에 보존한다.
Node/OpenSSL은 공개 키로 24개 결과 서명을 별도 검산한다. 5개 오프라인 보고서
테스트는 잘못된 매핑·추가 주석·미인증 출력·다른 호출 ID를 거부한다.

기존 primitive 보고서 계약은 유지한다. 이전 `sage.guard.mcp.result` projection
operation은 이 adapter에 연결하지 않았으므로 해당 기존 집계는 86 PASS /
16 UNSUPPORTED다. 이번 실제 MCP 인증 실행은 별도 `sage.guard.mcp.verify` 경로와
`guard-mcp-bindings-*` artifact에서만 보고하며 과거 증거를 덮어쓰지 않는다.
이 차이는 코어의 MCP 지원 부재를 뜻하지 않는다. primitive 집계 통합은 별도
검토 대상으로 남긴다.

## 남은 경계

전체 lifecycle 37개는 계속 NOT_RUN이며 적합성은 NOT_ESTABLISHED다.
실제 MCP setup·`sage_secure_call` 입력 스키마·RPC 요청/응답 상관관계,
notification/batch 거부, executor의 unsigned direct-call 차단, 실제 Source,
완전한 host interception 및 보호된 transport의 결합은 이번 결과 codec 검증으로
증명하지 않는다. 다음 작업은 이 입력·RPC 경계를 기존 dispatch/client API에
연결하고 안전한 로컬 transport 테스트로 검증하는 것이다.
