# 다음 작업 목록 — SAGE Inspector 0.10.0

작성일: 2026-09-14. 상태: 계획 수립 완료, INS-01·INS-02·INS-03·INS-04·INS-05·INS-06·INS-07·INS-08·INS-09·INS-10의 Inspector 구현 완료. INS-11은 실제 레코드 교환 실행 및 호스트 시험 도구 준비 완료, 전체 프로토콜·호스트 연결 대기. 코어 적합성은 별도 판정한다.
구현 위치: `/Users/0xtopaz/work/github/sage-x-project/sage-inspector`.
규범 원본: `../sage-spec`; 실제 코어 변경은 별도 작업으로 관리한다.

## 현재 기준선

- 독립 기대값을 사용하는 기반 벡터 26개, 로더, 외부 프로세스 어댑터 계약,
  JSON 보고서, 독립 실행 명령 `sage-conformance` 구현 완료.
- 새 패키지의 race 테스트·vet 및 내장/예제 어댑터 실행 확인 완료.
- 예제 어댑터는 같은 참조 구현을 사용한다. 실제 Go·Rust 코어 검증 실적이 아니다.
- 명세의 386개 계획 사례와 기반 벡터 26개는 서로 다른 집계 단위다.
  `386 - 26`으로 남은 작업 수를 계산하거나 규범 그룹 전체 통과로 표시하지 않는다.
- 현재 전체 Go race 테스트·vet·빌드와 CI가 통과했다. 과거 의존성 문제는 당시 기록으로 보존한다.
  기존 코드 정비 자체를 이번 개발의 주목표로 삼지 않는다.

## 작업과 완료 기준

각 작업의 체크는 코드 존재가 아니라 완료 기준의 증거를 확보한 후 표시한다.
P0는 다음 개발의 선행 조건, P1은 핵심 검증 기능, P2는 통합·운영 증거다.

| 상태 | ID / 우선순위 | 작업 | 선행 조건 | 완료 기준 |
|---|---|---|---|---|
| [x] | INS-01 / P0 | 명세 스냅샷과 사례 추적 고정 | 없음 | 규범 파일·traceability 해시를 기록하고, 386개 계획 사례를 실행/문서 검토/배포 검토 대상으로 분류한다. 26개 벡터와의 관계를 부분 검증으로 매핑하며 연결되지 않은 항목을 누락 없이 표시한다. |
| [x] | INS-02 / P0 | 실제 Go·Rust 코어 어댑터 연결 및 기능 차이 조사 | INS-01 | 코어별 revision·지원 연산·오류 변환을 고정한다. 실제 코어 API를 호출한 보고서를 생성한다. 없는 기능은 UNSUPPORTED, 존재하지만 규범과 다르면 FAIL로 남긴다. 기대값을 읽거나 Inspector 구현으로 부족한 코어 기능을 대신하지 않는다. |
| [x] | INS-03 / P1 | JCS와 서명 검증 벡터 확장 | INS-01 | RFC8785 정렬·숫자·Unicode 및 SAGE 거부 조건을 분리한다. Ed25519의 엄격한 부분군/인코딩 조건과 선택적 P-256·secp256k1 조건에 양성·음성 고정 자료를 마련한다. 출처와 독립 계산/검토 근거를 기록하고 지원 어댑터에서 실행한다. |
| [x] | INS-04 / P1 | RFC9421 및 전송 메시지 검증 | INS-02, INS-03 | 요청/응답 서명 입력, Content-Digest, `;req`, 헤더/본문 일치, 정확한 요청 해시 연결, 크기와 변조 거부를 검사한다. 원시 HTTP 바이트와 기대 서명 입력을 독립 고정하고 입력 계약·통합 실행·규칙별 보고를 구현한다. 현재 코어 판정은 비교 기록하되 코어의 미지원 기능은 Inspector 완료의 선행 조건으로 두지 않고 후속 연결 대상으로 관리한다. |
| [x] | INS-05 / P0 | 상태를 유지하는 시나리오 어댑터 계약과 실행기 | INS-01 | 한 사례 안에서 여러 단계와 상태를 유지하며 가상 시간·레지스트리 관측·장애·동시성 조절을 지원한다. 단계별 입력/결과/효과 카운터와 제한 시간을 기록한다. 현재 사례당 새 프로세스 계약과 버전으로 구분하고, 단계 누락·중단을 성공으로 처리하지 않는다. |
| [x] | INS-06 / P1 | HPKE 조합의 독립 중간값 자료와 검토 | INS-03, INS-05 | B/info/exportCtx/exporter/ssE2E/T/th/prk/seed/ack/sid를 추적하는 고정 자료를 만든다. 검사 대상 코어와 다른 근거로 기대값을 확인한다. 변조·역할 교체·0 공유값·잘못된 확인 메시지를 다룬다. 비밀성/인증/침해 시점 분석은 벡터 통과와 별도 기록한다. |
| [x] | INS-07 / P1 | 세션 수명·재전송·동시성 검증 | INS-02, INS-05, INS-06 | 방향별 키/시퀀스, 세대 경계, 1000개 상한, AAD 4033/4034 경계, 고정 DID·키, 임시 세션 확인, 만료·재시작·중복을 시험한다. 잘못된 레코드는 상태를 전진시키지 않고 중복은 한 번만 수락함을 관측한다. |
| [x] | INS-08 / P1 | DID·Card·레지스트리 관측 검증 | INS-02, INS-03, INS-05 | 통제된 권위 있는 관측 자료로 PoP/endorsement, 활성·폐기·만료, 버전 후퇴, stale 상태와 조회 실패를 시험한다. 비활성 DID 조회 성공과 인증 거부를 구분한다. 실제 체인 적합성은 명시적 배포 바인딩이 있을 때만 별도 판정한다. |
| [x] | INS-09 / P1 | Execution Guard 실행·결과·복구 검증 | INS-04, INS-05, INS-08 | 원본 연결, 정책 epoch/폐기, manifest와 실제 로드 대상, 실행 ledger를 검증한다. pending→terminal, 늦은 pending, 충돌 결과, 동일 요청 재조회, UNKNOWN, 거부/예약 경합에서 실제 dispatch 횟수·인자를 기록한다. CST-01..05 보완 사례를 포함한다. |
| [x] | INS-10 / P2 | CI 및 커버리지·증거 보고서 통합 | 최소 CI는 INS-01 후, 통합 판정은 INS-02..09 후 | 기반 테스트를 재현 가능한 환경에서 실행한다. 요구사항→사례→관측 결과를 연결하고 미실행/미지원/부분 검증을 표시한다. 주체 revision·명세/벡터 해시·실행 환경·효과 증거를 보존하며 부족한 증거로 전체 적합성 PASS를 만들지 않는다. |
| [ ] | INS-11 / P2 | 실제 호스트 우회 시험과 양방향 상호운용 | INS-04, INS-06..10 및 코어/호스트 준비 | Go→Rust·Rust→Go 교환과 고정 호스트 버전의 hook 누락/timeout/direct call/하위 프로세스/파일·네트워크 우회를 관측한다. 호스트 격리 증거가 없으면 Execution Guard 인증을 부여하지 않는다. |

## 권장 착수 묶음

첫 번째 묶음은 **INS-01 → INS-02**, 그리고 INS-01을 기준으로 한 **INS-05 계약 설계**다.
CI의 기반 테스트 등록도 이 시점부터 진행할 수 있다. 이렇게 하면 실제 코어의
지원 범위와 필요한 상태 시험 인터페이스를 먼저 확인한 뒤 벡터를 확장할 수 있다.

두 번째 묶음은 INS-03과 INS-04, INS-06이다. INS-08의 통제된 관측 자료는
INS-05 이후 별도로 준비할 수 있다. 이후 INS-07과 INS-09를 수행하고,
INS-10 통합 보고서와 INS-11 실제 환경 검증으로 마무리한다.

## 작업별 공통 원칙

1. 기대 결과는 대상 코어와 별도 출처/계산에서 정하고 출처를 고정한다.
2. 규범에 답이 없으면 Inspector에서 임의로 정하지 않고 sage-spec 이슈로 되돌린다.
3. 어댑터는 코어 호출과 오류 변환을 맡는다. 코어의 미구현 보안 기능을 숨기지 않는다.
4. 새 벡터·어댑터·보고서 변경에는 양성·음성·오류 경로 검증을 붙인다.
5. 정책/세션 상태 관측과 실제 외부 효과를 구분한다. 테스트 더블의 결과를 실제
   호스트 격리나 실제 체인 보안 증거로 표시하지 않는다.
6. 증거 수집 도구를 만드는 것과 전체 보안성을 승인하는 것은 별도 단계다.

## 범위 밖 후속 작업

코어의 0.10.0 미지원 기능 구현, SDK, 등록·조회 MCP 서비스, 비교 데모,
저장소의 실제 분리는 관련 저장소에서 별도 계획으로 진행한다. INS-02에서
발견한 코어 차이는 해당 소유 작업으로 연결하며 Inspector 계획에 감춰 넣지 않는다.
기존 전체 테스트 의존성 문제도 별도 환경/호환성 항목으로 추적한다.

참고: [현재 기반 검증 기록](foundation-verification.md),
[벡터·어댑터·보고서 계약](conformance.md),
[명세의 Inspector 검증 계획](../../sage-spec/verification/inspector-plan.md).

INS-01 완료 증거: [명세 기준선 및 사례 추적표](spec-baseline.md).

INS-02 완료 증거: [실제 코어 어댑터와 차이 보고서](core-adapters.md).

INS-05 완료 증거: [상태 유지 시나리오 계약과 검증](stateful-scenarios.md). 실제 코어의 상태 제어 바인딩은 INS-06..09에서 구현한다.

INS-03 완료 증거: [JCS 및 서명 검증 벡터와 관측](jcs-signature-vectors.md).

INS-04 완료 증거: [HTTP inspection 실행과 후속 코어 연결](http-inspection.md).
스펙 기준의 134개 사례, 독립 검산, 바이트를 보존하는 입력 계약, 통합 실행과
규칙별 보고를 구현했다. 현재 Go/Rust의 미지원·실패는 그대로 유지하며,
코어 구현 완료 후 어댑터를 연결하고 고정 자료를 다시 실행한다.
정확한 필드 크기 계산 기준은 조건부 사례로 명시하며 스펙 확정 후 다듬는다.
이는 사용자 지시에 따른 **Inspector 선구현 완료**이며 코어 적합성 승인과 다르다.

INS-06 완료 증거: [HPKE inspection](hpke-inspection.md), [암호 구성·침해 시점 검토](hpke-security-review.md). 독립 중간값 및 변조 67개 사례와 상태 시나리오 6개를 준비했다. 코어별 API 차이와 미지원/미실행을 보존하며, 실제 상태 연결과 보안 보증은 별도 후속 항목이다. 다음 항목은 INS-11의 실제 호스트·상호운용 연결이다.

INS-07 완료 증거: [세션 inspection](session-inspection.md). 55개 독립 레코드/키 사례와 37개 상태 시나리오(248단계), 규칙·해시 추적 및 실행/보고를 준비했다. 두 코어는 각각 11 PASS·26 FAIL·18 UNSUPPORTED이고 상태 시나리오는 37 NOT_RUN이다. Inspector 선구현 완료와 실제 코어·동시성 검증 완료를 구분한다.

INS-08 완료 증거: [레지스트리·DID·Card inspection](registry-inspection.md). 독립 사례 94개와 상태 시나리오 17개(83단계), 실제 DID/PoP/서명 API 연결, 규칙별 보고 및 독립 검산을 준비했다. 두 코어 각각 23 PASS·8 FAIL·63 UNSUPPORTED이며 실제 권위 관측 바인딩은 17 NOT_RUN이다. 배포·체인 보증과 Inspector 선구현 완료를 구분한다.

INS-09 완료 증거: [Execution Guard inspection](guard-inspection.md). 독립 사례 102개, 상태 시나리오 37개(297단계), 정확한 인자·실행 인스턴스·효과 카운터 계약, CST-01..05 자료 연결과 보고를 준비했다. 두 코어는 각각 8 PASS·94 UNSUPPORTED이며 Guard 상태는 37 NOT_RUN이다. 실제 Guard/호스트 격리 검증 완료와 구분한다.

INS-10 완료 증거: [통합 증거·커버리지 및 CI](evidence-integration.md). 코어별 525개 원시 관측, 97개 상태 시나리오(648단계), 45개 요구사항·77개 규칙·386개 계획 사례를 해시로 연결한다. CI는 통합 보고서 재현·변조 거부와 참조 기반 실행을 확인하고 원시 증거를 보존한다. 코어 FAIL/UNSUPPORTED와 상태 NOT_RUN을 유지하며 전체 적합성을 승인하지 않는다.

INS-11 진행 증거: [실제 교환 및 호스트 inspection](deployment-inspection.md).
Go→Rust·Rust→Go의 c2s/s2c 레코드 교환을 실행했다. 28 PASS·4 UNSUPPORTED이며,
transcript 바인딩 API 미지원을 숨기지 않는다. 호스트 우회 8개 시나리오(40단계)와
외부 관측 도구를 연결하는 실행·보고 계약을 준비했지만 실제 호스트가 지정되지 않아
8 NOT_RUN이다. INS-11 전체 완료로 표시하지 않는다.

### 현재 유닛 중심 작업 목록

사용자의 최신 지시에 따라 유닛 테스트 중심으로 개발하며 안전한 런타임 경로도 구현·검증한다.
공격 기능이 될 수 있는 취약점 재현과 실제 호스트 우회는 제외한다. 이번 작업에 시뮬레이터 제작은 필요하지 않다.
[검증 범위와 만료 단위 테스트](unit-test-verification.md)를 따른다.

| 상태 | 순서 | 작업 |
|---|---|---|
| [x] | 1 | 단위 테스트 중심 검증 범위를 문서와 저장소 작업 규칙에 반영하고 과거 실측을 구분 |
| [x] | 2 | 기존 만료 시나리오의 직전·경계·직후, 부수 효과, 임시 세션 처리 중 만료 및 보고서 판정 단위 테스트 보완 |
| [x] | 3 | 재시작·복구의 기대 동작·판정 단위 테스트 및 실제 CLI의 고정 응답·중단·오류·미지원 런타임 테스트 |
| [x] | 4 | 종료·수신 순서: 고정된 순서의 상태·효과·단계 상관관계 단위 테스트와 CLI 런타임 판정 검증 |
| [x] | 5 | transcript·HPKE 확인·HTTP/WS 연결의 고정 기대값 및 CLI 판정 테스트. 실제 전송·코어 바인딩과 분리 |
| [x] | 6 | Guard 방어: hook 누락·시간 초과·검증 실패의 실행 차단 및 오류 보고 테스트 |
| [x] | 7 | 단위 테스트 커버리지 정리 및 실제 코어 증거와 분리한 CI·보고서 갱신 |

이번 만료 테스트는 Inspector 판정과 고정 기대값의 검증이다. 실제 코어 만료
검증 완료로 표시하지 않으며, 기존 코어 FAIL/UNSUPPORTED와 상태 NOT_RUN을 유지한다.

### 후속 범위로 남긴 실제 연결

1. transcript 바인딩을 지원하는 코어 API 연결.
2. 완성된 0.10.0 HPKE 확인 및 HTTP/WS 양방향 교환.
3. 실제 만료·재시작 복구 및 개선된 종료·수신 계약의 검증.
4. 고정 Agent 호스트와 신뢰할 수 있는 외부 관측 도구를 사용하는 배포 검증.
5. 실제 실행 증거를 갖춘 이후 INS-11 및 배포 적합성 판정.

아래 기록은 과거 실측이며 현재 실행 계획이 아니다.

INS-11 추가 실측: [상태 유지 재전송·종료 검사](replay-inspection.md). Go↔Rust c2s/s2c 네 조합에서 같은 수신 세션에 9개 동작을 전달하여 36 PASS를 관측했고, 종료 대상 레코드의 활성 세션 양성 대조군 4개도 PASS다. 검증 도구에 재전송 필터를 구현하지 않았으며 실제 코어 판정을 기록했다. 만료·재시작·동시 경합·전체 0.10.0 및 호스트 검증 완료를 뜻하지 않는다.

INS-11 동시 경합 실측: [동시 코어 교환 검사](concurrent-inspection.md). Go↔Rust의 네 방향 조합을 각 8회 실행하여 224 PASS, 512개 작업자 결과를 관측했다. 64개 경합 그룹 모두 API 호출 구간이 중첩되었으며 유효 레코드당 한 번만 수락했다. Go race detector 실행에서도 오류가 보고되지 않았다. 전체 스케줄 증명이나 만료·복구·종료 경합·호스트 검증 완료를 의미하지 않는다.

INS-11 종료 경합 진단: [수신·종료 경합 검사](close-race-inspection.md). Go 순차 대조군 두 방향은 PASS이며, 병행 종료에서는 실제 race detector가 데이터 경합과 종료 코드 66을 기록했다. Rust는 배타 참조를 요구하는 close API 때문에 직접 병행 종료 바인딩이 UNSUPPORTED다. 실패 원문을 통합 증거에 보존하며 코어 수정과 전체 적합성 승인은 수행하지 않았다.

재시작·복구 검증: [단위·런타임 테스트](recovery-verification.md). 기존 시나리오 6개의 기대값과 보고서 판정을 단위 테스트하고, 실제 CLI에 고정 응답 프로세스를 연결하여 6개 런타임 경로를 확인한다. 코어의 저장·복구 구현이 실행된 것으로 집계하지 않는다.

종료·수신 순서 검증: [순서 기반 종료 테스트](session-close-order.md). 단위 테스트 5개와 CLI 런타임 18개 경로를 추가했다. 실제 동시 경합이나 코어의 종료 구현을 검증한 것으로 집계하지 않는다. 다음은 transcript·HPKE·HTTP/WS 연결의 판정 테스트다.

프로토콜 연결 판정 검증: [단위·런타임 테스트](protocol-binding-verification.md). 단위 테스트 6개와 CLI 경로 26개를 추가했다. WS는 테스트 전용 신뢰 경계 관측이며 실제 소켓·TLS·재조립 검증이 아니다. 다음은 Guard 실행 차단 및 오류 보고 판정 테스트다.

Guard 차단 판정 검증: [단위·런타임 테스트](guard-gate-verification.md). 단위 테스트 6개와 CLI 경로 37개를 추가했다. 실제 hook·호스트 방어를 실행한 결과가 아니다. 다음은 테스트 커버리지와 CI·보고서 정리다.

테스트 커버리지·CI 보고서 정리: [검증 항목과 실행 보고서](verification-test-coverage.md). 현재 유닛 중심 7개 작업을 완료했다. 실제 코어·호스트 연결은 위 후속 범위에 남으며 INS-11 전체 완료를 뜻하지 않는다.

실제 연결 선행 검토(2026-09-16): [Transcript 세션 연결 인계](core-binding-handoff.md). 두 코어의 revision과 고정 소스는 동일하며 현재 세션 API에 th 입력이 없다. 다음 실행 항목은 코어 API 제공 후 어댑터 연결과 bound 정상 대조군 추가다. 코어 구현은 별도 저장소 작업으로 유지한다.

0.10.0 레코드 연결: [새 코어 어댑터와 정상 대조군](record010-bindings.md). 코어별 독립 레코드 37개, 동일 API의 양방향 정상·transcript 거부 대조군과 제어 오류를 검증한다. 상태 유지 및 인증 tuple·registry 연결은 후속 항목이다.

0.10.0 상태 유지 레코드 연결: [실행 계약과 검증](record010-state-bindings.md). 코어별 14개 실제 세션 시나리오와 네 미지원 제어, 총 12개 입력 오류 경로를 검증한다. 다음은 인증 tuple·레지스트리·HPKE 확인 및 관측 API의 코어 지원 여부를 확인하고 필요한 연결 계약을 준비하는 작업이다.

인증 세션 연결 선행 검토: [코어 지원과 연결 계약](authenticated-session-handoff.md). 두 코어의 레코드 API와 v1 HPKE·resolver 경로를 대조했다. 인증 tuple, 요청별 권위 관측, 임시 응답자의 원자적 확인은 별도 코어 계약이 필요하다. 다음 실행 항목은 두 코어의 0.10.0 HPKE 파생 API와 독립 벡터·Inspector 연결이며 전체 핸드셰이크 완료로 집계하지 않는다.

0.10.0 HPKE seed·ACK 연결: [코어 API와 실행 검증](hpke010-bindings.md). 두 코어에 별도 combiner·ACK 생성·상수 시간 ACK 비교 API를 구현하고 코어별 실제 호출 152개 및 제어 오류 30개를 검증했다. 파생 작업 중 다음은 닫힌 B/T, 도메인 바인딩, RFC9180 exporter와 양쪽 E2E DH를 묶는 경로다. 전체 파생·인증 완료·레지스트리 및 pending 연결은 아직 완료로 표시하지 않는다.

0.10.0 전체 암호 파생 연결: [B/T·도메인·HPKE/DH 연결과 검증](hpke-derivation010.md). 두 코어의 파생 경로, 60개 벡터씩의 유닛·런타임 검사와 네 코어 조합 20개 교환 및 12개 제어 오류 경로를 연결했다. 다음은 REG-05 요청별 권위 관측과 고정 키 선택이다. 최신 지시에 따라 공격에 활용 가능한 재현 코드를 제외하고 변경 동작의 유닛 테스트와 런타임 테스트를 모두 구현·실행한다. 전체 인증 핸드셰이크 완료와는 구분한다.

0.10.0 요청별 권위 관측·고정 키 연결: [코어 경계와 영속 재시작 검증](registry010-bindings.md).
두 코어의 새 관측·정확한 서명/KEM 선택·고정 키 재검증·영속 버전/폐기 저널을 구현했다.
코어별 39개/107단계 단위·런타임 시나리오, 8개 실제 프로세스 재시작 조합과 22개
제어 경로를 연결했다. 다음은 인증 tuple, 서명된 완료와 pending 수명을 연결하는 작업이다.
실제 validating Source·체인 최종성 측정·세션 종료/dispatch 연결은 남아 있으며
REG-05 배포 검증이나 전체 인증 핸드셰이크 완료로 집계하지 않는다.

0.10.0 인증 완료·pending 연결: [서명·고정 tuple·수명 검증](completion010-bindings.md).
두 코어가 실제 서명된 요청·응답·완료, 원본 요청 해시, 고정 키와 ACK를 검증한 후
private seed/tuple 소유 결과를 생성하도록 연결했다. 코어별 완료 36개·추가 수명 8개,
네 프로세스 조합의 완료 144개·수명 32개·입력 오류 8개를 검증한다. 최종 저장 중
고정 키가 만료되는 경계도 포함한다. 다음은 **tuple 기반 레코드 수신과 응답자 첫
레코드의 원자적 replay/sequence 예약·확정 연결**이다. 일반 WireTransport의 선택
필드·HTTP/TLS·영속 replay/재시작 quarantine 및 배포 registry는 아직 완료하지 않았다.

0.10.0 인증 레코드 연결: [tuple 수신과 원자적 확인](authenticated-record010-bindings.md).
두 코어의 private 레코드 소유, 서명·tuple·현재 키·AEAD 검증 및 트랜잭션 저장소
최종 gate를 통해 순서/응답자 확인을 직렬화한다. 공통 32개 사례와 네 프로세스
조합의 128개 검사를 연결하며, application 인가·영속 저장소의 배포 증거는 별도다.
다음은 **session 응답의 request_hash/message_id 연결 및 양방향 응답 계약**이다.
HTTP/WS·quarantine·실제 Source와 호스트 검증은 이후 범위로 유지한다.

0.10.0 session 응답 연결: [원본 요청 및 terminal 검증](session-response010-bindings.md).
실제 보관 요청에서 message_id/request_hash를 검증하고 양쪽 역할의 성공/오류
응답을 한 번만 생성·수락한다. 공통 38개 사례와 네 코어 조합의 152개 실제 검사를
추가한다. 다음은 **RFC9421 기반 HTTP 요청·응답 바인딩**이며, TLS/WS·영속 저장소·
quarantine 및 실제 Source/호스트 검증은 별도 후속 범위다.

0.10.0 HTTP session 바인딩: [HTTP 서명 및 단일 승인 검증](http-session010-bindings.md).
두 코어에 canonical HTTPS POST session 요청·응답 서명과 보관 요청의 `;req` 연결,
HTTP 전용 세션의 bare API 차단을 구현했다. 공통 45개 유닛 시나리오와 추가 크기·
파라미터 경계, 독립 검산 5개 및 네 코어 조합의 180개 프로세스 시나리오를 연결한다.
이 기록은 세션 메시지의 제한된 HTTP 서명 프로파일이며 **전체 RFC9421/HTTP 완료가
아니다**. 다음 작업은 **실제 전송 메타데이터·중복 헤더를 보존하는 HTTP/TLS 연결과
핸드셰이크 HTTP 바인딩**, canonical 외 Structured Fields/URI 지원 범위 검토다.
WS·영속 replay/quarantine·실제 Source·호스트 검증은 계속 후속 범위로 유지한다.

0.10.0 HTTP 핸드셰이크·TLS 연결: [실제 바이트 및 인증 TLS 검증](http-handshake010-bindings.md).
두 코어의 핸드셰이크에 HTTP 서명·원본 요청 연결·단일 replay 예약을 적용하고,
엄격한 HTTP/1.1 코덱으로 원시 헤더와 길이·대상 주소를 검증한다. 공통 핸드셰이크
22개, 오프라인 프레이밍 거부 24개와 크기 경계, 프로세스 88개 및 실제 루프백 TLS
16개 검사를 연결했다. TLS는 Python/OpenSSL 기반의 통제된 전송 환경이며 실제
코어 파싱·암호 처리를 호출한다. 운영 Go/Rust TLS 서비스나 전체 HTTP 지원 완료로
표시하지 않는다. 다음은 **Structured Fields·URI의 표준 직렬화 지원 범위 확장과
독립 RFC 벡터 연결**이다. WS·영속 replay/quarantine·실제 Source·호스트는 후속 범위다.


0.10.0 HTTP 직렬화 상호운용성: [공통 벡터와 독립 RFC 검산](http-serialization010.md).
두 코어에서 Signature-Input의 표준 SP와 명시적 req=true를 직렬화하고, 수신된
파라미터 순서와 URI 원문을 보존한다. 공통 SF 34개·URI 17개, 실제 코어 조합
204개와 공개 RFC Ed25519 예제의 독립 검산을 연결한다. 일반 SF 타입·이스케이프
문자열·비정규 정수 및 일반 URI 정규화는 지원 완료로 표시하지 않는다.
다음은 **WebSocket 바인딩 계약과 안전한 실제 런타임 검증**이며, 영속 replay/
quarantine·배포 Source·호스트 검증은 이후 범위다.


0.10.0 WebSocket 바인딩: [계약과 실제 WSS 검증](websocket010-bindings.md).
Inspector의 wsproto/OpenSSL 전송 환경에 기존 두 코어의 envelope API를 연결했다.
오프라인 유닛 테스트 17개와 네 코어 조합의 실제 WSS 시나리오 32개로 텍스트
재조립·Ping/Pong·양방향 서명 메시지·오류 응답·종료·TLS 인증 실패를 검증한다.
잘못된 프레임은 오프라인에서만 처리하며, 운영 Go/Rust WS 서비스나 기존 WS 구현
검증으로 집계하지 않는다. 다음은 **영속 replay 저장 및 재시작 quarantine 계약과
안전한 유닛·런타임 검증**이다. 배포 Source·체인 최종성·호스트 집행은 이후 범위다.


0.10.0 영속 replay·quarantine: [저장 계약과 실제 복구 검증](durable-replay010.md).
두 코어에 Linux/macOS 영속 차단 저널, UTC·단조 시계 모두 360초 격리, 정상 복구와
시계 역행·부분 기록·중복 작성자 차단을 구현했다. 최종 gate 실패 시 수락·평문은
공개하지 않되 durable denial은 유지하는 보수적 계약을 명시한다. 코어 공통 12개/
53단계 및 실제 암호 세션 테스트, Inspector의 실제 프로세스 24개와 언어 간 복구
20개를 연결한다. 하드웨어 전원 장애·악의적 디스크 롤백·운영 저장소 적합성은
입증하지 않는다. 다음은 **배포 registry Source·체인 최종성 관측 계약과 검증**이며,
불가피한 호스트 집행·운영 통합·별도 실행 ledger 복구는 후속 범위다.


0.10.0 배포 Source 증거 계약: [설정·관측·지연 검사](registry-source010.md).
Inspector에 닫힌 배포 설정과 원문 해시를 연결한 관측 입력, 재시작 readiness·
확정 블록/버전 후퇴·혼합 블록 거부 및 지연 누락의 NOT_RUN 처리를 구현했다.
유닛 및 실제 로컬 CLI 계약 테스트를 CI에 연결했다. 이는 **증거 계약 구현 완료**이며
실제 validating Source·RPC·전체 record/PoP·배포 체인 측정은 아직 NOT_RUN이다.
다음은 지정된 배포 바인딩/신뢰 관측기 기반 Source 연결이다. 배포 자료가 없으면
독립적으로 진행 가능한 **execution ledger 복구 계약·안전한 검증**을 먼저 수행한다.


0.10.0 execution ledger 저장·복구: [실제 코어 및 언어 간 검증](execution-ledger010.md).
두 코어에 별도 durable call/nonce 예약·terminal 원문 보존·재시작 UNKNOWN 복구를
구현했다. 공통 14개/72단계, 프로세스 28개·복구 20개·파일 제어 6개를 연결한다.
이는 **저장 기반 완료**이며 signed intent/result·현재 정책·component·실제 dispatch
및 scope 전체 lost-ledger epoch 복구는 아직 통합되지 않았다. 다음은 **Guard의
canonical signed intent/result와 ledger 연결 및 dispatch gate 계약**이다.
배포 Source 지정과 실제 호스트 집행은 계속 별도 의존성으로 남는다.


0.10.0 Guard 연결 선행 계약: [서명·ledger·dispatch 구현 인계](guard-binding-handoff.md).
고정 profile과 두 코어 저장/핸드셰이크 경계를 검토하고 102개 primitive와 37개/297단계
scenario를 commitments→intent→ledger→dispatch→result 구현 역할에 연결했다.
기계 판독 계약·누락/승격 거부 검사 및 실제 검사 CLI의 출력 보존을 검증했다.
이는 **계약/준비 상태 검사 완료**이며 실제 Guard 바인딩은 모두 NOT_RUN이다.
다음 구현은 두 코어의 **commitments 및 closed signed intent/result 검증 API와
Inspector primitive 연결**이고, 그 뒤 private 검증 결과의 ledger bridge와 최종 gate다.


0.10.0 Guard primitive 실제 연결: [코어 API와 독립 벡터 실행](guard-primitives010.md).
두 코어의 commitment·엄격 JSON·closed signed intent/result API에 Inspector를 연결했다.
각 코어 86 PASS/16 UNSUPPORTED이며 37개/297단계 lifecycle은 NOT_RUN이다.
앞선 readiness 문서는 당시 revision의 이력으로 유지하며, 새 실행 증거와 합산하지 않는다.
다음은 **private verified intent → ledger bridge와 원자 예약/재조회**, 이어서
정책·component instance·최종 dispatch gate 직렬화다. MCP mapping과 client terminal
소비, 실제 Source와 호스트 집행은 별도 미완료 범위다.


0.10.0 Guard 원자 예약 연결: [검증된 intent와 영속 ledger](guard-reservations010.md).
두 코어의 private 검증 결과에서 저장 필드를 도출하고, 현재 키·정책·시각을 매번
검증하여 원자 예약/재조회를 구현했다. 유닛 테스트와 실제 프로세스 16개, 네 언어
조합의 재시작 UNKNOWN 보존을 검증한다. 기존 37개 lifecycle은 계속 NOT_RUN이며
전체 적합성은 NOT_ESTABLISHED다. 다음은 **정책 retirement·component instance와
최종 dispatch gate 직렬화**이고, signed pending/terminal 발행·client 단일 소비 및
MCP mapping·실제 Source·호스트 집행은 후속 범위다.


0.10.0 최종 dispatch gate 연결: [현재 인가와 실행 인계 직렬화](guard-dispatch010.md).
두 코어에서 정책 폐기·component 교체·검증·영속 EXECUTING·bounded 인계를 같은
gate에 연결했다. 최종 키/정책/시각/component 검사 실패와 인계 불확실성은 UNKNOWN
또는 저장소 불가로 처리하며 재실행하지 않는다. 유닛 경합 테스트와 실제 프로세스
30개(시나리오 20개, 네 언어 조합 복구 8개, missing 제어 2개)를 연결했다. 실제
불변 로더·분산/재시작 retirement·호스트 격리는 배포 통합 경계이며, 37개 lifecycle과
전체 적합성은 계속 NOT_RUN/NOT_ESTABLISHED다. 다음은 **signed pending/terminal
발행과 첫 terminal 원문 영속 저장**, 이어서 **client 단일 소비와 MCP mapping**이다.


0.10.0 Guard signed 결과 발행: [첫 terminal 저장과 호출별 응답](guard-results010.md).
두 코어에 gate 소유 completion token, 호출당 단일 응답 권한, 첫 signed terminal의
원자 저장과 원문 재사용을 구현했다. 유닛 테스트 및 실제 프로세스 44개, 네 언어
조합의 completed/rejected/unknown 복구와 독립 서명 검산 102개를 연결한다.
만료·폐기 결과는 재서명하지 않으며 pending 이후 같은 호출로 terminal을 보내지 않는다.
37개 lifecycle과 전체 적합성은 계속 NOT_RUN/NOT_ESTABLISHED다.
다음은 **client terminal 단일 소비와 polling 계약**, 이어서 **MCP result mapping**이다.


0.10.0 Guard client 소비·polling: [단일 terminal 소비와 영속 재시작](guard-client010.md).
두 코어가 첫 terminal을 저장한 뒤 output을 한 번만 반환하며, 늦은 pending·동일
terminal은 무시하고 충돌 terminal은 거부한다. 보호된 전송 인계를 직렬화하고
UTC·단조 시계의 1초 간격, 만료·폐기·실패 후 동일 원본 재조회를 검증한다.
코어별 독립 19개 시나리오와 추가 유닛 검사, 실제 프로세스 64개 및 네 언어 조합의
서버 결과 교환·client 저장소 복구를 연결했다. 저장 후 전달 전 장애는 재전달 대신
보호된 조정이 필요하며, 배포 호스트·전송 보호를 보증하지 않는다.
다음은 **MCP result mapping 및 표현 일치·버전 검사**다. 전체 lifecycle 37개와
적합성은 계속 NOT_RUN/NOT_ESTABLISHED로 유지한다.


0.10.0 MCP 결과 연결: [표현·매핑·버전 및 실제 인증](guard-mcp010.md).
두 코어에 strict 결과 codec, 인증된 snapshot의 상태 매핑 및 client 단일 소비를
연결했다. 독립 32개 사례·실제 프로세스 88개·독립 서명 24개를 별도 보고한다.
기존 primitive 집계는 그대로 유지하며 전체 37개 lifecycle과 적합성은
NOT_RUN/NOT_ESTABLISHED다. 다음은 **MCP 입력 스키마·RPC 경계와 dispatch/client
연결**, 이어서 실제 Source와 호스트 집행의 통합이다.


0.10.0 MCP RPC 경계 연결: [입력·호출 ID·dispatch와 client](guard-rpc010.md).
두 코어의 closed 도구 schema와 UUID RPC binding을 기존 gate·durable client에
연결했다. 요청 27개·응답 22개, 실제 프로세스 106개와 네 언어 조합 교환·서명
16개를 검증한다. 원본 효과·저장소·응답 증거를 별도 artifact로 보존하며 전체
37개 lifecycle과 적합성은 NOT_RUN/NOT_ESTABLISHED로 유지한다. 다음은 **실제
Source·보호 transport·호스트 집행 통합 계약과 지원 가능성 검토**이고, 이후
검증 가능한 연결부터 lifecycle 증거를 구축한다.


0.10.0 Guard 배포 통합 계약: [Source·전송·호스트의 책임과 증거](guard-integration010.md).
현재 두 코어 revision의 12개 API 소스와 규범 3개를 고정해 여섯 통합 경계를 검토했다.
검사기는 소스 식별과 계약의 무결성만 확인하며 배포 지원을 자동 인증하지 않는다.
HTTP intent payload와 MCP RPC 전체 메시지의 매핑을 별도 미결 경계로 명시했다.
계약 유닛·CLI 런타임 검사와 pinned checkout CI를 추가했고, 기존 증거는 유지한다.
다음은 **registry Gate → Guard Authority 연결과 최종 gate freshness 검증**이다.
실제 Source/호스트 배포 미지정 및 전체 lifecycle 37개 NOT_RUN/적합성
NOT_ESTABLISHED 상태는 유지한다.


0.10.0 Registry Authority 연결: [현재 키 관측과 실행 직전 검사](guard-registry010.md).
두 코어의 RegistryAuthority는 키 조회와 최종 시각 확인마다 새 registry 관측을
수행하며 첫 키 material/expiry를 고정한다. 8개 최종 gate 시나리오를 실제 프로세스
16개로 검증하고 32개 원문·journal 파일을 보존한다. 통제된 Source와 메모리 registry
Store를 사용하므로 live registry·호스트 인증은 아니며 전체 37개 lifecycle 판정은 유지한다.
다음은 **MCP 보호 전송의 인증 신원·exact RPC 바이트·invocation ID 연결**이다.


0.10.0 MCP 보호 세션 연결: [인증 신원·RPC 바이트·호출 ID 검증](mcp-session010.md).
두 코어의 기존 signed AEAD 세션에 exact RPC 바이트를 연결하고 outer message ID와
inner RPC UUID를 구분한다. 네 언어 조합의 실제 프로세스 8개·교환 8개·독립 서명
검사 32개를 별도 artifact로 보존한다. 이 검증은 전송 연결이며 dispatch와 durable
client 소비는 해당 보고서에서 NOT_RUN이다. 전체 lifecycle 37개와 적합성 판정은
유지한다. 다음은 **보호 세션 → 실제 Guard dispatch → durable client 소비 연결**,
이후 인증된 MCP 초기 협상과 호스트 집행 증거다.


0.10.0 보호 세션·Guard 실행·client 소비 통합: [실제 API 연결 검증](guard-session010.md).
네 언어 조합의 실제 프로세스 20개에서 보호 교환 8건, client 재시작 4건,
독립 서명 검사 44건을 확인한다. 실행 효과 1회와 정확한 인자, execution/client
journal의 상태 전이 및 재시작 후 중복 소비 거부를 검증한다. 신뢰된 로컬
오케스트레이션·통제된 Authority·inert effect의 범위이며 전체 lifecycle 판정은 유지한다.
다음은 **인증된 MCP 초기 설정·버전 협상 경계 검토**, 이후 선정된 호스트의 집행·복구 증거다.


0.10.0 인증된 MCP 초기 설정 검토: [미구현 경계와 명세 결정](mcp-setup010.md).
버전 지원 검사와 인증된 협상 완료를 구분했다. 인증 시작점·준비 상태·기능/도구·
알림 carriage·재연결·HTTP 매핑의 여섯 OPEN 결정을 해시로 고정한 계약과 검사기에
기록했다. 유닛 8개·CLI 런타임 2개는 검토 무결성만 확인하며 실제 MCP 협상 지원을
의미하지 않는다. 다음은 **비HTTP 초기 협상 명세 초안: 알림 carriage와 준비 상태**,
확정 후 코어 상태 기계·실제 협상 검증이다. 전체 lifecycle 37개와 적합성 판정은 유지한다.


MCP 초기 설정 제안은 sage-spec PR #8·#9에서 초안과 다섯 검토 보완을 반영했다.
정식 규범으로 채택하지 않았고, 원래 미커밋 명세를 보존했다.
[준비 상태 모델](mcp-setup-model.md)은 고정한 보완 초안의 송신 barrier·deadline·
종료·ID/replay 이력 불변식을 유닛과 유한 탐색으로 검증한다. 실제 코어·암호·
네트워크 검증이 아니므로 40개 제안 사례와 기존 lifecycle 37개는 NOT_RUN이다.
다음은 **외부 독립 검토 및 신뢰된 connection owner API 계약**이며, 규범 baseline·
traceability와 조정한 뒤 코어 구현과 실제 협상 검증으로 진행한다.
