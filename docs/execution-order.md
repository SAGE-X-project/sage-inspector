# SAGE 0.10.0 작업 순서 기준선

작성일: 2026-09-24. 이 문서는 진행 중인 프로토콜, 명세, 코어 및 Inspector
작업의 순서를 고정한다. 중간 검토에서 새 개선점이 발견되더라도 현재 계획을
완료하기 전에 규범이나 구현 방향을 바꾸지 않는다.

## 현재 기준선

| 대상 | 고정 revision | 의미 |
|---|---|---|
| `sage-spec` | `520e5ed9a896ff8ba8ade776484f41084957aaa2` | 채택된 SAGE 0.10.0 규범 설계 |
| Go `sage` | `1f2dd87643e42b7ed3beda6956158ff23dcc7ea2` | 현재 MCP 구현 검사 대상 |
| Rust `rs-sage-core` | `40b5a8c6d76d952131013d8a034f819fd31b7ca0` | 현재 MCP 구현 검사 대상 |
| `sage-inspector` | `27795685ca5d908a20455057f52c088086a6b119` | 기준선 정렬을 시작한 Inspector revision |
| 역사적 명세 snapshot | `f4a4e7fbf71a665785984eef7609b2e8fabe833d` | 기존 386개 사례와 증거를 보존하는 입력 |

`sage-spec`의 `docs/design-and-integration-review` 작업과 미커밋 파일은 후속
설계 입력으로 그대로 보존한다. 현재 계획을 실행하면서 그 브랜치를 정리하거나
현재 규범의 대체물로 사용하지 않는다.

## 확인된 불일치

`sage-spec`은 2026-09-21에 비HTTP MCP 설계를 `ADOPTED_NORMATIVE_DESIGN`으로
채택했다. 이후 생성된 Inspector의 MCP 실행 overlay는 71개 사례를 PASS로
관측했지만, 보존된 계약은 이전 제안 상태인 `PROPOSAL_NOT_ADOPTED`를 유지하고
채택 명세 revision을 직접 고정하지 않는다. 따라서 71 PASS는 실제 실행 증거지만
현재 규범에 대한 완결된 적합성 판정은 아니다.

2026-09-23의 MCP 채택 준비도 검토는 삭제하거나 현재 명세 판정으로 승격하지
않는다. 이미 채택된 규범보다 이전 제안 상태를 검토한 역사 자료로 보존하고,
그 발견은 현재 계획 종료 후 errata 검토에서 다시 판정한다.

## 변경할 수 없는 실행 순서

2026-09-24 실행 증거 기준으로 1~3단계의 revision 대조와 구현 검토가 완료되었고,
4단계의 [Inspector MCP 결합 증거](mcp-binding-evidence.md)는 부모 71건, 양쪽
코어의 필수 하위 스케줄 각 26건, 보호 교환 4조합과 재시작 8건을 확인했다.
5단계 [INS-11 코어 수명주기 증거](core-lifecycle-evidence.md)는 현행 레코드의
종료·수신, 만료/admission, 늦은 완료, replay/quarantine 복구 및
reservation/close 경계를 확인했다. 두 단계의 결과는 `EVIDENCE_CHECKED`이며
전체 프로토콜 적합성은 `NOT_ESTABLISHED`이다. 과거 구형 세션 race `FAIL`과
역사적 lifecycle 37건 `NOT_RUN`은 유지한다. 6단계의
[Registry Source 배포 감사](registry-source-deployment-audit.md)는 공개 주소
후보와 설정을 조사했으나 신뢰된 0.10.0 배포 바인딩이 없어 실제 체인 관측을
`NOT_RUN`으로 기록했다. 이 판정을 보존한 다음 순서는 7단계 실제 Agent 호스트
집행 검증이다.

### 1. 규범 기준선과 증거 provenance 정렬

채택 기록, 규범 profile, descriptor, traceability, 두 코어 revision과 Inspector
실행 증거를 하나의 기계 판독 기준선에 연결한다. 역사적 `71 NOT_RUN`과 현재
`71 PASS` overlay는 별도로 유지한다. 이 단계에서는 프로토콜 의미를 변경하지
않는다.

### 2. Go 구현 대조

채택 규범의 owner, admission, close, deadline, output barrier, 키 역할, durable
recovery 의무를 현재 Go 구현과 대조한다. 구현 결함만 수정하며 규범의 모호함은
후속 errata 후보로 기록한다.

### 3. Rust 구현 대조

Go와 동일한 관찰 결과를 기준으로 Rust 구현을 대조한다. 언어별 lock 또는 callback
구조가 같다고 가정하지 않는다.

### 4. Inspector MCP 실행 증거 완결

71개 binding 부모 사례와 26개 필수 하위 스케줄을 채택 명세 revision에 연결한다.
Go/Go, Go/Rust, Rust/Go, Rust/Rust의 원문, journal, effect와 admission 관측을
보존한다. 386개 baseline 부모 사례와 71개 binding 부모 사례는 총 457개다.
별도의 역사적 lifecycle 37개는 이 수에 더하지 않는다.

### 5. INS-11 코어 수명주기 잔여 검증

최신 코어에서 종료/수신 경합, 만료/admission 경합, stale completion, replay와
quarantine 복구, reservation/close 선형화를 순서대로 검증한다. 안전한 단위 테스트와
제한된 런타임 테스트를 모두 수행한다. 공격에 활용할 수 있는 우회 재현 코드는
작성하거나 실행하지 않는다.

### 6. 실제 Registry Source와 체인 관측

고정 배포 식별자, RPC, chain ID, contract code/ABI hash, finality, 확정 블록,
버전 후퇴, mixed-block, 폐기 및 관측 지연을 실제 Source에서 관측한다. 배포가
지정되지 않은 경우 테스트 더블을 실제 체인 증거로 승격하지 않고 NOT_RUN을 유지한다.

### 7. 실제 Agent 호스트 집행 검증

고정 호스트 실행 파일과 설정, 신뢰된 외부 관측기를 사용해 hook, timeout,
direct-call 차단, subprocess/file/network 효과 중재, signing-key 격리, 실제 dispatch와
복구를 검증한다. 공격 가능성이 있는 우회 시나리오는 단위 검증으로 제한하고 그
한계를 판정에 남긴다.

### 8. INS-11 및 현재 계획 최종 판정

명세와 대상 revision, 실행 원문, Registry Source, 호스트 격리 및 모든 실패·미지원·
미실행 상태를 통합한다. 증거가 부족하면 INS-11이나 전체 적합성을 완료로 표시하지
않는다.

## 현재 계획 종료 후의 순서

1. ADOPT-01..06을 채택된 규범 기준의 post-adoption errata로 재검토한다.
2. 보존한 `docs/design-and-integration-review` 작업을 재개한다.
3. 문서·그래프·레이어와 사용자가 원하는 구현 패턴을 반영해 명세를 개선한다.
4. 변경된 명세 snapshot과 traceability를 새 revision으로 고정한다.
5. Go와 Rust 코어를 리팩터링한다.
6. Inspector 전체 검사를 새 기준선으로 다시 실행한다.
7. SDK, MCP/등록 서비스, 비교 demo와 저장소 분리를 진행한다.
8. 외부 독립 검토와 릴리스 판정을 수행한다.

## 단계 전환 규칙

- 각 단계는 문서 존재가 아니라 고정 revision과 재현 가능한 증거로 완료한다.
- 현재 단계가 끝나기 전에 후속 단계의 규범 변경을 합치지 않는다.
- 새 발견은 즉시 기록하되 현재 기대 결과를 임의로 바꾸지 않는다.
- 코어 미지원은 `UNSUPPORTED`, 실행하지 못한 배포 검증은 `NOT_RUN`, 관측된
  불일치는 `FAIL`로 유지한다.
- 사람과 에이전트가 작성한 커밋과 PR은 영어 Conventional Commit을 사용하며
  emoji와 co-author attribution을 넣지 않는다.
- PR은 squash merge하고 작업 브랜치를 삭제한 뒤 로컬 `main`을 원격과 동기화한다.
