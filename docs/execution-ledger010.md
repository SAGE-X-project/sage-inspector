# 실제 execution ledger 저장·복구 검증

두 코어에 별도 영속 execution ledger를 추가했다. 기존 replay 저장소와 분리하여
호출·nonce를 한 번에 예약하고 exact intent/terminal bytes와 실행 상태를 저장한다.
Inspector 어댑터는 새 코어 API만 호출하며 없는 Guard 인증·정책 기능을 대신하지 않는다.

## 제공 범위

- `(issuer, call_id)`와 `(issuer, recipient, nonce)`를 한 fsync 행에 원자적으로 예약한다.
- 동일 intent 재시도는 changed=false이며, 달라진 proof 포함 원문·nonce·recipient·expiry는 거부한다.
- EXECUTING은 effects 이전에 기록해야 한다. 저장 성공은 별도 정책 인가나 dispatch 권한이 아니다.
- 재시작은 RESERVED/EXECUTING을 UNKNOWN으로 **영속화한 뒤** handle을 반환한다.
- UNKNOWN은 재실행·COMPLETED 전환이 불가능하며, 미서명 UNKNOWN에 최초 terminal bytes만 붙일 수 있다.
- COMPLETED/REJECTED/서명된 UNKNOWN은 원문을 재사용하고 재서명·시간 갱신을 허용하지 않는다.
- absent REJECTED도 nonce와 함께 저장하므로 이후 정책 변경으로 같은 호출을 실행할 수 없다.
- 신규 생성은 이전 승인이 없는 격리된 scope의 명시적 초기화 전용이다. 기존 파일 손실은 일반 reopen 실패다.

실제 검증된 서명·JCS·현재 identity/policy·만료·component·dispatch 직렬화는 호출자 의무다.
저장소는 전달된 identity projection과 opaque envelope의 일치 여부를 암호적으로 검증하지
않는다. fixture는 서명된 Guard 요청이 아닌 합성 바이트다. 실제 도구는 실행하지 않았다.
전체 Execution Guard 적합성, exactly-once 외부 효과, 호스트 격리 판정은 계속
`NOT_ESTABLISHED`다. 과거 Guard UNSUPPORTED/NOT_RUN 기록은 그대로 유지한다.

## 파일과 장애 경계

Go/Rust는 `sage-execution-ledger|0.10.0` 헤더와 동일한 엄격한 JSON 행을 사용한다.
Linux/macOS의 신뢰된 local filesystem과 exclusive writer를 전제로 한다. 최대 64 MiB,
4096개 행이며 자동 pruning은 없다. 복구 행도 용량을 소비하고 부족하면 fail-closed다.
최소 expires+30보다 오래 nonce·call·terminal·unresolved 상태를 보존한다.

healthy explicit close만 `.lock`을 해제한다. 프로세스 종료·쓰기/sync 실패에는 lock을
유지하며 실패한 handle은 조회도 거부한다. 운영자가 기존 writer와 tool 실행 소유자의
종료를 확인하기 전에는 lock을 제거하면 안 된다. 자동 stale-lock 해제나 ledger 삭제로
새 실행을 허용하는 기능이 없다. lost-ledger의 scope 전체 정책 retirement/새 epoch 승인은
아직 별도 후속 작업이다. 본 저장소 초기화 API로 그 절차를 대체하지 않는다.

## 검사와 재현

| 검사 | 범위 |
|---|---|
| 공통 fixture | 14개 시나리오·72단계, 각 코어 유닛/프로세스에서 동일 자료 |
| 실제 코어 시나리오 | Go 14 + Rust 14, 합계 144단계 |
| 중단 후 복구 | 네 언어 조합 × RESERVED/EXECUTING/COMPLETED/REJECTED/UNKNOWN, 20개 |
| 파일 제어 | 코어별 missing/torn/leftover-lock, 6개 |
| native 저장소 검사 | IO 실패 poison·lock 보존, capacity·partial row·writer exclusion·동시 예약 |

복구 런타임은 자신이 만든 child가 정상적으로 자체 종료하되 close를 생략하게 한다.
child 종료를 확인하고 재개 거부를 먼저 검사한 다음 **해당 임시 lock만** 제거한다.
이것은 실제 프로세스 생명주기 검증이며 OS 강제 종료·전원 차단·공격 재현은 아니다.
기록 손상은 자신의 임시 파일에 잘린 행을 붙여 검사하며 외부 자원에 접근하지 않는다.

```sh
(cd adapters/go && go build -o /tmp/sage-execution010-go ./cmd/sage-execution010)
cargo build --locked --manifest-path adapters/rust/Cargo.toml --bin execution010
python3 scripts/test_execution_ledger010.py \
  --go /tmp/sage-execution010-go \
  --rust adapters/rust/target/debug/execution010 \
  --output /tmp/new-execution-ledger-results
```

기본 실행은 고정 core revision·변경 여부·fixture 동일성을 검사한다. `--development`는
개발 중 실행만 위한 명시적 선택이며 보고서에 그대로 기록된다. 기대값은 어댑터에
전송하지 않는다. report.json은 fixture/실행파일/revision과 입력·stdout·stderr·종료 코드,
복구 전후 journal 원문 해시를 보존한다. 출력은 새 디렉터리여야 한다. CI는 기존
Record API bindings artifact의 execution-ledger010/ 아래에 원문과 결과를 보존한다.

## 다음 연결

이 작업은 **코어 저장·복구 기반 구현 완료**다. 실제 Guard 통합은 아직 완료가 아니다.
다음은 canonical signed intent/result 검증을 이 저장소에 연결하고 현재 identity·정책과
component 상태를 재검사하는 dispatch gate 계약이다. scope 전체 정책 retirement 및
lost-ledger 복구, 실제 호스트 집행도 남는다. 배포 Source는 별도 지정 자료를 기다린다.
