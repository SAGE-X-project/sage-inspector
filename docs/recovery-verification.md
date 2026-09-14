# 재시작·복구의 단위 및 런타임 검증

기존 고정 시나리오 6개를 재사용해 Inspector 판정을 단위 테스트하고, 실제
`sage-scenario` 실행 파일과 제한된 로컬 테스트 프로세스 사이의 계약을 런타임에서
검증한다. 실제 SAGE 코어, 호스트, 네트워크, 사용자 키 또는 실행 도구를 호출하지 않는다.

## 단위 테스트

`scripts/test_recovery_inspection.py`의 6개 테스트는 다음 기대값을 명시적으로 확인한다.

- `session-restart`: 재시작 이후 CLOSED와 키 비가용 상태, 추가 수신·송신 거부,
  기존 dispatch 횟수 보존.
- `guard-crash-reserved`, `guard-crash-executing`: 불확정 작업은 UNKNOWN으로 유지하고
  추가 dispatch와 완료 전환을 거부. 장애 이전에 이미 발생한 효과와 아직 발생하지
  않은 효과를 구분한다.
- `guard-terminal-persistence-failure`: 최종 결과 저장 실패 시 성공 응답으로 바꾸지
  않고, 고정된 오류 주입 지점에서 서명·응답 효과가 늘어나지 않음을 기대한다.
- `guard-lost-ledger`: 손실된 ledger를 빈 정상 ledger로 취급하지 않으며 잘못된 복구와
  요청 재처리를 거부한다.
- `guard-scope-recovery`: 불완전한 복구 거부, 전체 조건을 만족하는 복구 수락,
  이전 승인 거부와 새 승인 처리 및 사용한 정책의 재사용 거부를 구분한다.

관측 누락·추가 실행·변경된 입력·불리언 카운터와 미지원 단계 이후 허위 관측을
거부하는지도 검사한다. Guard가 별도 복제한 schema2 검증 함수를 사용하던 부분을
세션의 공통 함수로 연결하여 타입 및 NOT_RUN 검증이 동일하게 적용되도록 했다.
이 변경은 보고서 판정의 수정이며 실제 Guard 저장 로직의 수정이 아니다.

## 안전한 런타임 테스트

`scripts/test_recovery_runtime.py`는 빌드된 실제 CLI를 실행하고 임시 디렉터리의
Python 테스트 프로세스와 표준 입출력으로 통신한다. 프로세스는 사전 작성한
응답만 반환한다. 세션 상태 머신이나 저장소 복구를 구현하는 시뮬레이터가 아니다.
`restart`, `receive`, `send`라는 입력도 동작을 실행하지 않고 기록만 한다.
임시 파일에는 공개 테스트 입력과 응답 스크립트만 저장된다.

하나의 매개변수화 테스트가 여섯 경로를 실행한다.

| 경로 | CLI 기대 결과 |
|---|---|
| 정상 스크립트 | 9단계 PASS, 종료 코드 0 |
| 재시작 단계에서 테스트 프로세스 종료 코드 7 | FAIL, 이후 단계 NOT_RUN, CLI 종료 코드 1 |
| 같은 단계에서 출력 없이 정상 종료 | 관측이 없으므로 FAIL, 이후 NOT_RUN |
| 잘못된 closed 효과 | FAIL, 이후 NOT_RUN |
| 재시작 제어 미지원 | INCOMPLETE, 이후 NOT_RUN, CLI 종료 코드 3 |
| 모든 응답 뒤 프로세스 종료 코드 7 | 개별 단계 PASS여도 전체 FAIL |

프로세스에 기대 결과 필드가 전달되지 않는지, 단계별 입력·ID·순서와 요청 개수가
맞는지, 실행 파일 해시와 보고서 판정도 함께 확인한다. 각 CLI 실행에는 20초 상한을
둔다. 프로세스 종료는 테스트 코드가 자체적으로 반환하는 종료 코드이며, 취약점을
유발하거나 서비스에 장애를 가하는 코드가 아니다.

```sh
go build -o /private/tmp/sage-scenario-recovery ./cmd/sage-scenario
python3 scripts/test_recovery_inspection.py
python3 scripts/test_recovery_runtime.py /private/tmp/sage-scenario-recovery
```

CI에서도 위 단위·런타임 경로를 실행한다. 이는 Inspector CLI 실행 증거이며 실제
코어의 재시작·저장·복구 방어 증거가 아니다. 합성 보고서를 배포 증거로 출력하지
않으며, 기존 코어 판정·386개 계획 사례의 NOT_RUN 및 NOT_ESTABLISHED를 유지한다.
종료·수신 순서의 테스트는 [별도 검증](session-close-order.md)으로 추가했다. 다음은 프로토콜 연결의 판정 테스트다.
