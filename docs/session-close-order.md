# 종료·수신 순서의 단위 및 CLI 런타임 검증

실제 동시 경합을 유발하지 않고, 순서를 고정한 관측에 대해 Inspector가 잘못된
수락·효과·상태를 검출하는지 확인한다. 코어 실행, 호스트 우회, 취약점 재현이나
시뮬레이터는 포함하지 않는다.

## 순서와 입력

기존 `session-close.json`과 `session-absolute-boundary.json`의 공개 고정 입력을
재사용하여 테스트 메모리/임시 파일에서 세 가지 계약을 구성한다.
기존 종료 시나리오의 축약된 거부 입력 대신, 전체 record/AAD/envelope 입력을
사용한다. 기대값은 명시적으로 작성하고, 원본 벡터와 해시는 변경하지 않는다.

| 순서 | 고정 기대 동작 |
|---|---|
| close-first | 종료 완료 후 seq0 수신 거부, accepted/dispatch는 0 유지 |
| receive-first | seq0 수락 후 종료, 아직 수신하지 않은 seq1 거부, accepted/dispatch는 1 유지 |
| replay-after-close | seq0 수락 후 종료, 같은 seq0의 재수신 거부, 추가 효과 없음 |

세 경우 모두 CLOSED, 키 비가용, 기존 수신 목록과 마지막 활동 시각 보존을
확인한다. 재전송 사례의 거부만으로 종료 방어를 입증하지 않으며, 아직 수신하지
않은 레코드를 사용하는 두 사례와 구분한다. 수신과 종료가 내부에서 겹치는 경우의
스케줄 또는 선형화 가능성을 검증했다고 표시하지 않는다.

## 단위 테스트

`scripts/test_session_close_inspection.py`의 5개 테스트는 고정 기대값, 종료 후
잘못된 수락 및 누적 효과, 상태 재활성화, 단계 교환·종료 단계 누락·이전 단계의
응답 ID 재사용, 종료 제어 미지원 이후 허위 관측을 검사한다.

이는 Inspector 보고서 판정의 테스트다. 관측은 스크립트로 작성한 테스트 더블이며,
세션 정책이나 암호 검증을 대신 구현하여 실제 코어가 통과한 것처럼 보고하지 않는다.

## 런타임 테스트

`scripts/test_session_close_runtime.py`는 실제 `sage-scenario` CLI와 로컬 Python
테스트 프로세스 사이의 IPC를 실행한다. 프로세스는 임시 디렉터리에 입력을
기록하고 고정 응답을 반환할 뿐, 받은 `close`·`receive` 동작을 실제로 실행하지 않는다.
각 CLI 실행의 제한 시간은 20초다.

세 순서 각각에 아래 6개 관측 경로를 적용하여 총 18개를 실행한다.

- 정상 고정 응답: 전체 PASS와 종료 코드 0.
- 종료 이후 수락, 추가 dispatch, 이전 단계 응답 ID, 키 가용성의 잘못된 보고:
  FAIL과 종료 코드 1.
- 종료 제어 UNSUPPORTED: INCOMPLETE와 종료 코드 3.

실패·미지원 이후의 요청 전송이 중단되고 다음 단계가 관측 없이 NOT_RUN인지도
확인한다. 요청 입력·ID·순서·개수, 응답 판정, 테스트 실행 파일 해시를 검증한다.
기대 결과를 어댑터 요청에 보내지 않는다. 초기 고정 응답 자체는 테스트 목적으로
작성한 자료이며 독립 코어 실행 증거가 아니다.

```sh
go build -o /private/tmp/sage-scenario-close-order ./cmd/sage-scenario
python3 scripts/test_session_close_inspection.py
python3 scripts/test_session_close_runtime.py /private/tmp/sage-scenario-close-order
```

CI에도 두 검사를 등록한다. 과거 Go 경합 FAIL, Rust 직접 병행 종료 UNSUPPORTED,
386개 계획 사례의 NOT_RUN 및 전체 NOT_ESTABLISHED 판정은 그대로 유지한다.
프로토콜 연결의 판정 테스트는 [별도 검증](protocol-binding-verification.md)으로 추가했다. 다음은 Guard 방어 판정 테스트다.
