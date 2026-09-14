# Guard 실행 차단과 오류 보고 판정 검증

기존 Guard 시나리오 6개를 재사용하여 hook 누락·시간 초과·예외, 변경된 요청,
측정 이후 로드 대상 변경, 측정 범위 밖 대상의 기대값과 Inspector 판정을 검사한다.
원본 벡터·명세·증거 카탈로그는 변경하지 않는다.

## 단위 테스트

`scripts/test_guard_gate_inspection.py`의 6개 테스트는 다음을 확인한다.

- 장애 제어 설정의 ACCEPT와 이후 요청 처리의 REJECT를 구분한다.
- 비활성 정책에서 요청을 거부하고 dispatch·응답·결과 서명 효과가 증가하지 않는다.
- 로드 대상 검증 실패 시 실행하지 않고 예약 상태를 REJECTED로 바꾼다.
- 변경된 요청은 거부하지만 원래 요청의 예약은 유지하여 원본을 한 번 실행할 수 있다.
- 잘못된 수락, 추가 효과, 누락된 효과·단계, 다른 단계 ID를 검출한다.
- 미지원 제어 이후의 단계는 NOT_RUN이며 허위 관측을 허용하지 않는다.

관측은 기대값을 바탕으로 만든 합성 보고서다. 고정 기대값 확인과 보고서 변형의
거부를 검증하며 실제 Guard 구현이 방어했다는 증거로 사용하지 않는다.

## CLI 런타임 테스트

`scripts/test_guard_gate_runtime.py`는 실제 `sage-scenario` 실행기를 임시 디렉터리의
고정 응답 프로세스에 연결한다. 이 프로세스는 JSON 요청을 기록하고 지정된 응답만
반환한다. 입력에 포함된 작업·도구·경로를 실행하거나 실제 hook을 변경하지 않는다.

6개 시나리오 각각에 정상·잘못된 수락·추가 dispatch·효과 누락·미지원·프로세스
중단을 적용하여 36개 경로를 검사한다. 추가 1개 경로는 응답을 지연시켜 Inspector의
200 ms 어댑터 제한 시간이 FAIL과 `step timeout`으로 보고되는지 확인한다.
이는 실제 Agent hook의 시간 제한 구현을 검증하는 것이 아니다.

총 37개 경로에서 종료 코드, 보고서 판정, 요청 입력·순서·식별자, 실행 파일 해시,
실패 이후 요청 중단 및 NOT_RUN을 검사한다. 관측 없는 오류를 정상 REJECT로
대체하지 않는다. 각 CLI 호출에는 20초의 외부 제한 시간을 둔다.

```sh
go build -o /private/tmp/sage-scenario-guard-gate ./cmd/sage-scenario
python3 scripts/test_guard_gate_inspection.py
python3 scripts/test_guard_gate_runtime.py /private/tmp/sage-scenario-guard-gate
```

CI에도 두 테스트를 등록했다. 실제 코어·호스트 실행 증거와 분리하며 기존
FAIL/UNSUPPORTED/NOT_RUN과 전체 NOT_ESTABLISHED 판정은 유지한다.
다음 작업은 단위 테스트 커버리지와 CI·보고서 정리다.
