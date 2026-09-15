# Inspector 테스트 커버리지와 실행 보고서

이 문서의 커버리지는 검사 항목의 범위다. 코드 라인·분기 커버리지 비율이나
전체 프로토콜 통과율을 의미하지 않는다. 현재 유닛 중심 작업 1–7을 완료했다.

## 최근 추가한 검사 항목

| 범위 | 단위 테스트 메서드 | CLI 경로 | 확인하는 동작 | 실제 연결에서 남은 검증 |
|---|---:|---:|---|---|
| 만료 | 8 | 0 | 직전·경계·직후, 효과와 타입, 미실행 판정 | 코어 시간 제어·키 파기 |
| 재시작·복구 | 6 | 6 | 복구 기대값, 프로세스 종료·EOF·미지원 | 실제 저장·복구 구현 |
| 종료·수신 순서 | 5 | 18 | 세 가지 순서와 중복 거부, 효과·ID | 실제 동시 종료·수신 |
| 프로토콜 연결 | 6 | 26 | transcript·HPKE 확인·HTTP/WS 연결 판정 | 암호 연산·TLS·WS 파서·전체 교환 |
| Guard | 6 | 37 | 실패 시 차단, 원본 예약 보존, 오류 보고 | 실제 hook·측정·호스트 격리 |
| 실행 보고서 | 3 | 별도 집계 안 함 | 성공·오류·시간 초과·누락과 로그 해시 | 코어 적합성 판단 대상 아님 |

기존 다섯 범위는 단위 테스트 31개와 CLI 경로 87개다. 보고서 검증 3개를 더하면
단위 테스트 메서드 34개다. CLI 경로는 매개변수 조합의 문서상 수이며, unittest가
집계하는 메서드 수나 실행 관측 수와 합산하지 않는다. 모든 경로가 성공했는지는
각 런타임 테스트의 assertion과 보존된 로그로 확인한다. 보고서 검증도 제한된
로컬 Python 프로세스를 사용한다.

기존 HTTP/HPKE/session/registry/Guard 고정 자료 검산과 검사기 테스트는 CI에서
계속 실행한다. 과거 배포·재전송·동시 수신·종료 경합 테스트는 보존된 보고서의
무결성만 검사한다. 실제 코어 실행용 `test_*adapters.py` 파일은 이번 실행 목록에
포함하지 않는다. `test_*.py` 전체 자동 탐색으로 범위를 확장하지 않는다.

## 실행과 결과 보존

```sh
go build -o /tmp/sage-scenario-tests ./cmd/sage-scenario
go build -o /tmp/sage-conformance-tests ./cmd/sage-conformance
python3 scripts/run_verification_tests.py --scenario /tmp/sage-scenario-tests --primitive /tmp/sage-conformance-tests --output /tmp/inspector-tests-fresh
```

출력은 새 디렉터리여야 하며 기존 결과를 덮어쓰지 않는다. `docs/evidence` 아래에는
출력할 수 없다. 실행 목록은 `scripts/run_verification_tests.py`의 UNIT 6개 파일과
RUNTIME 4개 파일에 명시되어 있다. 각 파일은 독립 프로세스로 실행되며 한 파일이
실패해도 나머지 결과를 수집한다. 파일별 300초 제한을 넘으면 프로세스 그룹을
종료하고 TIMEOUT으로 기록한다. 기존 CLI 테스트는 호출별 20초 제한도 유지한다.

`report.json`에는 다음을 기록한다.

- 테스트 결과임을 나타내는 kind와 목적, `actual_core_execution: false`,
  `conformance: NOT_ESTABLISHED`.
- Inspector revision, 작업 트리 변경 여부, Python·OS, 시작·종료 시각.
- 실행 파일 해시와 scripts·고정 벡터 입력 해시. 해시는 실행 입력 추적용이며
  결과의 서명 인증이나 변경된 실행 환경에 대한 증명은 아니다.
- 명령별 분류·종료 코드·시간·상태 및 원본 stdout/stderr 로그 경로와 해시.

10개 명령이 모두 종료 코드 0일 때만 보고서와 실행 명령이 성공한다. 누락·오류·
시간 초과는 성공이 아니다. 중단된 실행은 RUNNING 상태와 이미 기록된 결과를
남기므로 완료된 PASS로 읽으면 안 된다. 로그에는 unittest 메서드 수와 실패가 남는다.
보고서는 테스트 메서드별 결과나 코드 커버리지 비율을 추출하지 않는다.

CI Test 작업에서 같은 명령을 실행하고 실패 시에도 별도 `inspector-tests-<revision>`
artifact에 보고서와 로그를 보존한다. 기존 evidence artifact와 적합성 집계에 섞지 않는다.
빌드 실패로 테스트가 시작되지 않았다면 보고서가 없으며 CI가 실패한다.

## 남은 범위

기존 Go·Rust FAIL/UNSUPPORTED, 상태 시나리오와 386개 계획 사례의 NOT_RUN,
전체 NOT_ESTABLISHED는 유지한다. 실제 transcript API, 완성된 HPKE·HTTP/WS 교환,
코어의 만료·복구·종료 계약 및 신뢰할 수 있는 호스트 관측 연결은 후속 작업이다.
현재 범위에서는 공격 기능이 될 수 있는 취약점 재현이나 호스트 우회 코드를 실행하지 않는다.
