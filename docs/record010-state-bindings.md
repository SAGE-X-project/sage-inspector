# 상태 유지 레코드 어댑터

새 Go·Rust RecordSession010 인스턴스를 한 schema2 프로세스 안에서 유지한다.
이 계약은 레코드 API의 관측이며, 기존 `control.session.create` 규범 시나리오의
인증 tuple·레지스트리·가상 시간·정책 상태를 대신 구현하는 계약이 아니다.
코어 revision은 [단일 요청 연결](record010-bindings.md)과 동일하게 고정한다.

## 연산과 관측

| 연산 | 입력 | 수락 출력 |
|---|---|---|
| record010.create | seed_hex, th_hex, initiator(bool) | session_id |
| record010.open | record_hex, caller_aad_hex | plaintext_hex |
| record010.seal | plaintext_hex, caller_aad_hex | record_hex |
| record010.close | 빈 객체 | 빈 객체 |

한 프로세스에 create는 한 번만 허용한다. 종료된 세션을 포함하여 인스턴스를
교체하거나 카운터를 초기화하는 제어는 제공하지 않는다. 개별 step_id는 중복될 수
없으며 case_id가 바뀌면 오류다. 기대값·효과 주장은 요청에 받지 않는다.
명령은 최대 128단계, 개별 입력은 약 4 MiB로 제한한다. 실제 실행기는 추가로
단계·프로세스 제한 시간을 적용한다. 따라서 이 경로를 최대 8 MiB 레코드의
전체 전송 경계 검증으로 해석하지 않는다.

효과는 어댑터가 직접 관측한 누적 호출 결과만 기록한다.

- `core_open_success`: 실제 코어 Open/open이 성공한 횟수.
- `core_seal_success`: 실제 코어 Seal/seal이 성공한 횟수.
- `core_close_calls`: 명시적인 close 단계에서 코어 Close/close를 호출한 횟수.
  프로세스 종료 시 정리 호출은 단계 관측에 포함하지 않는다.

거부된 호출은 성공 카운터를 증가시키지 않는다. dispatch, 예약 수, 키 파기 상태,
내부 시퀀스/재전송 윈도우, 마지막 활동 시각은 코어 관측 API가 없으므로 보고하지
않는다. close 후 거부를 관측하는 것은 메모리에서 모든 키 사본이 파기되었음을
측정한 것과 다르다. 공개된 wire/평문과 호출 성공만 코어 결과로 기록한다.

지원되지 않은 연산은 UNSUPPORTED이며 상태나 효과를 만들어내지 않는다.
구체적으로 가상 시간 전진, 내부 상태 inspect, restart 및 기존의 완전한
control.session.create는 지원하지 않는다. 잘못된 입력, 세션 교체, 생성 이전
호출, 다른 case 또는 중복 step은 어댑터 오류로 종료하며 정상 REJECT로 숨기지
않는다. 코어가 반환한 레코드 오류만 REJECT로 변환한다.

## 검증

Go와 Rust에 각각 두 단위 테스트를 추가하여 미지원 관측과 잘못된 스트림에서
가짜 관측이 생성되지 않는지 확인한다. `test_record010_state.py`는 실제
sage-scenario CLI를 두 어댑터에 연결한다.

각 방향(c2s/s2c)에서 다음 일곱 시나리오, 총 14개를 코어별로 실행한다.

1. 정상 두 레코드 순차 수신.
2. 같은 레코드 중복 거부 후 다음 레코드 수신.
3. 순서가 뒤바뀐 두 레코드 수신과 중복 거부.
4. 잘못된 태그의 거부 이후 같은 seq의 정상 레코드 수신.
5. 먼저 종료한 뒤 수신 거부.
6. 정상 수신 후 종료하고 다음 레코드 거부.
7. 같은 세션에서 두 레코드를 송신하고 종료 후 추가 송신 거부.

송신 wire와 수신 평문은 기존 독립 벡터의 seq 0/1 기대값과 비교한다. 어댑터에서
키 파생, 암호 검증, 재전송 필터나 가상 세션 상태를 구현하지 않는다. 실제 코어의
객체를 재사용하므로 중복 거부와 seq 증가가 각 요청의 새 인스턴스로 대체되지 않는다.

별도로 코어별 네 미지원 제어를 실행하여 INCOMPLETE와 이후 NOT_RUN을 확인한다.
중복 step, 다른 case, 인스턴스 교체, 알 수 없는 제어 필드, AAD 누락, 다른 schema의
여섯 오류 스트림을 각각 검사한다. 두 코어 합계는 28개 시나리오 PASS, 8개 예상된
INCOMPLETE, 12개 오류 스트림 검증이다. 미지원 기능이 통과했다는 집계가 아니다.

## 실행과 증거

```sh
go build -o /tmp/sage-state-runner ./cmd/sage-scenario
(cd adapters/go && go build -o /tmp/sage-state-go ./cmd/sage-record010-state)
cargo build --locked --manifest-path adapters/rust/Cargo.toml --target-dir /tmp/sage-state-rust
python3 scripts/test_record010_state.py --go /tmp/sage-state-go --rust /tmp/sage-state-rust/debug/record010_state --runner /tmp/sage-state-runner --output /tmp/sage-state-results-new
```

CI의 Record API bindings 작업에서 실행하고 기존 별도 artifact의 stateful/
하위에 입력 시나리오, 원시 CLI 보고서와 집계 보고서를 보존한다. 집계에는 코어
revision, 어댑터·실행기·원본 벡터 해시와 Inspector revision을 기록한다.
중단/실패한 실행을 성공으로 집계하지 않고 오류 원문을 보존한다.

과거 source lock·증거 카탈로그 및 규범 계획 사례 386개의 상태는 변경하지 않는다.
전체 프로토콜 적합성은 NOT_ESTABLISHED다. 실제 단조 시간 만료, HPKE 임시 확인,
인증 tuple·선택 키·registry 연결, 복구, 병행 스케줄과 호스트 실행은 이번 검증에
포함하지 않는다. 해당 관측과 코어 기능이 제공되어야 후속 연결이 가능하다.
