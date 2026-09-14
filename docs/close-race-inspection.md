# 수신과 세션 종료의 경합 검사

Inspector 0.10.0의 실제 코어 연결을 위한 **기존 API 동시 호출 안전성 진단**이다.
Go 코어 `c7709b7486e0da94336edc0931fddd87f6a45343`에서 데이터 경합을 재현했다.
검사 결과는 Go `FAIL`, Rust `UNSUPPORTED`이며, 전체 프로토콜 적합성은
`NOT_ESTABLISHED`다. 이 결과를 기존 525개 primitive 사례나 386개 계획 사례의
실행 결과로 합산하지 않는다. 실제 코어 소스는 수정하지 않았다.

## 검사 범위와 관측

`adapters/go/cmd/sage-close-probe`는 실제 `SecureSession`으로 레코드를 만들고
수신한다. 외부 서비스 연결 없이 메모리 안의 세션과 공개된 고정 테스트 seed를
사용한다. 양방향 역할 c2s/s2c를 검사하며, Go↔Rust 상호운용 검사는 아니다.

먼저 별도 프로세스에서 두 방향의 순차 대조군을 실행한다. 활성 세션의 서로 다른
레코드 8개 수신, 명시적 종료, 아직 수신하지 않은 9번째 레코드 거부를 확인했다.
9번째 레코드는 별도의 활성 세션에서 정상 수신되는지도 확인한다. 두 대조군은 PASS다.

경합 프로세스는 방향당 16회, 총 32개의 새 수신 세션을 사용한다. 각 회차에서
8개의 서로 다른 레코드를 수신하는 작업자와 종료 작업자 1개가 모두 준비된 뒤
같은 시작 게이트를 연다. 어댑터 잠금으로 코어 호출을 직렬화하지 않는다.
호출 시작/종료는 같은 회차의 단조 시간으로 기록하고, 모두 끝난 뒤 아직 사용하지
않은 레코드를 다시 수신한다. 종료와 겹친 수신은 정상 평문 수락 또는 거부를
허용한다. 종료 완료 뒤 시작한 수신의 수락은 허용하지 않는다.

최종 실행은 `-race`, `GORACE="halt_on_error=0 exitcode=66"`, `GOMAXPROCS=8`로
진행했다. 두 순차 대조군은 종료 코드 0, 경합 프로세스는 종료 코드 66이었다.
원시 stdout에는 32개 회차가 있지만 데이터 경합이 발생한 프로세스의 동작 결과를
성공 증거로 채택하지 않는다. 보고서의 `completed_rounds: 0`은 이 실패 경로에서
검증 완료로 인정한 회차가 없다는 의미다. 원문은 삭제하지 않는다.

race detector는 같은 `aeadIn` 필드에서 다음 충돌을 기록했다.

- `sage/pkg/agent/session/session.go:623`: `Close()`가 `s.aeadIn = nil`을 수행.
- `sage/pkg/agent/session/session.go:807`: `DecryptWithAADInbound()`가 `s.aeadIn`을 읽음.

`Close()`의 `s.mu`와 수신 경로의 `recvMu`는 이 접근을 함께 보호하지 않는다.
현재 API의 병행 종료 안전성을 승인할 수 없다. 이는 메모리 접근의 경합 증거이며,
원격 공격 가능성, 키 유출, 메시지 위조 또는 전체 프로토콜 규범 위반을 입증한 것은
아니다. 외부 호출자의 직렬화 계약과 실제 호스트 경로는 별도 검토 대상이다.
초기 진단에서도 동일한 경합을 확인했고, 출력 필드 이름을 `participants`로 명확히 한
바이너리로 최종 증거를 다시 수집했다. 실패를 없애기 위한 반복 실행은 하지 않았다.

## Rust 바인딩 경계

고정된 Rust revision `206bbbb5a66667ae2feb3b0e9991ed1ca4622bb2`의
`src/session/types.rs`는 `close(&mut self)`를 요구한다. 안전한 Rust 코드에서
수신용 공유 참조를 유지하면서 같은 객체를 병행 종료할 수 없다.
`src/session/manager.rs`의 `remove_session(&self)`는 맵에서 `Arc`를 제거할 뿐,
이미 반환한 핸들의 세션을 종료하지 않는다. 이를 종료 API로 대체하지 않는다.

따라서 현재 **직접 병행 종료 바인딩**은 UNSUPPORTED다. Rust가 안전하지 않다는
판정이 아니며, unsafe 추가나 어댑터 잠금으로 원하는 검사 모양을 만들지 않는다.
향후 코어가 공유 핸들용 종료 계약을 제공하면 해당 계약에 맞춰 연결한다.

## 재현과 증거 검증

저장소 루트에서 다음을 실행한다. sibling 코어의 revision과 소스 해시는
`core-source-lock.json`과 일치해야 한다. 출력 디렉터리는 새 경로여야 한다.

```sh
(cd adapters/go && go build -race -o /private/tmp/sage-close-probe ./cmd/sage-close-probe)
python3 scripts/inspect_close_race.py --probe /private/tmp/sage-close-probe --output-dir /private/tmp/sage-close-new
python3 scripts/test_close_inspection.py
python3 scripts/check_close_evidence.py
```

실행기는 프로세스별 30초 제한과 실패 stdout/stderr를 보존한다. Go 진단 실패면
종료 코드 1, Go에서 실패를 관측하지 않아도 Rust 바인딩이 없으므로 종료 코드 3이다.
프로세스 오류를 메시지의 정상적인 REJECT로 변환하지 않는다. 정상 종료한 경합
실행에서도 모든 회차의 수신·종료 호출 구간이 겹치지 않으면 INCOMPLETE다.
정상적인 제한 횟수 통과도 모든 내부 스케줄이나 선형화 가능성을 증명하지 않는다.

[원시 보고서](evidence/deployment/close-race/report.json),
[race detector stderr](evidence/deployment/close-race/race.stderr),
[출처와 해시](evidence/deployment/close-race/provenance.json)를 보존한다.
CI는 고정된 로그의 해시와 판정 재계산 및 변조 거부를 검사한다. CI가 실제 코어를
새로 실행했다거나 코어가 통과했다고 표시하지 않는다.

다음 작업은 실제 만료·재시작 복구 연결이다. Go 종료 경합 개선은 별도 코어 작업이며,
변경된 코어를 고정한 뒤 이 검사를 다시 실행한다. INS-11은 계속 진행 중이다.
