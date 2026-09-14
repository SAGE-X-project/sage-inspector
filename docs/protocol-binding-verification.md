# 프로토콜 연결의 단위 및 CLI 런타임 검증

transcript·HPKE 확인·HTTP 요청/응답 연결의 고정 자료와 WS 신뢰 경계의 테스트 전용
관측을 사용한다. Inspector의 기대값·입력 전달·결과 판정을 검증하며 실제 코어,
HTTP/WS 서버, TLS 연결 또는 취약점 재현 기능은 실행하지 않는다.

## 단위 테스트

`scripts/test_protocol_binding_inspection.py`는 6개 테스트로 다음을 확인한다.

- 동일한 세션 레코드 입력에서 th만 달라진 사례의 수락/거부 기대값.
- 올바른 HPKE 확인과 잘못된 ack·다른 pending 요청·서명 없는 확인·알 수 없는
  transcript 멤버의 구분. 상태 시나리오에서는 실패 시 새 세션이 생성되지 않고
  pending이 폐기되는 기대 효과와 CLOSED 상태를 확인한다.
- 서명 검증 자체는 성공해도 잘못된 요청 해시나 이전 요청 연결 때문에 전체 HTTP
  메시지는 거부해야 한다는 서로 다른 검증 단계의 구분.
- RFC9421 응답의 원래 요청 부재 및 다른 요청 서명 연결의 거부.
- WS 연결 신뢰와 메시지 서명·수신자·요청 연결 검증 결과의 구분.
- 잘못된 수락, 다른 사례 ID, 누락된 결과 및 미지원 결과를 PASS로 표시하는 보고서 거부.

기존 벡터 중 선택한 사례는 테스트 메모리에서 suite ID만 별도로 지정해 사용한다.
원본 명세, 고정 벡터 및 증거 카탈로그는 변경하지 않는다.

## WebSocket 테스트 전용 경계

`protocol_test_support.py`의 `test.ws.binding-observation`은 **테스트 전용 연산명**이다.
실제 코어 어댑터 API나 새로운 규범 인터페이스로 등록하지 않는다.
기존 공개 HTTP 요청에서 본문 envelope를 읽어 다음 여덟 조건을 선언한다.

| 조건 | 기대값 |
|---|---|
| 정상 텍스트 메시지 | ACCEPT |
| 같은 본문을 두 조각으로 표현 | ACCEPT |
| 바이너리 메시지 | REJECT |
| 메시지 압축 사용 | REJECT |
| 인증되지 않은 연결 | REJECT |
| 신뢰된 연결이지만 envelope 서명 미검증 | REJECT |
| 신뢰된 연결이지만 수신자 불일치 | REJECT |
| 신뢰된 연결이지만 요청 연결 불일치 | REJECT |

근거는 고정된 `sage-spec/spec/08-transport.md` TRANSPORT-06이다. TLS 인증·서명·수신자·
요청 연결 플래그는 테스트가 제공하는 신뢰 경계의 선언값이지 실제 검증 결과가 아니다.
조각 연결 시 본문 바이트가 같다는 것은 확인하지만 실제 WS 프레임 파서, UTF-8 오류
처리, 재조립 중 16 MiB 상한, 압축 협상 차단 또는 네트워크 격리를 구현·검증한 것은
아니다. 이런 바인딩을 준비한 것으로 표시하지 않는다.

## 안전한 CLI 런타임 테스트

`scripts/test_protocol_binding_runtime.py`는 실제 `sage-conformance`와 `sage-scenario`를
빌드해 로컬 고정 응답 프로세스에 연결한다. 프로세스는 공개 테스트 입력을 임시
파일에 기록하고 지정된 JSON 응답을 반환한다. 입력의 메시지·작업·URI를 실행하지 않는다.

- primitive suite 다섯 개(HPKE, session transcript, RFC9421, HTTP 연결, WS 선언)에
  정상·잘못된 수락·다른 사례 ID·미지원 응답을 적용: 20개 CLI 경로.
- HPKE 정상·잘못된 ack·다른 pending 상태 시나리오에 정상 관측과 추가 세션 생성
  효과를 적용: 6개 CLI 경로.

총 26개 경로에서 종료 코드, 사례별 판정, 입력·순서·식별자·실행 파일 해시를 확인한다.
상태 시나리오 실패 이후에는 요청을 더 보내지 않고 NOT_RUN을 유지해야 한다.
primitive 사례는 서로 독립적으로 계속 실행되며 결과를 빠짐없이 보고한다.
각 CLI 실행의 제한 시간은 20초다. 기대값은 실제 어댑터 요청에 포함하지 않는다.

```sh
go build -o /private/tmp/sage-conformance-protocol ./cmd/sage-conformance
go build -o /private/tmp/sage-scenario-protocol ./cmd/sage-scenario
python3 scripts/test_protocol_binding_inspection.py
python3 scripts/test_protocol_binding_runtime.py /private/tmp/sage-conformance-protocol /private/tmp/sage-scenario-protocol
```

CI에서도 실행한다. 결과는 Inspector 실행 경로에 대한 테스트이며 암호 연산,
상태 정책, WebSocket 보안이나 완전한 프로토콜 상호운용의 실제 코어 통과 증거가 아니다.
기존 FAIL/UNSUPPORTED/NOT_RUN과 전체 NOT_ESTABLISHED 판정은 그대로 유지한다.
다음 작업은 Guard의 hook 누락·시간 초과·검증 실패에 대한 판정 테스트다.
