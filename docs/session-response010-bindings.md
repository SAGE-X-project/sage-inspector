# Session 응답의 원본 요청 연결

두 코어가 보낸 요청의 독립 복사본과 수락한 요청의 전체 canonical envelope를
보관한다. 응답 생성은 해당 세션에서 수락한 요청 ID만 입력받고, 응답 검증은
보관한 **서명 포함 전체 요청의 JCS SHA-256**과 message_id를 확인한다.
호출자가 request_hash 또는 verified boolean으로 신뢰를 부여할 수 없다.

양쪽 역할의 응답을 지원한다. participant, 고정 key, role, session/context 일치와
새 ID/nonce를 검사하고, 응답 전용 서명 domain과 AEAD를 함께 검증한다.
AAD는 data/signature를 제외한 응답 전체 JCS다. 따라서 성공 상태·오류 코드와
원본 요청 연결도 AEAD에 포함된다. 선택 task/metadata는 아직 지원하지 않는다.

요청당 최종 응답 생성·수락은 한 번이다. 잘못된 응답과 저장 실패는 순서·요청을
소비하지 않는다. ID/nonce 예약과 레코드 수락 이후 소유권 잠금/배타 접근 안에서
요청을 terminal로 표시한다. 이후 애플리케이션 거부는 암호 수락을 취소하지 않는다.
반환된 바이트의 재전송만 가능하며 새 응답을 다시 암호화하는 API 호출은 거부한다.

success=false는 규정된 네 error 중 하나가 필수이고 true이면 error가 없어야 한다.
검증된 결과에 message_id, success, error, 복호화 data를 함께 반환한다. 빈 평문도
36바이트 암호 레코드로 교환하며 plaintext fallback은 없다. 요청은 세션 종료까지
보관하고 방향별 1000개 레코드 제한으로 개수가 제한된다. restart 복원은 없다.

공통 38개 시나리오를 두 코어 유닛 테스트와 네 조합 **152개 실제 프로세스 검사**로
확인한다. Node로 응답 서명을 독립 검증하고 Python으로 전체 요청 해시와 참여자·역할·
context/session을 대조한다. 거부 후 정상 응답 재시도, 응답 순서 변경, 양방향 요청,
저장 도중 키 만료, 오류 응답의 terminal 동작도 검사한다. 추가 유닛 검사는 반환된
요청 버퍼를 변경해도 내부 원본이 유지되는지와 최대 크기 경계를 확인한다.
Go의 16개 동시 최종 응답 수신 검사는 race detector와 함께 실행한다.

```sh
python3 scripts/test_session_response010.py --go /tmp/sage-completion010-go --rust adapters/rust/target/debug/completion010 --output /tmp/new-session-response010-results
```

기존 completion CLI 빌드를 사용한다. 새 결과 경로에 report.json/raw.jsonl을 보존하며,
CI artifact의 session-response010/에 코어 revision 및 실행 파일·fixture·원시 기록
해시를 함께 보관한다. 실패도 유지하며 과거 FAIL/NOT_RUN을 덮어쓰지 않는다.

다음은 **RFC9421 기반 HTTP 요청·응답 바인딩**이다. 실제 TLS/WS, 영속 replay
저장소·quarantine, 배포 registry 및 호스트 강제 경계 검증은 남아 있다.
현재 테스트 저장소는 트랜잭션 의무의 배포 증명이 아니며 전체 NOT_ESTABLISHED를 유지한다.
