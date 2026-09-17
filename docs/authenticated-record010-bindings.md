# 인증된 세션 요청과 첫 레코드 확인

완료 결과가 생성 시점부터 private 레코드 상태를 소유한다. 호출자가 seed 또는
검증 boolean을 전달해 이 결과를 만드는 API는 없다. 두 코어의 session 요청
송수신을 CLI에 직접 연결하여 서명·고정 tuple·현재 키·AEAD를 확인한다.

지원 범위는 metadata/task 없는 session **요청**이며 역할·context를 명시한다.
양쪽 역할의 요청을 지원하지만 request_hash에 연결되는 response 형식이나
HTTP 서명·TLS·WebSocket은 이번 구현에 포함하지 않는다. JSON 32 KiB,
레코드 16384바이트, 평문 16348바이트로 제한하며 나머지는 거부한다.

응답자는 첫 유효 레코드 전에는 송신할 수 없다. 첫 순서는 0일 필요가 없다.
레코드의 서명·태그·tuple 실패 시 재전송 항목, 순서, 확인 상태가 변하지 않는다.
Go endpoint mutex 또는 Rust 배타 접근 안에서 저장소의 트랜잭션과 순서 소비,
ESTABLISHED 전환을 처리한 후에만 평문을 반환한다. 이후 애플리케이션 거부는
암호 수락을 취소하지 않으며 이 API는 보호된 작업을 실행하지 않는다.

필수 저장소 계약은 ID/nonce의 동시 검사·영속 예약 및 최종 시각 검사 callback이다.
실패 가능한 저장 작업은 callback 전에 수행하고, callback 실패 시 어느 항목도
게시하지 않아야 한다. 성공 후 추가 실패 단계 없이 두 항목을 영속화해야 한다.
코어는 마지막 경계에서 관측 나이·envelope/pending/session/키 만료를 검사한다.
callback 이후 프로세스가 중단되면 세션을 복구하지 않고 폐기한다. 영속 예약은
거부 상태로 유지한다. 이 계약을 구현하지 않은 저장소는 레코드 수신을 거부한다.
테스트용 제한된 메모리 저장소는 이 의무의 배포 검증을 대신하지 않는다.

공통 32개 사례를 코어별 유닛 테스트와 네 Go/Rust 조합의 **128개 실제 프로세스
검사**로 연결한다. 원본 요청·응답·완료 및 레코드 서명을 Node로 독립 검증하고,
프로세스가 반환한 평문·상태·예약 횟수와 실패 후 정상 재시도를 검사한다.
추가 유닛 검사는 provisional 시간을 포함한 절대 수명, 잘못된 입력의 idle 갱신
금지와 최대 크기 경계를 다룬다. Go는 동일 레코드 16개 동시 호출도 검증한다.
Rust는 배타 소유권으로 직렬화하며 멀티스레드 런타임 검사로 집계하지 않는다.

```sh
python3 scripts/test_authenticated_record010.py --go /tmp/sage-completion010-go --rust adapters/rust/target/debug/completion010 --output /tmp/new-authenticated-record010-results
```

기존 completion CLI 빌드를 사용한다. 결과는 새 경로의 report.json/raw.jsonl과
CI Record API bindings artifact의 authenticated-record010/에 보존한다.
실행 파일·fixture·원시 기록 해시와 코어 revision을 기록하며 실패도 보존한다.
과거 FAIL·NOT_RUN·고정 증거는 변경하지 않고 전체 NOT_ESTABLISHED를 유지한다.

다음 작업은 **session 응답의 원본 요청 해시·message_id 연결과 양방향 응답 계약**이다.
그 후 HTTP/WS 바인딩, 실제 영속 replay 저장소·quarantine 및 registry/호스트
배포 경계를 각각 검증해야 한다.
