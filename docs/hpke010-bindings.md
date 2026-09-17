# 0.10.0 HPKE seed·ACK 파생 연결

새 코어 API는 HPKE-03의 combiner와 ACK 파생을 제공한다. 기존 v1 handshake와
legacy `sage.hpke.combine` 관측은 유지한다. 이번 연결은 seed/ACK primitive
범위이며 `sage.hpke.derive`의 전체 B/T·HPKE·완료 서명 계산이나 인증된 완료,
레지스트리 관측, pending 상태 전환을 구현한 것으로 표시하지 않는다.

고정 커밋: Go `ff31edd485644a37cb4d27b94e029cf97ea5a14b`,
Rust `768fde4d368635363ddd4b810a3ffac93079f98b`.

## 코어 API와 입력 계약

| 연산 | Go | Rust | 입력과 결과 |
|---|---|---|---|
| sage.hpke.schedule010.combine | CombineSecrets010 | combine_secrets_010 | exporter_hex, ss_e2e_hex, th_hex → seed_hex |
| sage.hpke.schedule010.ack | MakeAckTag010 | make_ack_tag_010 | seed_hex, th_hex → ack_tag_hex |
| sage.hpke.schedule010.verify | VerifyAckTag010 | verify_ack_tag_010 | seed_hex, th_hex, ack_tag_hex → valid:true 또는 REJECT |

모든 바이너리 입력은 32바이트다. combiner는 0 E2E 공유 비밀도 거부한다.
ACK 비교는 일정 시간 비교 함수를 사용한다. 길이가 맞는 exporter 자체가
0이라는 이유로 DH 실패로 해석하지 않는다. HPKE KEM의 0 공유 결과 거부는
exporter를 생성하는 상위 API의 책임이다. th 역시 검증된 T의 JCS 해시라는
전제가 필요하며 이 primitive는 임의 입력의 인증 여부를 판별하지 않는다.

어댑터는 코어를 직접 호출하며 HKDF/HMAC이나 0 결과 방어를 대신 구현하지 않는다.
잘못된 hex·필드 누락·null·타입·추가 필드는 IPC 오류로 종료한다. 올바른 hex로
표현된 잘못된 길이와 변조된 ACK는 코어가 거부하며 출력은 빈 객체다.
seed/ACK 출력은 공개 고정 벡터 검증용이다. 운영 비밀의 로그 출력을 위한 API가 아니다.

코어는 임시 IKM/PRK/ACK 키를 가능한 범위에서 지우고, Rust 반환 seed에는
Zeroizing을 적용한다. Go 반환 seed의 수명과 소거는 호출자 책임이다. 라이브러리
내부 상태·복사본까지 물리적으로 소거됨을 증명하는 검증은 수행하지 않았다.

## 독립 기대값과 검증

기존 `vectors/0.10.0/hpke-schedule.json`의 schedule-0/1/2에서 기대 seed와
ACK를 그대로 읽는다. 두 코어의 단위 테스트 fixture도 같은 값과 원본 SHA-256,
Inspector revision을 기록한다. 기대값을 코어 실행으로 재생성하지 않는다.
기존 Node 독립 감사는 67개 HPKE 사례와 6개 수명 fixture를 검산한다.

- 코어 단위 테스트: 고정 기대값 3개, 각 ACK의 모든 바이트 변조, transcript 변경,
  입력 길이 경계, 0 공유 비밀 거부, v1 seed와의 차이를 확인한다.
- 실제 로컬 어댑터: 코어별 152개 primitive 호출과 30개 제어 오류를 검증한다.
  정상 결과뿐 아니라 seed/th/ACK 변조 거부도 실제 코어 응답으로 확인한다.
- 기존 HPKE 회귀 테스트와 새 revision의 레코드 연결 테스트를 함께 검증한다.
  네트워크 공격·실제 호스트 우회·취약점 재현 프로그램은 실행하지 않는다.

```sh
python3 scripts/test_hpke010_adapters.py \
  --go /absolute/path/go-adapter \
  --rust /absolute/path/rust-adapter \
  --output /absolute/path/new-results
```

스크립트는 [현재 고정 커밋](../scripts/test_record010_adapters.py)의 실제 HEAD와
tracked source 무변경을 확인하고, 바이너리·원본 fixture 해시, 각 요청과 stdout,
stderr 및 종료 코드를 별도 보고서에 기록한다. 출력 디렉터리 재사용과 과거 증거
디렉터리 쓰기를 거부한다. CI도 새 보고서를 artifact에 보관한다.

이전 [레코드 연결 기록](record010-bindings.md)의 revision은 당시 실행 기준이다.
현재 CI는 HPKE 변경을 포함한 후속 커밋으로 레코드 회귀 검사도 수행한다.
과거 통합 보고서·실패·source lock을 새 결과로 덮어쓰지 않는다.
386개 규범 계획 사례는 NOT_RUN, 전체 적합성은 NOT_ESTABLISHED로 유지한다.

## 남은 연결

[인증 세션 인계](authenticated-session-handoff.md)의 파생 항목 중 seed/ACK가
완료되었다. 다음은 **B/T의 닫힌 형식과 도메인 바인딩, RFC9180 exporter 및
양쪽 E2E DH를 묶는 0.10.0 파생 경로**다. 그 뒤 요청별 권위 관측·고정 키 tuple,
인증된 완료·pending 수명·응답자 첫 레코드 원자적 확인을 연결한다.
전체 `sage.hpke.derive`와 완료 검증은 연결 전까지 UNSUPPORTED를 유지한다.
