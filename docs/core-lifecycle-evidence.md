# INS-11 코어 수명주기 잔여 검증

고정된 0.10.0 명세 revision `520e5ed9a896ff8ba8ade776484f41084957aaa2`에
대해 현행 Go·Rust 코어의 다섯 경계를 순서대로 확인했다. 판정은 **코어 증거 확인
`EVIDENCE_CHECKED`**, 전체 INS-11 및 프로토콜 적합성은 **`NOT_ESTABLISHED`**다.
원시 결과와 revision은 [증거 manifest](evidence/core-lifecycle/manifest.json)에
고정했다.

| 경계 | 관측 | 범위와 한계 |
|---|---|---|
| 종료/수신 | Go 0.10.0 `RecordSession010`의 인증 수신과 종료 중첩 32회가 `go test -race`에서 통과했다. 종료 후 미사용 레코드는 거부되고 seed는 지워졌다. Rust의 직접 레코드 API는 배타 `&mut self`이고, MCP owner의 실제 로컬 TCP 수신 종료 테스트는 통과했다. | Rust 직접 병행 호출은 `UNSUPPORTED`다. 과거 구형 Go `SecureSession`의 레이스 `FAIL`은 별도 역사적 발견으로 유지한다. 새 테스트가 그 API를 수정하거나 재검증하지 않았다. |
| 만료/admission | Go의 요청 만료 전·후 삽입, 최종 admission 전 보호 deadline, Rust의 ready-session 만료·최종 deadline 테스트 통과. | 주입한 시계와 로컬 실행 경계이며 실제 Registry Source의 최종성 관측은 다음 단계다. |
| stale completion | Go와 Rust의 READY 이후 늦은 setup 완료 테스트 통과. | 고정 코어 구현에 대한 단위 증거다. |
| replay/quarantine 복구 | 양쪽 코어의 journal 벡터·고장 테스트 통과. 별도 프로세스 journal 시나리오 24건과 Go/Go·Go/Rust·Rust/Go·Rust/Rust 재시작 20건 통과. | 합성된 임시 journal과 주입 시계이며 전원 차단·실제 배포 저장장치 보증은 아니다. |
| reservation/close | 두 코어의 close-before-reservation, fence 중 close, durable 결과 보존·효과 0 또는 1의 경계 테스트 통과. Rust 로컬 TCP 보호 요청 테스트도 통과. | 모든 가능한 스케줄의 형식적 선형화 증명은 아니다. |

Go는 `go test -race -count=1 -v`로 세 패키지에서 아래 checker의 핵심
수명주기 테스트 10개를 선별했고, Rust는 `cargo test --lib`로 검증했다.
Go 세 패키지의 전체 race 테스트도 통과했으나, 그 출력에는 테스트가 생성한
임시 공유 비밀값이 있어 증거 묶음에는 넣지 않았다. 저장된 선별 로그는 각각
gzip 압축했고 Inspector의 checker가 필요한 테스트의 PASS 원문과 전체 실행
종료, 해시를 재확인한다. replay 실행은 격리된 로컬 자식 프로세스와 임시 파일만
사용했다. 원시 process 입력·출력과 journal 전후 스냅샷도 checker가 해시로
대조한다. 공격 재현 도구와 호스트 우회 코드는 실행하지 않았다.
기존 replay 실행기의 하드코딩된 과거 core pin과 현재 revision이 달라 실행에는
`--development`를 사용했다. 저장된 증거 checker는 대신 보고서에 기록한 양쪽
core revision과 출력 해시를 현재 단계의 독립 기준으로 고정한다.

구형 Go `SecureSession`의 과거 데이터 레이스 `FAIL`, Rust의 직접 병행 close
`UNSUPPORTED`, 별도의 역사적 lifecycle 37건 `NOT_RUN`은 그대로 보존한다.
이들을 현행 레코드 API의 PASS나 457개 부모 사례에 합산하지 않는다. 다음 고정
순서는 실제 Registry Source와 체인 관측이며, 이어서 호스트 집행과 최종 판정을
수행한다.

```sh
python3 -B scripts/test_core_lifecycle_evidence.py
python3 -B scripts/check_core_lifecycle_evidence.py
```
