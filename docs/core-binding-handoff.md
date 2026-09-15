# Transcript 세션 연결 인계

2026-09-16에 로컬 코어 소스와 Inspector 연결 지점을 읽기 전용으로 검토했다.
실제 코어 실행이나 적합성 재판정을 수행하지 않았다. 다음 구현의 선행 조건을
정리한 문서이며 새로운 규범이나 특정 언어의 공개 함수 이름을 요구하지 않는다.

## 현재 연결 가능 여부

| 코어 | 확인한 revision | 고정 소스 대조 | 현재 생성 API |
|---|---|---|---|
| Go sage | c7709b7486e0da94336edc0931fddd87f6a45343 | 308개 파일 해시 동일 | NewSecureSessionFromExporterWithRole(sid, exporter, initiator, cfg) |
| Rust rs-sage-core | 206bbbb5a66667ae2feb3b0e9991ed1ca4622bb2 | 78개 파일 해시 동일 | SecureSession::from_exporter_with_role(session_id, exporter, is_initiator, config) |

근거는 `docs/evidence/core-source-lock.json`과 현재 checkout의 대조다. Go의 기존
미추적 contracts/는 남아 있으며 이 대조에 포함하지 않는다. Rust 작업 트리는 깨끗하다.
전체 미추적 파일이나 런타임 환경의 동일성까지 보증하는 대조는 아니다.

Go `pkg/agent/session/session.go`의 생성자와 directional derivation,
Rust `src/session/secure_session.rs`의 생성자·build는 transcript hash 입력 없이
sid를 salt로 사용하는 기존 키 파생을 연결한다. `th`를 받는 0.10.0 API를 이 경로에
연결할 수 없다. Inspector의 `adapters/go/session.go`와
`adapters/rust/src/session_checks.rs`는 기존 API를 투영한다. 입력의 th 길이를
검사하는 것만으로 transcript 바인딩이 구현되는 것은 아니다.

## 코어가 제공해야 할 동작

규범 원본은 고정된 `sage-spec/spec/05-session.md` SESSION-01..03이다.

| 규범 | 필요한 코어 동작 | Inspector 인계 조건 |
|---|---|---|
| SESSION-01 | 32-byte seed·th, 고정 역할과 인증된 tuple 보존, th로부터 sid 도출 | 기존 exporter 경로와 구별되는 실제 API 및 입력 검증 계약 |
| SESSION-02 | seed를 PRK로 사용하는 HKDF-Expand, 방향·th·세대 g를 info에 결합 | 기존 salt/extract 방식으로 우회하지 않고 고정 키 벡터와 일치 |
| SESSION-03 | 8-byte seq·고정 nonce·암호문·tag, th와 방향 등을 포함한 AAD | 코어가 직접 wire/AAD를 구성·검증하고 크기 경계 적용 |
| SESSION-01 / REG-05 | 인증 tuple·선택 키와 현재 상태를 확인 | 저수준 레코드 성공과 별도 연결·판정. 없는 관측은 미연결로 보존 |

Inspector는 입력 전달, 바이트 인코딩, 코어 오류의 보고 변환을 맡는다. 어댑터에서
부족한 키 파생·AAD 조립·tuple 검사·재전송 필터를 대신 구현하지 않는다.
th를 callerAAD에 임의로 덧붙여 기존 API를 호출하거나 sid 인자로만 전달하는 것도
규범상의 키 파생과 AAD 계약을 대체하지 못한다.

## 연결 후 검증 순서

1. 코어별 새 revision과 실제 변경 파일, 공개 API 및 오류 계약을 다시 검토한다.
   현재 source lock은 과거 실행 근거이므로 새 코어에 맞춰 조용히 덮어쓰지 않는다.
2. `session-records.json`의 c2s/s2c-key-* 및 open-*로 초기값과
   255/256·511/512·767/768·999 세대 경계를 확인한다. 기대값은 기존 독립 자료를
   사용한다. 정상이 실패하면 잘못된 입력 거부만으로 방어 통과를 주장하지 않는다.
3. transcript 사례와 정상 c2s-open-0의 대응 관계를 검증한다. th 외의 입력을
   고정하고 수락/거부를 구분하며, 누락되거나 다른 결과를 PASS로 바꾸지 않는다.
4. aad-open/seal-4033/4034, nonce-valid-tag, seq-1000, reflection 및 크기
   벡터로 각 계약을 구분한다. 현 범위에서는 시나리오 단위 테스트를 중심으로 하고,
   실제 실행은 공격 기능을 만들지 않는 제한된 경로에만 적용한다.
5. 완성된 0.10.0 송신과 수신을 같은 프로파일로 연결한다. 기존 레코드와 새로운
   수신기를 혼합해 실패를 transcript 방어 성공으로 기록하지 않는다.
6. 정상과 다른 th의 관측을 같은 bound API에서 쌍으로 확보한 뒤 양방향 교환
   결과를 판정한다. tuple·레지스트리·수명·호스트 보안은 각각 별도 증거가 필요하다.

현재 `pkg/conformance/exchange.go`는 legacy open을 정상 대조군에 사용하고,
transcript 변경 경로에만 `sage.session.record.open.bound`를 요청한다.
이 구조는 현재 미지원 상태를 표시하는 용도다. 새로운 코어를 연결할 때는
**bound 정상 대조군과 같은 프로파일의 송신 연결을 먼저 추가해야 한다.**
단순히 bound 분기만 구현하고 기존 정상 대조군을 재사용해서는 충분하지 않다.
어댑터의 새 연산명과 입력 확장은 이 계약을 검토할 때 결정한다.

## 다음 작업과 완료 조건

| 순서 | 소유 위치 | 작업 | 착수/완료 조건 |
|---|---|---|---|
| 1 | sage, rs-sage-core | 0.10.0 세션 API 구현 | 별도 코어 작업. 이번 Inspector 변경에 포함하지 않음 |
| 2 | sage-inspector | 실제 API에 맞춘 어댑터 연결 및 정상 bound 대조군 | 새 코어 revision·API 제공 후 착수 |
| 3 | sage-inspector | 독립 벡터 및 안전한 교환 경로 실행 | 정상·변경 입력의 개별 결과와 원시 증거 보존 |
| 4 | 각 코어 및 Inspector | HPKE 확인·HTTP/WS·수명·복구 연결 | 레코드 바인딩 완료와 구분하여 추적 |
| 5 | 호스트 통합 프로젝트 및 Inspector | 신뢰된 관측과 배포 적합성 | 호스트/관측 계약 제공 후 범위 검토 |

연결되지 않은 기능의 UNSUPPORTED/NOT_RUN, 과거 코어 FAIL과 전체
NOT_ESTABLISHED는 유지한다. 이번 인계 완료는 실제 연결 또는 INS-11 완료가 아니다.
