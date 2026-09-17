# 0.10.0 HPKE 암호 파생 경로

B/T의 닫힌 형식, JCS, info/exportCtx, RFC9180 exporter, 두 참여자의 E2E DH와
seed·ACK를 연결했다. Go와 Rust 모두 기존 HPKE 라이브러리를 호출한다.
이 경로는 서명·레지스트리 권위·pending 만료를 검증하거나 세션을 확정하지 않는다.

고정 커밋: Go `8a700c851fe22c3e9e87c84c735cf78b3277d333`,
Rust `b3d610922d1f929ec687a40e666411c397f267ec`.

## 코어 계약

| 동작 | Go | Rust |
|---|---|---|
| B 검증과 도메인 계산 | BuildDomains010 | build_domains_010 |
| 송신자의 새 HPKE·C 키 생성 | StartInitiator010 | start_initiator_010 |
| 응답자의 고정 입력 파생 | DeriveResponder010 | derive_responder_010 |
| 응답자의 새 S 키·handle 생성과 파생 | RespondFresh010 | respond_fresh_010 |
| 보관한 송신자 재료로 T 검증·파생 | Initiator010.Derive | Initiator010::derive |

입력은 최대 16 KiB의 JSON 바이트다. 미등록·중복·누락·null·잘못된 타입과
추가 JSON 문서를 거부한다. B는 정확한 version/suite/combiner, UUIDv4,
16바이트 nonce, 지원하는 DID 문법과 소유자에 맞는 키 URL을 요구한다.
enc/ephC/ephS는 32바이트의 정규 unpadded base64url이어야 한다.
입력 형태 검사는 HPKE/DH 전에 수행한다. DH의 0 공유 결과도 거부한다.

B의 파생 문맥은 항상 코어가 재계산하며 peer가 제공한 info/exportCtx를 사용하지
않는다. T에는 원래 initiation 필드를 덮어쓰지 않고 ephS/kid만 추가한다.
송신자는 모든 원래 필드의 일치를 확인한 뒤 자신의 C 비밀키로 DH를 수행한다.
응답자는 자신의 S 비밀키로 같은 공유 비밀을 얻는다. 두 결과의 transcript,
th, seed, ACK와 sid가 일치해야 한다.

새 송신자 API는 HPKE 캡슐화와 C에 독립 난수를 사용한다. 새 응답자 API는 S와
UUIDv4 handle을 생성한다. 명시적 키를 받는 하위 응답자 API는 고정 벡터에도
사용하며, 운영 호출자는 새 독립 S 키와 handle을 공급해야 한다.
context/nonce의 생성·재사용 방지, 정확한 kemKid 공개 키 선택은 호출자 책임이다.
web DID의 구문 수락은 web 등록의 권위를 인정하거나 블록체인 정책을 대체하지 않는다.

송신자 재료는 한 번의 파생 시도 후 소비된다. Go는 잠금과 종료 표시를 사용하고
보관 byte buffer를 지운다. Rust는 self를 소비하며 비밀을 Zeroizing으로 소유한다.
Go는 포기 시 Close, Rust는 drop으로 정리한다. 라이브러리 내부 복사본까지
물리적으로 소거되었음을 증명하지는 않는다. 파생 성공 후에도 서명·현재 키·ACK·
pending 만료를 검사하기 전에는 보호된 작업이나 인증된 세션 생성에 사용할 수 없다.

## 유닛 테스트와 런타임 테스트

두 코어는 각각 60개 고정·경계 벡터를 실행한다. 정상 B/T 및 파생 결과는 기존
`hpke-schedule.json`의 독립 기대값에서 가져왔으며 원본 SHA-256과 revision을
기록한다. 부정 사례에는 잘못된 도메인, 키 URL, 중복 필드, 0/low-order DH 입력,
16 KiB 경계와 잘못된 private-key 길이가 포함된다. fixture 재현 검사는
`python3 scripts/generate_hpke_derivation010.py --check`로 수행한다.

추가 코어 유닛 테스트는 새 난수 교환, 임시 공개 키 중복 여부, 원래 필드 변경,
잘못된 KEM 키, 파생 시도 후 재사용 거부를 확인한다. 어댑터 유닛 테스트는
입력 오류에서 가짜 관측을 만들지 않는지, 인증 같은 미지원 연산이 미지원으로
남는지 확인한다.

실제 로컬 프로세스 테스트는 다음을 실행한다.

- Go/Rust 각 60개 고정 벡터: 총 120개.
- Go→Go, Go→Rust, Rust→Go, Rust→Rust: 정상 및 네 가지 transcript 거부 경로로 총 20개 교환.
- 로컬 제어의 null·타입·hex·누락·추가 필드·상태 부재: 총 12개 오류 경로.

네 조합 모두 실제 코어에서 새로운 HPKE/C/S 키를 만들고 JSON으로 전달한다.
인증된 transport나 실제 네트워크 배포 테스트는 아니다. 고정 테스트용 context,
nonce와 recipient 비밀키를 재사용하며 운영 재사용을 허용한다는 의미가 아니다.
테스트 프로세스는 최대 16개 요청·요청당 256 KiB로 제한되고 네트워크를 열지 않는다.
반환 seed는 공개 테스트 재료로부터 얻은 검사 결과이며 운영 로그 API가 아니다.

```sh
python3 scripts/test_hpke_derivation010.py \
  --go /absolute/path/sage-hpke010 \
  --rust /absolute/path/hpke010 \
  --output /absolute/path/new-results
```

[스크립트의 고정 커밋](../scripts/test_record010_adapters.py), 바이너리·fixture·
검증 스크립트 해시와 원시 요청/응답을 보고서에 남긴다. CI는 이 런타임 검사와
어댑터 유닛 테스트를 모두 수행하고 새 보고서를 별도 artifact로 보관한다.
기존 원시 증거와 source lock은 갱신하지 않는다.

## 남은 작업

암호 파생 경로의 연결을 완료했으므로 다음은 **REG-05의 요청별 권위 관측과
고정 키 선택**이다. 이후 인증 tuple·완료 서명과 pending 수명·응답자 첫 레코드
확인을 연결한다. 기존 `sage.hpke.derive` 연산은 완료 서명과 추가 내부 중간값까지
요구하는 별도 계약이므로 이번 부분 출력으로 PASS 처리하지 않는다.
서명·권위·상태가 필요한 사례는 계속 UNSUPPORTED/NOT_RUN이며, 전체 적합성은
NOT_ESTABLISHED다. 자세한 후속 범위는 [인증 세션 인계](authenticated-session-handoff.md)를 따른다.
