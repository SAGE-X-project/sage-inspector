# INS-02 실제 코어 어댑터 연결

2026-09-14. 기반 프로파일의 실제 Go/Rust 호출, 기능 매핑 및 결과 기록 완료.
이 단계는 0.10.0 전체 적합성 판정이 아니다. 코어의 소스는 변경하지 않았다.

## 연결 범위

| 연산 | Go sage | Rust rs-sage-core |
|---|---|---|
| json.syntax | `pkg/agent/crypto/jcs.Canonicalize`의 오류 여부 | `jcs::canonicalize`의 오류 여부 |
| sha256 | UNSUPPORTED: 이 어댑터에서 대응 코어 API를 연결하지 않음 | `hpke::sha256_hash_hex` |
| hkdf-sha256 | UNSUPPORTED: 내부 HKDF는 공개 범용 extract/expand 계약과 다름 | UNSUPPORTED: combiner/hmac_expand는 범용 HKDF 계약과 다름 |
| base64url-raw.decode | UNSUPPORTED: 대응 독립 코어 API 미연결 | UNSUPPORTED: 대응 독립 코어 API 미연결 |

UNSUPPORTED는 이 연산 계약으로 관측할 수 없다는 뜻이다. 코어에 암호/인코딩 기능이
전혀 없다는 뜻이 아니다. 어댑터에서 표준 라이브러리 암호 연산으로 대체하지 않는다.
JSON 시험은 원시 바이트를 코어에 전달한다. 외부 요청 JSON만 파싱하고 내부 문서의
중복 키나 숫자를 정규화하지 않는다. canonicalization 출력의 정확성은 INS-03 대상이다.

## 고정한 주체와 결과

| 주체 | revision | PASS | FAIL | UNSUPPORTED |
|---|---|---:|---:|---:|
| Go | c7709b7486e0da94336edc0931fddd87f6a45343 | 5 | 4 | 17 |
| Rust | 206bbbb5a66667ae2feb3b0e9991ed1ca4622bb2 | 8 | 2 | 16 |

둘 다 전체 결과 FAIL, 명령 종료 코드 1이다. 실패는 코어 수정 필요성을 보여주는
관측이며 Inspector 테스트 실행 실패나 미지원으로 숨기지 않는다.

| 실패 입력 | Go 관측 | Rust 관측 | 0.10.0 기대 |
|---|---|---|---|
| json-duplicate | ACCEPT | REJECT | REJECT |
| json-unpaired | ACCEPT | REJECT | REJECT |
| json-negative-zero | ACCEPT | ACCEPT | REJECT |
| json-negative-underflow | ACCEPT | ACCEPT | REJECT |

[Go 보고서](evidence/core-go.json), [Rust 보고서](evidence/core-rust.json)는
기대/실제 결과, 입력 해시, 실행 파일 해시를 담는다.
[소스 고정 기록](evidence/core-source-lock.json)은 실제 참조한 checkout의 revision,
상태 및 추적된 Go/Rust 소스·의존성 파일 해시를 담는다. Go에는 기존 미추적 contracts/
디렉터리가 있으나 JCS 빌드에 포함하지 않았다. Rust는 깨끗한 checkout이었다.
빌드는 임시 작업 디렉터리에서 형제 코어 경로를 연결하여 수행했다.
Rust의 최초 오프라인 빌드는 캐시 부재로 실패했고, 공개 의존성 다운로드 후
Cargo.lock을 생성하고 `--offline --locked` 재빌드를 통과했다.

## 빌드 및 재현

저장소들을 sage-inspector와 형제 디렉터리로 배치한다. 각 어댑터는 별도 모듈이므로
Inspector의 기존 go.mod 또는 코어의 의존성 파일을 변경하지 않는다.
먼저 소스 고정 기록과 현재 checkout을 대조한다. 변경되었으면 새로운 revision과
새 증거를 기록한다. 아래 REVISION은 실제 checkout의 값으로 제공한다.

```sh
(cd adapters/go && go build -o /tmp/sage-go-adapter .)
(cd adapters/rust && cargo build --locked --target-dir /tmp/sage-rust-target)
go build -o /tmp/sage-conformance ./cmd/sage-conformance
/tmp/sage-conformance -suite vectors/0.10.0/foundation.json \
  -adapter /tmp/sage-go-adapter -subject sage-go -revision REVISION -report go-report.json
/tmp/sage-conformance -suite vectors/0.10.0/foundation.json \
  -adapter /tmp/sage-rust-target/debug/sage-inspector-rust-adapter \
  -subject rs-sage-core -revision REVISION -report rust-report.json
python3 scripts/test_core_adapters.py /tmp/sage-go-adapter \
  /tmp/sage-rust-target/debug/sage-inspector-rust-adapter
```

코어가 반환한 문서 오류만 REJECT로 변환한다. 잘못된 어댑터 요청/hex 등은 비정상
종료하므로 Inspector가 FAIL로 판정한다. 입력에 expected 필드를 추가하면 거부한다.
어댑터별 6개 전송/오류 검사 및 Go vet를 통과했다.

## 후속 기능 차이 조사

| 기능 | 발견한 구현 위치 | 남은 증거 / 소유 작업 |
|---|---|---|
| JCS·서명 | Go crypto/jcs 및 crypto/keys, Rust jcs 및 crypto | 위 거부 차이는 코어 수정 작업으로 인계; 정규 출력·엄격 서명 벡터는 INS-03 |
| RFC9421 | Go core/rfc9421, Rust rfc9421 | 필수 필드·응답 연결·크기와 오류 경로는 INS-04, 아직 NOT_RUN |
| HPKE | Go hpke, Rust hpke | 공개 조합 함수가 있다고 0.10.0 일치를 주장하지 않음; INS-06 |
| 세션 | Go session, Rust session | 임시 세션·키 고정·경합·만료는 INS-05/07의 상태 계약 필요 |
| DID/레지스트리 | Go did, Rust did | 실제 배포 바인딩과 현재 상태 관측은 INS-08 |
| Execution Guard | 별도 검증 계약 필요 | 원본/정책/ledger/효과 증거는 INS-09/11; 이번 어댑터로 인증하지 않음 |

기존 386개 사례의 NOT_RUN 상태를 이번 부분 실행으로 일괄 변경하지 않는다.
다음 선행 작업은 INS-05 상태 유지 계약이며, INS-03 벡터 확장은 독립적으로 진행 가능하다.
