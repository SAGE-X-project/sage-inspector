# INS-01 명세 기준선과 사례 추적표

작성일: 2026-09-14. INS-01 완료. 실행 적합성 판정은 아직 하지 않았다.

## 고정한 입력

`verification/0.10.0/snapshot.json`은 규범 출처와 추적/검토 자료의 파일별 SHA-256을 고정한다.
`snapshot/`은 재현을 위한 당시 바이트 보관본이며, 규범 원본은 sage-spec이다.
원본 작업 트리가 수정된 상태이므로 Git HEAD만으로 동일성을 주장하지 않는다.

## 검증 분류

원본 mode를 보존하고 Inspector가 필요한 검증 경로를 추가했다. 복수 경로는 모두 필요하다.
문서·배포 검토로 분류되었던 버전/값 검사도 실행 증거를 요구하며, 호스트 보안은 배포 증거를 함께 요구한다.

| 경로 조합 | 사례 수 |
|---|---:|
| document_review | 18 |
| runtime | 328 |
| runtime/deployment_review | 29 |
| runtime/document_review | 8 |
| runtime/document_review/deployment_review | 3 |

45개 요구사항 → 77개 규칙 → 386개 사례를 모두 보존했다. 전 사례는 `NOT_RUN`이다.
26개 기반 벡터 중 11개를 구체 사례의 부분 검사로 연결했다.
이는 8개 계획 사례와 연결되며, 나머지 378개 사례에는 연결된 구체 벡터가 없다.
연결되지 않은 벡터도 primitive_prerequisite_only로 모두 기록한다.
부분 연결도 원래 시나리오 전체나 실제 코어의 통과를 의미하지 않는다.
특히 SHA-256 abc는 CRYPTO-02 관련 태그를 보존하되 서명 사례에 연결하지 않는다.

## 재검증

저장소 루트에서 다음을 실행한다. Python 표준 라이브러리만 사용한다.

```sh
python3 scripts/check_spec_baseline.py
python3 scripts/check_spec_baseline.py --spec ../sage-spec
```

첫 명령은 보관본·벡터 해시, 중복/누락 ID, 양방향 요구사항/규칙/사례 연결을 확인한다.
두 번째는 현재 명세와의 변경도 검출한다. 실패 시 기존 기준선을 자동 갱신하지 말고 변경을 검토한다.
이 검사는 파일 무결성/매핑 검사이며 서명된 공급망 증명이나 보안성 인증은 아니다.

## 사례 목록

전체 필드와 벡터별 한계는 [case-map.json](../verification/0.10.0/case-map.json)에 있다.

| 사례 | 검증 경로 | 부분 벡터 |
|---|---|---|
| OVERVIEW-01-P | document_review | 없음 |
| OVERVIEW-01-N01 | document_review | 없음 |
| OVERVIEW-02-P | document_review | 없음 |
| OVERVIEW-02-N01 | document_review | 없음 |
| OVERVIEW-03-P | runtime, document_review | 없음 |
| OVERVIEW-03-N01 | runtime, document_review | 없음 |
| OVERVIEW-03-N02 | runtime, document_review | 없음 |
| OVERVIEW-03-N03 | runtime, document_review | 없음 |
| OVERVIEW-04-P | document_review | 없음 |
| OVERVIEW-04-N01 | document_review | 없음 |
| CRYPTO-01-P | runtime | 없음 |
| CRYPTO-01-N01 | runtime | 없음 |
| CRYPTO-01-N02 | runtime | 없음 |
| CRYPTO-01-N03 | runtime | 없음 |
| CRYPTO-01-N04 | runtime | 없음 |
| CRYPTO-02-P | runtime | 없음 |
| CRYPTO-02-N01 | runtime | 없음 |
| CRYPTO-02-N02 | runtime | 없음 |
| CRYPTO-02-N03 | runtime | 없음 |
| CRYPTO-02-N04 | runtime | 없음 |
| CRYPTO-02-N05 | runtime | 없음 |
| CRYPTO-03-P | runtime | 없음 |
| CRYPTO-03-N01 | runtime | 없음 |
| CRYPTO-03-N02 | runtime | 없음 |
| CRYPTO-03-N03 | runtime | 없음 |
| CRYPTO-03-N04 | runtime | 없음 |
| CRYPTO-04-P | runtime | 없음 |
| CRYPTO-04-N01 | runtime | 없음 |
| CRYPTO-04-N02 | runtime | 없음 |
| CRYPTO-04-N03 | runtime | 없음 |
| CRYPTO-05-P | runtime, deployment_review | 없음 |
| CRYPTO-05-N01 | runtime, deployment_review | 없음 |
| CRYPTO-05-N02 | runtime, deployment_review | 없음 |
| CRYPTO-05-N03 | runtime, deployment_review | 없음 |
| JCS-01-P | runtime | json-valid, json-valid-surrogate-pair |
| JCS-01-N01 | runtime | json-duplicate |
| JCS-01-N02 | runtime | json-bom |
| JCS-01-N03 | runtime | json-unpaired |
| JCS-01-N04 | runtime | 없음 |
| JCS-01-N05 | runtime | json-negative-zero |
| JCS-01-N06 | runtime | json-negative-underflow |
| JCS-02-P | runtime | 없음 |
| JCS-02-N01 | runtime | 없음 |
| JCS-02-N02 | runtime | 없음 |
| JCS-02-N03 | runtime | 없음 |
| JCS-02-N04 | runtime | 없음 |
| JCS-03-P | runtime | 없음 |
| JCS-03-N01 | runtime | 없음 |
| JCS-03-N02 | runtime | 없음 |
| JCS-03-N03 | runtime | 없음 |
| JCS-04-P | runtime | 없음 |
| JCS-04-N01 | runtime | 없음 |
| JCS-04-N02 | runtime | 없음 |
| JCS-04-N03 | runtime | 없음 |
| MSG-01-P | runtime | 없음 |
| MSG-01-N01 | runtime | 없음 |
| MSG-01-N02 | runtime | 없음 |
| MSG-01-N03 | runtime | 없음 |
| MSG-01-N04 | runtime | 없음 |
| MSG-02-P | runtime | 없음 |
| MSG-02-N01 | runtime | 없음 |
| MSG-02-N02 | runtime | 없음 |
| MSG-02-N03 | runtime | 없음 |
| MSG-02-N04 | runtime | 없음 |
| MSG-02-N05 | runtime | 없음 |
| MSG-03-P | runtime | 없음 |
| MSG-03-N01 | runtime | 없음 |
| MSG-03-N02 | runtime | 없음 |
| MSG-03-N03 | runtime | 없음 |
| MSG-03-N04 | runtime | 없음 |
| MSG-04-P | runtime | 없음 |
| MSG-04-N01 | runtime | 없음 |
| MSG-04-N02 | runtime | 없음 |
| MSG-04-N03 | runtime | 없음 |
| MSG-04-N04 | runtime | 없음 |
| MSG-04-N05 | runtime | 없음 |
| MSG-05-P | runtime | 없음 |
| MSG-05-N01 | runtime | 없음 |
| MSG-05-N02 | runtime | 없음 |
| MSG-05-N03 | runtime | 없음 |
| MSG-05-N04 | runtime | 없음 |
| MSG-05-N05 | runtime | 없음 |
| MSG-06-P | runtime | 없음 |
| MSG-06-N01 | runtime | 없음 |
| MSG-06-N02 | runtime | 없음 |
| MSG-06-N03 | runtime | 없음 |
| HPKE-01-P | runtime | 없음 |
| HPKE-01-N01 | runtime | 없음 |
| HPKE-01-N02 | runtime | 없음 |
| HPKE-01-N03 | runtime | 없음 |
| HPKE-02-P | runtime | 없음 |
| HPKE-02-N01 | runtime | 없음 |
| HPKE-02-N02 | runtime | 없음 |
| HPKE-02-N03 | runtime | 없음 |
| HPKE-02-N04 | runtime | 없음 |
| HPKE-03-P | runtime | hkdf-a1, hkdf-a2, hkdf-a3 |
| HPKE-03-N01 | runtime | 없음 |
| HPKE-03-N02 | runtime | 없음 |
| HPKE-03-N03 | runtime | 없음 |
| HPKE-03-N04 | runtime | 없음 |
| HPKE-04-P | runtime | 없음 |
| HPKE-04-N01 | runtime | 없음 |
| HPKE-04-N02 | runtime | 없음 |
| HPKE-04-N03 | runtime | 없음 |
| HPKE-04-N04 | runtime | 없음 |
| HPKE-05-P | runtime | 없음 |
| HPKE-05-N01 | runtime | 없음 |
| HPKE-05-N02 | runtime | 없음 |
| HPKE-05-N03 | runtime | 없음 |
| HPKE-05-N04 | runtime | 없음 |
| HPKE-06-P | runtime | 없음 |
| HPKE-06-N01 | runtime | 없음 |
| HPKE-06-N02 | runtime | 없음 |
| HPKE-06-N03 | runtime | 없음 |
| HPKE-06-N04 | runtime | 없음 |
| SESSION-01-P | runtime | 없음 |
| SESSION-01-N01 | runtime | 없음 |
| SESSION-01-N02 | runtime | 없음 |
| SESSION-01-N03 | runtime | 없음 |
| SESSION-02-P | runtime | 없음 |
| SESSION-02-N01 | runtime | 없음 |
| SESSION-02-N02 | runtime | 없음 |
| SESSION-02-N03 | runtime | 없음 |
| SESSION-02-N04 | runtime | 없음 |
| SESSION-03-P | runtime | 없음 |
| SESSION-03-N01 | runtime | 없음 |
| SESSION-03-N02 | runtime | 없음 |
| SESSION-03-N03 | runtime | 없음 |
| SESSION-03-N04 | runtime | 없음 |
| SESSION-03-N05 | runtime | 없음 |
| SESSION-04-P | runtime | 없음 |
| SESSION-04-N01 | runtime | 없음 |
| SESSION-04-N02 | runtime | 없음 |
| SESSION-04-N03 | runtime | 없음 |
| SESSION-05-P | runtime | 없음 |
| SESSION-05-N01 | runtime | 없음 |
| SESSION-05-N02 | runtime | 없음 |
| SESSION-05-N03 | runtime | 없음 |
| SESSION-05-N04 | runtime | 없음 |
| SESSION-06-P | runtime | 없음 |
| SESSION-06-N01 | runtime | 없음 |
| SESSION-06-N02 | runtime | 없음 |
| SESSION-06-N03 | runtime | 없음 |
| SESSION-06-N04 | runtime | 없음 |
| SESSION-06-N05 | runtime | 없음 |
| ID-01-P | runtime | 없음 |
| ID-01-N01 | runtime | 없음 |
| ID-01-N02 | runtime | 없음 |
| ID-01-N03 | runtime | 없음 |
| ID-01-N04 | runtime | 없음 |
| ID-01-N05 | runtime | 없음 |
| ID-02-P | runtime | 없음 |
| ID-02-N01 | runtime | 없음 |
| ID-02-N02 | runtime | 없음 |
| ID-02-N03 | runtime | 없음 |
| ID-03-P | runtime | 없음 |
| ID-03-N01 | runtime | 없음 |
| ID-03-N02 | runtime | 없음 |
| ID-03-N03 | runtime | 없음 |
| ID-03-N04 | runtime | 없음 |
| ID-03-N05 | runtime | 없음 |
| ID-04-P | runtime | 없음 |
| ID-04-N01 | runtime | 없음 |
| ID-04-N02 | runtime | 없음 |
| ID-04-N03 | runtime | 없음 |
| CARD-01-P | runtime | 없음 |
| CARD-01-N01 | runtime | 없음 |
| CARD-01-N02 | runtime | 없음 |
| CARD-01-N03 | runtime | 없음 |
| CARD-01-N04 | runtime | 없음 |
| CARD-01-N05 | runtime | 없음 |
| CARD-02-P | runtime | 없음 |
| CARD-02-N01 | runtime | 없음 |
| CARD-02-N02 | runtime | 없음 |
| CARD-02-N03 | runtime | 없음 |
| CARD-02-N04 | runtime | 없음 |
| CARD-03-P | runtime | 없음 |
| CARD-03-N01 | runtime | 없음 |
| CARD-03-N02 | runtime | 없음 |
| CARD-03-N03 | runtime | 없음 |
| CARD-03-N04 | runtime | 없음 |
| TRANSPORT-01-P | runtime | 없음 |
| TRANSPORT-01-N01 | runtime | 없음 |
| TRANSPORT-01-N02 | runtime | 없음 |
| TRANSPORT-01-N03 | runtime | base64-reject-padded |
| TRANSPORT-01-N04 | runtime | 없음 |
| TRANSPORT-02-P | runtime | 없음 |
| TRANSPORT-02-N01 | runtime | 없음 |
| TRANSPORT-02-N02 | runtime | 없음 |
| TRANSPORT-02-N03 | runtime | 없음 |
| TRANSPORT-02-N04 | runtime | 없음 |
| TRANSPORT-03-P | runtime | 없음 |
| TRANSPORT-03-N01 | runtime | 없음 |
| TRANSPORT-03-N02 | runtime | 없음 |
| TRANSPORT-03-N03 | runtime | 없음 |
| TRANSPORT-03-N04 | runtime | 없음 |
| TRANSPORT-03-N05 | runtime | 없음 |
| TRANSPORT-03-N06 | runtime | 없음 |
| TRANSPORT-04-P | runtime | 없음 |
| TRANSPORT-04-N01 | runtime | 없음 |
| TRANSPORT-04-N02 | runtime | 없음 |
| TRANSPORT-04-N03 | runtime | 없음 |
| TRANSPORT-04-N04 | runtime | 없음 |
| TRANSPORT-05-P | runtime | 없음 |
| TRANSPORT-05-N01 | runtime | 없음 |
| TRANSPORT-05-N02 | runtime | 없음 |
| TRANSPORT-05-N03 | runtime | 없음 |
| TRANSPORT-06-P | runtime | 없음 |
| TRANSPORT-06-N01 | runtime | 없음 |
| TRANSPORT-06-N02 | runtime | 없음 |
| TRANSPORT-06-N03 | runtime | 없음 |
| TRANSPORT-06-N04 | runtime | 없음 |
| REG-01-P | runtime | 없음 |
| REG-01-N01 | runtime | 없음 |
| REG-01-N02 | runtime | 없음 |
| REG-01-N03 | runtime | 없음 |
| REG-01-N04 | runtime | 없음 |
| REG-02-P | runtime | 없음 |
| REG-02-N01 | runtime | 없음 |
| REG-02-N02 | runtime | 없음 |
| REG-02-N03 | runtime | 없음 |
| REG-03-P | runtime | 없음 |
| REG-03-N01 | runtime | 없음 |
| REG-03-N02 | runtime | 없음 |
| REG-03-N03 | runtime | 없음 |
| REG-03-N04 | runtime | 없음 |
| REG-04-P | runtime | 없음 |
| REG-04-N01 | runtime | 없음 |
| REG-04-N02 | runtime | 없음 |
| REG-04-N03 | runtime | 없음 |
| REG-04-N04 | runtime | 없음 |
| REG-05-P | runtime | 없음 |
| REG-05-N01 | runtime | 없음 |
| REG-05-N02 | runtime | 없음 |
| REG-05-N03 | runtime | 없음 |
| REG-05-N04 | runtime | 없음 |
| REG-05-N05 | runtime | 없음 |
| REG-06-P | runtime, deployment_review | 없음 |
| REG-06-N01 | runtime, deployment_review | 없음 |
| REG-06-N02 | runtime, deployment_review | 없음 |
| REG-06-N03 | runtime, deployment_review | 없음 |
| REG-06-N04 | runtime, deployment_review | 없음 |
| REG-07-P | runtime | 없음 |
| REG-07-N01 | runtime | 없음 |
| REG-08-P | runtime | 없음 |
| REG-08-N01 | runtime | 없음 |
| REG-08-N02 | runtime | 없음 |
| REG-08-N03 | runtime | 없음 |
| REG-08-N04 | runtime | 없음 |
| RESOLVE-01-P | runtime | 없음 |
| RESOLVE-01-N01 | runtime | 없음 |
| RESOLVE-01-N02 | runtime | 없음 |
| RESOLVE-01-N03 | runtime | 없음 |
| RESOLVE-02-P | runtime | 없음 |
| RESOLVE-02-N01 | runtime | 없음 |
| RESOLVE-02-N02 | runtime | 없음 |
| RESOLVE-02-N03 | runtime | 없음 |
| RESOLVE-02-N04 | runtime | 없음 |
| RESOLVE-02-N05 | runtime | 없음 |
| RESOLVE-03-P | runtime | 없음 |
| RESOLVE-03-N01 | runtime | 없음 |
| RESOLVE-03-N02 | runtime | 없음 |
| RESOLVE-03-N03 | runtime | 없음 |
| RESOLVE-04-P | runtime | 없음 |
| RESOLVE-04-N01 | runtime | 없음 |
| RESOLVE-04-N02 | runtime | 없음 |
| RESOLVE-04-N03 | runtime | 없음 |
| RESOLVE-04-N04 | runtime | 없음 |
| RESOLVE-04-N05 | runtime | 없음 |
| RESOLVE-05-P | runtime | 없음 |
| RESOLVE-05-N01 | runtime | 없음 |
| RESOLVE-05-N02 | runtime | 없음 |
| RESOLVE-05-N03 | runtime | 없음 |
| RESOLVE-05-N04 | runtime | 없음 |
| TABLE-01-P | runtime, document_review | 없음 |
| TABLE-01-N01 | runtime, document_review | 없음 |
| TABLE-01-N02 | runtime, document_review | 없음 |
| TABLE-01-N03 | runtime, document_review | 없음 |
| TABLE-02-P | runtime | 없음 |
| TABLE-02-N01 | runtime | 없음 |
| TABLE-02-N02 | runtime | 없음 |
| TABLE-03-P | runtime | 없음 |
| TABLE-03-N01 | runtime | 없음 |
| TABLE-03-N02 | runtime | 없음 |
| TABLE-04-P | runtime | 없음 |
| TABLE-04-N01 | runtime | 없음 |
| TABLE-04-N02 | runtime | 없음 |
| TABLE-04-N03 | runtime | 없음 |
| TABLE-05-P | runtime | 없음 |
| TABLE-05-N01 | runtime | 없음 |
| TABLE-05-N02 | runtime | 없음 |
| TABLE-06-P | runtime | 없음 |
| TABLE-06-N01 | runtime | 없음 |
| TABLE-06-N02 | runtime | 없음 |
| TABLE-07-P | runtime | 없음 |
| TABLE-07-N01 | runtime | 없음 |
| TABLE-07-N02 | runtime | 없음 |
| EXEC-01-P | runtime, deployment_review | 없음 |
| EXEC-01-N01 | runtime, deployment_review | 없음 |
| EXEC-01-N02 | runtime, deployment_review | 없음 |
| EXEC-01-N03 | runtime, deployment_review | 없음 |
| EXEC-01-N04 | runtime, deployment_review | 없음 |
| EXEC-02-P | runtime, deployment_review | 없음 |
| EXEC-02-N01 | runtime, deployment_review | 없음 |
| EXEC-02-N02 | runtime, deployment_review | 없음 |
| EXEC-02-N03 | runtime, deployment_review | 없음 |
| EXEC-03-P | runtime | 없음 |
| EXEC-03-N01 | runtime | 없음 |
| EXEC-03-N02 | runtime | 없음 |
| EXEC-03-N03 | runtime | 없음 |
| EXEC-03-N04 | runtime | 없음 |
| EXEC-03-N05 | runtime | 없음 |
| EXEC-04-P | runtime | 없음 |
| EXEC-04-N01 | runtime | 없음 |
| EXEC-04-N02 | runtime | 없음 |
| EXEC-04-N03 | runtime | 없음 |
| EXEC-04-N04 | runtime | 없음 |
| EXEC-04-N05 | runtime | 없음 |
| EXEC-05-P | runtime | 없음 |
| EXEC-05-N01 | runtime | 없음 |
| EXEC-05-N02 | runtime | 없음 |
| EXEC-05-N03 | runtime | 없음 |
| EXEC-05-N04 | runtime | 없음 |
| EXEC-05-N05 | runtime | 없음 |
| EXEC-06-P | runtime, deployment_review | 없음 |
| EXEC-06-N01 | runtime, deployment_review | 없음 |
| EXEC-06-N02 | runtime, deployment_review | 없음 |
| EXEC-06-N03 | runtime, deployment_review | 없음 |
| EXEC-06-N04 | runtime, deployment_review | 없음 |
| EXEC-06-N05 | runtime, deployment_review | 없음 |
| EXEC-07-P | runtime | 없음 |
| EXEC-07-N01 | runtime | 없음 |
| EXEC-07-N02 | runtime | 없음 |
| EXEC-07-N03 | runtime | 없음 |
| EXEC-07-N04 | runtime | 없음 |
| EXEC-07-N05 | runtime | 없음 |
| EXEC-08-P | runtime | 없음 |
| EXEC-08-N01 | runtime | 없음 |
| EXEC-08-N02 | runtime | 없음 |
| EXEC-08-N03 | runtime | 없음 |
| EXEC-08-N04 | runtime | 없음 |
| EXEC-08-N05 | runtime | 없음 |
| EXEC-08-N06 | runtime | 없음 |
| EXEC-09-P | document_review | 없음 |
| EXEC-09-N01 | document_review | 없음 |
| EXEC-09-N02 | document_review | 없음 |
| PROC-01-P | document_review | 없음 |
| PROC-01-N01 | document_review | 없음 |
| PROC-01-N02 | document_review | 없음 |
| PROC-02-P | document_review | 없음 |
| PROC-02-N01 | document_review | 없음 |
| PROC-02-N02 | document_review | 없음 |
| PROC-03-P | document_review | 없음 |
| PROC-03-N01 | document_review | 없음 |
| PROC-03-N02 | document_review | 없음 |
| EVIDENCE-01-P | runtime, document_review, deployment_review | 없음 |
| EVIDENCE-01-N01 | runtime, document_review, deployment_review | 없음 |
| EVIDENCE-01-N02 | runtime, document_review, deployment_review | 없음 |
| CST-01-01 | runtime | 없음 |
| CST-01-02 | runtime | 없음 |
| CST-01-03 | runtime | 없음 |
| CST-01-04 | runtime | 없음 |
| CST-01-05 | runtime | 없음 |
| CST-01-06 | runtime | 없음 |
| CST-01-07 | runtime | 없음 |
| CST-01-08 | runtime | 없음 |
| CST-01-09 | runtime | 없음 |
| CST-01-10 | runtime | 없음 |
| CST-02-01 | runtime, deployment_review | 없음 |
| CST-02-02 | runtime, deployment_review | 없음 |
| CST-02-03 | runtime, deployment_review | 없음 |
| CST-02-04 | runtime, deployment_review | 없음 |
| CST-02-05 | runtime, deployment_review | 없음 |
| CST-03-01 | runtime | 없음 |
| CST-03-02 | runtime | 없음 |
| CST-04-01 | runtime | 없음 |
| CST-04-02 | runtime | 없음 |
| CST-04-03 | runtime | 없음 |
| CST-04-04 | runtime | 없음 |
| CST-05-01 | runtime | 없음 |
| CST-05-02 | runtime | 없음 |
| CST-05-03 | runtime | 없음 |
| CST-05-04 | runtime | 없음 |
| CST-05-05 | runtime | 없음 |
| CST-05-06 | runtime | 없음 |
| CST-05-07 | runtime | 없음 |

## 이번 검증 결과

보관본과 현재 명세의 해시 대조 및 45/77/386/26 항목 연결 검사를 통과했다.
임시 복제본에서 보관본 변조, 사례 누락, 사례 중복, 알 수 없는 사례 연결,
기반 벡터 변경의 5개 오류를 주입하여 모두 거부함을 확인했다.
