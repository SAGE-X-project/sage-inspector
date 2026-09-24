# INS-11 통합 판정 — SAGE 0.10.0

고정 순서의 1~8단계 **증거 수집·검토 절차는 종료**했다. 결과는
**INS-11 `INCOMPLETE`**, 전체 프로토콜 적합성 `NOT_ESTABLISHED`, 적합성 주장은
`NOT_READY`다. 6·7단계의 감사는 완료됐지만 실제 Registry Source와 Agent
호스트 검증은 각각 `NOT_RUN`이다. [기계 판독 판정](evidence/ins11-integrated-verdict/report.json)이
채택 명세 revision, 범위별 코어 revision, 원문 보고서 해시와 미해결 상태를 연결한다.

| 범위 | 확인한 결과 | 적용 revision·한계 |
|---|---|---|
| 규범 기준선 | 0.10.0 `ADOPTED_NORMATIVE_DESIGN` 고정 | `sage-spec` `520e5ed9a896ff8ba8ade776484f41084957aaa2`; 보존된 설계 브랜치는 미반영 |
| Go/Rust 구현 대조 | 필수 하위 스케줄 각 26건 `DIRECT` | Go `1f2dd87643e42b7ed3beda6956158ff23dcc7ea2`, Rust `40b5a8c6d76d952131013d8a034f819fd31b7ca0`; 정적 매핑과 선택 테스트 |
| MCP 결합 | 부모 71건 PASS, 각 코어 하위 26건 PASS, 보호 교환 4조합 및 완료 journal 재시작 8건 PASS | 위 구현 대조 revision의 선택 실행. 역사적 제안 catalog의 71 `NOT_RUN`을 보존하며 전체 적합성 PASS가 아님 |
| 현행 코어 수명주기 | 종료·수신, 만료/admission, 늦은 완료, replay/quarantine 복구, reservation/close의 지정 테스트와 로컬 실행 증거 확인 | Go `2fb4755ba38d1c90adea5089402fcc6b8981fd71`, Rust `40b5a8c6d76d952131013d8a034f819fd31b7ca0`; 배포 통합 증거가 아님 |
| Registry Source | 실제 체인 `NOT_RUN` | 선정된 0.10.0 배포·코드/ABI·RPC·finality·관측기 바인딩 부재 |
| Agent 호스트 | 8개 시나리오·40단계 `NOT_RUN` | 고정 실행 파일·설정·독립 관측기 바인딩 부재. Go 내부 host 정상 교환은 배포 격리 증거가 아님 |

MCP 결합의 Go revision과 이후 수명주기 감사의 Go revision은 다르다. 두 증거는
각각의 대상에 대해 유효하지만 **하나의 동일한 Go 배포 revision에서 전체 흐름을
검증한 결과로 합치지 않는다**. Rust revision 일치만으로 이 격차가 없어지지 않는다.
CI의 [실행 기록](https://github.com/SAGE-X-project/sage-inspector/actions/runs/35933387031)에서
선택한 baseline·Go/Rust review·MCP binding 보고서의 원문을
[증거 디렉터리](evidence/ins11-integrated-verdict/ci-reports)에 보존했다. 해당 CI
artifact의 ID와 SHA-256 digest를 판정에 기록했다. 원시 프레임·로그가 포함된
CI artifact는 30일 보존이므로, 만료 뒤 심층 재검사에는 고정 revision으로 다시
실행해야 한다. 선택 보고서의 저장소 복사본만으로 모든 원시 관측을 재구성할 수는 없다.
artifact digest는 GitHub가 제공한 메타데이터이며 로컬 checker는 복사한 보고서의
해시와 의미를 검사한다. `--artifact`를 제공하면 해당 원시 자료의 MCP 결합도
별도로 재검사한다.

기존 386개 baseline 계획 사례는 각 역사적 코어 집계에서 전부 `NOT_RUN`이다.
현재 채택 MCP 부모 71건 PASS와 단위가 다르며 서로 빼거나 적합성 비율로 합산하지
않는다. 별도 역사적 lifecycle 37건도 `NOT_RUN`이다. 과거 primitive 집계에는
Go 69 FAIL·311 UNSUPPORTED, Rust 63 FAIL·303 UNSUPPORTED가
남아 있다. 이 집계는 각각 과거 Go/Rust revision의 결과이며 현행 코어의 새 실패로
옮겨 적지 않는다. 오래된 Go `SecureSession`
동시 close의 데이터 레이스 `FAIL`과 Rust 직접 병행 close의 `UNSUPPORTED`를
원문과 함께 보존한다. 이는 현행 Go `RecordSession010`의 별도 통과 결과를
부정하거나, 구형 실패가 현행 API에서 재현됐다는 뜻이 아니다. 레거시 레코드
교환의 transcript-bound 바인딩 4건 `UNSUPPORTED`, 완전한 HPKE 확인·HTTP/WS
종단 교환과 배포 Source·호스트의 누락도 전체 승인에서 제외할 수 없다.

검사기는 기존 각 단계의 checker, 과거 통합 집계의 재생성, 저장된 CI 보고서의
상태·해시·revision 결합을 다시 확인한다. 선택한 CI artifact를 보유한 경우
`--artifact`로 원시 MCP 결합 증거도 재검사한다.

```sh
python3 -B scripts/test_ins11_integrated_verdict.py
python3 -B scripts/check_ins11_integrated_verdict.py
python3 -B scripts/check_ins11_integrated_verdict.py \
  --artifact /absolute/path/to/downloaded/mcp-native-interop-artifact
```

checker 통과는 **판정 기록의 일관성**을 뜻한다. 배포 적합성 통과가 아니다.
고정 계획 종료 후에는 [작업 순서 기준선](execution-order.md)의 후속 순서를
따른다. 먼저 ADOPT-01..06을 채택 규범에 대한 errata로 재검토하고, 보존된
`sage-spec` 설계 브랜치와 사용자가 원하는 구현 패턴을 검토한다. 변경 명세를
새 revision으로 고정한 다음 두 코어와 Inspector를 다시 맞춘다. 기존 규범과
실행 결과는 그때까지 이 판정 그대로 보존한다.
