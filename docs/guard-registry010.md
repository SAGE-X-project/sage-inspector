# Registry Gate와 Guard Authority 연결

두 코어의 `RegistryAuthority`는 관리자가 지정한 issuer/keyid 한 쌍을 신뢰된
registry Gate에 연결한다. `ActiveKey`뿐 아니라 `Now`도 매번 새 관측을 수행한다.
따라서 기존 Guard의 정책 검사 후·durable EXECUTING 저장 후·component 검사 후
최종 시각 확인이 현재 키의 활성·만료·freshness 검사까지 수행한다.

`SelectWithTime` / `select_with_time`은 선택된 키와 저장 지연 후 최종 gate 시각을
같은 작업에서 반환한다. 반환값은 이후 작업의 portable 권한이 아니다. 첫 선택의
키 material과 expiry를 binding 수명 동안 고정하고 같은 keyid의 조용한 교체를
거부한다. 변경은 관리자가 새 binding을 설치해야 한다. intent issuer와 result
executor에는 각각 별도 binding을 사용한다. 두 시점 사이에 발생한 폐기를 예견하거나
이미 commit된 효과를 취소하는 보장은 없다.

Go는 기존 registry Gate를 사용하며 context cancellation을 확인한다. Rust는
기존 `Gate::new`를 보존하고, Guard가 소유할 수 있도록 `SendGate::new_send`를
추가했다. 두 alias는 같은 `RegistryGate` 로직을 사용한다. C API 변경은 없다.
Source·Clock·Store는 계속 신뢰 의존성이다. 무제한 callback을 강제로 종료하는
기능이나 실제 체인 resolver를 추가한 것은 아니다. 반복 관측의 지연도 배포에서
측정해야 하며 긍정 cache로 검사를 생략해서는 안 된다.

## 테스트와 증거

코어 유닛 테스트는 양성 관측 재사용 금지, 잘못된 keyid, 키 교체, 취소/빈 Go 객체와
최종 실행 gate의 8개 시나리오를 확인한다. Inspector는 동일 공개 signed intent를
실제 코어 dispatch로 전달하는 bounded 로컬 CLI **16개**를 실행한다.

| 시나리오 | 실행 결과 | 실행 journal |
|---|---|---|
| 정상, 관측 후 저장 지연 5000ms | 각각 효과 1회 | RESERVED → EXECUTING |
| 최종 component 확인 후 키 폐기·readiness 상실·Source 오류·시계 오류·5001ms 저장 지연·단조 시계 역행 | 효과 0회 | RESERVED → EXECUTING → UNKNOWN |

정상 호출의 관측 9회와 시계 오류/역행 시 8회 등 callback 경계도 확인한다.
고정 관측 횟수는 이 구현의 회귀 기대값이며 새 wire 규칙이 아니다. 원본 입력·stdout·
stderr·종료 코드와 실제 journal **32개 파일**을 SHA-256으로 보존하고 모든 행의
identity·exact intent·상태·비어 있는 result를 대조한다. 오프라인 보고서 테스트 4개는
허위 성공·효과·관측 누락·저장 상태/intent 변경을 거부한다.

```sh
python3 scripts/test_guard_registry_reports.py
python3 scripts/test_guard_registry010.py --go /path/to/go-adapter \
  --rust /path/to/rust-adapter --output /tmp/new-registry-authority-results
```

이 실행은 **통제된 test Source·메모리 registry Store·inert sink**를 사용한다.
실행 ledger는 실제 코어의 로컬 영속 journal이지만, registry watermark의 영속성이나
실제 record/PoP·finality·배포 신뢰 검증을 증명하지 않는다. 공개 fixture 서명은 코어가
실제로 검증하며, 새 독립 암호 벡터나 새 live-chain 측정으로 집계하지 않는다.
`live_registry: NOT_RUN`, 전체 lifecycle 37개 `NOT_RUN`, 전체 적합성
`NOT_ESTABLISHED`를 유지한다. 과거 증거는 변경하지 않는다.

다음은 **선택한 MCP 전송의 인증 신원·exact RPC 바이트·invocation ID 연결**이다.
HTTP carriage와 비HTTP MCP의 매핑을 구분하며, 보호된 Source 배포·정책/로더·호스트
전체 중재는 각 경계의 실제 증거가 마련될 때 별도로 검증한다.
