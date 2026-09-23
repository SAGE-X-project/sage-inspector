# 실제 Agent 호스트 집행 감사

고정 계획 7단계에서 SAGE 0.10.0 명세 revision
`520e5ed9a896ff8ba8ade776484f41084957aaa2`에 연결할 Agent 호스트를
조사했다. **배포 호스트 집행 검증은 `NOT_RUN`**, 전체 적합성은
`NOT_ESTABLISHED`다. [감사 manifest](evidence/agent-host-deployment-audit/manifest.json)는
확인한 소스의 revision·해시와 [미설정 호스트 실행 원문](evidence/agent-host-deployment-audit/unconfigured/summary.json)을
고정한다.

Go 코어의 비공개 `mcpHost`는 worker·deadline·owner 정리를 구현하고 로컬
테스트에서 실행된다. 그러나 이 구조체 자체는 선정된 Agent 호스트 실행 파일이나
plugin의 모든 파일·네트워크·하위 프로세스 효과를 중재하는 배포 경계가 아니다.
Go/Rust Guard 설명도 불변 로더, 키 권한, 전체 호스트 중재를 통합 책임으로
남긴다. Inspector의 기존 8개 호스트 시나리오는 실행 계약과 합성 테스트이며,
실제 호스트 어댑터·독립 관측기를 제공하지 않는다. 기존 데모와 예제도
0.10.0 Guard 배포 대상으로 선택되거나 외부 관측기에 결합된 자료가 없다.

실행을 시작하려면 선정된 호스트 실행 파일과 설정의 revision·해시, 실제
호스트를 기동하는 어댑터, plugin 신뢰 영역 밖의 관측기와 격리 경계, 보호할
효과 경로 목록, signing-key 권한 분리, 동일 불변 component의 Check→Commit
결합, 복구·운영 정책이 필요하다. 이 입력 없이 호스트 후보의 이름이나 코어
라이브러리 테스트를 배포 방어 증거로 승격할 수 없다.

`inspect_host.py`를 runner·adapter·binding 없이 실제 로컬 CLI로 실행했다.
종료 코드 3, 요약 `INCOMPLETE`, 8개 시나리오·40단계 모두 `NOT_RUN`,
관측 효과 `null`, 외부 증거 파일 0건이다. hook 누락과 timeout, direct call,
하위 프로세스·파일·네트워크, verifier 교체, signing-key 접근의 실제 차단 여부는
측정하지 않았다. 실제 dispatch, 종료 후 복구 및 정상 요청의 양성 대조군도
배포 호스트에서는 실행되지 않았다. Go 내부
`TestMCPHostRuntimeExchange`는 고정 소스에서 정상 경로를 다시 실행해 통과했으며
[원시 출력](evidence/agent-host-deployment-audit/go-internal-host.stdout)을 보존했다.
이는 내부 코어 런타임 대조군이고 합성 Inspector 테스트와 마찬가지로 배포 호스트
누락을 채우지 않는다.

보존된 원문과 판정을 재검사하려면 다음을 실행한다.

```sh
python3 -B scripts/test_agent_host_deployment_audit.py
python3 -B scripts/check_agent_host_deployment_audit.py \
  --go-root /Users/0xtopaz/work/github/sage-x-project/sage \
  --rust-root /Users/0xtopaz/work/github/sage-x-project/rs-sage-core
python3 -B scripts/test_deployment_inspection.py
```

감사 checker는 소스·시나리오·CLI 원문의 해시와 미실행 판정을 검사하고,
관측 효과를 임의로 채우거나 `PASS`로 승격한 기록을 거부한다. 이 checker와
미설정 CLI의 성공은 실제 호스트 방어 검증이 아니다. 운영 바인딩이 정해지면
별도 격리 환경에서 정상 서명 요청·실제 dispatch·복구를 안전하게 관측하고,
우회 가능성이 있는 사례는 단위 seam 검증으로 한정해야 한다.

고정 계획의 다음 순서는 8단계 INS-11 통합 판정이다. 그 판정은 Registry Source와
Agent 호스트의 `NOT_RUN`을 그대로 포함해야 한다.
