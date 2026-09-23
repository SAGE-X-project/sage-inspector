# 실제 Registry Source 배포 감사

SAGE 0.10.0 명세 revision `520e5ed9a896ff8ba8ade776484f41084957aaa2`의
Registry Source 경계를 현재 저장소의 배포 자료와 대조했다. **실제 체인 관측 결과는
`NOT_RUN`**이며 전체 적합성은 `NOT_ESTABLISHED`다. [감사 manifest](evidence/registry-source-deployment-audit/manifest.json)는
조사한 파일의 revision·해시와 [미설정 CLI 원문](evidence/registry-source-deployment-audit/unconfigured-report.json)을
고정한다.

Go `sage` README는 Sepolia의 `AgentCardRegistry` 주소를 게시한다. 이는 **후보**다.
같은 저장소의 production·staging YAML은 서로 다른 네트워크의 chain ID를 적고
RPC와 registry 주소는 환경변수 자리표시자로 둔다. Inspector의
`registry-source-binding.json`은 `environment: synthetic`과 예제 주소·해시를
명시한다. 이 세 자료 중 어느 것도 선택된 0.10.0 배포 바인딩 또는 신뢰된
체인 관측기 실행 증거가 아니다. 기존 계약 ABI나 README 주소를 0.10.0
규범의 read/write 의미에 맞는다고 추정하지 않았다.
현재 실행 환경에서도 관련 RPC·registry 주소 변수는 설정되지 않았다. 변수의
값이나 비밀은 보고서에 기록하지 않았다.

실제 실행에 필요한 미확정 항목은 다음과 같다.

| 경계 | 현재 확인된 입력 | 실제 검증에 필요한 입력 |
|---|---|---|
| 네트워크와 대상 | Sepolia README 주소 후보 및 production·staging 설정 | 운영자가 선택한 chain ID, registry 주소, 신뢰할 RPC/노드 또는 resolver 신원 |
| 배포 코드와 권한 | 일반 배포 설명 | 해당 주소의 배포 코드 해시, 업그레이드 정책, 운영자 범위와 트랜잭션 인가 |
| 규범 ABI | 합성 Inspector 설정 | 0.10.0 registry 동작에 매핑한 검토된 read/write ABI 원문과 해시 |
| 관측·최종성 | 합성 시계와 블록 입력 | 최종 블록 판정·readiness 정책, 신뢰 관측기 revision/실행물, 동일 확정 블록의 전체 record·키·PoP 증거 |
| 시간 측정 | 합성 발행·확정 시각 | 실제 발행 시각, 최종성 도달 시각, 조회·인가 시각과 원시 관측 |

`inspect_registry_source010.py --output <새 경로>`를 배포 바인딩 없이 실행하자
종료 코드 3, `status: NOT_RUN`, `live_chain_verification: NOT_RUN`, 측정값 0건이
기록됐다. stdout·stderr와 보고서 원문을 별도 해시로 보존했다. 기존 Source 계약의
단위 테스트 15건과 격리된 로컬 CLI 런타임의
7개 입력 경로는 통과했다. 이 테스트는 잘못된 입력을 거부하는 Inspector
동작을 검증하며 실제 체인·코어 Source 실행으로 합산하지 않는다.

저장된 감사 checker는 README 후보나 합성 설정을 인증된 배포로 승격하거나
미설정 CLI의 결과를 PASS로 바꾸면 실패한다. 파일 원문을 다시 대조할 수 있는
로컬 실행은 다음과 같다.

```sh
python3 -B scripts/test_registry_source_deployment_audit.py
python3 -B scripts/check_registry_source_deployment_audit.py \
  --go-root /Users/0xtopaz/work/github/sage-x-project/sage
```

선택된 배포 바인딩이 제공되면 신뢰할 관측기로 chain ID, 코드·ABI,
finality/readiness, 같은 확정 블록의 record·키, 버전 후퇴·폐기·혼합 블록과
실제 지연을 측정해야 한다. 그 전까지 6단계의 실제 체인 항목은 `NOT_RUN`으로
보존한다. 고정 순서의 다음 항목은 실제 Agent 호스트 집행 검증이며, 최종
판정에서도 이 누락을 그대로 반영한다.
