# 인증된 MCP 초기 설정 검토

검토 결과: **현재 인증된 MCP 초기 협상은 미구현**이다. 지원 버전 검사, 보호된
RPC 교환 및 Guard 실행·영속 소비는 존재하지만 초기 협상 완료를 증명하지 않는다.
이번 변경은 경계 검토·검토 계약 검사이며 새 프로토콜이나 협상 구현이 아니다.
전체 lifecycle 37개 `NOT_RUN`, 전체 적합성 `NOT_ESTABLISHED`를 유지한다.

## 근거와 현재 API

MCP 2025-06-18은 `initialize` 요청·응답 뒤 `notifications/initialized`를 보내는
초기 절차와 버전·기능 협상을 정의한다. 요청 버전을 서버가 지원하면 같은 버전을
반환하고, 지원하지 않으면 서버가 지원하는 버전을 반환한다. 이는 SAGE의 현재
단일 지원 버전 검사와 구분된다. [MCP lifecycle](https://modelcontextprotocol.io/specification/2025-06-18/basic/lifecycle)

MCP는 custom transport를 허용한다. HTTP에는 별도 메시지·세션·버전 헤더 규칙이
있으므로 비HTTP 연결의 성공을 HTTP 지원으로 확장할 수 없다.
[MCP transports](https://modelcontextprotocol.io/specification/2025-06-18/basic/transports)

SAGE의 고정된 EXEC-08은 structured tool results를 요구하고 `2025-06-18`을
baseline으로 둔다. 검토한 코어 구현은 그 문자열만 허용한다. **baseline이라는
명세 표현을 모든 미래 MCP 버전의 영구 금지로 해석하지 않는다.**

- Go `CheckMCPVersion`과 Rust `check_mcp_version`은 로컬 지원 여부만 검사한다.
- endpoint와 client sender 생성자는 초기 협상의 출처를 신뢰된 호스트 입력으로 받는다.
- `MCPSessionCall`은 `tools/call`만 처리한다. 일반 initialize나 알림 전달 API가 아니다.
- SAGE HPKE handshake는 피어·암호 세션을 인증하지만 MCP 버전·capabilities 협상은
  포함하지 않는다. 따라서 handshake 성공만으로 MCP READY를 선언할 수 없다.
- 이전 [통합 런타임](guard-session010.md)의 초기 설정은 신뢰된 테스트 입력이다.
  테스트 전체를 인증된 초기 협상의 실적으로 재분류하지 않는다.

## 명세에서 먼저 결정할 여섯 경계

| 경계 | 권장 방향 | 구현 전 필요한 결정·증거 |
|---|---|---|
| 인증 시작점 | 비HTTP custom transport에서 SAGE 인증 채널을 먼저 수립하고, 그 위에서 최초 MCP initialize를 교환 | 정확한 피어·세션과 초기 요청/응답의 연결, 신뢰된 로컬 Guard 인계 |
| 준비 상태 | 채널 인증 → 초기 응답 검증 → initialized 처리 → 보호 호출 허용의 상태 구분 | 요청 ID·버전·피어·세션 고정, 신뢰된 초기화 deadline과 순서 오류·중복·늦은 응답·닫힌 세션의 거부. 로컬 readiness는 이식 가능한 wire 권한이 아님 |
| 버전·기능·도구 | 현재 지원 버전과 tools 기능, 보호 도구 계약을 확인 | 도구 schema 조회의 인증 경로, 미지원 버전 거부. 별도의 structuredContent capability 플래그를 임의로 발명하지 않음 |
| 알림 전송 | initialized의 MCP 알림 의미를 보존 | 기존 outer request/response 레코드에 싣는 방법, outer 확인·수명·replay·자원 회수 규칙. JSON-RPC 응답이나 요청 ID를 알림에 임의로 추가하지 않음 |
| 종료·재연결 | 세션 교체 시 readiness를 폐기하고 새 연결에서 다시 협상 | 오래된 초기 메시지 재사용 거부, 새 연결과 별개로 Guard ledger·terminal 소비 유지 |
| HTTP 매핑 | 비HTTP와 별도로 설계 | 초기 메시지 및 후속 헤더/본문의 인증·매핑. SAGE 버전, MCP 버전, MCP session ID, 암호 session ID를 구분 |

표의 상태는 모두 **OPEN**이다. 권장 설계가 기존 규범에서 이미 확정된 것처럼
MUST 요구사항이나 PASS 판정을 만들지 않는다. 지원 버전 값·서버 이름·instructions·
capability 선언·MCP session ID 자체는 원본 요청의 인가나 피어 인증 증거가 아니다.

특히 초기 알림을 기존 `SealRequest`로 암호화할 수 있다는 사실만으로 mapping이
완성되지는 않는다. 응답 대기 상태·responder 확인·중복·timeout의 수명 처리가 필요하다.
반대로 알림을 무조건 거부하는 현재 protected tools/call 제한을 전체 MCP 알림 금지로
확대해서도 안 된다. SAGE 보호 도구 호출과 MCP 생명주기 메시지는 구분해야 한다.

## 검토 계약과 검사

[검토 계약](../verification/0.10.0/mcp-setup-review.json)은 고정 integration 계약의
해시, 두 코어 버전 검사 파일 해시, 버전별 공식 참고 링크, 여섯 결정과 필요한 증거를
보존한다. integration 계약이 가리키는 명세·코어 소스도 함께 검증한다. 외부 문서 링크는
참고 출처이며 원문 해시나 자동 네트워크 검증을 제공한다고 주장하지 않는다.

```sh
python3 scripts/test_mcp_setup.py
python3 scripts/inspect_mcp_setup.py --go-root ../sage --rust-root ../rs-sage-core \
  --output /tmp/new-mcp-setup-review
# exit 3: review audit PASS, specification decisions still required
```

유닛 테스트 8개는 누락·중복·해시/버전 변경·빈 근거·허위 완료 판정을 검사한다.
CLI 런타임 테스트 2개는 실제 로컬 프로세스의 보고서 생성·출력 보존·오류 종료를
확인한다. **CLI 실행은 실제 MCP 협상 테스트가 아니다.** 잘못된 입력은 종료 2이며
기존 출력이나 과거 증거를 덮지 않는다. 코어 경로 생략 시 소스 식별은 `NOT_CHECKED`다.
CI는 고정 코어 checkout을 대조하고 `mcp-setup-review-<revision>` artifact를 남긴다.

다음 작업은 이 여섯 경계를 반영한 **비HTTP 초기 협상 명세 초안**을 작성하는 것이다.
알림 carriage와 준비 상태를 먼저 확정한 뒤 코어 상태 기계와 실제 협상 런타임 검증을
구현한다. HTTP 매핑과 선정된 호스트의 전체 중재·복구 검증은 별도 후속이다.
