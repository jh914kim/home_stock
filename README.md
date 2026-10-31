# Home Stock (통합 주식 포트폴리오 대시보드)

토스증권 및 한국투자증권(KIS) Open API를 연동하여 여러 계좌(일반 위탁, 연금저축, ISA, IRP)의 자산을 하나의 대시보드에서 통합 관리하고 실시간 평가 및 구간별 수익률 변화를 정밀 분석하는 웹 대시보드 및 PWA(모바일 웹앱)입니다.

---

## 주요 기능

1. **멀티 증권사 & 다계좌 실시간 통합 관리**
   - 토스증권 Open API (국내 및 해외 주식)
   - 한국투자증권 Open API (연금저축, 중개형 ISA, 개인형 IRP, 일반위탁)
   - 실시간 평가금액, 매수원금, 총 평가손익, 수익률 종합 산출

2. **구간별 수익률 변화 정밀 분석 (차별화 기능)**
   - **조회 주기**: 일별 / 월별 / 연별
   - **조회 범위**: 30일 / 90일 / 180일 / 1년 / 3년 / 전체
   - **지표 전환**: 수익률(%), 손익금액(원), 평가금액(원)
   - **기준점 선택**: 초기값 대비 누적 변화 / 직전 구간 대비 변동분
   - 구간 핵심 성과 카드 (기간 총 수익, 최고/최저 수익률, 평균 변동폭)

3. **포트폴리오 비중 및 기여도 시각화**
   - 종목별 포트폴리오 비중 도넛 차트 & TOP 5 리스트
   - 종목별 수익금 기여도 수평 바 차트
   - 국내상장 해외추종 ETF 분류 토글 (해외주식으로 포함/미포함)
   - 순수 투자 원금(실입금) 장부 연동 및 계좌별 필터링

4. **모바일 최적화 및 PWA (Progressive Web App) 완벽 지원**
   - Chrome / Safari 모바일 홈 화면 설치 지원 (독립 실행형 PWA)
   - 고해상도 벡터 그래픽 기반의 매끄러운 스플라인 차트 스플래시 & 아이콘
   - 모바일에 최적화된 하단 세그먼트 네비게이션:
     - `비중·손익` (차트)
     - `구간 수익률` (히스토리 차트 & 타임라인)
     - `보유 종목` (검색 및 정렬 지원 리스트)

5. **보안 및 프라이버시 보호**
   - PBKDF2 암호화 해싱 기반 로그인 인증
   - `.env` 내 API Key / Secret 자동 대칭키 암호화 (`ENC$v1$...`)

---

## 설치 및 실행 방법

### 1. 환경 설정
`.env.example` 파일을 복사하여 `.env` 파일을 생성하고 발급받은 API 키를 입력합니다:
```bash
cp .env.example .env
```

`capital_ledger.example.json` 파일을 복사하여 실입금 원금 정보를 설정할 수 있습니다 (선택사항):
```bash
cp capital_ledger.example.json capital_ledger.json
```

### 2. 실행
Windows 배치 파일 또는 Python으로 직접 실행합니다:
```bash
# Windows
run.bat

# 직접 실행
python server.py
```

브라우저에서 `http://localhost:8080` 접속:
- PC 버전: `http://localhost:8080`
- 모바일 전용 UI: `http://localhost:8080/mobile`

---

## 기술 스택
- **Backend**: Python 3 (표준 라이브러리 `http.server`, `urllib`, `hashlib`, `hmac` 기반 경량 고속 서버)
- **Frontend**: Vanilla JavaScript (ES6+), HTML5, CSS3, Chart.js
- **PWA**: Service Worker (`sw.js`), Web App Manifest (`manifest.json`)
