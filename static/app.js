const ALL_ACCTS = ["BROKERAGE", "RIA", "KIS_1", "KIS_2", "KIS_3", "KIS_4"];
const KIS_ACCTS = ["KIS_1", "KIS_2", "KIS_3", "KIS_4"];
const ACCT_LABELS = {
  BROKERAGE: "토스 종합",
  RIA: "토스 RIA",
  KIS_1: "한투 연금저축",
  KIS_2: "한투 ISA",
  KIS_3: "한투 IRP",
  KIS_4: "한투 위탁",
};

const state = {
  dashboard: null,
  scope: "ALL",
  selectedScopes: new Set(),
  afterCost: false,
  krwUnified: true,
  overseasEtfAsUs: false,
  filter: "ALL",
  search: "",
  sortField: "marketValueKrw",
  sortDesc: true,
  weightChartMode: "marketValue",
  profitChartMode: "amount",
  historyData: null,
  historyUnit: "daily",
  historyDays: 90,
  historyMonths: "12",
  historyMetric: "profit",
  historyDeltaMetric: "amount",
  ordersLoaded: false,
  rawOrders: [],
  capital: null,
};

function isItemOverseasClassified(item) {
  if (!item) return false;
  if (item.currency === "USD" || item.marketCountry === "US") return true;
  if (state.overseasEtfAsUs && item.isOverseasEtf) return true;
  return false;
}

let purchaseVsValueChartInstance = null;
let profitContributionChartInstance = null;
let portfolioWeightChartInstance = null;
let stockCandleChartInstance = null;
let historyReturnChartInstance = null;
let historyDeltaChartInstance = null;
let searchDebounceTimer = null;
let resizeTimer = null;
let dashboardReqSeq = 0;
let historyReqSeq = 0;

function fmtKrw(num, signed = false) {
  if (num === null || num === undefined || isNaN(num)) return "-";
  const rounded = Math.round(Number(num));
  const absStr = Math.abs(rounded).toLocaleString("ko-KR") + "원";
  if (rounded > 0) return (signed ? "+" : "") + absStr;
  if (rounded < 0) return "-" + absStr;
  return "0원";
}

function fmtUsd(num, signed = false) {
  if (num === null || num === undefined || isNaN(num)) return "-";
  const val = Number(num);
  const absStr =
    "$" +
    Math.abs(val).toLocaleString("en-US", {
      minimumFractionDigits: 2,
      maximumFractionDigits: 2,
    });
  if (val > 0) return (signed ? "+" : "") + absStr;
  if (val < 0) return "-" + absStr;
  return "$0.00";
}

function fmtCurr(num, currency = "KRW", signed = false) {
  return currency === "USD" ? fmtUsd(num, signed) : fmtKrw(num, signed);
}

function fmtPct(num, signed = true) {
  if (num === null || num === undefined || isNaN(num)) return "0.00%";
  const val = Number(num);
  const sign = signed && val > 0 ? "+" : "";
  return `${sign}${val.toFixed(2)}%`;
}

function fmtQty(num) {
  const val = Number(num);
  if (Number.isInteger(val)) return val.toLocaleString("ko-KR") + "주";
  return (
    val.toLocaleString("ko-KR", {
      minimumFractionDigits: 0,
      maximumFractionDigits: 6,
    }) + "주"
  );
}

function signClass(num) {
  const val = Number(num);
  if (val > 0) return "text-up";
  if (val < 0) return "text-down";
  return "";
}

function pillClass(num) {
  const val = Number(num);
  if (val > 0) return "rate-pill rate-up";
  if (val < 0) return "rate-pill rate-down";
  return "rate-pill rate-zero";
}

// 대시보드 데이터 로드
let refreshDoneTimer = null;
let logoAnimTimer = null;
async function fetchDashboard(forceRefresh = false) {
  const errorBanner = document.getElementById("errorBanner");
  const refreshBtn = document.getElementById("refreshBtn");
  const refreshBtnText = document.getElementById("refreshBtnText");
  const brandLogoBtn = document.getElementById("brandLogoBtn");
  errorBanner.classList.add("hidden");
  refreshBtn.disabled = true;

  if (forceRefresh) {
    clearTimeout(refreshDoneTimer);
    clearTimeout(logoAnimTimer);
    refreshBtn.classList.remove("is-done");
    refreshBtn.classList.add("is-refreshing");
    if (refreshBtnText) refreshBtnText.textContent = "갱신 중";
    if (brandLogoBtn) {
      brandLogoBtn.classList.remove("is-refreshing");
      void brandLogoBtn.offsetWidth;
      brandLogoBtn.classList.add("is-refreshing");
    }
  }

  const mySeq = ++dashboardReqSeq;

  try {
    const qs = new URLSearchParams({ scope: state.scope });
    if (forceRefresh) qs.set("refresh", "1");
    qs.set("_t", String(Date.now()));
    const resp = await fetch(`/api/dashboard?${qs.toString()}`, {
      cache: "no-store",
    });
    const data = await resp.json();
    if (mySeq !== dashboardReqSeq) return;
    if (!resp.ok || data.error) {
      throw new Error(data.error || "API 응답 오류");
    }
    state.dashboard = data;
    if (data.capitalSummary) {
      state.capital = data.capitalSummary;
    }
    renderAll();

    // 만약 현재 구간별 수익률 탭이나 원금 탭이 열려 있다면 함께 갱신
    if (document.getElementById("tab-history").classList.contains("active")) {
      await fetchReturnsHistory(forceRefresh);
    } else if (document.getElementById("tab-orders").classList.contains("active")) {
      await fetchOrdersTab();
    } else if (document.getElementById("tab-capital").classList.contains("active")) {
      renderCapitalTab();
    }

    if (forceRefresh && mySeq === dashboardReqSeq) {
      refreshBtn.classList.remove("is-refreshing");
      refreshBtn.classList.add("is-done");
      if (refreshBtnText) refreshBtnText.textContent = "갱신 완료";
      refreshDoneTimer = setTimeout(() => {
        refreshBtn.classList.remove("is-done");
        if (refreshBtnText) refreshBtnText.textContent = "새로고침";
      }, 1200);
    }
  } catch (err) {
    if (mySeq !== dashboardReqSeq) return;
    errorBanner.textContent = `데이터 조회 실패: ${err.message}`;
    errorBanner.classList.remove("hidden");
    if (forceRefresh) {
      refreshBtn.classList.remove("is-refreshing");
      if (refreshBtnText) refreshBtnText.textContent = "새로고침";
    }
  } finally {
    if (mySeq === dashboardReqSeq) {
      refreshBtn.disabled = false;
      refreshBtn.classList.remove("is-refreshing");
      if (brandLogoBtn) {
        logoAnimTimer = setTimeout(() => {
          brandLogoBtn.classList.remove("is-refreshing");
        }, 900);
      }
    }
  }
}

function renderAll() {
  if (!state.dashboard) return;
  renderHeader();
  renderHeroSection();
  renderCharts();
  renderHoldingsTable();
  renderRiaManageTable();
  renderRiaSalesTable();
  renderCapitalTab();
}

function renderHeader() {
  const d = state.dashboard;
  const acc = d.selectedAccount;
  const fx = d.exchangeRate;
  const counts = d.counts || {
    all: 0,
    brokerage: 0,
    ria: 0,
    kisAll: 0,
    kis1: 0,
    kis2: 0,
    kis3: 0,
    kis4: 0,
  };

  document.getElementById("scopeCountAll").textContent = counts.all;
  document.getElementById("scopeCountBrokerage").textContent = counts.brokerage;
  document.getElementById("scopeCountRia").textContent = counts.ria;
  const elKisAll = document.getElementById("scopeCountKisAll");
  if (elKisAll) elKisAll.textContent = counts.kisAll || 0;
  const elKis1 = document.getElementById("scopeCountKis1");
  if (elKis1) elKis1.textContent = counts.kis1 || 0;
  const elKis2 = document.getElementById("scopeCountKis2");
  if (elKis2) elKis2.textContent = counts.kis2 || 0;
  const elKis3 = document.getElementById("scopeCountKis3");
  if (elKis3) elKis3.textContent = counts.kis3 || 0;
  const elKis4 = document.getElementById("scopeCountKis4");
  if (elKis4) elKis4.textContent = counts.kis4 || 0;
  document.getElementById("riaTabBadge").textContent = counts.ria;

  let badgeText = "전체 6개 계좌 통합 (토스 종합 + 토스 RIA + 한국투자 4계좌 합산)";
  if (state.selectedScopes.size > 0) {
    const names = ALL_ACCTS.filter((id) => state.selectedScopes.has(id)).map(
      (id) => ACCT_LABELS[id]
    );
    badgeText =
      names.length === 1
        ? `${names[0]} 계좌 전용 성적표`
        : `선택 계좌 합산 (${names.join(" + ")})`;
  }
  document.getElementById("heroScopeBadge").textContent = badgeText;

  const kisAccSummary = (d.kisAccounts || [])
    .map((k) => `${k.accountNo}`)
    .join(" · ");
  document.getElementById("accountInfoText").textContent = acc
    ? `토스 종합(${acc.accountNo}) + 토스 RIA + 한국투자 ${d.kisAccounts?.length || 0}계좌(${kisAccSummary || "연동됨"})`
    : "연동된 계좌 없음";

  document.getElementById("fxText").textContent = `실시간 환율 1 USD = ${Number(
    fx.rate
  ).toLocaleString("ko-KR", {
    minimumFractionDigits: 1,
    maximumFractionDigits: 2,
  })}원`;

  document.getElementById("lastUpdatedText").textContent = `기준시각: ${d.timestamp}`;
}

function renderHeroSection() {
  const d = state.dashboard;
  const tot = d.totalKrw;
  const kr = d.krwMarket;
  const us = d.usdMarket;
  const after = state.afterCost;
  const counts = d.counts || { ria: 0 };

  const totalPurchase = tot.purchaseAmount;
  const totalMv = after ? tot.marketValueAfterCost : tot.marketValue;
  const totalPl = after ? tot.profitLossAfterCost : tot.profitLoss;
  const totalRate = after ? tot.returnRateAfterCostPct : tot.returnRatePct;
  const sdkRate = after ? tot.sdkReturnRateAfterCostPct : tot.sdkReturnRatePct;

  const allItems = d.items || [];
  const etfItems = state.overseasEtfAsUs
    ? allItems.filter((i) => i.currency === "KRW" && i.isOverseasEtf)
    : [];
  const etfPurchaseKrw = etfItems.reduce((s, i) => s + (i.purchaseAmountKrw || 0), 0);
  const etfMvKrw = etfItems.reduce(
    (s, i) => s + (after ? i.marketValueAfterCostKrw || 0 : i.marketValueKrw || 0),
    0
  );
  const etfPlKrw = etfItems.reduce(
    (s, i) => s + (after ? i.profitLossAfterCostKrw || 0 : i.profitLossKrw || 0),
    0
  );
  const etfDailyPlKrw = etfItems.reduce((s, i) => s + (i.dailyProfitLossKrw || 0), 0);

  const krPurchaseEff = Math.max(0, kr.purchaseAmount - etfPurchaseKrw);
  const krMvRaw = after ? kr.marketValueAfterCost : kr.marketValue;
  const krMvEff = Math.max(0, krMvRaw - etfMvKrw);
  const krPlRaw = after ? kr.profitLossAfterCost : kr.profitLoss;
  const krPlEff = krPlRaw - etfPlKrw;
  const krDailyPlEff = kr.dailyProfitLoss - etfDailyPlKrw;
  const krRateEff = krPurchaseEff > 0 ? (krPlEff / krPurchaseEff) * 100 : 0;

  const usPurchaseKrwEff = us.purchaseAmountKrw + etfPurchaseKrw;
  const usMvKrwRaw = after ? us.marketValueAfterCostKrw : us.marketValueKrw;
  const usMvKrwEff = usMvKrwRaw + etfMvKrw;
  const usMvUsd = after ? us.marketValueAfterCost : us.marketValue;
  const usPlUsd = after ? us.profitLossAfterCost : us.profitLoss;
  const usPlKrwRaw = after ? us.profitLossAfterCostKrw : us.profitLossKrw;
  const usPlKrwEff = usPlKrwRaw + etfPlKrw;
  const usDailyPlKrwEff = us.dailyProfitLossKrw + etfDailyPlKrw;
  const usRateEff =
    etfItems.length > 0
      ? usPurchaseKrwEff > 0
        ? (usPlKrwEff / usPurchaseKrwEff) * 100
        : 0
      : after
      ? us.returnRateAfterCostPct
      : us.returnRatePct;

  document.getElementById("totalMvLabel").textContent = after
    ? "현재 총 평가금액 (수수료·세금 차감 후)"
    : "현재 총 평가금액 (세전)";
  document.getElementById("totalPlLabel").textContent = after
    ? "전체 투자 대비 순수익 (제비용 차감)"
    : "전체 투자 대비 총 수익 (세전)";

  document.getElementById("totalPurchaseKrw").textContent = fmtKrw(totalPurchase);
  document.getElementById("totalPurchaseBreakdown").textContent =
    etfItems.length > 0
      ? `국내 ${fmtKrw(krPurchaseEff)} + 해외 ${fmtKrw(usPurchaseKrwEff)} (직투 ${fmtUsd(
          us.purchaseAmount
        )} + 국내상장 해외ETF ${fmtKrw(etfPurchaseKrw)})`
      : `국내 ${fmtKrw(krPurchaseEff)} + 해외 ${fmtKrw(usPurchaseKrwEff)} (${fmtUsd(
          us.purchaseAmount
        )})`;

  document.getElementById("totalMarketValueKrw").textContent = fmtKrw(totalMv);
  document.getElementById("totalMvBreakdown").textContent =
    etfItems.length > 0
      ? `국내 ${fmtKrw(krMvEff)} + 해외 ${fmtKrw(usMvKrwEff)} (직투 ${fmtUsd(
          usMvUsd
        )} + 국내상장 해외ETF ${fmtKrw(etfMvKrw)})`
      : `국내 ${fmtKrw(krMvEff)} + 해외 ${fmtKrw(usMvKrwEff)} (${fmtUsd(usMvUsd)})`;

  const plEl = document.getElementById("totalProfitLossKrw");
  plEl.textContent = fmtKrw(totalPl, true);
  plEl.className = `kpi-value ${signClass(totalPl)}`;

  const profitBox = document.getElementById("heroProfitBox");
  profitBox.classList.toggle("is-loss", totalPl < 0);

  const ratePill = document.getElementById("totalReturnRatePill");
  ratePill.textContent = fmtPct(totalRate);
  ratePill.className = pillClass(totalRate);

  const sdkLabel =
    state.scope === "ALL"
      ? `공식 ${fmtPct(sdkRate)}`
      : state.scope === "BROKERAGE"
      ? `토스 ${fmtPct(sdkRate)}`
      : `계좌 ${fmtPct(sdkRate)}`;
  const sdkNoteEl = document.getElementById("sdkReturnRateNote");
  if (sdkNoteEl) {
    sdkNoteEl.textContent = sdkLabel;
    sdkNoteEl.title =
      state.scope === "ALL"
        ? `토스 공식 환차익+한투+RIA 반영 수익률: ${fmtPct(sdkRate)}`
        : `환차익 반영 공식 수익률: ${fmtPct(sdkRate)}`;
  }

  const isAllScope = state.scope === "ALL";

  // 순수 투자 원금 카드 표시/숨김 (전체 합산일 때만 노출)
  const heroPureBox = document.getElementById("heroPureCapitalBox");
  if (heroPureBox) {
    heroPureBox.style.display = isAllScope ? "" : "none";
  }
  const heroKpiRow = document.querySelector(".hero-kpi-row");
  if (heroKpiRow) {
    heroKpiRow.classList.toggle("no-pure-card", !isAllScope);
  }

  // Pure Capital (내가 넣은 순수 현금 원금) 업데이트
  const cap = state.capital || (state.dashboard && state.dashboard.capitalSummary);
  const pureCap = (cap && cap.totalNetCapitalKrw) || 226942111;
  const pureEl = document.getElementById("heroPureCapitalKrw");
  if (pureEl) {
    pureEl.textContent = fmtKrw(pureCap);
  }
  const pureProfit = totalMv - pureCap;
  const pureRate = pureCap > 0 ? (pureProfit / pureCap) * 100 : 0;

  const pureRatePill = document.getElementById("heroPureRatePill");
  if (pureRatePill) {
    pureRatePill.style.display = isAllScope ? "" : "none";
    pureRatePill.textContent = `순수 ${fmtPct(pureRate)}`;
    pureRatePill.className = `pure-rate-pill ${signClass(pureProfit)}`;
    pureRatePill.title = `실제 순수 입금 원금(${fmtKrw(pureCap)}) 대비 총 수익률: ${fmtPct(pureRate)}`;
  }
  const pureProfitVal = document.getElementById("heroPureProfitVal");
  if (pureProfitVal) {
    pureProfitVal.textContent = fmtKrw(pureProfit, true);
    pureProfitVal.className = `sub-val ${signClass(pureProfit)}`;
  }
  const pureProfitStrip = document.getElementById("heroPureProfitStrip");
  if (pureProfitStrip) {
    const subSep = pureProfitStrip.querySelector(".sub-sep");
    const subFirstSpan = pureProfitStrip.firstElementChild;
    if (subFirstSpan) subFirstSpan.style.display = isAllScope ? "" : "none";
    if (subSep) subSep.style.display = isAllScope ? "" : "none";
  }

  // 게이지 바 순수원금 행 제어
  const rowPureBar = document.getElementById("rowPureBar");
  if (rowPureBar) {
    rowPureBar.style.display = isAllScope ? "" : "none";
  }

  const maxBar = isAllScope
    ? Math.max(pureCap, totalPurchase, totalMv, 1)
    : Math.max(totalPurchase, totalMv, 1);
  const pureWidth = Math.max(8, Math.round((pureCap / maxBar) * 100));
  const pWidth = Math.max(8, Math.round((totalPurchase / maxBar) * 100));
  const cWidth = Math.max(8, Math.round((totalMv / maxBar) * 100));

  const barPure = document.getElementById("barPure");
  if (barPure) barPure.style.width = `${pureWidth}%`;
  const barPureVal = document.getElementById("barPureVal");
  if (barPureVal) barPureVal.textContent = fmtKrw(pureCap);

  const barPurchase = document.getElementById("barPurchase");
  if (barPurchase) barPurchase.style.width = `${pWidth}%`;
  const barCurr = document.getElementById("barCurrent");
  if (barCurr) {
    barCurr.style.width = `${cWidth}%`;
    barCurr.classList.toggle("is-loss", totalPl < 0);
  }

  const barPurchaseVal = document.getElementById("barPurchaseVal");
  if (barPurchaseVal) barPurchaseVal.textContent = fmtKrw(totalPurchase);
  const barCurrVal = document.getElementById("barCurrentVal");
  if (barCurrVal) {
    barCurrVal.textContent = fmtKrw(totalMv);
    barCurrVal.className = `dual-bar-val ${signClass(totalPl)}`;
  }

  const mult = pureCap > 0 ? (totalMv / pureCap).toFixed(2) : "1.00";
  const purMult = totalPurchase > 0 ? (totalMv / totalPurchase).toFixed(2) : "1.00";
  const gaugeText = document.getElementById("gaugeSummaryText");
  if (gaugeText) {
    gaugeText.textContent = isAllScope
      ? `순수 원금의 ${mult}배 (${fmtKrw(pureProfit, true)}) · 매수원금의 ${purMult}배`
      : `투자 매수원금의 ${purMult}배 (${fmtKrw(totalPl, true)})`;
  }

  const dplEl = document.getElementById("dailyPlKrw");
  dplEl.textContent = `${fmtKrw(tot.dailyProfitLoss, true)} (${fmtPct(
    tot.dailyReturnRatePct
  )})`;
  dplEl.className = `mini-val ${signClass(tot.dailyProfitLoss)}`;

  document.getElementById("totalCostKrw").textContent = fmtKrw(tot.totalCost);
  document.getElementById("totalCashKrw").textContent = `${fmtKrw(
    tot.cashBuyingPower
  )} (₩${Math.round(kr.cashBuyingPower).toLocaleString()} + ${fmtUsd(
    us.cashBuyingPower
  )})`;
  document.getElementById("totalAssetKrw").textContent = fmtKrw(tot.totalAsset);

  // 우측: 국내주식 카드
  const krTitleEl = document.getElementById("krwCardTitle");
  if (krTitleEl) {
    krTitleEl.textContent = state.overseasEtfAsUs
      ? "국내주식 (국내자산)"
      : "국내주식 (KRW)";
  }
  const krWeight =
    totalPurchase > 0 ? ((krPurchaseEff / totalPurchase) * 100).toFixed(1) : "0.0";
  const krMvWeight =
    totalMv > 0 ? ((krMvEff / totalMv) * 100).toFixed(1) : "0.0";

  document.getElementById(
    "krwWeightText"
  ).textContent = `매수원금 비중 ${krWeight}% · 현재 평가금액 비중 ${krMvWeight}%`;
  const krPill = document.getElementById("krwReturnPill");
  krPill.textContent = fmtPct(krRateEff);
  krPill.className = pillClass(krRateEff);

  document.getElementById("krwPurchase").textContent = fmtKrw(krPurchaseEff);
  document.getElementById("krwMarketValue").textContent = fmtKrw(krMvEff);
  const krPlEl = document.getElementById("krwProfitLoss");
  krPlEl.textContent = fmtKrw(krPlEff, true);
  krPlEl.className = signClass(krPlEff);
  document.getElementById("krwDailyAndCash").textContent = `${fmtKrw(
    krDailyPlEff,
    true
  )} / 현금 ${fmtKrw(kr.cashBuyingPower)}`;

  // 우측: 해외주식 카드
  const usTitleEl = document.getElementById("usdCardTitle");
  if (usTitleEl) {
    usTitleEl.textContent = state.overseasEtfAsUs
      ? `해외주식 (직투 + 해외추종 ETF ${etfItems.length}종)`
      : "해외주식 (USD)";
  }
  const usWeight =
    totalPurchase > 0
      ? ((usPurchaseKrwEff / totalPurchase) * 100).toFixed(1)
      : "0.0";
  const usMvWeight =
    totalMv > 0
      ? ((usMvKrwEff / totalMv) * 100).toFixed(1)
      : "0.0";

  document.getElementById(
    "usdWeightText"
  ).textContent = `매수원금 비중 ${usWeight}% · 현재 평가금액 비중 ${usMvWeight}%`;
  const usPill = document.getElementById("usdReturnPill");
  usPill.textContent = fmtPct(usRateEff);
  usPill.className = pillClass(usRateEff);

  if (state.overseasEtfAsUs && etfItems.length > 0) {
    document.getElementById("usdPurchaseMain").textContent = fmtKrw(usPurchaseKrwEff);
    document.getElementById(
      "usdPurchaseSub"
    ).textContent = `직투 ${fmtUsd(us.purchaseAmount)} (${fmtKrw(
      us.purchaseAmountKrw
    )}) + 해외ETF ${fmtKrw(etfPurchaseKrw)}`;
    document.getElementById("usdMarketValueMain").textContent = fmtKrw(usMvKrwEff);
    document.getElementById(
      "usdMarketValueSub"
    ).textContent = `직투 ${fmtUsd(usMvUsd)} (${fmtKrw(
      usMvKrwRaw
    )}) + 해외ETF ${fmtKrw(etfMvKrw)}`;
    const usPlMain = document.getElementById("usdProfitLossMain");
    usPlMain.textContent = fmtKrw(usPlKrwEff, true);
    usPlMain.className = signClass(usPlKrwEff);
    document.getElementById(
      "usdProfitLossSub"
    ).textContent = `직투 ${fmtUsd(usPlUsd, true)} + 해외ETF ${fmtKrw(etfPlKrw, true)}`;
    document.getElementById("usdDailyAndCash").textContent = `${fmtKrw(
      usDailyPlKrwEff,
      true
    )} (직투 ${fmtUsd(us.dailyProfitLoss, true)}) / ${fmtUsd(us.cashBuyingPower)}`;
  } else if (state.krwUnified) {
    document.getElementById("usdPurchaseMain").textContent = fmtKrw(usPurchaseKrwEff);
    document.getElementById("usdPurchaseSub").textContent = fmtUsd(us.purchaseAmount);
    document.getElementById("usdMarketValueMain").textContent = fmtKrw(usMvKrwEff);
    document.getElementById("usdMarketValueSub").textContent = fmtUsd(usMvUsd);
    const usPlMain = document.getElementById("usdProfitLossMain");
    usPlMain.textContent = fmtKrw(usPlKrwEff, true);
    usPlMain.className = signClass(usPlKrwEff);
    document.getElementById("usdProfitLossSub").textContent = fmtUsd(usPlUsd, true);
    document.getElementById("usdDailyAndCash").textContent = `${fmtUsd(
      us.dailyProfitLoss,
      true
    )} (${fmtKrw(us.dailyProfitLossKrw, true)}) / ${fmtUsd(us.cashBuyingPower)}`;
  } else {
    document.getElementById("usdPurchaseMain").textContent = fmtUsd(us.purchaseAmount);
    document.getElementById("usdPurchaseSub").textContent = `약 ${fmtKrw(
      usPurchaseKrwEff
    )}`;
    document.getElementById("usdMarketValueMain").textContent = fmtUsd(usMvUsd);
    document.getElementById("usdMarketValueSub").textContent = `약 ${fmtKrw(usMvKrwEff)}`;
    const usPlMain = document.getElementById("usdProfitLossMain");
    usPlMain.textContent = fmtUsd(usPlUsd, true);
    usPlMain.className = signClass(usPlUsd);
    document.getElementById("usdProfitLossSub").textContent = `약 ${fmtKrw(
      usPlKrwEff,
      true
    )}`;
    document.getElementById("usdDailyAndCash").textContent = `${fmtUsd(
      us.dailyProfitLoss,
      true
    )} (${fmtKrw(us.dailyProfitLossKrw, true)}) / ${fmtUsd(us.cashBuyingPower)}`;
  }
}

// 차트 3종 렌더링
function renderCharts() {
  const items = [...(state.dashboard?.items || [])];
  const after = state.afterCost;

  const byValue = [...items].sort((a, b) => b.marketValueKrw - a.marketValueKrw);
  const labels1 = byValue.map((i) => i.name);
  const purchaseData = byValue.map((i) => Math.round(i.purchaseAmountKrw));
  const mvData = byValue.map((i) =>
    Math.round(after ? i.marketValueAfterCostKrw : i.marketValueKrw)
  );
  const mvColors = byValue.map((i) => {
    const pl = after ? i.profitLossAfterCostKrw : i.profitLossKrw;
    return pl >= 0 ? "rgba(240, 68, 82, 0.85)" : "rgba(49, 130, 246, 0.85)";
  });

  const ctx1 = document.getElementById("purchaseVsValueChart").getContext("2d");
  if (purchaseVsValueChartInstance) purchaseVsValueChartInstance.destroy();
  purchaseVsValueChartInstance = new Chart(ctx1, {
    type: "bar",
    data: {
      labels: labels1,
      datasets: [
        {
          label: "매수 원금 (내가 투자한 돈)",
          data: purchaseData,
          backgroundColor: "rgba(107, 118, 132, 0.45)",
          borderColor: "rgba(107, 118, 132, 0.9)",
          borderWidth: 1,
          borderRadius: 6,
          pointStyle: "line",
        },
        {
          label: after ? "현재 평가금액 (순수익 기준)" : "현재 평가금액",
          data: mvData,
          backgroundColor: mvColors,
          borderColor: "#f04452",
          borderWidth: 1,
          borderRadius: 6,
          pointStyle: "line",
        },
      ],
    },
    options: {
      responsive: true,
      maintainAspectRatio: false,
      interaction: { mode: "index", intersect: false },
      plugins: {
        legend: {
          position: "top",
          labels: {
            usePointStyle: true,
            pointStyle: "line",
            pointStyleWidth: 28,
            boxWidth: 28,
            font: { family: "Pretendard", size: 12 },
            generateLabels: (chart) => {
              const defaultLabels = Chart.defaults.plugins.legend.labels.generateLabels(chart);
              return defaultLabels.map((item) => {
                item.pointStyle = "line";
                item.lineWidth = 3;
                if (item.datasetIndex === 0) {
                  item.strokeStyle = "rgba(107, 118, 132, 1)";
                } else if (item.datasetIndex === 1) {
                  item.strokeStyle = "#f04452";
                }
                return item;
              });
            },
          },
        },
        tooltip: {
          callbacks: {
            label: (ctx) => `${ctx.dataset.label}: ${fmtKrw(ctx.raw)}`,
            afterBody: (itemsTooltip) => {
              const idx = itemsTooltip[0].dataIndex;
              const item = byValue[idx];
              const pl = after ? item.profitLossAfterCostKrw : item.profitLossKrw;
              const rate = after ? item.returnRateAfterCostPct : item.returnRatePct;
              return `투자 대비 손익: ${fmtKrw(pl, true)} (${fmtPct(rate)})`;
            },
          },
        },
      },
      scales: {
        y: {
          ticks: {
            callback: (val) => (val / 10000).toLocaleString("ko-KR") + "만",
            font: { size: 11 },
          },
          grid: { color: "#f2f4f6" },
        },
        x: {
          grid: { display: false },
          ticks: {
            autoSkip: false,
            maxRotation: 40,
            minRotation: 0,
            font: { family: "Pretendard", weight: "600", size: 11 },
          },
        },
      },
    },
  });

  renderProfitContributionChart();
  renderWeightChart();
}

function renderProfitContributionChart() {
  const items = [...(state.dashboard?.items || [])];
  const after = state.afterCost;
  const isRate = state.profitChartMode === "rate";

  const byProfit = [...items].sort((a, b) => {
    if (isRate) {
      const ra = after ? a.returnRateAfterCostPct : a.returnRatePct;
      const rb = after ? b.returnRateAfterCostPct : b.returnRatePct;
      return rb - ra;
    }
    const pla = after ? a.profitLossAfterCostKrw : a.profitLossKrw;
    const plb = after ? b.profitLossAfterCostKrw : b.profitLossKrw;
    return plb - pla;
  });

  const labels2 = byProfit.map((i) => i.name);
  const profitData = byProfit.map((i) =>
    isRate
      ? Number((after ? i.returnRateAfterCostPct : i.returnRatePct).toFixed(2))
      : Math.round(after ? i.profitLossAfterCostKrw : i.profitLossKrw)
  );
  const profitColors = profitData.map((v) =>
    v >= 0 ? "rgba(240, 68, 82, 0.85)" : "rgba(49, 130, 246, 0.85)"
  );

  const titleEl = document.getElementById("profitContribTitle");
  if (titleEl) {
    titleEl.textContent = isRate ? "종목별 수익률(%) 순위" : "종목별 수익금 기여도";
  }

  const ctx2 = document.getElementById("profitContributionChart").getContext("2d");
  if (profitContributionChartInstance) profitContributionChartInstance.destroy();
  profitContributionChartInstance = new Chart(ctx2, {
    type: "bar",
    data: {
      labels: labels2,
      datasets: [
        {
          label: isRate ? "수익률 (%)" : "평가 손익 (원화 환산)",
          data: profitData,
          backgroundColor: profitColors,
          borderRadius: 5,
        },
      ],
    },
    options: {
      indexAxis: "y",
      responsive: true,
      maintainAspectRatio: false,
      plugins: {
        legend: { display: false },
        tooltip: {
          callbacks: {
            label: (ctx) => {
              const item = byProfit[ctx.dataIndex];
              const pl = after ? item.profitLossAfterCostKrw : item.profitLossKrw;
              const rate = after ? item.returnRateAfterCostPct : item.returnRatePct;
              return `수익: ${fmtKrw(pl, true)} (${fmtPct(rate)})`;
            },
          },
        },
      },
      scales: {
        x: {
          ticks: {
            callback: (val) =>
              isRate ? `${val}%` : (val / 10000).toLocaleString("ko-KR") + "만",
            font: { size: 11 },
          },
          grid: { color: "#f2f4f6" },
        },
        y: {
          grid: { display: false },
          ticks: {
            autoSkip: false,
            font: { family: "Pretendard", weight: "600", size: 11 },
          },
        },
      },
    },
  });
}

function renderWeightChart() {
  const items = [...(state.dashboard?.items || [])];
  const isPurchase = state.weightChartMode === "purchase";
  const sorted = items.sort((a, b) =>
    isPurchase
      ? b.purchaseAmountKrw - a.purchaseAmountKrw
      : b.marketValueKrw - a.marketValueKrw
  );

  const palette = [
    "#3182f6",
    "#f04452",
    "#00b894",
    "#f59f00",
    "#7950f2",
    "#12b886",
    "#e64980",
    "#4c6ef5",
    "#fd7e14",
    "#868e96",
  ];

  const ctx3 = document.getElementById("portfolioWeightChart").getContext("2d");
  if (portfolioWeightChartInstance) portfolioWeightChartInstance.destroy();
  portfolioWeightChartInstance = new Chart(ctx3, {
    type: "doughnut",
    data: {
      labels: sorted.map((i) => i.name),
      datasets: [
        {
          data: sorted.map((i) =>
            Math.round(isPurchase ? i.purchaseAmountKrw : i.marketValueKrw)
          ),
          backgroundColor: sorted.map((_, idx) => palette[idx % palette.length]),
          borderWidth: 2,
          borderColor: "#ffffff",
        },
      ],
    },
    options: {
      responsive: true,
      maintainAspectRatio: false,
      cutout: "60%",
      plugins: {
        legend: {
          position: "right",
          labels: { boxWidth: 10, font: { family: "Pretendard", size: 11 } },
        },
        tooltip: {
          callbacks: {
            label: (ctx) => {
              const item = sorted[ctx.dataIndex];
              const pct = isPurchase
                ? item.weightByPurchasePct
                : item.weightByMarketValuePct;
              return `${item.name}: ${fmtKrw(ctx.raw)} (${pct.toFixed(1)}%)`;
            },
          },
        },
      },
    },
  });
}

// 구간별 수익률 변화 (일별 / 월별 / 연도별) 로드 및 렌더링
async function fetchReturnsHistory(forceRefresh = false) {
  const tbody = document.getElementById("historyTableBody");
  tbody.innerHTML = `<tr><td colspan="7" class="empty-cell">보유 종목의 시계열 일봉 데이터를 분석하는 중입니다...</td></tr>`;
  const mySeq = ++historyReqSeq;

  try {
    const qs = new URLSearchParams({ scope: state.scope, pages: "4", _t: String(Date.now()) });
    if (forceRefresh) qs.set("refresh", "1");
    const resp = await fetch(`/api/returns-history?${qs.toString()}`, {
      cache: "no-store",
    });
    const data = await resp.json();
    if (mySeq !== historyReqSeq) return;
    if (!resp.ok || data.error) {
      throw new Error(data.error || "시계열 조회 실패");
    }
    state.historyData = data;
    renderReturnsHistory();
  } catch (e) {
    if (mySeq !== historyReqSeq) return;
    tbody.innerHTML = `<tr><td colspan="7" class="empty-cell">시계열 조회 실패: ${e.message}</td></tr>`;
  }
}

function renderReturnsHistory() {
  if (!state.historyData) return;
  const unit = state.historyUnit; // 'daily' | 'monthly' | 'yearly'
  const rangePills = document.getElementById("historyRangePills");
  const monthRangePills = document.getElementById("historyMonthRangePills");
  if (rangePills) {
    rangePills.classList.toggle("hidden", unit !== "daily");
    rangePills.style.display = unit === "daily" ? "inline-flex" : "none";
  }
  if (monthRangePills) {
    monthRangePills.classList.toggle("hidden", unit !== "monthly");
    monthRangePills.style.display = unit === "monthly" ? "inline-flex" : "none";
  }

  let series = [...(state.historyData[unit] || [])];
  if (series.length > 0) {
    const lastItem = series[series.length - 1];
    const lastDate = new Date(lastItem.period);

    if (unit === "daily" && state.historyDays < 9999) {
      const cutoff = new Date(lastDate);
      cutoff.setDate(cutoff.getDate() - state.historyDays);
      const cutoffStr = cutoff.toISOString().slice(0, 10);
      const filtered = series.filter((r) => r.period >= cutoffStr);
      if (filtered.length > 0) series = filtered;
    } else if (unit === "monthly") {
      if (state.historyMonths === "YTD") {
        const curYearPrefix = `${new Date().getFullYear()}-`;
        const ytdFiltered = series.filter((r) => String(r.period).startsWith(curYearPrefix));
        if (ytdFiltered.length > 0) series = ytdFiltered;
      } else {
        const mCount = Number(state.historyMonths || 9999);
        if (mCount < 9999) {
          const cutoff = new Date(lastDate);
          cutoff.setMonth(cutoff.getMonth() - mCount);
          const cutoffStr = cutoff.toISOString().slice(0, 7);
          const filtered = series.filter((r) => r.period >= cutoffStr);
          if (filtered.length > 0) series = filtered;
        }
      }
    }
  }

  const tbody = document.getElementById("historyTableBody");
  if (series.length === 0) {
    tbody.innerHTML = `<tr><td colspan="7" class="empty-cell">표시할 구간 데이터가 없습니다.</td></tr>`;
    return;
  }

  const first = series[0];
  const last = series[series.length - 1];

  // 구간 손익 및 수익률 (선택 구간 동안 발생한 실질 손익 및 자산 증가율)
  const periodProfitDiff = (last.profitLossKrw || 0) - (first.profitLossKrw || 0);
  const startMv = first.marketValueKrw || 0;
  const endMv = last.marketValueKrw || 0;
  const periodGainPct = startMv > 0 ? ((endMv - startMv) / startMv * 100) : 0;
  const periodRateDiffPct = (last.returnRatePct || 0) - (first.returnRatePct || 0);

  const peak = series.reduce(
    (max, r) => (r.returnRatePct > max.returnRatePct ? r : max),
    series[0]
  );
  const trough = series.reduce(
    (min, r) => (r.returnRatePct < min.returnRatePct ? r : min),
    series[0]
  );

  // KPI 4개 업데이트
  const startEndEl = document.getElementById("histStartToEndRate");
  startEndEl.textContent = `${fmtKrw(periodProfitDiff, true)} (${periodGainPct >= 0 ? "+" : ""}${periodGainPct.toFixed(2)}%)`;
  startEndEl.className = signClass(periodProfitDiff);
  startEndEl.title = `구간 시작일 ${first.period} (${fmtKrw(startMv)}) → 현재 (${fmtKrw(endMv)}) / 수익률 변동: ${periodRateDiffPct >= 0 ? "+" : ""}${periodRateDiffPct.toFixed(2)}%p`;

  const peakEl = document.getElementById("histPeakRate");
  peakEl.textContent = `${fmtKrw(peak.profitLossKrw, true)} (${fmtPct(peak.returnRatePct)} · ${peak.period})`;
  peakEl.className = signClass(peak.profitLossKrw);

  const troughEl = document.getElementById("histTroughRate");
  troughEl.textContent = `${fmtKrw(trough.profitLossKrw, true)} (${fmtPct(trough.returnRatePct)} · ${trough.period})`;
  troughEl.className = signClass(trough.profitLossKrw);

  const latestEl = document.getElementById("histLatestDelta");
  latestEl.textContent = `${fmtKrw(last.periodProfitChangeKrw, true)} (${last.periodRateDiffPct >= 0 ? "+" : ""}${last.periodRateDiffPct.toFixed(2)}%p)`;
  latestEl.className = signClass(last.periodProfitChangeKrw);

  const unitLabelMap = { daily: "일별", monthly: "월별", yearly: "연도별" };
  const uLabel = unitLabelMap[unit] || "일별";
  const metric = state.historyMetric || "rate";

  const titleMap = {
    rate: `${uLabel} 매수원금 대비 누적 수익률(%) 추이`,
    profit: `${uLabel} 매수원금 대비 누적 수익금(원) 추이`,
    value: `${uLabel} 총 평가금액 vs 매수원금(원) 추이`,
  };
  document.getElementById("histMainChartTitle").textContent =
    titleMap[metric] || titleMap.rate;
  document.getElementById(
    "histBarChartTitle"
  ).textContent = `${uLabel} 평가손익 증감액 (직전 ${uLabel.replace("별", "")} 대비)`;

  const labels = series.map((r) =>
    unit === "daily" ? r.period.slice(5) : r.period
  );

  // 차트 1: 선택된 모드(수익률 % / 누적 수익금 원 / 총 평가금액 vs 원금 원)에 따라 데이터셋 구성
  const ctxLine = document.getElementById("historyReturnChart").getContext("2d");
  if (historyReturnChartInstance) historyReturnChartInstance.destroy();
  const isOverallPositive = last.profitLossKrw >= 0;
  const mainColor = isOverallPositive ? "#f04452" : "#3182f6";
  const fillBg = isOverallPositive
    ? "rgba(240, 68, 82, 0.1)"
    : "rgba(49, 130, 246, 0.1)";

  let lineDatasets = [];
  if (metric === "rate") {
    lineDatasets = [
      {
        label: `${uLabel} 누적 수익률 (%)`,
        data: series.map((r) => r.returnRatePct),
        borderColor: mainColor,
        backgroundColor: fillBg,
        borderWidth: 2.3,
        pointRadius: unit === "daily" && series.length > 45 ? 0 : 3,
        pointHoverRadius: 5,
        pointStyle: "line",
        fill: true,
        tension: 0.2,
      },
    ];
  } else if (metric === "profit") {
    lineDatasets = [
      {
        label: `${uLabel} 누적 수익금 (원)`,
        data: series.map((r) => r.profitLossKrw),
        borderColor: mainColor,
        backgroundColor: fillBg,
        borderWidth: 2.3,
        pointRadius: unit === "daily" && series.length > 45 ? 0 : 3,
        pointHoverRadius: 5,
        pointStyle: "line",
        fill: true,
        tension: 0.2,
      },
    ];
  } else {
    lineDatasets = [
      {
        label: `${uLabel} 총 평가금액 (원)`,
        data: series.map((r) => r.marketValueKrw),
        borderColor: mainColor,
        backgroundColor: fillBg,
        borderWidth: 2.3,
        pointRadius: unit === "daily" && series.length > 45 ? 0 : 3,
        pointHoverRadius: 5,
        pointStyle: "line",
        fill: true,
        tension: 0.2,
      },
      {
        label: "총 매수원금 (내가 투자한 돈)",
        data: series.map((r) => r.purchaseAmountKrw),
        borderColor: "#191f28",
        borderWidth: 1.8,
        borderDash: [6, 4],
        pointRadius: 0,
        pointStyle: "line",
        fill: false,
      },
    ];
  }

  historyReturnChartInstance = new Chart(ctxLine, {
    type: "line",
    data: {
      labels,
      datasets: lineDatasets,
    },
    options: {
      responsive: true,
      maintainAspectRatio: false,
      interaction: { mode: "index", intersect: false },
      plugins: {
        legend: {
          position: "top",
          labels: {
            usePointStyle: true,
            pointStyle: "line",
            pointStyleWidth: 28,
            boxWidth: 28,
            font: { family: "Pretendard", size: 12 },
          },
        },
        tooltip: {
          callbacks: {
            title: (items) => series[items[0].dataIndex].period,
            label: (ctx) => {
              if (ctx.datasetIndex === 1 && metric !== "value") return null;
              const row = series[ctx.dataIndex];
              if (ctx.datasetIndex === 1 && metric === "value") {
                return `총 매수원금: ${fmtKrw(row.purchaseAmountKrw)}`;
              }
              return `누적 수익: ${fmtKrw(row.profitLossKrw, true)} (${fmtPct(
                row.returnRatePct
              )})`;
            },
            afterBody: (items) => {
              const row = series[items[0].dataIndex];
              return [
                `총 평가금액: ${fmtKrw(row.marketValueKrw)}`,
                `총 매수원금: ${fmtKrw(row.purchaseAmountKrw)}`,
                `직전 구간 대비: ${fmtKrw(row.periodProfitChangeKrw, true)} (${fmtPct(
                  row.periodRateDiffPct
                )}p)`,
              ];
            },
          },
        },
      },
      scales: {
        y: {
          ticks: {
            callback: (v) =>
              metric === "rate"
                ? `${v}%`
                : (v / 10000).toLocaleString("ko-KR") + "만",
            font: { size: 11 },
          },
          grid: { color: "#e5e8eb" },
        },
        x: {
          grid: { display: false },
          ticks: { maxTicksLimit: 12, font: { size: 11 } },
        },
      },
    },
  });

  // 차트 2: 구간별 손익 증감액(원) / 구간 등락률(%) / 누적수익률 변화(%p) 바 차트
  const deltaMode = state.historyDeltaMetric || "amount";
  const barTitleMap = {
    amount: `${uLabel} 평가손익 증감액 (직전 ${uLabel.replace("별", "")} 대비)`,
    pct: `${uLabel} 자산 등락률 (%) (직전 ${uLabel.replace("별", "")} 대비)`,
    rateDiff: `${uLabel} 누적 수익률 변화폭 (%p) (직전 ${uLabel.replace("별", "")} 대비)`,
  };
  document.getElementById("histBarChartTitle").textContent =
    barTitleMap[deltaMode] || barTitleMap.amount;

  const deltas = series.map((r) => {
    if (deltaMode === "pct") return r.periodReturnPct;
    if (deltaMode === "rateDiff") return r.periodRateDiffPct;
    return r.periodProfitChangeKrw;
  });
  const deltaColors = deltas.map((v) =>
    v >= 0 ? "rgba(240, 68, 82, 0.85)" : "rgba(49, 130, 246, 0.85)"
  );

  const barDatasetLabel =
    deltaMode === "pct"
      ? `${uLabel} 자산 등락률 (%)`
      : deltaMode === "rateDiff"
      ? `${uLabel} 누적 수익률 변화 (%p)`
      : `${uLabel} 손익 증감액 (원)`;

  const ctxBar = document.getElementById("historyDeltaChart").getContext("2d");
  if (historyDeltaChartInstance) historyDeltaChartInstance.destroy();
  historyDeltaChartInstance = new Chart(ctxBar, {
    type: "bar",
    data: {
      labels,
      datasets: [
        {
          label: barDatasetLabel,
          data: deltas,
          backgroundColor: deltaColors,
          borderRadius: 4,
        },
      ],
    },
    options: {
      responsive: true,
      maintainAspectRatio: false,
      interaction: { mode: "index", intersect: false },
      plugins: {
        legend: {
          position: "top",
          labels: {
            usePointStyle: true,
            pointStyle: "line",
            pointStyleWidth: 28,
            boxWidth: 28,
            font: { family: "Pretendard", size: 12 },
          },
        },
        tooltip: {
          callbacks: {
            title: (items) => series[items[0].dataIndex].period,
            label: (ctx) => {
              const row = series[ctx.dataIndex];
              return `손익 증감: ${fmtKrw(
                row.periodProfitChangeKrw,
                true
              )} (구간 등락 ${fmtPct(row.periodReturnPct)} / 누적수익률 ${fmtPct(
                row.periodRateDiffPct
              )}p)`;
            },
          },
        },
      },
      scales: {
        y: {
          ticks: {
            callback: (val) => {
              if (deltaMode === "pct") return `${val}%`;
              if (deltaMode === "rateDiff") return `${val}%p`;
              return (val / 10000).toLocaleString("ko-KR") + "만";
            },
            font: { size: 11 },
          },
          grid: { color: "#e5e8eb" },
        },
        x: {
          grid: { display: false },
          ticks: { maxTicksLimit: 12, font: { size: 11 } },
        },
      },
    },
  });

  // 하단 상세 테이블 (최신순 정렬)
  const reversed = [...series].reverse();
  tbody.innerHTML = reversed
    .map((r) => {
      return `
        <tr>
          <td><strong>${r.period}</strong></td>
          <td class="text-right">${fmtKrw(r.purchaseAmountKrw)}</td>
          <td class="text-right"><strong>${fmtKrw(r.marketValueKrw)}</strong></td>
          <td class="text-right ${signClass(r.profitLossKrw)}"><strong>${fmtKrw(
        r.profitLossKrw,
        true
      )}</strong></td>
          <td class="text-right"><span class="${pillClass(
            r.returnRatePct
          )}">${fmtPct(r.returnRatePct)}</span></td>
          <td class="text-right ${signClass(r.periodProfitChangeKrw)}">${fmtKrw(
        r.periodProfitChangeKrw,
        true
      )}</td>
          <td class="text-right ${signClass(r.periodRateDiffPct)}">${fmtPct(
        r.periodRateDiffPct
      )}p</td>
        </tr>
      `;
    })
    .join("");
}

// 보유 종목 상세 테이블 렌더링
function renderHoldingsTable() {
  const d = state.dashboard;
  if (!d) return;
  const items = d.items || [];
  const after = state.afterCost;
  const unified = state.krwUnified;

  document.getElementById("countAll").textContent = items.length;
  document.getElementById("countKR").textContent = items.filter(
    (i) => !isItemOverseasClassified(i)
  ).length;
  document.getElementById("countUS").textContent = items.filter(
    (i) => isItemOverseasClassified(i)
  ).length;
  document.getElementById("countProfit").textContent = items.filter(
    (i) => (after ? i.profitLossAfterCostKrw : i.profitLossKrw) > 0
  ).length;
  document.getElementById("countLoss").textContent = items.filter(
    (i) => (after ? i.profitLossAfterCostKrw : i.profitLossKrw) < 0
  ).length;

  const filtered = items.filter((item) => {
    const pl = after ? item.profitLossAfterCostKrw : item.profitLossKrw;
    if (state.filter === "KR" && isItemOverseasClassified(item)) return false;
    if (state.filter === "US" && !isItemOverseasClassified(item)) return false;
    if (state.filter === "PROFIT" && pl <= 0) return false;
    if (state.filter === "LOSS" && pl >= 0) return false;

    if (state.search) {
      const q = state.search.toLowerCase();
      const matchName = (item.name || "").toLowerCase().includes(q);
      const matchSym = (item.symbol || "").toLowerCase().includes(q);
      if (!matchName && !matchSym) return false;
    }
    return true;
  });

  filtered.sort((a, b) => {
    const field = state.sortField;
    let va = a[field];
    let vb = b[field];
    if (field === "marketValueKrw" && after) {
      va = a.marketValueAfterCostKrw;
      vb = b.marketValueAfterCostKrw;
    } else if (field === "profitLossKrw" && after) {
      va = a.profitLossAfterCostKrw;
      vb = b.profitLossAfterCostKrw;
    } else if (field === "returnRatePct" && after) {
      va = a.returnRateAfterCostPct;
      vb = b.returnRateAfterCostPct;
    }

    if (typeof va === "string") {
      return state.sortDesc ? vb.localeCompare(va) : va.localeCompare(vb);
    }
    return state.sortDesc ? vb - va : va - vb;
  });

  const tbody = document.getElementById("holdingsTableBody");
  const tfoot = document.getElementById("holdingsTableFoot");

  document.querySelectorAll(".holdings-table th.sortable").forEach((th) => {
    const baseLabel = th.getAttribute("data-label") || th.textContent.replace(/\s*[↓↑]$/, "");
    const f = th.getAttribute("data-sort");
    if (f === state.sortField) {
      th.textContent = `${baseLabel} ${state.sortDesc ? "↓" : "↑"}`;
    } else {
      th.textContent = baseLabel;
    }
  });

  if (filtered.length === 0) {
    tbody.innerHTML = `<tr><td colspan="9" class="empty-cell">조건에 맞는 보유 종목이 없습니다.</td></tr>`;
    tfoot.innerHTML = "";
    return;
  }

  let sumPurchaseKrw = 0;
  let sumMvKrw = 0;
  let sumPlKrw = 0;
  let sumDailyKrw = 0;

  tbody.innerHTML = filtered
    .map((item, idx) => {
      const isUs = item.currency === "USD";
      const flag = isItemOverseasClassified(item) ? "🇺🇸" : "🇰🇷";
      const isRia = item.accountTag === "RIA";
      const isCombined = item.accountTag === "COMBINED";
      const ovEtfBadge = item.isOverseasEtf
        ? `<span class="acct-tag ov-etf" title="국내 상장 해외주식 추종 ETF">해외추종 ETF</span>`
        : "";

      const mvKrw = after ? item.marketValueAfterCostKrw : item.marketValueKrw;
      const mvOrig = after ? item.marketValueAfterCost : item.marketValue;
      const plKrw = after ? item.profitLossAfterCostKrw : item.profitLossKrw;
      const plOrig = after ? item.profitLossAfterCost : item.profitLoss;
      const ratePct = after ? item.returnRateAfterCostPct : item.returnRatePct;

      sumPurchaseKrw += item.purchaseAmountKrw;
      sumMvKrw += mvKrw;
      sumPlKrw += plKrw;
      sumDailyKrw += item.dailyProfitLossKrw;

      const avgPriceMain =
        isUs && !unified
          ? fmtUsd(item.averagePurchasePrice)
          : fmtKrw(item.averagePurchasePriceKrw);
      const lastPriceMain =
        isUs && !unified ? fmtUsd(item.lastPrice) : fmtKrw(item.lastPriceKrw);
      const priceSub = isUs
        ? unified
          ? `평단 ${fmtUsd(item.averagePurchasePrice)} → 현재 ${fmtUsd(item.lastPrice)}`
          : `평단 ${fmtKrw(item.averagePurchasePriceKrw)} → 현재 ${fmtKrw(
              item.lastPriceKrw
            )}`
        : `평단 대비 ${fmtPct(ratePct)}`;

      const purchMain =
        isUs && !unified
          ? fmtUsd(item.purchaseAmount)
          : fmtKrw(item.purchaseAmountKrw);
      const purchSub = isUs
        ? unified
          ? fmtUsd(item.purchaseAmount)
          : fmtKrw(item.purchaseAmountKrw)
        : `원금 비중 ${item.weightByPurchasePct.toFixed(1)}%`;

      const mvMain = isUs && !unified ? fmtUsd(mvOrig) : fmtKrw(mvKrw);
      const mvSub = isUs
        ? unified
          ? fmtUsd(mvOrig)
          : fmtKrw(mvKrw)
        : `제비용 ${fmtKrw(item.totalCostKrw)}`;

      const plMain = isUs && !unified ? fmtUsd(plOrig, true) : fmtKrw(plKrw, true);
      const plSub = isUs
        ? unified
          ? fmtUsd(plOrig, true)
          : fmtKrw(plKrw, true)
        : after
        ? "수수료·세금 차감 후"
        : `세후 ${fmtKrw(item.profitLossAfterCostKrw, true)}`;

      const dplMain = isRia
        ? "-"
        : isUs && !unified
        ? fmtUsd(item.dailyProfitLoss, true)
        : fmtKrw(item.dailyProfitLossKrw, true);

      return `
        <tr class="stock-row" data-idx="${idx}">
          <td>
            <div class="stock-cell">
              <div class="stock-avatar">${flag}</div>
              <div class="stock-name-wrap">
                <span class="stock-name">${item.name}</span>
                <span class="stock-meta">
                  ${item.symbol} · ${item.currency}
                  <span class="acct-tag ${isRia || isCombined ? "ria" : ""}">${
        item.accountLabel || "종합매매"
      }</span>${ovEtfBadge}
                </span>
              </div>
            </div>
          </td>
          <td class="text-right">
            <div class="cell-primary">${fmtQty(item.quantity)}</div>
            ${
              item.quantityBreakdown
                ? `<div class="cell-secondary">${item.quantityBreakdown}</div>`
                : ""
            }
          </td>
          <td class="text-right">
            <div class="cell-primary">${avgPriceMain} → ${lastPriceMain}</div>
            <div class="cell-secondary">${priceSub}</div>
          </td>
          <td class="text-right">
            <div class="cell-primary">${purchMain}</div>
            <div class="cell-secondary">${purchSub}</div>
          </td>
          <td class="text-right">
            <div class="cell-primary">${mvMain}</div>
            <div class="cell-secondary">${mvSub}</div>
          </td>
          <td class="text-right">
            <div class="cell-primary ${signClass(plKrw)}">${plMain}</div>
            <div class="cell-secondary">${plSub}</div>
          </td>
          <td class="text-right">
            <span class="${pillClass(ratePct)}">${fmtPct(ratePct)}</span>
          </td>
          <td class="text-right">
            <div class="cell-primary">${item.weightByPurchasePct.toFixed(
              1
            )}% → ${item.weightByMarketValuePct.toFixed(1)}%</div>
            <div class="weight-bar-mini"><div style="width:${Math.min(
              100,
              item.weightByMarketValuePct
            )}%"></div></div>
          </td>
          <td class="text-right">
            <div class="cell-primary ${signClass(
              item.dailyProfitLossKrw
            )}">${dplMain}</div>
            <div class="cell-secondary ${signClass(item.dailyReturnRatePct)}">${
        isRia ? "실시간 시세" : fmtPct(item.dailyReturnRatePct)
      }</div>
          </td>
        </tr>
      `;
    })
    .join("");

  const sumRatePct = sumPurchaseKrw > 0 ? (sumPlKrw / sumPurchaseKrw) * 100 : 0;
  tfoot.innerHTML = `
    <tr>
      <td colspan="3">선택된 종목 합계 (${filtered.length}종목 · 원화 환산 기준)</td>
      <td class="text-right">${fmtKrw(sumPurchaseKrw)}</td>
      <td class="text-right">${fmtKrw(sumMvKrw)}</td>
      <td class="text-right ${signClass(sumPlKrw)}">${fmtKrw(sumPlKrw, true)}</td>
      <td class="text-right"><span class="${pillClass(sumRatePct)}">${fmtPct(
    sumRatePct
  )}</span></td>
      <td class="text-right">100.0%</td>
      <td class="text-right ${signClass(sumDailyKrw)}">${fmtKrw(
    sumDailyKrw,
    true
  )}</td>
    </tr>
  `;

  tbody.querySelectorAll("tr.stock-row").forEach((tr) => {
    tr.addEventListener("click", () => {
      const idx = Number(tr.getAttribute("data-idx"));
      const item = filtered[idx];
      if (item) openStockModal(item);
    });
  });
}

// RIA 관리 탭 테이블 렌더링
function renderRiaManageTable() {
  const riaItems = state.dashboard?.riaConfig?.items || [];
  const tbody = document.getElementById("riaManageTableBody");
  if (!tbody) return;

  if (riaItems.length === 0) {
    tbody.innerHTML = `<tr><td colspan="9" class="empty-cell">등록된 RIA 계좌 보유종목이 없습니다. 위 입력창에서 종목을 추가해 보세요!</td></tr>`;
    return;
  }

  tbody.innerHTML = riaItems
    .map((it) => {
      return `
        <tr>
          <td>
            <div class="cell-primary">${it.name}</div>
            <div class="cell-secondary">${it.symbol} · ${it.currency}</div>
          </td>
          <td>
            <span class="acct-tag ria">${it.purchaseDate || "자동추정"}</span>
          </td>
          <td class="text-right">${fmtQty(it.quantity)}</td>
          <td class="text-right">${fmtCurr(it.averagePurchasePrice, it.currency)}</td>
          <td class="text-right"><strong>${fmtCurr(
            it.lastPrice,
            it.currency
          )}</strong></td>
          <td class="text-right">${fmtCurr(it.purchaseAmount, it.currency)}</td>
          <td class="text-right"><strong>${fmtCurr(
            it.marketValue,
            it.currency
          )}</strong></td>
          <td class="text-right">
            <span class="${signClass(it.profitLoss)}"><strong>${fmtCurr(
        it.profitLoss,
        it.currency,
        true
      )}</strong></span>
            <span class="${pillClass(it.returnRatePct)}" style="margin-left:6px;">${fmtPct(
        it.returnRatePct
      )}</span>
          </td>
          <td class="text-right">
            <button class="btn-outline" style="padding:5px 9px;font-size:12px;margin-right:4px;" data-edit-sym="${it.symbol}">수정</button>
            <button class="btn-danger-sm" data-del-sym="${it.symbol}">삭제</button>
          </td>
        </tr>
      `;
    })
    .join("");

  tbody.querySelectorAll("button[data-edit-sym]").forEach((btn) => {
    btn.addEventListener("click", () => {
      const sym = btn.getAttribute("data-edit-sym");
      const found = riaItems.find((i) => i.symbol === sym);
      if (!found) return;
      document.getElementById("riaSymbolInput").value = found.symbol;
      document.getElementById("riaNameInput").value = found.name;
      document.getElementById("riaCurrencySelect").value = found.currency;
      document.getElementById("riaQtyInput").value = found.quantity;
      document.getElementById("riaAvgPriceInput").value = found.averagePurchasePrice;
      document.getElementById("riaPurchaseAmtInput").value = found.purchaseAmount;
      const dateIn = document.getElementById("riaDateInput");
      if (dateIn) dateIn.value = found.purchaseDate || "";
    });
  });

  tbody.querySelectorAll("button[data-del-sym]").forEach((btn) => {
    btn.addEventListener("click", async () => {
      const sym = btn.getAttribute("data-del-sym");
      await fetch("/api/ria-holdings", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ action: "delete_item", symbol: sym }),
      });
      state.historyData = null;
      await fetchDashboard(false);
    });
  });
}

// RIA 이관·매도 내역 테이블 렌더링
function renderRiaSalesTable() {
  const cfg = state.dashboard?.riaConfig || {};
  const sales = cfg.sales || [];
  const sum = cfg.salesSummary || {};
  const tbody = document.getElementById("riaSalesTableBody");
  if (!tbody) return;

  document.getElementById("riaSaleCountStat").textContent = `${sum.count || 0}건`;
  document.getElementById("riaSaleSellStat").textContent = fmtKrw(sum.sellAmountKrw || 0);
  document.getElementById("riaSaleCostStat").textContent = fmtKrw(sum.purchaseAmountKrw || 0);
  document.getElementById("riaSaleFeeStat").textContent = fmtKrw(sum.feeKrw || 0);
  const profitEl = document.getElementById("riaSaleProfitStat");
  profitEl.textContent = `${fmtKrw(sum.profitKrw || 0, true)} (${fmtPct(sum.returnRatePct || 0)})`;
  profitEl.className = signClass(sum.profitKrw || 0);

  if (sales.length === 0) {
    tbody.innerHTML = `<tr><td colspan="8" class="empty-cell">등록된 RIA 매도 내역이 없습니다.</td></tr>`;
    return;
  }

  tbody.innerHTML = sales
    .slice()
    .reverse()
    .map((s) => {
      const fee = Number(s.commissionKrw || 0) + Number(s.taxKrw || 0);
      return `
        <tr>
          <td>${s.soldAt || "-"}</td>
          <td>
            <div class="cell-primary">${s.name}</div>
            <div class="cell-secondary">${s.symbol} · ${s.currency}</div>
          </td>
          <td class="text-right">${fmtQty(s.quantity)}</td>
          <td class="text-right">
            <div class="cell-primary">${fmtKrw(s.sellAmountKrw)}</div>
            ${s.currency === "USD" ? `<div class="cell-secondary">${fmtUsd(s.sellAmountUsd)}</div>` : ""}
          </td>
          <td class="text-right">
            <div class="cell-primary">${fmtKrw(s.purchaseAmountKrw)}</div>
            ${s.currency === "USD" ? `<div class="cell-secondary">${fmtUsd(s.purchaseAmountUsd)}</div>` : ""}
          </td>
          <td class="text-right">${fmtKrw(fee)}</td>
          <td class="text-right">
            <span class="${signClass(s.finalProfitKrw)}"><strong>${fmtKrw(s.finalProfitKrw, true)}</strong></span>
          </td>
          <td class="text-right">
            <button class="btn-outline" style="padding:5px 9px;font-size:12px;margin-right:4px;" data-edit-sale="${s.id}">수정</button>
            <button class="btn-danger-sm" data-del-sale="${s.id}">삭제</button>
          </td>
        </tr>
      `;
    })
    .join("");

  tbody.querySelectorAll("button[data-edit-sale]").forEach((btn) => {
    btn.addEventListener("click", () => {
      const found = sales.find((x) => x.id === btn.getAttribute("data-edit-sale"));
      if (!found) return;
      document.getElementById("riaSaleIdInput").value = found.id;
      document.getElementById("riaSaleSymbolInput").value = found.symbol;
      document.getElementById("riaSaleNameInput").value = found.name;
      document.getElementById("riaSaleCurrencySelect").value = found.currency;
      document.getElementById("riaSaleDateInput").value = found.soldAt || "";
      document.getElementById("riaSaleQtyInput").value = found.quantity;
      document.getElementById("riaSaleSellKrwInput").value = found.sellAmountKrw;
      document.getElementById("riaSaleBuyKrwInput").value = found.purchaseAmountKrw;
      document.getElementById("riaSaleSellUsdInput").value = found.sellAmountUsd || "";
      document.getElementById("riaSaleBuyUsdInput").value = found.purchaseAmountUsd || "";
      document.getElementById("riaSaleCommInput").value = found.commissionKrw || "";
      document.getElementById("riaSaleTaxInput").value = found.taxKrw || "";
      document.getElementById("riaSaleSymbolInput").scrollIntoView({ behavior: "smooth", block: "center" });
    });
  });

  tbody.querySelectorAll("button[data-del-sale]").forEach((btn) => {
    btn.addEventListener("click", async () => {
      if (!confirm("이 매도 내역을 삭제할까요?")) return;
      await fetch("/api/ria-holdings", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ action: "delete_sale", id: btn.getAttribute("data-del-sale") }),
      });
      state.historyData = null;
      await fetchDashboard(false);
    });
  });
}

// 종목 상세 모달
async function openStockModal(item) {
  const modal = document.getElementById("stockModal");
  modal.classList.remove("hidden");

  const isUs = item.currency === "USD";
  document.getElementById("modalFlag").textContent =
    item.marketCountry === "US" ? "🇺🇸" : "🇰🇷";
  document.getElementById("modalStockName").textContent = item.name;
  document.getElementById("modalStockSymbol").textContent = `${item.symbol} (${
    item.accountLabel || "종합매매"
  })`;

  const avgFormatted = fmtCurr(item.averagePurchasePrice, item.currency);
  const lastFormatted = fmtCurr(item.lastPrice, item.currency);
  document.getElementById(
    "modalStockSummary"
  ).textContent = `내 평균 매수가 ${avgFormatted} → 현재가 ${lastFormatted} (${fmtPct(
    item.returnRatePct
  )})`;

  const kpiGrid = document.getElementById("modalKpiGrid");
  kpiGrid.innerHTML = `
    <div class="modal-kpi-item">
      <span>보유 수량</span>
      <strong>${fmtQty(item.quantity)}${
    item.quantityBreakdown
      ? ` <small style="font-size:12px;font-weight:500;color:#6b7684;">(${item.quantityBreakdown})</small>`
      : ""
  }</strong>
    </div>
    <div class="modal-kpi-item">
      <span>매수 원금 (구매금액)</span>
      <strong>${fmtKrw(item.purchaseAmountKrw)}${
    isUs ? ` (${fmtUsd(item.purchaseAmount)})` : ""
  }</strong>
    </div>
    <div class="modal-kpi-item">
      <span>현재 평가금액</span>
      <strong>${fmtKrw(item.marketValueKrw)}${
    isUs ? ` (${fmtUsd(item.marketValue)})` : ""
  }</strong>
    </div>
    <div class="modal-kpi-item">
      <span>투자 대비 수익 (세전)</span>
      <strong class="${signClass(item.profitLossKrw)}">${fmtKrw(
    item.profitLossKrw,
    true
  )} (${fmtPct(item.returnRatePct)})</strong>
    </div>
  `;

  loadModalCandles(item);
  loadModalOrders(item);
}

async function loadModalCandles(item) {
  const ctx = document.getElementById("stockCandleChart").getContext("2d");
  if (stockCandleChartInstance) stockCandleChartInstance.destroy();

  try {
    const resp = await fetch(
      `/api/candles?symbol=${encodeURIComponent(item.symbol)}&interval=1d&count=90`
    );
    const data = await resp.json();
    const candles = (data.candles || []).slice().reverse();

    const labels = candles.map((c) => (c.timestamp || "").slice(5, 10));
    const closes = candles.map((c) => Number(c.closePrice));
    const avgLine = candles.map(() => Number(item.averagePurchasePrice));

    const isProfit = item.lastPrice >= item.averagePurchasePrice;
    const lineColor = isProfit ? "#f04452" : "#3182f6";

    stockCandleChartInstance = new Chart(ctx, {
      type: "line",
      data: {
        labels,
        datasets: [
          {
            label: `종가 (${item.currency})`,
            data: closes,
            borderColor: lineColor,
            backgroundColor: isProfit
              ? "rgba(240, 68, 82, 0.08)"
              : "rgba(49, 130, 246, 0.08)",
            borderWidth: 2.2,
            pointRadius: 0,
            pointStyle: "line",
            fill: true,
            tension: 0.2,
          },
          {
            label: `내 평균 매수가 (${fmtCurr(
              item.averagePurchasePrice,
              item.currency
            )})`,
            data: avgLine,
            borderColor: "#191f28",
            borderWidth: 2,
            borderDash: [6, 4],
            pointRadius: 0,
            pointStyle: "line",
            fill: false,
          },
        ],
      },
      options: {
        responsive: true,
        maintainAspectRatio: false,
        interaction: { mode: "index", intersect: false },
        plugins: {
          legend: {
            position: "top",
            labels: {
              usePointStyle: true,
              pointStyle: "line",
              pointStyleWidth: 28,
              boxWidth: 28,
              font: { family: "Pretendard", size: 11 },
            },
          },
        },
      },
    });
  } catch (e) {
    console.error("Candles error:", e);
  }
}

async function loadModalOrders(item) {
  const tbody = document.getElementById("modalOrdersBody");
  tbody.innerHTML = `<tr><td colspan="6" class="empty-cell">주문 내역을 불러오는 중...</td></tr>`;
  try {
    const resp = await fetch(
      `/api/orders?status=CLOSED&symbol=${encodeURIComponent(item.symbol)}&exactSymbol=1&limit=50`
    );
    const data = await resp.json();
    const orders = (data.orders || []).filter(
      (o) => o.status === "FILLED" || o.status === "PARTIAL_FILLED"
    );

    if (orders.length === 0) {
      tbody.innerHTML = `<tr><td colspan="6" class="empty-cell">조회된 체결 내역이 없습니다.</td></tr>`;
      return;
    }

    tbody.innerHTML = orders
      .map((o) => {
        const ex = o.execution || {};
        const isBuy = o.side === "BUY";
        const dt = (ex.filledAt || o.orderedAt || "").replace("T", " ").slice(0, 19);
        return `
        <tr>
          <td>${dt}</td>
          <td><span class="rate-pill ${isBuy ? "rate-up" : "rate-down"}">${
          isBuy ? "매수" : "매도"
        }</span></td>
          <td>${o.status}</td>
          <td class="text-right">${fmtQty(ex.filledQuantity || o.quantity)}</td>
          <td class="text-right">${fmtCurr(
            ex.averageFilledPrice || o.price,
            o.currency
          )}</td>
          <td class="text-right"><strong>${fmtCurr(
            ex.filledAmount || o.orderAmount,
            o.currency
          )}</strong></td>
        </tr>
      `;
      })
      .join("");
  } catch (e) {
    tbody.innerHTML = `<tr><td colspan="6" class="empty-cell">주문 내역 조회 실패</td></tr>`;
  }
}

async function fetchOrdersTab() {
  const status = document.getElementById("orderStatusSelect").value;
  const symbol = document.getElementById("orderSymbolInput").value.trim();
  const tbody = document.getElementById("ordersTableBody");
  tbody.innerHTML = `<tr><td colspan="8" class="empty-cell">주문 내역을 불러오는 중입니다...</td></tr>`;

  try {
    const qs = new URLSearchParams({ status, limit: "100" });
    if (symbol) qs.set("symbol", symbol);
    const resp = await fetch(`/api/orders?${qs.toString()}`);
    const data = await resp.json();
    state.rawOrders = data.orders || [];
    state.ordersLoaded = true;
    renderOrdersTab();
  } catch (e) {
    tbody.innerHTML = `<tr><td colspan="8" class="empty-cell">주문 내역 조회 실패: ${e.message}</td></tr>`;
  }
}

function renderOrdersTab() {
  const filledFilter = document.getElementById("orderFilledFilter").value;
  const tbody = document.getElementById("ordersTableBody");
  const nameMap = {};
  (state.dashboard?.items || []).forEach((i) => {
    nameMap[i.symbol] = i.name;
  });

  const list = state.rawOrders.filter((o) => {
    if (filledFilter === "FILLED_ONLY") {
      return o.status === "FILLED" || o.status === "PARTIAL_FILLED";
    }
    return true;
  });

  let buyKrw = 0,
    sellKrw = 0,
    buyUsd = 0,
    sellUsd = 0,
    filledCount = 0;

  list.forEach((o) => {
    const ex = o.execution || {};
    const amt = Number(ex.filledAmount || 0);
    if (amt > 0) {
      filledCount++;
      if (o.currency === "KRW") {
        if (o.side === "BUY") buyKrw += amt;
        else sellKrw += amt;
      } else if (o.currency === "USD") {
        if (o.side === "BUY") buyUsd += amt;
        else sellUsd += amt;
      }
    }
  });

  document.getElementById("ordCountStat").textContent = `${list.length}건 (체결 ${filledCount}건)`;
  document.getElementById("ordBuyKrwStat").textContent = fmtKrw(buyKrw);
  document.getElementById("ordSellKrwStat").textContent = fmtKrw(sellKrw);
  document.getElementById("ordBuyUsdStat").textContent = fmtUsd(buyUsd);
  document.getElementById("ordSellUsdStat").textContent = fmtUsd(sellUsd);

  if (list.length === 0) {
    tbody.innerHTML = `<tr><td colspan="8" class="empty-cell">조건에 해당하는 주문 내역이 없습니다.</td></tr>`;
    return;
  }

  tbody.innerHTML = list
    .map((o) => {
      const ex = o.execution || {};
      const isBuy = o.side === "BUY";
      const stockName = o.name || nameMap[o.symbol] || o.symbol;
      const dt = (ex.filledAt || o.orderedAt || "").replace("T", " ").slice(0, 19);
      const comm = Number(ex.commission || 0);
      const tax = Number(ex.tax || 0);
      return `
        <tr>
          <td>${dt}</td>
          <td>
            <div class="cell-primary">${stockName}</div>
            <div class="cell-secondary">${o.symbol} · ${o.currency}</div>
          </td>
          <td><span class="rate-pill ${isBuy ? "rate-up" : "rate-down"}">${
        isBuy ? "매수" : "매도"
      }</span></td>
          <td>${o.status}</td>
          <td class="text-right">${fmtQty(o.quantity)} / <strong>${fmtQty(
        ex.filledQuantity || 0
      )}</strong></td>
          <td class="text-right">${fmtCurr(
            ex.averageFilledPrice || o.price || 0,
            o.currency
          )}</td>
          <td class="text-right"><strong>${fmtCurr(
            ex.filledAmount || o.orderAmount || 0,
            o.currency
          )}</strong></td>
          <td class="text-right">${fmtCurr(comm + tax, o.currency)}</td>
        </tr>
      `;
    })
    .join("");
}

function resizeAllCharts() {
  [
    purchaseVsValueChartInstance,
    profitContributionChartInstance,
    portfolioWeightChartInstance,
    stockCandleChartInstance,
    historyReturnChartInstance,
    historyDeltaChartInstance,
  ].forEach((inst) => {
    if (inst) {
      inst.resize();
    }
  });
}

// ==========================================
// 순수 투자 원금 & 입출금 관리 로직
// ==========================================
async function fetchCapitalData() {
  try {
    const res = await fetch("/api/capital?_t=" + Date.now());
    const data = await res.json();
    state.capital = data;
    renderCapitalTab();
    if (state.dashboard) {
      renderHeroSection();
    }
  } catch (err) {
    console.error("원금 데이터 조회 실패:", err);
  }
}

function renderCapitalTab() {
  const cap = state.capital || (state.dashboard && state.dashboard.capitalSummary);
  if (!cap) return;

  const baseSummary = cap.baseSummary || {};
  const manualTxs = cap.manualTransactions || [];
  const baseNet = cap.baseNetKrw || 0;
  const manualNet = cap.manualNetKrw || 0;
  const totalPure = cap.totalNetCapitalKrw || (baseNet + manualNet);

  // 현재 총 자산 평가금 (dashboard.totalKrw 기준)
  let totalMv = 0;
  if (state.dashboard && state.dashboard.totalKrw) {
    totalMv = state.afterCost
      ? state.dashboard.totalKrw.marketValueAfterCost
      : state.dashboard.totalKrw.marketValue;
  }

  const profit = totalMv - totalPure;
  const rate = totalPure > 0 ? (profit / totalPure) * 100 : 0;

  // 상단 KPI 업데이트
  const elTotalPure = document.getElementById("capTotalPureKrw");
  if (elTotalPure) elTotalPure.textContent = fmtKrw(totalPure);

  const elBaseVsManual = document.getElementById("capBaseVsManual");
  if (elBaseVsManual) {
    elBaseVsManual.textContent = `기준 원금 ${fmtKrw(baseNet)} + 수기 변동 ${fmtKrw(manualNet, true)}`;
  }

  const elTotalMv = document.getElementById("capTotalMvKrw");
  if (elTotalMv) elTotalMv.textContent = fmtKrw(totalMv);

  const elProfit = document.getElementById("capTotalProfitKrw");
  if (elProfit) {
    elProfit.textContent = fmtKrw(profit, true);
    elProfit.className = `cap-kpi-val profit-val ${signClass(profit)}`;
  }

  const elRate = document.getElementById("capTotalRatePct");
  if (elRate) {
    elRate.textContent = fmtPct(rate);
    elRate.className = signClass(profit);
  }

  const elManualNet = document.getElementById("capManualNetKrw");
  if (elManualNet) {
    elManualNet.textContent = fmtKrw(manualNet, true);
    elManualNet.className = `cap-kpi-val ${signClass(manualNet)}`;
  }

  const elManualCount = document.getElementById("capManualCountText");
  if (elManualCount) {
    elManualCount.textContent = `총 ${manualTxs.length}건 등록됨`;
  }

  // 1. 기준 원금 테이블 렌더링
  const baseTableBody = document.getElementById("capBaseTableBody");
  if (baseTableBody) {
    let html = "";
    let totDep = 0;
    let totWd = 0;
    let totN = 0;

    for (const [k, item] of Object.entries(baseSummary)) {
      const dep = item.deposit || 0;
      const wd = item.withdraw || 0;
      const net = item.net || 0;
      totDep += dep;
      totWd += wd;
      totN += net;

      html += `
        <tr>
          <td>
            <strong>${item.name || k}</strong>
            <div style="font-size:11px; color:var(--text-muted);">${item.account || ""}</div>
          </td>
          <td class="text-right">${fmtKrw(dep)}</td>
          <td class="text-right">${wd > 0 ? fmtKrw(wd) : "-"}</td>
          <td class="text-right highlight font-bold">${fmtKrw(net)}</td>
          <td style="font-size:12px; color:var(--text-sub);">${item.note || ""}</td>
        </tr>
      `;
    }
    baseTableBody.innerHTML = html;

    const elDepTot = document.getElementById("capBaseDepositTotal");
    if (elDepTot) elDepTot.textContent = fmtKrw(totDep);
    const elWdTot = document.getElementById("capBaseWithdrawTotal");
    if (elWdTot) elWdTot.textContent = fmtKrw(totWd);
    const elNetTot = document.getElementById("capBaseNetTotal");
    if (elNetTot) elNetTot.textContent = fmtKrw(totN);
  }

  // 2. 수기 등록 내역 테이블 렌더링
  const manualTableBody = document.getElementById("capManualTableBody");
  if (manualTableBody) {
    if (manualTxs.length === 0) {
      manualTableBody.innerHTML = `
        <tr>
          <td colspan="7" class="empty-cell" style="padding: 24px; text-align: center; color: var(--text-muted);">
            등록된 수기 입출금 내역이 없습니다. 위 폼을 통해 급여 적립이나 추가 투자금을 입력해 보세요.
          </td>
        </tr>
      `;
    } else {
      let html = "";
      for (const tx of manualTxs) {
        const isDep = tx.type === "DEPOSIT";
        const typeBadge = isDep
          ? `<span class="badge-deposit">입금 (+)</span>`
          : `<span class="badge-withdraw">출금 (-)</span>`;
        const amtStr = (isDep ? "+" : "-") + fmtKrw(tx.amount || 0);

        html += `
          <tr>
            <td><strong>${tx.date || "-"}</strong></td>
            <td>${typeBadge}</td>
            <td>${tx.account || "기타"}</td>
            <td class="text-right font-bold ${isDep ? "is-profit" : "is-loss"}">${amtStr}</td>
            <td>${tx.memo || "-"}</td>
            <td style="font-size:11px; color:var(--text-muted);">${tx.createdAt || "-"}</td>
            <td class="text-center">
              <button class="btn-delete-tx" data-id="${tx.id}">삭제</button>
            </td>
          </tr>
        `;
      }
      manualTableBody.innerHTML = html;
    }
  }
}

async function handleCapitalFormSubmit(e) {
  e.preventDefault();
  const date = document.getElementById("capTxDate").value;
  const type = document.getElementById("capTxType").value;
  const account = document.getElementById("capTxAccount").value;
  const amount = parseFloat(document.getElementById("capTxAmount").value);
  const memo = document.getElementById("capTxMemo").value.trim();

  if (!amount || amount <= 0) {
    alert("0보다 큰 금액을 입력해 주세요.");
    return;
  }

  const btn = document.getElementById("btnSubmitCapitalTx");
  if (btn) btn.disabled = true;

  try {
    const res = await fetch("/api/capital", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        action: "add_transaction",
        date,
        type,
        account,
        amount,
        memo,
      }),
    });
    const result = await res.json();
    if (result.ok && result.summary) {
      state.capital = result.summary;
      renderCapitalTab();
      if (state.dashboard) renderHeroSection();
      document.getElementById("capTxAmount").value = "";
      document.getElementById("capTxMemo").value = "";
      alert("입출금 내역이 성공적으로 등록되었습니다!");
    } else {
      alert("등록 실패: " + (result.error || "오류가 발생했습니다."));
    }
  } catch (err) {
    alert("등록 중 오류가 발생했습니다: " + err.message);
  } finally {
    if (btn) btn.disabled = false;
  }
}

async function handleCapitalDelete(e) {
  const btn = e.target.closest(".btn-delete-tx");
  if (!btn) return;
  const id = btn.getAttribute("data-id");
  if (!id) return;
  if (!confirm("해당 입출금 내역을 삭제하시겠습니까?")) return;

  try {
    const res = await fetch("/api/capital", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        action: "delete_transaction",
        id,
      }),
    });
    const result = await res.json();
    if (result.ok && result.summary) {
      state.capital = result.summary;
      renderCapitalTab();
      if (state.dashboard) renderHeroSection();
    }
  } catch (err) {
    alert("삭제 중 오류가 발생했습니다: " + err.message);
  }
}

function switchTab(tabId) {
  document.querySelectorAll(".main-tab").forEach((b) => {
    b.classList.toggle("active", b.getAttribute("data-tab") === tabId);
  });
  document.querySelectorAll(".tab-panel").forEach((p) => {
    p.classList.toggle("active", p.id === `tab-${tabId}`);
  });
  if (tabId === "history") {
    if (!state.historyData) {
      fetchReturnsHistory();
    } else {
      renderReturnsHistory();
    }
  } else if (tabId === "orders" && !state.ordersLoaded) {
    fetchOrdersTab();
  } else if (tabId === "capital") {
    fetchCapitalData();
  }
  setTimeout(resizeAllCharts, 50);
}

document.addEventListener("DOMContentLoaded", () => {
  fetchDashboard(false);

  const handleViewportOrZoomChange = () => {
    clearTimeout(resizeTimer);
    resizeTimer = setTimeout(resizeAllCharts, 80);
  };
  window.addEventListener("resize", handleViewportOrZoomChange);
  if (window.visualViewport) {
    window.visualViewport.addEventListener("resize", handleViewportOrZoomChange);
  }
  const mainContainer = document.querySelector(".container");
  if (mainContainer && typeof ResizeObserver !== "undefined") {
    const ro = new ResizeObserver(handleViewportOrZoomChange);
    ro.observe(mainContainer);
  }

  const triggerRefresh = () => {
    state.historyData = null;
    fetchDashboard(true);
  };
  document.getElementById("refreshBtn").addEventListener("click", triggerRefresh);
  const brandLogoBtn = document.getElementById("brandLogoBtn");
  if (brandLogoBtn) {
    brandLogoBtn.addEventListener("click", triggerRefresh);
    brandLogoBtn.addEventListener("keydown", (e) => {
      if (e.key === "Enter" || e.key === " ") {
        e.preventDefault();
        triggerRefresh();
      }
    });
  }

  // 계좌 범위 멀티 선택/취소 스위치 (전체 합산 클릭 시 외에는 자동 선택 취소 없음)
  function syncScopePillsUI() {
    const isAllMode = state.selectedScopes.size === 0;

    document.querySelectorAll("#accountScopePills .scope-pill").forEach((b) => {
      const s = b.getAttribute("data-scope");
      if (s === "ALL") {
        b.classList.toggle("active", isAllMode);
      } else {
        b.classList.toggle("active", state.selectedScopes.has(s));
      }
    });
  }

  document.querySelectorAll("#accountScopePills .scope-pill").forEach((btn) => {
    btn.addEventListener("click", () => {
      const clicked = btn.getAttribute("data-scope");
      if (clicked === "ALL") {
        state.selectedScopes.clear();
        state.scope = "ALL";
      } else {
        if (state.selectedScopes.has(clicked)) {
          state.selectedScopes.delete(clicked);
        } else {
          state.selectedScopes.add(clicked);
        }

        if (state.selectedScopes.size === 0) {
          state.scope = "ALL";
        } else {
          state.scope = ALL_ACCTS.filter((id) =>
            state.selectedScopes.has(id)
          ).join(",");
        }
      }

      syncScopePillsUI();
      state.historyData = null;
      fetchDashboard(false);
    });
  });

  document.getElementById("afterCostToggle").addEventListener("change", (e) => {
    state.afterCost = e.target.checked;
    renderAll();
  });

  document.getElementById("krwUnifiedToggle").addEventListener("change", (e) => {
    state.krwUnified = e.target.checked;
    renderAll();
  });

  const ovEtfToggle = document.getElementById("overseasEtfToggle");
  if (ovEtfToggle) {
    ovEtfToggle.addEventListener("change", (e) => {
      state.overseasEtfAsUs = e.target.checked;
      renderAll();
    });
  }

  document.querySelectorAll(".main-tab").forEach((btn) => {
    btn.addEventListener("click", () => {
      switchTab(btn.getAttribute("data-tab"));
    });
  });

  // 구간별 수익률 변화 탭: 일별 / 월별 / 연도별 단위 전환
  document.querySelectorAll("#historyUnitPills .unit-pill").forEach((btn) => {
    btn.addEventListener("click", () => {
      document
        .querySelectorAll("#historyUnitPills .unit-pill")
        .forEach((b) => b.classList.remove("active"));
      btn.classList.add("active");
      state.historyUnit = btn.getAttribute("data-unit");
      renderReturnsHistory();
    });
  });

  // 구간별 수익률 변화 탭: 일별 조회 기간 전환
  document.querySelectorAll("#historyRangePills .range-pill").forEach((btn) => {
    btn.addEventListener("click", () => {
      document
        .querySelectorAll("#historyRangePills .range-pill")
        .forEach((b) => b.classList.remove("active"));
      btn.classList.add("active");
      state.historyDays = Number(btn.getAttribute("data-days"));
      renderReturnsHistory();
    });
  });

  // 구간별 수익률 변화 탭: 월별 조회 기간 전환
  document.querySelectorAll("#historyMonthRangePills .range-pill").forEach((btn) => {
    btn.addEventListener("click", () => {
      document
        .querySelectorAll("#historyMonthRangePills .range-pill")
        .forEach((b) => b.classList.remove("active"));
      btn.classList.add("active");
      state.historyMonths = btn.getAttribute("data-months");
      renderReturnsHistory();
    });
  });

  // 구간별 수익률 변화 탭: 차트 표시 기준 전환 (수익률 % / 누적 수익금 원 / 총 평가금액 vs 원금)
  document.querySelectorAll("#historyMetricTabs .mini-tab").forEach((btn) => {
    btn.addEventListener("click", () => {
      document
        .querySelectorAll("#historyMetricTabs .mini-tab")
        .forEach((b) => b.classList.remove("active"));
      btn.classList.add("active");
      state.historyMetric = btn.getAttribute("data-metric");
      renderReturnsHistory();
    });
  });

  // 구간별 수익률 변화 탭: 우측 증감 바 차트 기준 전환 (증감액 원 / 구간 등락률 % / 누적수익률 변화 %p)
  document.querySelectorAll("#historyDeltaTabs .mini-tab").forEach((btn) => {
    btn.addEventListener("click", () => {
      document
        .querySelectorAll("#historyDeltaTabs .mini-tab")
        .forEach((b) => b.classList.remove("active"));
      btn.classList.add("active");
      state.historyDeltaMetric = btn.getAttribute("data-delta");
      renderReturnsHistory();
    });
  });

  // 메인 탭: 종목별 수익금 기여도 (수익금 원 / 수익률 %) 전환
  document.querySelectorAll("#profitModeTabs .mini-tab").forEach((btn) => {
    btn.addEventListener("click", () => {
      document
        .querySelectorAll("#profitModeTabs .mini-tab")
        .forEach((b) => b.classList.remove("active"));
      btn.classList.add("active");
      state.profitChartMode = btn.getAttribute("data-mode");
      renderProfitContributionChart();
    });
  });

  // RIA 종목 자동완성 검색
  const riaSearchInput = document.getElementById("riaSearchInput");
  const acList = document.getElementById("riaAutocompleteList");

  riaSearchInput.addEventListener("input", (e) => {
    const q = e.target.value.trim();
    clearTimeout(searchDebounceTimer);
    if (!q) {
      acList.classList.add("hidden");
      return;
    }
    searchDebounceTimer = setTimeout(async () => {
      try {
        const resp = await fetch(`/api/stock-search?q=${encodeURIComponent(q)}`);
        const data = await resp.json();
        const results = data.results || [];
        if (results.length === 0) {
          acList.innerHTML = `<div class="ac-item">검색 결과가 없습니다 (직접 코드 입력 가능)</div>`;
          acList.classList.remove("hidden");
          return;
        }
        acList.innerHTML = results
          .map(
            (r) => `
            <div class="ac-item" data-sym="${r.symbol}" data-name="${r.name}" data-curr="${r.currency}">
              <span><strong>${r.name}</strong> (${r.symbol})</span>
              <span class="acct-tag">${r.market} · ${r.currency}</span>
            </div>
          `
          )
          .join("");
        acList.classList.remove("hidden");

        acList.querySelectorAll(".ac-item[data-sym]").forEach((el) => {
          el.addEventListener("click", () => {
            document.getElementById("riaSymbolInput").value =
              el.getAttribute("data-sym");
            document.getElementById("riaNameInput").value =
              el.getAttribute("data-name");
            document.getElementById("riaCurrencySelect").value =
              el.getAttribute("data-curr");
            riaSearchInput.value = `${el.getAttribute("data-name")} (${el.getAttribute(
              "data-sym"
            )})`;
            acList.classList.add("hidden");
          });
        });
      } catch (err) {
        console.error(err);
      }
    }, 220);
  });

  // 종목코드 직접 입력 시에도 자동으로 종목명/통화 조회
  const riaSymbolInput = document.getElementById("riaSymbolInput");
  riaSymbolInput.addEventListener("blur", async () => {
    const sym = riaSymbolInput.value.trim().toUpperCase();
    if (!sym) return;
    const nameInput = document.getElementById("riaNameInput");
    if (nameInput.value.trim() && nameInput.value.trim().toUpperCase() !== sym) return;
    try {
      const resp = await fetch(`/api/stock-search?q=${encodeURIComponent(sym)}`);
      const data = await resp.json();
      const exact = (data.results || []).find(
        (r) => (r.symbol || "").toUpperCase() === sym
      );
      if (exact) {
        nameInput.value = exact.name;
        document.getElementById("riaCurrencySelect").value = exact.currency;
      }
    } catch (e) {
      console.error(e);
    }
  });

  // 수량 × 평단가 자동 계산
  const qtyIn = document.getElementById("riaQtyInput");
  const avgIn = document.getElementById("riaAvgPriceInput");
  const purchIn = document.getElementById("riaPurchaseAmtInput");

  function syncPurch() {
    const q = Number(qtyIn.value || 0);
    const a = Number(avgIn.value || 0);
    if (q > 0 && a > 0) {
      purchIn.value = (q * a).toFixed(2).replace(/\.00$/, "");
    }
  }
  qtyIn.addEventListener("input", syncPurch);
  avgIn.addEventListener("input", syncPurch);

  // RIA 종목 저장
  document.getElementById("saveRiaItemBtn").addEventListener("click", async () => {
    const symbol = document.getElementById("riaSymbolInput").value.trim();
    const name = document.getElementById("riaNameInput").value.trim();
    const currency = document.getElementById("riaCurrencySelect").value;
    const quantity = Number(qtyIn.value || 0);
    const averagePurchasePrice = Number(avgIn.value || 0);
    const purchaseAmount = Number(purchIn.value || 0);
    const dateIn = document.getElementById("riaDateInput");
    const purchaseDate = dateIn ? dateIn.value.trim() : "";

    if (!symbol || quantity <= 0) {
      alert("종목코드(티커)와 보유수량을 입력해 주세요.");
      return;
    }

    const resp = await fetch("/api/ria-holdings", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        action: "upsert_item",
        symbol,
        name: name || symbol,
        currency,
        quantity,
        averagePurchasePrice,
        purchaseAmount,
        purchaseDate,
      }),
    });
    const resData = await resp.json();
    if (!resp.ok || resData.error) {
      alert(resData.error || "저장 실패");
      return;
    }

    riaSearchInput.value = "";
    document.getElementById("riaSymbolInput").value = "";
    document.getElementById("riaNameInput").value = "";
    qtyIn.value = "";
    avgIn.value = "";
    purchIn.value = "";
    if (dateIn) dateIn.value = "";

    state.historyData = null;
    await fetchDashboard(false);
  });

  document.getElementById("saveRiaSaleBtn").addEventListener("click", async () => {
    const val = (id) => document.getElementById(id).value.trim();
    const symbol = val("riaSaleSymbolInput");
    const quantity = Number(val("riaSaleQtyInput") || 0);
    if (!symbol || quantity <= 0) {
      alert("종목코드(티커)와 매도 수량을 입력해 주세요.");
      return;
    }
    const resp = await fetch("/api/ria-holdings", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        action: "upsert_sale",
        id: val("riaSaleIdInput"),
        symbol,
        name: val("riaSaleNameInput"),
        currency: val("riaSaleCurrencySelect"),
        soldAt: val("riaSaleDateInput"),
        quantity,
        sellAmountKrw: Number(val("riaSaleSellKrwInput") || 0),
        purchaseAmountKrw: Number(val("riaSaleBuyKrwInput") || 0),
        sellAmountUsd: Number(val("riaSaleSellUsdInput") || 0),
        purchaseAmountUsd: Number(val("riaSaleBuyUsdInput") || 0),
        commissionKrw: Number(val("riaSaleCommInput") || 0),
        taxKrw: Number(val("riaSaleTaxInput") || 0),
      }),
    });
    const resData = await resp.json();
    if (!resp.ok || resData.error) {
      alert(resData.error || "저장 실패");
      return;
    }
    [
      "riaSaleIdInput",
      "riaSaleSymbolInput",
      "riaSaleNameInput",
      "riaSaleDateInput",
      "riaSaleQtyInput",
      "riaSaleSellKrwInput",
      "riaSaleBuyKrwInput",
      "riaSaleSellUsdInput",
      "riaSaleBuyUsdInput",
      "riaSaleCommInput",
      "riaSaleTaxInput",
    ].forEach((id) => (document.getElementById(id).value = ""));
    state.historyData = null;
    await fetchDashboard(false);
  });

  document.querySelectorAll("#weightModeTabs .mini-tab").forEach((btn) => {
    btn.addEventListener("click", () => {
      document
        .querySelectorAll("#weightModeTabs .mini-tab")
        .forEach((b) => b.classList.remove("active"));
      btn.classList.add("active");
      state.weightChartMode = btn.getAttribute("data-mode");
      renderWeightChart();
    });
  });

  document.querySelectorAll("#holdingFilterPills .filter-pill").forEach((btn) => {
    btn.addEventListener("click", () => {
      document
        .querySelectorAll("#holdingFilterPills .filter-pill")
        .forEach((b) => b.classList.remove("active"));
      btn.classList.add("active");
      state.filter = btn.getAttribute("data-filter");
      renderHoldingsTable();
    });
  });

  document.getElementById("stockSearchInput").addEventListener("input", (e) => {
    state.search = e.target.value.trim();
    renderHoldingsTable();
  });

  document.querySelectorAll(".holdings-table th.sortable").forEach((th) => {
    th.addEventListener("click", () => {
      const field = th.getAttribute("data-sort");
      if (state.sortField === field) {
        state.sortDesc = !state.sortDesc;
      } else {
        state.sortField = field;
        state.sortDesc = true;
      }
      renderHoldingsTable();
    });
  });

  document.getElementById("loadOrdersBtn").addEventListener("click", fetchOrdersTab);
  document.getElementById("orderStatusSelect").addEventListener("change", fetchOrdersTab);
  document.getElementById("orderSymbolInput").addEventListener("keydown", (e) => {
    if (e.key === "Enter") {
      e.preventDefault();
      fetchOrdersTab();
    }
  });
  document
    .getElementById("orderFilledFilter")
    .addEventListener("change", renderOrdersTab);

  document.getElementById("closeModalBtn").addEventListener("click", () => {
    document.getElementById("stockModal").classList.add("hidden");
  });
  document.getElementById("stockModal").addEventListener("click", (e) => {
    if (e.target.id === "stockModal") {
      document.getElementById("stockModal").classList.add("hidden");
    }
  });

  // 순수 투자 원금 & 입출금 관리 이벤트 바인딩
  const heroPureBox = document.getElementById("heroPureCapitalBox");
  if (heroPureBox) {
    heroPureBox.addEventListener("click", () => switchTab("capital"));
  }

  const capForm = document.getElementById("capitalTxForm");
  if (capForm) {
    capForm.addEventListener("submit", handleCapitalFormSubmit);
  }

  const capRefreshBtn = document.getElementById("btnRefreshCapital");
  if (capRefreshBtn) {
    capRefreshBtn.addEventListener("click", async () => {
      capRefreshBtn.disabled = true;
      const originalText = capRefreshBtn.textContent;
      capRefreshBtn.textContent = "갱신 중...";
      try {
        await Promise.all([fetchCapitalData(), fetchDashboard(true)]);
      } catch (err) {
        console.error("원금 새로고침 오류:", err);
      } finally {
        capRefreshBtn.disabled = false;
        capRefreshBtn.textContent = originalText || "새로고침";
      }
    });
  }

  const capManualTbody = document.getElementById("capManualTableBody");
  if (capManualTbody) {
    capManualTbody.addEventListener("click", handleCapitalDelete);
  }

  const btnGoMobile = document.getElementById("btnGoMobile");
  if (btnGoMobile) {
    btnGoMobile.addEventListener("click", () => {
      try {
        sessionStorage.removeItem("preferred_view");
      } catch (e) {}
    });
  }

  const capDateInput = document.getElementById("capTxDate");
  if (capDateInput && !capDateInput.value) {
    capDateInput.value = new Date().toISOString().split("T")[0];
  }

  // PWA Service Worker 및 크롬 설치 프롬프트 지원
  if ("serviceWorker" in navigator) {
    navigator.serviceWorker
      .register("/sw.js", { scope: "/" })
      .then((reg) => {
        // SW 등록 성공
      })
      .catch((err) => {
        console.warn("PWA ServiceWorker 등록 실패:", err);
      });
  }

  let deferredInstallPrompt = null;
  window.addEventListener("beforeinstallprompt", (e) => {
    e.preventDefault();
    deferredInstallPrompt = e;
    const btnInstall = document.getElementById("btnInstallPwa");
    if (btnInstall) {
      btnInstall.style.display = "inline-flex";
      btnInstall.onclick = async () => {
        if (deferredInstallPrompt) {
          deferredInstallPrompt.prompt();
          const { outcome } = await deferredInstallPrompt.userChoice;
          if (outcome === "accepted") {
            btnInstall.style.display = "none";
          }
          deferredInstallPrompt = null;
        }
      };
    }
  });

  window.addEventListener("appinstalled", () => {
    const btnInstall = document.getElementById("btnInstallPwa");
    if (btnInstall) btnInstall.style.display = "none";
    deferredInstallPrompt = null;
  });
});
