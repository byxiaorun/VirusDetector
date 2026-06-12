/**
 * 银狐木马检测 - Popup UI (v1.1)
 * 适配新5规则评分体系
 */
(function () {
  'use strict';

  const SCORE_THRESHOLD = 100;

  const $ = (id) => document.getElementById(id);

  const els = {
    header: $('header'), loading: $('loading'),
    safePanel: $('safe-panel'), warningPanel: $('warning-panel'),
    scoreValue: $('score-value'), statusText: $('status-text'),
    currentDomain: $('current-domain'),
    warningScoreValue: $('warning-score-value'),
    warningStatusText: $('warning-status-text'),
    officialLinkSection: $('official-link-section'),
    officialLinkBtn: $('official-link-btn'),
    officialLinkText: $('official-link-text'),
    safetyTips: $('safety-tips'),
    refreshBtn: $('refresh-btn'),
    whitelistBtn: $('whitelist-btn'),
    detailRules: {
      rule1: $('detail-rule1'), rule2: $('detail-rule2'),
      rule3: $('detail-rule3'), rule4: $('detail-rule4'),
      rule5: $('detail-rule5')
    }
  };

  function showLoading() {
    els.loading.style.display = 'block';
    els.safePanel.style.display = 'none';
    els.warningPanel.style.display = 'none';
    els.safetyTips.style.display = 'none';
    els.officialLinkSection.style.display = 'none';
    els.header.className = 'header-safe';
    els.header.style.background = '';
    // 清除白名单指示器
    var indicator = $('whitelist-indicator');
    if (indicator) indicator.remove();
  }

  function updateWhitelistButton(isWhitelisted) {
    if (isWhitelisted) {
      els.whitelistBtn.textContent = '❌ 移出白名单';
      els.whitelistBtn.classList.add('active');
    } else {
      els.whitelistBtn.textContent = '⭐ 加入白名单';
      els.whitelistBtn.classList.remove('active');
    }
  }

  function showSafe(data) {
    els.loading.style.display = 'none';
    els.safePanel.style.display = 'block';
    els.warningPanel.style.display = 'none';
    els.safetyTips.style.display = 'none';
    els.officialLinkSection.style.display = 'none';
    els.header.className = 'header-safe';
    els.scoreValue.textContent = data.score || 0;
    els.statusText.textContent = data.isWhitelisted ? '白名单' : '安全';
    els.currentDomain.textContent = data.domain || '-';
  }

  function showWhitelisted(data) {
    els.loading.style.display = 'none';
    els.safePanel.style.display = 'block';
    els.warningPanel.style.display = 'none';
    els.safetyTips.style.display = 'none';
    els.officialLinkSection.style.display = 'none';
    els.header.className = 'header-safe';
    els.header.style.background = 'linear-gradient(135deg,#0D47A1,#1565C0)';
    els.scoreValue.textContent = '✓';
    els.statusText.textContent = '已加入白名单';
    els.currentDomain.textContent = data.domain || '-';
    // 添加白名单指示器
    if (!$('whitelist-indicator')) {
      var indicator = document.createElement('div');
      indicator.id = 'whitelist-indicator';
      indicator.className = 'whitelist-indicator';
      indicator.innerHTML = '<span class="wl-icon">🛡️</span> 该网站已加入白名单，跳过所有检测';
      els.safePanel.insertBefore(indicator, els.safePanel.firstChild);
    }
  }

  function showWarning(data) {
    els.loading.style.display = 'none';
    els.safePanel.style.display = 'none';
    els.warningPanel.style.display = 'block';
    els.safetyTips.style.display = 'block';
    els.header.className = 'header-danger';
    els.header.style.background = '';
    els.warningScoreValue.textContent = data.score || 0;
    els.warningStatusText.textContent = '⚠️ 危险警告';
    // 清除白名单指示器
    var indicator = $('whitelist-indicator');
    if (indicator) indicator.remove();

    if (data.correctUrl) {
      els.officialLinkSection.style.display = 'block';
      els.officialLinkBtn.href = data.correctUrl;
      els.officialLinkText.textContent = data.correctUrl;
    } else {
      els.officialLinkSection.style.display = 'none';
    }
  }

  function updateDetails(ruleResults) {
    if (!ruleResults) return;
    for (const key of Object.keys(els.detailRules)) {
      const rule = ruleResults[key];
      const el = els.detailRules[key];
      if (!el) continue;
      const iconEl = el.querySelector('.detail-icon');
      const textEl = el.querySelector('.detail-text');
      if (rule && rule.detailCN) {
        if (rule.triggered) {
          iconEl.textContent = '✗'; iconEl.style.color = '#F44336';
          textEl.style.color = '#F44336';
        } else if (rule.detailCN.startsWith('✓')) {
          iconEl.textContent = '✓'; iconEl.style.color = '#4CAF50';
          textEl.style.color = '#4CAF50';
        } else {
          iconEl.textContent = '-'; iconEl.style.color = '#a0a0a0';
          textEl.style.color = '#a0a0a0';
        }
        textEl.textContent = rule.detailCN;
      }
    }
  }

  function showError(msg) {
    els.loading.innerHTML = `<div style="text-align:center;padding:20px;">
      <p style="color:#F44336;">⚠️ ${msg || '无法获取检测结果'}</p>
      <p style="font-size:12px;color:#a0a0a0;margin-top:8px;">请确保已打开网页，点击"重新检测"重试</p></div>`;
    els.loading.style.display = 'block';
    els.safePanel.style.display = 'none';
    els.warningPanel.style.display = 'none';
    els.safetyTips.style.display = 'none';
  }

  async function fetchState() {
    try {
      const resp = await chrome.runtime.sendMessage({ type: 'GET_TAB_STATE', payload: {} });
      return (resp && resp.success) ? resp.data : null;
    } catch (e) { return null; }
  }

  async function requestReanalysis() {
    try {
      const tabs = await chrome.tabs.query({ active: true, currentWindow: true });
      if (tabs.length > 0) {
        await chrome.tabs.sendMessage(tabs[0].id, { type: 'REQUEST_PAGE_TEXT', payload: {} });
      }
      await new Promise(r => setTimeout(r, 1500));
    } catch (e) { /* content script may not be ready */ }
  }

  async function render() {
    showLoading();
    let data = await fetchState();
    if (!data || !data.isAnalyzed) {
      await requestReanalysis();
      data = await fetchState();
    }
    if (!data) { showError('无法获取页面分析结果'); return; }

    // 白名单优先显示
    if (data.isWhitelisted) {
      showWhitelisted(data);
    } else if (data.score >= SCORE_THRESHOLD) {
      showWarning(data);
    } else {
      showSafe(data);
    }

    updateDetails(data.ruleResults);
    updateWhitelistButton(!!data.isWhitelisted);
  }

  els.refreshBtn.addEventListener('click', async () => {
    showLoading();
    els.refreshBtn.textContent = '⏳ 检测中...';
    els.refreshBtn.disabled = true;
    await requestReanalysis();
    await render();
    els.refreshBtn.textContent = '🔄 重新检测';
    els.refreshBtn.disabled = false;
  });

  // 白名单按钮
  els.whitelistBtn.addEventListener('click', async () => {
    showLoading();
    els.whitelistBtn.disabled = true;
    try {
      const tabs = await chrome.tabs.query({ active: true, currentWindow: true });
      if (tabs.length === 0) return;
      const url = tabs[0].url || '';

      // 先检查当前白名单状态
      const checkResp = await chrome.runtime.sendMessage({
        type: 'CHECK_WHITELIST',
        payload: { url }
      });
      const isCurrentlyWhitelisted = checkResp?.isWhitelisted || false;

      if (isCurrentlyWhitelisted) {
        // 移出白名单
        await chrome.runtime.sendMessage({
          type: 'REMOVE_FROM_WHITELIST',
          payload: { url }
        });
      } else {
        // 加入白名单
        await chrome.runtime.sendMessage({
          type: 'ADD_TO_WHITELIST',
          payload: { url }
        });
      }

      // 等待后台处理完成
      await new Promise(r => setTimeout(r, 300));
      await render();
    } catch (e) {
      console.error('[Popup] 白名单操作失败:', e);
    }
    els.whitelistBtn.disabled = false;
  });

  if (document.readyState === 'complete' || document.readyState === 'interactive') {
    render();
  } else {
    document.addEventListener('DOMContentLoaded', render);
  }
})();
