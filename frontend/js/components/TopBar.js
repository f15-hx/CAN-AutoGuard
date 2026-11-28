export function renderTopBar(pageTitle="Overview"){
  return `
    <div class="topbar-content">
      <div class="topbar-left">
        <div class="topbar-title">${pageTitle}</div>
        <div class="topbar-subtitle">Automotive Cybersecurity Monitoring</div>
      </div>
      <div class="topbar-right">
        <div class="monitoring-status">
          <span class="status-dot"></span>
          <span>Monitoring Ready</span>
        </div>
        <div class="topbar-divider"></div>
        <div class="topbar-system">
          <span class="system-icon">◈</span>
          <span>CAN Bus</span>
        </div>
      </div>
    </div>
  `;
}
