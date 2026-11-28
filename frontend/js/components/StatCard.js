export function renderStatCard(title,value,subtitle="",icon="◈"){
  return `
    <div class="card stat-card">
      <div class="stat-card-header">
        <span class="stat-label">${title}</span>
        <span class="stat-icon">${icon}</span>
      </div>
      <div class="stat-value">${value}</div>
      <div class="stat-change">${subtitle}</div>
    </div>
  `;
}
