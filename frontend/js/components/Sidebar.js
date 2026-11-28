export function renderSidebar(activePage="overview"){
  const items=[
    {id:"overview",icon:"◈",label:"Overview"},
    {id:"traffic",icon:"⌁",label:"Live Traffic"},
    {id:"alerts",icon:"⚠",label:"Alerts"},
    {id:"attacklab",icon:"⌘",label:"Attack Lab"},
    {id:"analytics",icon:"▥",label:"Analytics"},
    {id:"settings",icon:"⚙",label:"Settings"}
  ];
  return `
    <div class="sidebar-content">
      <div class="sidebar-brand">
        <div class="brand-icon">C</div>
        <div>
          <div class="brand-name">CAN GUARD</div>
          <div class="brand-subtitle">Vehicle Security</div>
        </div>
      </div>
      <div class="sidebar-section-label">MONITORING</div>
      <nav class="sidebar-nav">
        ${items.map(item=>`
          <a href="#${item.id}" class="nav-item ${activePage===item.id?"active":""}" data-page="${item.id}">
            <span class="nav-icon">${item.icon}</span>
            <span class="nav-label">${item.label}</span>
          </a>
        `).join("")}
      </nav>
      <div class="sidebar-footer">
        <div class="sidebar-system-status">
          <span class="status-dot"></span>
          <div>
            <div class="status-title">System Monitor</div>
            <div class="status-subtitle">Ready to monitor</div>
          </div>
        </div>
        <div class="sidebar-version">CAN Guard · v1.0</div>
      </div>
    </div>
  `;
}
