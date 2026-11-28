import {renderStatusBadge} from "./StatusBadge.js";

export function renderAlertTable(alerts=[]){
  if(!alerts.length){
    return `
      <div class="empty-state">
        No security alerts detected.
      </div>
    `;
  }
  return `
    <div class="table-container">
      <table>
        <thead>
          <tr>
            <th>Time</th>
            <th>Severity</th>
            <th>ECU</th>
            <th>Alert Type</th>
            <th>Description</th>
          </tr>
        </thead>
        <tbody>
          ${alerts.map(alert=>`
            <tr>
              <td>${alert.time||"N/A"}</td>
              <td>${renderStatusBadge(alert.severity)}</td>
              <td>${alert.ecu||"Unknown"}</td>
              <td>${alert.type||"Unknown"}</td>
              <td>${alert.description||"No description"}</td>
            </tr>
          `).join("")}
        </tbody>
      </table>
    </div>
  `;
}
