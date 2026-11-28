import {renderStatusBadge} from "./StatusBadge.js";

export function renderEcuHealthGrid(ecus=[]){
  if(!ecus.length){
    return `<div class="empty-state">No ECU health data available.</div>`;
  }
  return `
    <div class="ecu-grid">
      ${ecus.map(ecu=>`
        <div class="ecu-card">
          <div class="ecu-card-header">
            <span class="ecu-name">${ecu.name}</span>
            ${renderStatusBadge(ecu.status)}
          </div>
          <div class="ecu-details">
            <span>Message rate</span>
            <strong>${ecu.rate??0} frames/s</strong>
          </div>
          <div class="ecu-details">
            <span>Last message</span>
            <strong>${ecu.lastSeen||"N/A"}</strong>
          </div>
        </div>
      `).join("")}
    </div>
  `;
}
