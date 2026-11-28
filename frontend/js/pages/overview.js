import {renderStatCard} from "../components/StatCard.js";
import {renderEcuHealthGrid} from "../components/EcuHealthGrid.js";
import {renderAlertTable} from "../components/AlertTable.js";
import {renderLineChart} from "../components/Charts.js";

export function renderOverview(){
  const stats=[
    {title:"Total Frames",value:"0",subtitle:"CAN frames received",icon:"◈"},
    {title:"Security Alerts",value:"0",subtitle:"Alerts detected",icon:"⚠"},
    {title:"Active ECUs",value:"0",subtitle:"Connected ECUs",icon:"⌘"},
    {title:"System Status",value:"Ready",subtitle:"Waiting for simulation",icon:"●"}
  ];
  const ecus=[];
  const alerts=[];
  return `
    <div class="overview-page">
      <div class="overview-welcome">
        <div>
          <h2>Security Overview</h2>
          <p>Monitor vehicle network activity and security health.</p>
        </div>
        <span class="badge badge-info">Simulation Dashboard</span>
      </div>
      <div class="stats-grid">
        ${stats.map(stat=>renderStatCard(stat.title,stat.value,stat.subtitle,stat.icon)).join("")}
      </div>
      <div class="overview-grid">
        ${renderLineChart("traffic-chart","CAN Traffic Overview")}
        <div class="panel">
          <div class="panel-header">
            <h3 class="card-title">ECU Health</h3>
          </div>
          <div class="panel-body">
            ${renderEcuHealthGrid(ecus)}
          </div>
        </div>
      </div>
      <div class="panel overview-alerts">
        <div class="panel-header">
          <h3 class="card-title">Recent Security Alerts</h3>
        </div>
        <div class="panel-body">
          ${renderAlertTable(alerts)}
        </div>
      </div>
    </div>
  `;
}

export function initOverviewCharts(){
  const canvas=document.getElementById("traffic-chart");
  if(!canvas||!window.Chart)return;
  new window.Chart(canvas,{
    type:"line",
    data:{
      labels:["0s","5s","10s","15s","20s","25s"],
      datasets:[{
        label:"Frames per second",
        data:[0,0,0,0,0,0],
        borderColor:"#38d996",
        backgroundColor:"rgba(56,217,150,0.12)",
        fill:true,
        tension:0.3
      }]
    },
    options:{
      responsive:true,
      maintainAspectRatio:false,
      plugins:{legend:{display:true}},
      scales:{
        y:{beginAtZero:true},
        x:{grid:{display:false}}
      }
    }
  });
}
