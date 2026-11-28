export function renderLineChart(canvasId,title){
  return `
    <div class="panel">
      <div class="panel-header">
        <h3 class="card-title">${title}</h3>
      </div>
      <div class="panel-body chart-container">
        <canvas id="${canvasId}"></canvas>
      </div>
    </div>
  `;
}

export function renderBarChart(canvasId,title){
  return `
    <div class="panel">
      <div class="panel-header">
        <h3 class="card-title">${title}</h3>
      </div>
      <div class="panel-body chart-container">
        <canvas id="${canvasId}"></canvas>
      </div>
    </div>
  `;
}
