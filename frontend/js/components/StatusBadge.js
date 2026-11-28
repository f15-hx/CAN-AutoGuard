export function renderStatusBadge(status){
  const value=String(status||"Unknown");
  const type=value.toLowerCase();
  let color="badge-info";
  if(["normal","online","safe","success","healthy"].includes(type)){
    color="badge-success";
  }else if(["warning","warn","suspicious"].includes(type)){
    color="badge-warning";
  }else if(["critical","error","offline","danger"].includes(type)){
    color="badge-danger";
  }
  return `<span class="badge ${color}">${value}</span>`;
}
