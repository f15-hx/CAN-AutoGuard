import {renderSidebar} from "./components/Sidebar.js";
import {renderTopBar} from "./components/TopBar.js";

const pages={
  overview:{title:"Overview",content:"Dashboard overview will appear here."},
  traffic:{title:"Live Traffic",content:"Live traffic page is being developed by M1."},
  alerts:{title:"Alerts",content:"Security alerts will appear here."},
  attacklab:{title:"Attack Lab",content:"Attack Lab is being developed by M2."},
  analytics:{title:"Analytics",content:"Analytics charts will appear here."},
  settings:{title:"Settings",content:"Settings and reports will appear here."}
};

function renderApp(){
  const pageId=location.hash.slice(1)||"overview";
  const page=pages[pageId]||pages.overview;
  document.getElementById("sidebar").innerHTML=renderSidebar(pageId);
  document.getElementById("topbar").innerHTML=renderTopBar(page.title);
  document.getElementById("page-content").innerHTML=`
    <div class="page-placeholder">
      <h2>${page.title}</h2>
      <p>${page.content}</p>
    </div>
  `;
}

window.addEventListener("hashchange",renderApp);
renderApp();
