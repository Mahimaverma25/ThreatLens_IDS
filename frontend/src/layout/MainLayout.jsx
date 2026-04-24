import Navbar from "../components/AppNavbar.jsx";
import Sidebar from "../components/AppSidebar.jsx";
import "../styles/layout.css";

function MainLayout({ children }) {
  return (
    <div className="layout">
      <Navbar />
      <div className="layout-body">
        <Sidebar />
        <main className="main-content">
          {children}
        </main>
      </div>
    </div>
  );
}

export default MainLayout;