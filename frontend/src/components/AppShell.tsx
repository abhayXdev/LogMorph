import { useEffect, useState } from "react";
import { Link, NavLink, Outlet, useLocation, useNavigate } from "react-router";
import { Menu, X, LogOut, ExternalLink } from "lucide-react";
import { useAuth } from "../context/AuthContext";
import { healthApi } from "../lib/api";

const navItems = [
  { to: "/dashboard", label: "Dashboard", icon: "fd32e.svg", activeIcon: "05fd0.svg" },
  { to: "/logs", label: "Log Explorer", icon: "f3499.svg", activeIcon: "21388.svg" },
  { to: "/sandbox", label: "Sandbox", icon: "0ae1e.svg", activeIcon: "a1820.svg" },
  { to: "/keys", label: "API Keys", icon: "bae6a.svg", activeIcon: "249c4.svg" },
  { to: "/sources", label: "Sources", icon: "c03d4.svg", activeIcon: "5d706.svg" },
  { to: "/settings", label: "Settings", icon: "81d52.svg", activeIcon: "b94f0.svg" },
];

export function AppShell() {
  const navigate = useNavigate();
  const location = useLocation();
  const { user, logout } = useAuth();
  const [mobileOpen, setMobileOpen] = useState(false);
  const [apiStatus, setApiStatus] = useState<"connected" | "checking" | "offline">("checking");

  useEffect(() => {
    setMobileOpen(false);
  }, [location.pathname]);

  // Periodic health ping
  useEffect(() => {
    let mounted = true;
    const check = async () => {
      try {
        const res = await healthApi.check();
        if (mounted) setApiStatus(res.status === "healthy" ? "connected" : "checking");
      } catch {
        if (mounted) setApiStatus("offline");
      }
    };
    check();
    const interval = setInterval(check, 45_000);
    return () => {
      mounted = false;
      clearInterval(interval);
    };
  }, []);

  const handleLogout = () => {
    logout();
    navigate("/login", { replace: true });
  };

  const initials = (user?.full_name || user?.email || "LM")
    .split(/\s|@/)
    .map((v) => v[0])
    .filter(Boolean)
    .slice(0, 2)
    .join("")
    .toUpperCase();

  return (
    <div className="app-light min-h-screen bg-[#faf6f0] text-[#1a1d15]">
      {/* Mobile Hamburger Toggle */}
      <button
        type="button"
        aria-label="Open navigation menu"
        onClick={() => setMobileOpen(true)}
        className="fixed left-4 top-4 z-30 grid size-10 place-items-center rounded-lg border border-[#c6c8bb] bg-white text-[#45483e] shadow-sm md:hidden cursor-pointer"
      >
        <Menu className="size-5" />
      </button>

      {/* Backdrop for Mobile Drawer */}
      {mobileOpen && (
        <div
          role="button"
          tabIndex={0}
          aria-label="Close navigation"
          className="fixed inset-0 z-40 bg-[#1a1d15]/40 backdrop-blur-xs md:hidden"
          onClick={() => setMobileOpen(false)}
          onKeyDown={(e) => e.key === "Escape" && setMobileOpen(false)}
        />
      )}

      {/* Sidebar */}
      <aside
        className={`fixed inset-y-0 left-0 z-50 flex w-64 flex-col justify-between border-r border-[#c6c8bb] bg-[#f6efe5] px-5 py-6 transition-transform duration-200 ease-in-out md:translate-x-0 ${
          mobileOpen ? "translate-x-0" : "-translate-x-full"
        }`}
      >
        <div className="flex flex-col gap-6">
          {/* Logo & Close on mobile */}
          <div className="flex items-center justify-between">
            <Link to="/dashboard" className="flex items-center gap-2.5">
              <span className="grid size-9 place-items-center rounded-lg bg-[#590907] shadow-sm">
                <img src="/assets/a807c.svg" alt="LogMorph" className="size-5" />
              </span>
              <div className="flex flex-col">
                <span className="font-heading-semibold text-lg leading-tight tracking-tight text-[#1a1d15]">
                  LogMorph
                </span>
                <span className="font-mono-medium text-[10px] tracking-wider text-[#76786d] uppercase">
                  Telemetry Engine
                </span>
              </div>
            </Link>
            <button
              type="button"
              aria-label="Close navigation"
              onClick={() => setMobileOpen(false)}
              className="grid size-8 place-items-center rounded-lg text-[#76786d] hover:bg-[#efe6da] hover:text-[#1a1d15] md:hidden cursor-pointer"
            >
              <X className="size-5" />
            </button>
          </div>

          {/* Navigation Links */}
          <nav className="space-y-1">
            {navItems.map((item) => (
              <NavLink
                key={item.to}
                to={item.to}
                className={({ isActive }) =>
                  `font-ui-medium flex items-center gap-2.5 rounded-lg px-3 py-2 text-sm leading-5 transition duration-150 ${
                    isActive
                      ? "border border-[#c6c8bb] bg-[#e8d2b5] font-semibold text-[#590907] shadow-xs"
                      : "border border-transparent text-[#45483e] hover:translate-x-0.5 hover:bg-[#efe6da] hover:text-[#1a1d15]"
                  }`
                }
              >
                {({ isActive }) => (
                  <>
                    <img
                      src={`/assets/${isActive ? item.activeIcon : item.icon}`}
                      alt=""
                      className="size-4 shrink-0"
                    />
                    <span>{item.label}</span>
                  </>
                )}
              </NavLink>
            ))}
          </nav>
        </div>

        {/* Bottom Section: API Status, Docs link, User Card */}
        <div className="flex flex-col gap-3 border-t border-[#c6c8bb] pt-4">
          {/* Live API Status Indicator */}
          <div className="flex items-center justify-between rounded-md bg-white/70 px-2.5 py-1.5 border border-[#c6c8bb]/60 text-xs">
            <span className="flex items-center gap-1.5 text-[#45483e] font-mono text-[11px]">
              <span
                className={`size-2 rounded-full ${
                  apiStatus === "connected"
                    ? "bg-[#1b5e3a] animate-pulse"
                    : apiStatus === "checking"
                    ? "bg-[#855300] animate-pulse"
                    : "bg-[#93000a]"
                }`}
              />
              {apiStatus === "connected"
                ? "Backend Connected"
                : apiStatus === "checking"
                ? "Checking API..."
                : "Offline / Sleeping"}
            </span>
            <a
              href="https://logmorph.onrender.com/docs"
              target="_blank"
              rel="noreferrer"
              className="text-[#590907] hover:underline flex items-center gap-0.5 font-mono text-[11px]"
            >
              Docs <ExternalLink className="size-2.5" />
            </a>
          </div>

          {/* User profile card */}
          <div className="flex items-center gap-2.5 px-1 py-1">
            <span className="font-ui-medium grid size-8 shrink-0 place-items-center rounded-full border border-[#c6c8bb] bg-[#e8d2b5] text-xs font-semibold text-[#590907]">
              {initials}
            </span>
            <div className="min-w-0 flex-1">
              <p className="font-ui-medium truncate text-sm leading-5 font-medium text-[#1a1d15]">
                {user?.full_name || "Enterprise User"}
              </p>
              <p className="font-mono-medium truncate text-xs leading-4 text-[#76786d]">
                {user?.email || "user@logmorph.internal"}
              </p>
            </div>
          </div>

          {/* Sign Out Button */}
          <button
            type="button"
            onClick={handleLogout}
            className="font-ui-medium flex w-full items-center gap-2 rounded-lg px-3 py-2 text-sm text-[#45483e] hover:bg-[#ffdad5]/40 hover:text-[#93000a] transition cursor-pointer"
          >
            <LogOut className="size-4 shrink-0 text-[#76786d]" />
            <span>Sign Out</span>
          </button>
        </div>
      </aside>

      {/* Main Content Area */}
      <main className="min-h-screen md:pl-64">
        <div key={location.pathname} className="animate-page-in">
          <Outlet />
        </div>
      </main>
    </div>
  );
}
