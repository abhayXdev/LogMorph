import { Navigate, useLocation } from "react-router";
import { useAuth } from "../context/AuthContext";
import { LoaderCircle } from "lucide-react";

export function ProtectedRoute({ children }: { children: React.ReactNode }) {
  const { isAuthenticated, isLoading } = useAuth();
  const location = useLocation();

  if (isLoading) {
    return (
      <div className="flex min-h-screen flex-col items-center justify-center gap-3 bg-[#faf6f0] text-[#1a1d15]">
        <div className="grid size-12 place-items-center rounded-xl border border-[#c6c8bb] bg-[#e8d2b5] shadow-sm">
          <LoaderCircle className="size-6 animate-spin text-[#590907]" />
        </div>
        <p className="font-mono-medium text-xs text-[#76786d]">Authenticating session...</p>
      </div>
    );
  }

  if (!isAuthenticated) {
    return <Navigate to="/login" state={{ from: location }} replace />;
  }

  return <>{children}</>;
}
