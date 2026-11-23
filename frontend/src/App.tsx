import { useEffect } from "react";
import { createBrowserRouter, RouterProvider } from "react-router";
import { AuthProvider } from "./context/AuthContext";
import { ProtectedRoute } from "./components/ProtectedRoute";
import { AppShell } from "./components/AppShell";
import {
  LandingPage,
  LoginPage,
  SignupPage,
  VerifyEmailPage,
  ForgotPasswordPage,
  ResetPasswordPage,
  NotFoundPage,
} from "./pages/PublicPages";
import {
  DashboardPage,
  LogsPage,
  EventDetailPage,
  SandboxPage,
  KeysPage,
  SourcesPage,
  SettingsPage,
} from "./pages/AppPages";
import { useScrollReveal } from "./lib/useScrollReveal";
import { warmUpApi } from "./lib/api";

const router = createBrowserRouter([
  { path: "/", Component: LandingPage },
  { path: "/login", Component: LoginPage },
  { path: "/signup", Component: SignupPage },
  { path: "/verify-email", Component: VerifyEmailPage },
  { path: "/forgot-password", Component: ForgotPasswordPage },
  { path: "/reset-password", Component: ResetPasswordPage },
  {
    element: (
      <ProtectedRoute>
        <AppShell />
      </ProtectedRoute>
    ),
    children: [
      { path: "/dashboard", Component: DashboardPage },
      { path: "/logs", Component: LogsPage },
      { path: "/logs/:eventId", Component: EventDetailPage },
      { path: "/sandbox", Component: SandboxPage },
      { path: "/keys", Component: KeysPage },
      { path: "/sources", Component: SourcesPage },
      { path: "/settings", Component: SettingsPage },
    ],
  },
  { path: "*", Component: NotFoundPage },
]);

export default function App() {
  useScrollReveal();

  useEffect(() => {
    warmUpApi();
  }, []);

  return (
    <AuthProvider>
      <RouterProvider router={router} />
    </AuthProvider>
  );
}
