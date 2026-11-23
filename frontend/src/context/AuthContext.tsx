import { createContext, useContext, useEffect, useState, type ReactNode } from "react";
import {
  type User,
  authApi,
  clearSession,
  getToken,
  getUser,
  saveSession,
  warmUpApi,
} from "../lib/api";

interface AuthContextType {
  user: User | null;
  token: string | null;
  isAuthenticated: boolean;
  isLoading: boolean;
  login: (email: string, password: string) => Promise<void>;
  signup: (email: string, password: string, fullName?: string) => Promise<void>;
  logout: () => void;
  refreshUser: () => Promise<void>;
}

const AuthContext = createContext<AuthContextType | undefined>(undefined);

export function AuthProvider({ children }: { children: ReactNode }) {
  const [token, setToken] = useState<string | null>(() => getToken());
  const [user, setUser] = useState<User | null>(() => getUser());
  const [isLoading, setIsLoading] = useState<boolean>(true);

  // Background ping to wake Render early
  useEffect(() => {
    warmUpApi();
  }, []);

  // Sync session on mount
  useEffect(() => {
    const existingToken = getToken();
    if (existingToken) {
      authApi
        .me()
        .then((fetchedUser) => {
          setUser(fetchedUser);
          saveSession({ access_token: existingToken, user: fetchedUser });
        })
        .catch(() => {
          // If token validation fails, clear stale session
          clearSession();
          setToken(null);
          setUser(null);
        })
        .finally(() => {
          setIsLoading(false);
        });
    } else {
      setIsLoading(false);
    }

    const handleAuthExpired = () => {
      setToken(null);
      setUser(null);
    };

    window.addEventListener("logmorph:auth-expired", handleAuthExpired);
    return () => {
      window.removeEventListener("logmorph:auth-expired", handleAuthExpired);
    };
  }, []);

  const login = async (email: string, password: string) => {
    setIsLoading(true);
    try {
      const res = await authApi.login({ email, password });
      setToken(res.access_token);
      let resolvedUser = res.user;
      if (!resolvedUser) {
        // Fetch /auth/me if login response doesn't embed user object
        try {
          saveSession({ access_token: res.access_token });
          resolvedUser = await authApi.me();
        } catch {
          resolvedUser = { id: "usr_me", email };
        }
      }
      setUser(resolvedUser);
      saveSession({ access_token: res.access_token, user: resolvedUser });
    } finally {
      setIsLoading(false);
    }
  };

  const signup = async (email: string, password: string, fullName?: string) => {
    setIsLoading(true);
    try {
      const res = await authApi.signup({ email, password, full_name: fullName });
      setToken(res.access_token);
      const resolvedUser = res.user || {
        id: "usr_new",
        email,
        full_name: fullName,
        is_verified: false,
      };
      setUser(resolvedUser);
      saveSession({ access_token: res.access_token, user: resolvedUser });
    } finally {
      setIsLoading(false);
    }
  };

  const logout = () => {
    clearSession();
    setToken(null);
    setUser(null);
  };

  const refreshUser = async () => {
    try {
      const fetched = await authApi.me();
      setUser(fetched);
      if (token) saveSession({ access_token: token, user: fetched });
    } catch {
      // Ignored
    }
  };

  return (
    <AuthContext.Provider
      value={{
        user,
        token,
        isAuthenticated: Boolean(token),
        isLoading,
        login,
        signup,
        logout,
        refreshUser,
      }}
    >
      {children}
    </AuthContext.Provider>
  );
}

export function useAuth(): AuthContextType {
  const context = useContext(AuthContext);
  if (!context) {
    throw new Error("useAuth must be used within an AuthProvider");
  }
  return context;
}
