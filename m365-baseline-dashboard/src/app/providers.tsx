'use client';

import * as React from 'react';
import {
  FluentProvider,
  webDarkTheme,
} from '@fluentui/react-components';

export const AuthContext = React.createContext<{
  isAuthenticated: boolean;
  login: () => void;
  logout: () => void;
}>({
  isAuthenticated: false,
  login: () => {},
  logout: () => {},
});

export function Providers({ children }: { children: React.ReactNode }) {
  const [isMounted, setIsMounted] = React.useState(false);
  const [isAuthenticated, setIsAuthenticated] = React.useState(false);

  React.useEffect(() => {
    setIsMounted(true);
  }, []);

  const login = () => setIsAuthenticated(true);
  const logout = () => setIsAuthenticated(false);

  if (!isMounted) {
    return <div style={{ visibility: 'hidden' }}>{children}</div>;
  }

  return (
    <AuthContext.Provider value={{ isAuthenticated, login, logout }}>
      <FluentProvider theme={webDarkTheme}>
        {children}
      </FluentProvider>
    </AuthContext.Provider>
  );
}
