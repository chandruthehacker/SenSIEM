import { ReactNode } from "react";
import Navigation from "./Navigation";

interface LayoutProps {
  children: ReactNode;
}

const Layout = ({ children }: LayoutProps) => {
  return (
    <div className="min-h-screen bg-background flex flex-col md:flex-row">
      {/* Sidebar for large screens / Bottom bar for small screens */}
      <Navigation />

      {/* Main content */}
      <main className="flex-1 md:ml-64 mb-16 md:mb-0">
        {children}
      </main>
    </div>
  );
};

export default Layout;
