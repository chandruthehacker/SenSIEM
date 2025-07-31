import { Link, useLocation } from "react-router-dom";
import {
  Search,
  BarChart3,
  FileText,
  AlertTriangle,
  Settings,
  Shield,
  Home,
  Github, // Import Github icon for the source code link
} from "lucide-react";
import { cn } from "@/lib/utils";
import { motion, AnimatePresence } from "framer-motion"; // Import motion and AnimatePresence

const Navigation = () => {
  const location = useLocation();

  const navItems = [
    { href: "/", icon: Home, label: "Home" },
    { href: "/search", icon: Search, label: "Search" },
    { href: "/dashboards", icon: BarChart3, label: "Dashboards" },
    { href: "/logs", icon: FileText, label: "Logs" },
    { href: "/alerts", icon: AlertTriangle, label: "Alerts" },
    { href: "/settings", icon: Settings, label: "Settings" },
  ];

  const isActive = (path: string) => location.pathname === path;

  // Animation variants for the source code button text
  const textVariants = {
    hidden: { opacity: 0, y: 10 },
    visible: { opacity: 1, y: 0, transition: { duration: 0.5, staggerChildren: 0.1 } },
  };

  const letterVariants = {
    hidden: { opacity: 0, y: 10 },
    visible: { opacity: 1, y: 0 },
  };

  const words = "This is a sample project. View the source code, download, use, and feel it.".split(" ");

  return (
    <>
      {/* Sidebar for md+ */}
      <nav className="hidden md:flex bg-card border-r border-border w-64 h-screen fixed left-0 top-0 flex-col">
        <div className="p-6 border-b border-border">
          <div className="flex items-center gap-3">
            <div className="w-10 h-10 bg-gradient-primary rounded-lg flex items-center justify-center animate-cyber-pulse">
              <Shield className="w-6 h-6 text-primary-foreground" />
            </div>
            <div>
              <h1 className="text-xl font-bold text-foreground">SenSIEM</h1>
              <p className="text-xs text-muted-foreground">Cyber Analytics</p>
            </div>
          </div>
        </div>
        <div className="flex-1 p-4 space-y-2">
          {navItems.map((item) => (
            <Link
              key={item.href}
              to={item.href}
              className={cn(
                "flex items-center gap-3 px-4 py-3 rounded-lg transition-all duration-200 group",
                isActive(item.href)
                  ? "bg-primary text-primary-foreground shadow-cyber"
                  : "text-muted-foreground hover:text-foreground hover:bg-secondary"
              )}
            >
              <item.icon className={cn(
                "w-5 h-5 transition-transform duration-200",
                isActive(item.href) ? "text-primary-foreground" : "group-hover:scale-110"
              )} />
              <span className="font-medium">{item.label}</span>
            </Link>
          ))}
        </div>

        {/* Source Code Link for Desktop (bottom of sidebar) */}
        <div className="p-4 border-t border-border mt-auto"> {/* mt-auto pushes it to the bottom */}
          <motion.div
            initial="hidden"
            animate="visible"
            variants={textVariants}
            className="text-center text-xs text-muted-foreground mb-3"
          >
            {words.map((word, i) => (
              <motion.span key={i} variants={letterVariants} className="inline-block mr-1">
                {word}
              </motion.span>
            ))}
          </motion.div>
          <Link
            to="https://github.com/chandruthehacker/SenSIEM/" // <--- REPLACE WITH YOUR GITHUB REPO LINK
            target="_blank" // Opens in a new tab
            rel="noopener noreferrer" // Security best practice for target="_blank"
            className="w-full flex items-center justify-center gap-2 px-4 py-3 rounded-lg bg-gradient-to-r from-purple-600 to-indigo-600 text-white font-medium text-sm hover:shadow-cyber transition-all duration-300 transform hover:scale-105"
          >
            <Github className="w-5 h-5" />
            <span>Source Code</span>
          </Link>
        </div>
      </nav>

      {/* Bottom navbar for mobile */}
      <nav className="fixed bottom-0 w-full bg-card border-t border-border md:hidden z-50">
        <div className="flex justify-around items-center p-2">
          {navItems.map((item) => (
            <Link key={item.href} to={item.href} className="flex flex-col items-center text-muted-foreground hover:text-foreground transition-all">
              <item.icon className={cn("w-5 h-5", isActive(item.href) && "text-primary")} />
              <span className="text-[10px]">{item.label}</span>
            </Link>
          ))}
        </div>
      </nav>

      {/* Floating Source Code Button for Mobile (above the nav) */}
      <AnimatePresence>
        <motion.div
          initial={{ opacity: 0, y: 100 }}
          animate={{ opacity: 1, y: 0 }}
          exit={{ opacity: 0, y: 100 }}
          transition={{ type: "spring", stiffness: 120, damping: 10 }}
          className="fixed bottom-[70px] right-4 md:hidden z-40" // Adjust bottom value to be above the mobile nav
        >
          <Link
            to="https://github.com/your-repo-link" // <--- REPLACE WITH YOUR GITHUB REPO LINK
            target="_blank"
            rel="noopener noreferrer"
            className="flex items-center gap-2 p-3 rounded-full bg-gradient-to-r from-purple-600 to-indigo-600 text-white shadow-lg hover:shadow-cyber-lg transition-all duration-300 transform hover:scale-110"
          >
            <Github className="w-6 h-6" />
            {/* Optional: Add text on hover for mobile, or keep it icon-only for space */}
            {/* <span className="hidden group-hover:block text-sm">Source Code</span> */}
          </Link>
        </motion.div>
      </AnimatePresence>
    </>
  );
};

export default Navigation;