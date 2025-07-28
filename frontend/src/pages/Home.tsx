import { Button } from "@/components/ui/button"
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card"
import { Badge } from "@/components/ui/badge"
import { 
  Shield, 
  Search, 
  BarChart3, 
  AlertTriangle, 
  Globe, 
  Github, 
  Instagram,
  Linkedin,
  ChevronRight,
  Activity,
  Lock,
  Zap,
  Eye
} from "lucide-react"
import { Link, useNavigate } from "react-router-dom"
import heroCyber from "@/assets/hero-cyber.jpg"
import Layout from "@/components/layout/Layout"
import hero from "@/assets/hero.png";

const features = [
  {
    icon: Search,
    title: "Advanced Log Search",
    description: "Query logs with powerful filters and real-time search capabilities",
    color: "text-primary"
  },
  {
    icon: BarChart3,
    title: "Visual Dashboards",
    description: "Create custom dashboards with drag-and-drop widgets",
    color: "text-accent"
  },
  {
    icon: AlertTriangle,
    title: "Threat Detection",
    description: "Automated anomaly detection and security alerts",
    color: "text-destructive"
  },
  {
    icon: Activity,
    title: "Real-time Monitoring",
    description: "Live log streaming and system health monitoring",
    color: "text-success"
  },
  {
    icon: Lock,
    title: "Secure Infrastructure",
    description: "Enterprise-grade security with encrypted data handling",
    color: "text-warning"
  },
  {
    icon: Zap,
    title: "High Performance",
    description: "Optimized for handling large volumes of log data",
    color: "text-primary-glow"
  }
]

const socialLinks = [
  {
    icon: Globe,
    label: "Portfolio",
    href: "https://chandruthehacker.github.io/",
    color: "hover:text-primary"
  },
  {
    icon: Github,
    label: "GitHub",
    href: "https://github.com/chandruthehacker",
    color: "hover:text-primary"
  },
  {
    icon: Instagram,
    label: "Instagram", 
    href: "https://instagram.com/dgl_chandru",
    color: "hover:text-primary"
  },
  {
    icon: Linkedin,
    label: "LinkedIn",
    href: "https://linkedin.com/in/chandruthehacker",
    color: "hover:text-blue-400"
  }
]

export default function Home() {
  const navigate = useNavigate()

  return (
    <Layout>
    <div className="space-y-8 p-10">
      {/* Hero Section */}
      <section className="relative min-h-[60vh] flex items-center justify-center overflow-hidden rounded-2xl bg-gradient-cyber">
        <div
          className="absolute inset-0 bg-cover bg-center opacity-20"
          style={{ backgroundImage: `url(${heroCyber})` }}
        />
        <div className="absolute inset-0 bg-gradient-to-r from-background/90 via-transparent to-background/90" />
        
        <div className="relative z-10 text-center space-y-6 px-8 animate-fade-in">
          <div className="inline-flex items-center space-x-2 bg-card/50 backdrop-blur-sm rounded-full px-4 py-2 border border-primary/30">
            <Shield className="h-4 w-4 text-primary animate-pulse-soft" />
            <span className="text-sm font-medium">Security Intelligence Platform</span>
          </div>
          
          <h1 className="text-5xl md:text-7xl font-bold space-y-2">
            <div className="hero-text">SenSIEM</div>
            <div className="text-2xl md:text-3xl text-muted-foreground font-normal">
              Sensitive & Smart SIEM
            </div>
          </h1>
          
          <p className="text-xl text-muted-foreground max-w-2xl mx-auto leading-relaxed">
            Advanced cybersecurity log analysis platform designed for modern security operations. 
            Monitor, analyze, and respond to threats with intelligent automation.
          </p>
          
          <div className="flex flex-col sm:flex-row gap-4 justify-center pt-4">
            <Button 
              size="lg" 
              className="cyber-button text-lg px-8 hover:bg-primary/70 transition duration-300"
              onClick={() => navigate("/search")}
            >
              Start Monitoring Logs
              <ChevronRight className="ml-2 h-5 w-5" />
            </Button>
            <Button 
              size="lg" 
              variant="outline" 
              className="border-primary/30 hover:bg-primary/10 text-lg px-8 transition duration-300"
              onClick={() => navigate("/dashboards")}
            >
              <Eye className="mr-2 h-5 w-5" />
              View Dashboards
            </Button>
          </div>
        </div>
      </section>

      {/* Author Section */}
      <section className="text-center space-y-4 animate-slide-up">
        <h1 className="font-sans my-3 font-bold text-xl">Author</h1>
        <a href="https://chandruthehacker.github.io/" target="_blank">
        <div className="inline-flex items-center space-x-3 bg-card/80 backdrop-blur-sm rounded-2xl px-6 py-4 border border-border/50 cursor-pointern hover:border-primary transform hover:scale-110 hover:rotate-2 transition duration-300">
          <div className="h-12 w-12 rounded-full bg-gradient-cyber flex items-center justify-center">
            <img src={hero} alt="My Image" className="h-12 w-12 rounded-full" />
          </div>
          <div className="text-left">
            <h3 className="text-lg font-semibold">Chandraprakash C</h3>
            <p className="text-sm text-muted-foreground">Cybersecurity Engineer</p>
          </div>
        </div>
        </a>
        
        <div className="flex justify-center space-x-4">
          {socialLinks.map((link) => (
            <Button
              key={link.label}
              variant="ghost"
              size="sm"
              className={`cyber-border ${link.color} transition-all duration-200`}
              asChild
            >
              <a href={link.href} target="_blank" rel="noopener noreferrer">
                <div className="flex items-center space-x-2">
                  <link.icon className="h-6 w-6" />
                  <span>{link.label}</span>
                </div>
              </a>
            </Button>
          ))}
        </div>
      </section>

      {/* Features Section */}
      <section className="space-y-8 animate-slide-up">
        <div className="text-center space-y-4">
          <h2 className="text-3xl font-bold hero-text">Platform Features</h2>
          <p className="text-lg text-muted-foreground max-w-2xl mx-auto">
            Comprehensive security tools designed for efficiency and intelligence
          </p>
        </div>
        
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6">
          {features.map((feature, index) => (
            <Card 
              key={feature.title}
              className="cyber-border hover:shadow-glow transition-all duration-300 group"
              style={{ animationDelay: `${index * 100}ms` }}
            >
              <CardHeader className="text-center pb-4">
                <div className={`inline-flex items-center justify-center h-12 w-12 rounded-xl bg-gradient-subtle mx-auto mb-4 group-hover:scale-110 transition-transform duration-200`}>
                  <feature.icon className={`h-6 w-6 ${feature.color}`} />
                </div>
                <CardTitle className="text-lg">{feature.title}</CardTitle>
              </CardHeader>
              <CardContent>
                <CardDescription className="text-center">
                  {feature.description}
                </CardDescription>
              </CardContent>
            </Card>
          ))}
        </div>
      </section>

      {/* Quick Actions */}
      <section className="space-y-6 animate-slide-up">
        <h2 className="text-2xl font-bold text-center hero-text">Quick Actions</h2>
        <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
          <Button
            variant="outline"
            className="cyber-border h-20 flex-col space-y-2 hover:shadow-cyber"
            asChild
          >
            <Link to="/search">
              <div className="flex flex-col items-center space-y-2">
                <Search className="h-6 w-6 text-primary" />
                <span>Search Logs</span>
              </div>
            </Link>
          </Button>
          <Button
            variant="outline"
            className="cyber-border h-20 flex-col space-y-2 hover:shadow-cyber"
            asChild
          >
            <Link to="/dashboards">
              <div className="flex flex-col items-center space-y-2">
                <BarChart3 className="h-6 w-6 text-accent" />
                <span>Dashboards</span>
              </div>
            </Link>
          </Button>
          <Button
            variant="outline"
            className="cyber-border h-20 flex-col space-y-2 hover:shadow-cyber"
            asChild
          >
            <Link to="/alerts">
              <div className="flex flex-col items-center space-y-2">
                <AlertTriangle className="h-6 w-6 text-destructive" />
                <span>View Alerts</span>
              </div>
            </Link>
          </Button>
          <Button
            variant="outline"
            className="cyber-border h-20 flex-col space-y-2 hover:shadow-cyber"
            asChild
          >
            <Link to="/settings">
              <div className="flex flex-col items-center space-y-2">
                <Shield className="h-6 w-6 text-success" />
                <span>Settings</span>
              </div>
            </Link>
          </Button>
        </div>
      </section>

      {/* System Status */}
      <section className="text-center space-y-4 animate-fade-in">
        <Card className="cyber-border max-w-md mx-auto">
          <CardContent className="pt-6">
            <div className="flex items-center justify-center space-x-2 text-success">
              <div className="h-3 w-3 bg-success rounded-full animate-pulse-soft"></div>
              <span className="font-medium">System Operational</span>
            </div>
            <p className="text-sm text-muted-foreground mt-2">
              All security monitoring services are running normally
            </p>
          </CardContent>
        </Card>
      </section>
    </div>
    </Layout>
  )
}