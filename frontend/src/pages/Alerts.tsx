import { AlertsList } from "@/components/alerts/AlertsList"
import { AlertTriangle } from "lucide-react"
import Layout from "@/components/layout/Layout";

export default function Alerts() {
  return (
    <Layout>
      <div className="p-6 space-y-6">
        <div className="flex items-center gap-3">
          <AlertTriangle className="h-8 w-8 text-primary" />
          <div>
            <h1 className="text-3xl font-bold text-foreground">Security Alerts</h1>
            <p className="text-muted-foreground">Monitor and manage security events across your infrastructure</p>
          </div>
        </div>
        
        <AlertsList />
      </div>
    </Layout>
  )
}