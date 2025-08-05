import { useState } from "react"
import { Badge } from "@/components/ui/badge"
import { Button } from "@/components/ui/button"
import { Card, CardContent, CardHeader } from "@/components/ui/card"
import { AlertTriangle, Calendar, Globe, Server, FileText, Shield, Eye, Check, CheckCheck } from "lucide-react"
import { AlertConfirmDialog } from "./AlertConfirmDialog"
import { AlertDetailsDialog } from "./AlertDetailsDialog"

export interface Alert {
  id: number
  alert_time: string
  severity: "Critical" | "High" | "Medium" | "Low"
  rule_type: string
  message: string
  ip: string
  host?: string
  source: string
  status: "new" | "acknowledged" | "resolved"
  rule_name: string
  timestamp: string
}

interface AlertCardProps {
  alert: Alert
  onAcknowledge: (id: number) => void
  onResolve: (id: number) => void
}

const severityColors = {
  Critical: "bg-rose-700 text-white",      // Red
  High: "bg-orange-600 text-white",        // Orange
  Medium: "bg-yellow-400 text-black",      // Yellow
  Low: "bg-sky-400 text-black",            // Blue
};

const statusColors = {
  new: "bg-indigo-600 text-white",         // Indigo
  acknowledged: "bg-blue-700 text-white",  // Deep blue
  resolved: "bg-status-resolved text-background",   // Green
};

const statusLabels = {
  new: "New",
  acknowledged: "Acknowledged",
  resolved: "Resolved",
}

export function AlertCard({ alert, onAcknowledge, onResolve }: AlertCardProps) {
  const [showAckDialog, setShowAckDialog] = useState(false)
  const [showResolveDialog, setShowResolveDialog] = useState(false)
  const [showDetailsDialog, setShowDetailsDialog] = useState(false)

  const formatTimestamp = (timestamp: string) => {
    return new Date(timestamp).toLocaleString()
  }

  return (
    <>
      <Card className="bg-gradient-card text-white shadow-card border border-zinc-800 hover:shadow-glow transition-shadow duration-300">
        <CardHeader className="pb-3">
          <div className="flex items-start justify-between">
            <div className="flex items-center gap-4">
              <AlertTriangle className="h-5 w-5 text-rose-500" />
              <div className="space-y-2">
                <div className="flex items-center gap-4 mb-1">
                  <Badge className={severityColors[alert.severity]}>
                    {alert.severity}
                  </Badge>
                  <Badge className="bg-white/10 text-white text-xs font-medium">
                    {alert.rule_type}
                  </Badge>
                </div>
                <Badge className={statusColors[alert.status]}>
                  {statusLabels[alert.status]}
                </Badge>
              </div>
            </div>
            <div className="text-xs text-muted-foreground">
              ID: {alert.id}
            </div>
          </div>
        </CardHeader>
        
        <CardContent className="space-y-4">
          <div className="space-y-3">
            <p className="text-sm leading-relaxed text-zinc-200">{alert.message}</p>
            
            <div className="grid grid-cols-2 gap-3 text-xs">
              <div className="flex items-center gap-2">
                <Calendar className="h-3 w-3 text-muted-foreground" />
                <span className="text-zinc-400">Timestamp:</span>
                <span>{formatTimestamp(alert.alert_time)}</span>
              </div>
              
              <div className="flex items-center gap-2">
                <Globe className="h-3 w-3 text-muted-foreground" />
                <span className="text-muted-foreground">Source IP:</span>
                <span className="font-mono">{alert.ip}</span>
              </div>
              
              {alert.host && (
                <div className="flex items-center gap-2">
                  <Server className="h-3 w-3 text-muted-foreground" />
                  <span className="text-muted-foreground">Hostname:</span>
                  <span className="font-mono">{alert.host}</span>
                </div>
              )}
              
              <div className="flex items-center gap-2">
                <FileText className="h-3 w-3 text-muted-foreground" />
                <span className="text-muted-foreground">Log Source:</span>
                <span>{alert.source}</span>
              </div>
              
              <div className="flex items-center gap-2 col-span-2">
                <Shield className="h-3 w-3 text-muted-foreground" />
                <span className="text-muted-foreground">Rule:</span>
                <span>{alert.rule_name}</span>
              </div>
            </div>
          </div>
          
          <div className="flex items-center gap-4 pt-3 border-t border-border">
            <Button
              size="sm"
              variant="ghost"
              onClick={() => setShowDetailsDialog(true)}
              className="h-8 bg-accent"
            >
              <Eye className="h-3 w-3" />
              Details
            </Button>
            
            {alert.status === "new" && (
              <Button
                size="sm"
                variant="acknowledge"
                onClick={() => setShowAckDialog(true)}
                className="h-8"
              >
                <Check className="h-3 w-3" />
                Acknowledge
              </Button>
            )}
            
            {(alert.status === "new" || alert.status === "acknowledged") && (
              <Button
                size="sm"
                variant="resolve"
                onClick={() => setShowResolveDialog(true)}
                className="h-8"
              >
                <CheckCheck className="h-3 w-3" />
                Resolve
              </Button>
            )}
          </div>
        </CardContent>
      </Card>

      <AlertConfirmDialog
        open={showAckDialog}
        onOpenChange={setShowAckDialog}
        onConfirm={() => onAcknowledge(alert.id)}
        title="Acknowledge Alert"
        description={`Are you sure you want to acknowledge this ${alert.severity.toLowerCase()} alert?`}
        action="acknowledge"
      />

      <AlertConfirmDialog
        open={showResolveDialog}
        onOpenChange={setShowResolveDialog}
        onConfirm={() => onResolve(alert.id)}
        title="Resolve Alert"
        description={`Are you sure you want to resolve this ${alert.severity.toLowerCase()} alert?`}
        action="resolve"
      />

      <AlertDetailsDialog
        open={showDetailsDialog}
        onOpenChange={setShowDetailsDialog}
        alert={alert}
      />
    </>
  )
}