import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog"
import { Badge } from "@/components/ui/badge"
import { Calendar, Globe, Server, FileText, Shield, AlertTriangle } from "lucide-react"
import { Alert } from "./AlertCard"

interface AlertDetailsDialogProps {
  open: boolean
  onOpenChange: (open: boolean) => void
  alert: Alert
}

const severityColors = {
  Critical: "bg-severity-critical text-white",
  High: "bg-severity-high text-background",
  Medium: "bg-severity-medium text-background",
  Low: "bg-severity-low text-background",
}

const statusColors = {
  new: "bg-status-new text-white",
  acknowledged: "bg-status-acknowledged text-background",
  resolved: "bg-status-resolved text-background",
}

const statusLabels = {
  new: "New",
  acknowledged: "Acknowledged",
  resolved: "Resolved",
}

export function AlertDetailsDialog({ open, onOpenChange, alert }: AlertDetailsDialogProps) {
  const formatTimestamp = (timestamp: string) => {
    return new Date(timestamp).toLocaleString('en-US', {
      year: 'numeric',
      month: 'long',
      day: 'numeric',
      hour: '2-digit',
      minute: '2-digit',
      second: '2-digit',
      timeZoneName: 'short'
    })
  }

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent className="max-w-2xl max-h-[80vh] max-w-[90vw] overflow-y-auto custom-scrollbar">
        <DialogHeader>
          <DialogTitle className="flex items-center gap-2">
            <AlertTriangle className="h-5 w-5 text-destructive" />
            Alert Details
          </DialogTitle>
          <DialogDescription>
            Detailed information for alert ID: {alert.id}
          </DialogDescription>
        </DialogHeader>
        
        <div className="space-y-6">
          <div className="flex items-center gap-3">
            <Badge className={severityColors[alert.severity]}>
              {alert.severity}
            </Badge>
            <Badge variant="outline">
              {alert.rule_type}
            </Badge>
            <Badge className={statusColors[alert.status]}>
              {statusLabels[alert.status]}
            </Badge>
          </div>
          
          <div className="space-y-4">
            <div>
              <h4 className="text-sm font-semibold mb-2">Alert Message</h4>
              <p className="text-sm p-3 bg-muted rounded-lg">{alert.message}</p>
            </div>
            
            <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
              <div className="space-y-3">
                <h4 className="text-sm font-semibold">Event Information</h4>
                
                <div className="space-y-2 text-sm">
                  <div className="flex items-center gap-2">
                    <Calendar className="h-4 w-4 text-muted-foreground" />
                    <span className="text-muted-foreground">Timestamp:</span>
                  </div>
                  <p className="ml-6 font-mono text-xs">{formatTimestamp(alert.alert_time)}</p>
                  
                  <div className="flex items-center gap-2">
                    <Globe className="h-4 w-4 text-muted-foreground" />
                    <span className="text-muted-foreground">Source IP:</span>
                  </div>
                  <p className="ml-6 font-mono">{alert.ip}</p>
                  
                  {alert.host && (
                    <>
                      <div className="flex items-center gap-2">
                        <Server className="h-4 w-4 text-muted-foreground" />
                        <span className="text-muted-foreground">Hostname:</span>
                      </div>
                      <p className="ml-6 font-mono">{alert.host}</p>
                    </>
                  )}
                </div>
              </div>
              
              <div className="space-y-3">
                <h4 className="text-sm font-semibold">Detection Information</h4>
                
                <div className="space-y-2 text-sm">
                  <div className="flex items-center gap-2">
                    <FileText className="h-4 w-4 text-muted-foreground" />
                    <span className="text-muted-foreground">Log Source:</span>
                  </div>
                  <p className="ml-6">{alert.source}</p>
                  
                  <div className="flex items-center gap-2">
                    <Shield className="h-4 w-4 text-muted-foreground" />
                    <span className="text-muted-foreground">Detection Rule:</span>
                  </div>
                  <p className="ml-6">{alert.rule_name}</p>
                </div>
              </div>
            </div>
            
            <div>
              <h4 className="text-sm font-semibold mb-2">Additional Context</h4>
              <div className="p-3 bg-muted rounded-lg space-y-2 text-sm">
                <p><span className="text-muted-foreground">Alert Type:</span> {alert.rule_type}</p>
                <p><span className="text-muted-foreground">Severity Level:</span> {alert.severity}</p>
                <p><span className="text-muted-foreground">Current Status:</span> {statusLabels[alert.status]}</p>
                <p><span className="text-muted-foreground">Alert ID:</span> <code className="text-xs bg-background px-1 py-0.5 rounded">{alert.id}</code></p>
              </div>
            </div>
          </div>
        </div>
      </DialogContent>
    </Dialog>
  )
}