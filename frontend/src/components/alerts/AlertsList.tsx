import { useState, useEffect } from "react"
import { AlertCard, Alert } from "./AlertCard"
import { AlertFilters, FilterState } from "./AlertFilters"
import { Button } from "@/components/ui/button"
import { Loader2, AlertCircle } from "lucide-react"
import { useToast } from "@/hooks/use-toast"
import backendConfig from "@/configs/config.json";
import axios from "axios"

// Mock data - replace with actual API calls
// const mockAlerts: Alert[] = [
//   {
//     id: "ALT-2025-001",
//     timestamp: "2025-07-28T14:23:00Z",
//     severity: "Critical",
//     type: "Brute-force",
//     message: "Multiple failed SSH login attempts detected from external IP. 15 failed attempts in 2 minutes.",
//     ip: "192.168.1.100",
//     host: "kali.local",
//     source: "auth.log",
//     status: "new",
//     rule: "SSH Brute-force Detector"
//   },
//   {
//     id: "ALT-2025-002",
//     timestamp: "2025-07-28T14:18:00Z",
//     severity: "High",
//     type: "Suspicious Login",
//     message: "Login from unusual geographic location detected for user admin.",
//     ip: "203.0.113.42",
//     host: "web-server-01",
//     source: "access.log",
//     status: "acknowledged",
//     rule: "Geographic Anomaly Detection"
//   },
//   {
//     id: "ALT-2025-003",
//     timestamp: "2025-07-28T14:15:00Z",
//     severity: "Medium",
//     type: "Port Scan",
//     message: "Port scanning activity detected from external source targeting multiple services.",
//     ip: "198.51.100.25",
//     source: "firewall.log",
//     status: "resolved",
//     rule: "Port Scan Detection"
//   },
//   {
//     id: "ALT-2025-004",
//     timestamp: "2025-07-28T14:10:00Z",
//     severity: "High",
//     type: "Malware",
//     message: "Malicious file detected in email attachment. Hash matches known threat database.",
//     ip: "172.16.0.50",
//     host: "mail-server",
//     source: "antivirus.log",
//     status: "new",
//     rule: "Malware Hash Detection"
//   },
//   {
//     id: "ALT-2025-005",
//     timestamp: "2025-07-28T14:05:00Z",
//     severity: "Low",
//     type: "Suspicious Login",
//     message: "Multiple login attempts from same IP within short timeframe.",
//     ip: "10.0.0.15",
//     host: "internal-workstation",
//     source: "auth.log",
//     status: "acknowledged",
//     rule: "Login Frequency Monitor"
//   },
// ]

export function AlertsList() {
  const [alerts, setAlerts] = useState<Alert[]>([])
  const [filteredAlerts, setFilteredAlerts] = useState<Alert[]>([])
  const [isLoading, setIsLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)
  const { toast } = useToast()
  
  const [filters, setFilters] = useState<FilterState>({
    search: "",
    status: "all",
    severity: "all",
    type: "all",
    sortBy: "alert_time",   // ✅ shows latest first
    sortOrder: "desc",     // ✅ descending order
  })

  // Simulate API call
  const fetchAlerts = async () => {
    setIsLoading(true);
    try {
      const response = await axios.get(`${backendConfig.apiUrl}/get-alerts`);
      
      const alerts = Array.isArray(response.data) ? response.data : [];

      console.log("Fetched alerts:", alerts);

      await new Promise(resolve => setTimeout(resolve, 800));

      if (response.status !== 200 || alerts.length === 0) {
        setAlerts([]); // fallback to empty
        toast({
          title: "No Alerts",
          description: "No alerts found or failed to retrieve data.",
          variant: "default", // or "destructive" if you prefer
        });
      } else {
        setAlerts(alerts); // ✅ Use backend alerts
      }

      setError(null);
    } catch (err) {
      console.error("Error fetching alerts:", err);
      setAlerts([]); // fallback to empty
      setError("Failed to fetch alerts");
      toast({
        title: "Error",
        description: "Failed to fetch alerts. Please try again.",
        variant: "destructive",
      });
    } finally {
      setIsLoading(false);
    }
  };



  // Filter and sort alerts
  useEffect(() => {
    let filtered = [...alerts]

    // Apply filters
    if (filters.search) {
      const searchLower = filters.search.toLowerCase()
      filtered = filtered.filter(alert =>
        alert.message.toLowerCase().includes(searchLower) ||
        alert.ip.includes(searchLower) ||
        alert.host?.toLowerCase().includes(searchLower) ||
        alert.rule_type.toLowerCase().includes(searchLower)
      )
    }

    if (filters.status !== "all") {
      filtered = filtered.filter(alert => alert.status === filters.status)
    }

    if (filters.severity !== "all") {
      filtered = filtered.filter(alert => alert.severity === filters.severity)
    }

    if (filters.type !== "all") {
      filtered = filtered.filter(alert => alert.rule_type === filters.type)
    }

    // Apply sorting
    filtered.sort((a, b) => {
      let aValue: any;
      let bValue: any;

      if (filters.sortBy === "alert_time") {
        // ✅ FIX: Use 'alert_time' property for sorting by timestamp
        aValue = new Date(a.alert_time).getTime();
        bValue = new Date(b.alert_time).getTime();
      } else if (filters.sortBy === "severity") {
        const severityOrder = { Critical: 4, High: 3, Medium: 2, Low: 1 };
        aValue = severityOrder[a.severity as keyof typeof severityOrder];
        bValue = severityOrder[b.severity as keyof typeof severityOrder];
      } else {
        // For other string-based sorts
        const aProp = a[filters.sortBy as keyof Alert] ?? "";
        const bProp = b[filters.sortBy as keyof Alert] ?? "";
        aValue = String(aProp).toLowerCase();
        bValue = String(bProp).toLowerCase();
      }

      // Correctly handle comparison for asc/desc order
      if (filters.sortOrder === "asc") {
        return aValue > bValue ? 1 : aValue < bValue ? -1 : 0;
      } else {
        return aValue < bValue ? 1 : aValue > bValue ? -1 : 0;
      }
    });


    setFilteredAlerts(filtered)
  }, [alerts, filters])

  // Calculate alert counts
  const alertCounts = {
    total: alerts.length,
    new: alerts.filter(a => a.status === "new").length,
    acknowledged: alerts.filter(a => a.status === "acknowledged").length,
    resolved: alerts.filter(a => a.status === "resolved").length,
  }

const handleAcknowledge = async (id: number) => {
  try {
    const res = await fetch(`${backendConfig.apiUrl}/alerts/${id}/acknowledge`, {
      method: "POST",
    });

    if (!res.ok) throw new Error("Acknowledge failed");

    setAlerts(prev =>
      prev.map(alert =>
        alert.id === id ? { ...alert, status: "acknowledged" as const } : alert
      )
    );

    toast({
      title: "Alert Acknowledged",
      description: `Alert ${id} has been acknowledged successfully.`,
    });
  } catch (err) {
    toast({
      title: "Error",
      description: "Failed to acknowledge alert. Please try again.",
      variant: "destructive",
    });
  }
};

const handleResolve = async (id: number) => {
  try {
    const res = await fetch(`${backendConfig.apiUrl}/alerts/${id}/resolve`, {
      method: "POST",
    });

    if (!res.ok) throw new Error("Resolve failed");

    setAlerts(prev =>
      prev.map(alert =>
        alert.id === id ? { ...alert, status: "resolved" as const } : alert
      )
    );

    toast({
      title: "Alert Resolved",
      description: `Alert ${id} has been resolved successfully.`,
    });
  } catch (err) {
    toast({
      title: "Error",
      description: "Failed to resolve alert. Please try again.",
      variant: "destructive",
    });
  }
};


  useEffect(() => {
    fetchAlerts()
  }, [])

  if (error && !alerts.length) {
    return (
      <div className="flex flex-col items-center justify-center h-96 space-y-4">
        <AlertCircle className="h-12 w-12 text-destructive" />
        <div className="text-center">
          <h3 className="text-lg font-semibold">Error Loading Alerts</h3>
          <p className="text-muted-foreground">{error}</p>
          <Button onClick={fetchAlerts} className="mt-4">
            Try Again
          </Button>
        </div>
      </div>
    )
  }

  return (
    <div className="space-y-6">
      <AlertFilters
        filters={filters}
        onFiltersChange={setFilters}
        onRefresh={fetchAlerts}
        isLoading={isLoading}
        alertCounts={alertCounts}
      />

      {isLoading && !alerts.length ? (
        <div className="flex items-center justify-center h-96">
          <div className="flex items-center space-x-2">
            <Loader2 className="h-6 w-6 animate-spin" />
            <span>Loading alerts...</span>
          </div>
        </div>
      ) : filteredAlerts.length === 0 ? (
        <div className="text-center py-12">
          <AlertCircle className="h-12 w-12 text-muted-foreground mx-auto mb-4" />
          <h3 className="text-lg font-semibold">No alerts found</h3>
          <p className="text-muted-foreground">
            {alerts.length === 0 
              ? "No alerts have been detected yet." 
              : "No alerts match your current filters."}
          </p>
        </div>
      ) : (
        <div className="space-y-4">
          <div className="flex justify-between items-center">
            <h3 className="text-lg font-semibold">
              {filteredAlerts.length} Alert{filteredAlerts.length !== 1 ? 's' : ''}
            </h3>
            {isLoading && (
              <div className="flex items-center space-x-2 text-sm text-muted-foreground">
                <Loader2 className="h-4 w-4 animate-spin" />
                <span>Refreshing...</span>
              </div>
            )}
          </div>
          
          <div className="grid gap-6">
            {filteredAlerts.map((alert) => (
              <AlertCard
                key={alert.id}
                alert={alert}
                onAcknowledge={handleAcknowledge}
                onResolve={handleResolve}
              />
            ))}
          </div>
        </div>
      )}
    </div>
  )
}