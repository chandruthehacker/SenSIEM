import { useState } from "react"
import { Button } from "@/components/ui/button"
import { Input } from "@/components/ui/input"
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select"
import { Badge } from "@/components/ui/badge"
import { Search, Filter, X, RefreshCw } from "lucide-react"

export interface FilterState {
  search: string
  status: string
  severity: string
  type: string
  sortBy: string
  sortOrder: "asc" | "desc"
}

interface AlertFiltersProps {
  filters: FilterState
  onFiltersChange: (filters: FilterState) => void
  onRefresh: () => void
  isLoading?: boolean
  alertCounts: {
    total: number
    new: number
    acknowledged: number
    resolved: number
  }
}

const statusOptions = [
  { value: "all", label: "All Status" },
  { value: "new", label: "New" },
  { value: "acknowledged", label: "Acknowledged" },
  { value: "resolved", label: "Resolved" },
]

const severityOptions = [
  { value: "all", label: "All Severity" },
  { value: "Critical", label: "Critical" },
  { value: "High", label: "High" },
  { value: "Medium", label: "Medium" },
  { value: "Low", label: "Low" },
]

const typeOptions = [
  { value: "all", label: "All Types" },
  { value: "Brute-force", label: "Brute-force" },
  { value: "Suspicious Login", label: "Suspicious Login" },
  { value: "Port Scan", label: "Port Scan" },
  { value: "Malware", label: "Malware" },
  { value: "DDoS", label: "DDoS" },
]

const sortOptions = [
  // ✅ FIX: Changed value to "alert_time" to match the alert object property
  { value: "alert_time", label: "Timestamp" }, 
  { value: "severity", label: "Severity" },
  { value: "status", label: "Status" },
  { value: "rule_type", label: "Type" },
]

export function AlertFilters({ filters, onFiltersChange, onRefresh, isLoading, alertCounts }: AlertFiltersProps) {
  const [showAdvancedFilters, setShowAdvancedFilters] = useState(false)

  const updateFilter = (key: keyof FilterState, value: string) => {
    onFiltersChange({ ...filters, [key]: value })
  }

  const clearFilters = () => {
    onFiltersChange({
      search: "",
      status: "all",
      severity: "all",
      type: "all",
      sortBy: "alert_time",
      sortOrder: "desc",
    })
  }

  const hasActiveFilters = filters.search || filters.status !== "all" || filters.severity !== "all" || filters.type !== "all"

  return (
    <div className="space-y-4">
      {/* Summary Stats */}
      <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
        <div className="bg-gradient-card p-4 rounded-lg border border-border">
          <div className="text-2xl font-bold text-foreground">{alertCounts.total}</div>
          <div className="text-sm text-muted-foreground">Total Alerts</div>
        </div>
        <div className="bg-gradient-card p-4 rounded-lg border border-border">
          <div className="text-2xl font-bold text-status-new">{alertCounts.new}</div>
          <div className="text-sm text-muted-foreground">New</div>
        </div>
        <div className="bg-gradient-card p-4 rounded-lg border border-border">
          <div className="text-2xl font-bold text-status-acknowledged">{alertCounts.acknowledged}</div>
          <div className="text-sm text-muted-foreground">Acknowledged</div>
        </div>
        <div className="bg-gradient-card p-4 rounded-lg border border-border">
          <div className="text-2xl font-bold text-status-resolved">{alertCounts.resolved}</div>
          <div className="text-sm text-muted-foreground">Resolved</div>
        </div>
      </div>

      {/* Main Filters */}
      <div className="flex flex-col md:flex-row gap-4">
        <div className="relative flex-1">
          <Search className="absolute left-3 top-1/2 transform -translate-y-1/2 h-4 w-4 text-muted-foreground" />
          <Input
            placeholder="Search alerts by message, IP, hostname..."
            value={filters.search}
            onChange={(e) => updateFilter("search", e.target.value)}
            className="pl-9"
          />
        </div>
        
        <div className="flex gap-2">
          <Select value={filters.status} onValueChange={(value) => updateFilter("status", value)}>
            <SelectTrigger className="w-40">
              <SelectValue />
            </SelectTrigger>
            <SelectContent>
              {statusOptions.map((option) => (
                <SelectItem key={option.value} value={option.value}>
                  {option.label}
                </SelectItem>
              ))}
            </SelectContent>
          </Select>

          <Button
            variant="outline"
            size="icon"
            onClick={() => setShowAdvancedFilters(!showAdvancedFilters)}
            className={showAdvancedFilters ? "bg-accent" : ""}
          >
            <Filter className="h-4 w-4" />
          </Button>

          <Button
            variant="outline"
            size="icon"
            onClick={onRefresh}
            disabled={isLoading}
          >
            <RefreshCw className={`h-4 w-4 ${isLoading ? "animate-spin" : ""}`} />
          </Button>
        </div>
      </div>

      {/* Advanced Filters */}
      {showAdvancedFilters && (
        <div className="grid grid-cols-1 md:grid-cols-3 gap-4 p-4 bg-muted/30 rounded-lg border border-border">
          <Select value={filters.severity} onValueChange={(value) => updateFilter("severity", value)}>
            <SelectTrigger>
              <SelectValue placeholder="Severity" />
            </SelectTrigger>
            <SelectContent>
              {severityOptions.map((option) => (
                <SelectItem key={option.value} value={option.value}>
                  {option.label}
                </SelectItem>
              ))}
            </SelectContent>
          </Select>

          <Select value={filters.type} onValueChange={(value) => updateFilter("type", value)}>
            <SelectTrigger>
              <SelectValue placeholder="Alert Type" />
            </SelectTrigger>
            <SelectContent>
              {typeOptions.map((option) => (
                <SelectItem key={option.value} value={option.value}>
                  {option.label}
                </SelectItem>
              ))}
            </SelectContent>
          </Select>

          <div className="flex gap-2">
            <Select value={filters.sortBy} onValueChange={(value) => updateFilter("sortBy", value)}>
              <SelectTrigger className="flex-1">
                <SelectValue placeholder="Sort by" />
              </SelectTrigger>
              <SelectContent>
                {sortOptions.map((option) => (
                  <SelectItem key={option.value} value={option.value}>
                    {option.label}
                  </SelectItem>
                ))}
              </SelectContent>
            </Select>

            <Button
              variant="outline"
              size="sm"
              onClick={() => updateFilter("sortOrder", filters.sortOrder === "asc" ? "desc" : "asc")}
              className="px-3"
            >
              {filters.sortOrder === "asc" ? "↑" : "↓"}
            </Button>
          </div>
        </div>
      )}

      {/* Active Filters */}
      {hasActiveFilters && (
        <div className="flex items-center gap-2 flex-wrap">
          <span className="text-sm text-muted-foreground">Active filters:</span>
          {filters.search && (
            <Badge variant="secondary" className="gap-1">
              Search: "{filters.search}"
              <X className="h-3 w-3 cursor-pointer" onClick={() => updateFilter("search", "")} />
            </Badge>
          )}
          {filters.status !== "all" && (
            <Badge variant="secondary" className="gap-1">
              Status: {filters.status}
              <X className="h-3 w-3 cursor-pointer" onClick={() => updateFilter("status", "all")} />
            </Badge>
          )}
          {filters.severity !== "all" && (
            <Badge variant="secondary" className="gap-1">
              Severity: {filters.severity}
              <X className="h-3 w-3 cursor-pointer" onClick={() => updateFilter("severity", "all")} />
            </Badge>
          )}
          {filters.type !== "all" && (
            <Badge variant="secondary" className="gap-1">
              Type: {filters.type}
              <X className="h-3 w-3 cursor-pointer" onClick={() => updateFilter("type", "all")} />
            </Badge>
          )}
          <Button variant="ghost" size="sm" onClick={clearFilters} className="h-6 px-2 text-xs">
            Clear all
          </Button>
        </div>
      )}
    </div>
  )
}