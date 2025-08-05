"use client"

import { useEffect, useState, useRef } from "react"
import {
  Card,
  CardHeader,
  CardTitle,
  CardDescription,
  CardContent,
} from "@/components/ui/card"
import { Switch } from "@/components/ui/switch"
import { Badge } from "@/components/ui/badge"
import { AlertCircle, PencilIcon } from "lucide-react" // Import PencilIcon
import axios from "axios"
import BackendConfig from "@/configs/config.json" // Ensure this path is correct
import {
  Dialog,
  DialogContent,
  DialogHeader,
  DialogTitle,
  DialogDescription,
  DialogFooter,
} from "@/components/ui/dialog"
import { Button } from "@/components/ui/button"
import { Input } from "@/components/ui/input" // Assuming you have an Input component
import clsx from "clsx"

// Import Select components from your UI library
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select"

interface DetectionRule {
  id: number
  name: string
  description: string
  rule_type: string
  log_type: string
  condition: string
  threshold: number
  time_window: number
  interval_minutes: number
  active: boolean
  last_run_id: number | null // Corrected type based on your data
  created_at: string // Corrected type based on your data
}

export default function DetectionRules() {
  const [rules, setRules] = useState<DetectionRule[]>([])
  const [loading, setLoading] = useState(true)
  const [disableConfirm, setDisableConfirm] = useState(false)
  const [pendingToggle, setPendingToggle] = useState<DetectionRule | null>(null)
  // New state to hold the selected log type filter
  const [selectedLogType, setSelectedLogType] = useState("all")

  // New states for the edit dialog
  const [editDialogOpen, setEditDialogOpen] = useState(false)
  const [editingRule, setEditingRule] = useState<DetectionRule | null>(null)
  const [editedThreshold, setEditedThreshold] = useState<number>(0)
  const [editedIntervalMinutes, setEditedIntervalMinutes] = useState<number>(0)

  useEffect(() => {
    fetchRules()
  }, [])

  const fetchRules = async () => {
    try {
      const res = await axios.get(`${BackendConfig.apiUrl}/detection-rules`)
      setRules(res.data)
    } catch (err) {
      console.error("Error fetching rules", err)
    } finally {
      setLoading(false)
    }
  }

  const toggleRule = async (id: number, active: boolean) => {
    try {
      await axios.patch(`${BackendConfig.apiUrl}/detection-rules/${id}`, { active })
      setRules((prev) =>
        prev.map((r) => (r.id === id ? { ...r, active } : r))
      )
    } catch (err) {
      console.error("Failed to toggle rule", err)
    }
  }

  const onSwitchChange = (rule: DetectionRule, checked: boolean) => {
    if (!checked) {
      setPendingToggle(rule)
      setDisableConfirm(true)
    } else {
      toggleRule(rule.id, checked)
    }
  }

  const confirmDisable = () => {
    if (pendingToggle) {
      toggleRule(pendingToggle.id, false)
      setDisableConfirm(false)
      setPendingToggle(null)
    }
  }

  // Handler for opening the edit dialog
  const handleEditClick = (rule: DetectionRule) => {
    setEditingRule(rule)
    setEditedThreshold(rule.threshold)
    setEditedIntervalMinutes(rule.interval_minutes)
    setEditDialogOpen(true)
  }

  // Handler for saving changes from the edit dialog
  const handleSaveEdit = async () => {
    if (!editingRule) return;

    // Check if any changes were actually made before saving
    if (editedThreshold === editingRule.threshold && editedIntervalMinutes === editingRule.interval_minutes) {
        setEditDialogOpen(false); // Close dialog if no changes
        setEditingRule(null);
        return;
    }

    try {
      await axios.patch(`${BackendConfig.apiUrl}/detection-rules/${editingRule.id}`, {
        threshold: editedThreshold,
        interval_minutes: editedIntervalMinutes,
      });
      setEditDialogOpen(false);
      setEditingRule(null);
      fetchRules(); // Re-fetch rules to show updated values
    } catch (err) {
      console.error("Failed to update rule parameters", err);
      // Optionally, add user-facing error feedback here
    }
  };


  // Filter rules based on the selected log type
  const filteredRules = selectedLogType === "all"
    ? rules
    : rules.filter((rule) => rule.log_type === selectedLogType);


  return (
    <>
      <Card className="shadow-md border border-border rounded-xl">
        <CardHeader className="relative">
          <CardTitle className="flex items-center gap-2 text-lg">
            <AlertCircle className="w-5 h-5 text-primary" />
            Detection Rules
          </CardTitle>
          <CardDescription className="flex items-center gap-4">
            <span>
              Enable or disable detection rules for different log types.
            </span>
            {/* Log type filter dropdown */}
            <Select onValueChange={setSelectedLogType} defaultValue="all">
              <SelectTrigger className="w-[180px]">
                <SelectValue placeholder="Filter by log type" />
              </SelectTrigger>
              <SelectContent>
                {/* All Option */}
                <SelectItem value="all" className="hover:bg-gray-700 hover:cursor-pointer">All Log Types</SelectItem>

                {/* System Logs */}
                <SelectItem value="auth.log" className="hover:bg-gray-700 hover:cursor-pointer">Auth Log</SelectItem>
                <SelectItem value="syslog" className="hover:bg-gray-700 hover:cursor-pointer">Syslog</SelectItem>
                <SelectItem value="windows_event" className="hover:bg-gray-700 hover:cursor-pointer">Windows Event Logs</SelectItem>

                {/* Web Server Logs */}
                <SelectItem value="apache" className="hover:bg-gray-700 hover:cursor-pointer">Apache Log</SelectItem>
                <SelectItem value="nginx" className="hover:bg-gray-700 hover:cursor-pointer">Nginx Log</SelectItem>
                <SelectItem value="waf" className="hover:bg-gray-700 hover:cursor-pointer">Web Application Firewall Log</SelectItem>

                {/* Network & Security Logs */}
                <SelectItem value="antivirus" className="hover:bg-gray-700 hover:cursor-pointer">Antivirus Log</SelectItem>
                <SelectItem value="dns" className="hover:bg-gray-700 hover:cursor-pointer">DNS Logs</SelectItem>
                <SelectItem value="firewall" className="hover:bg-gray-700 hover:cursor-pointer">Firewall Log</SelectItem>
                <SelectItem value="ids_ips" className="hover:bg-gray-700 hover:cursor-pointer">IDS/IPS Log</SelectItem>
                <SelectItem value="proxy" className="hover:bg-gray-700 hover:cursor-pointer">Proxy Log</SelectItem>
                <SelectItem value="vpn" className="hover:bg-gray-700 hover:cursor-pointer">VPN Log</SelectItem>
                <SelectItem value="zeek" className="hover:bg-gray-700 hover:cursor-pointer">Zeek Log</SelectItem>

                {/* Application & Cloud Logs */}
                <SelectItem value="cloud" className="hover:bg-gray-700 hover:cursor-pointer">Cloud Log</SelectItem>
                <SelectItem value="database" className="hover:bg-gray-700 hover:cursor-pointer">Database Log</SelectItem>
                <SelectItem value="email" className="hover:bg-gray-700 hover:cursor-pointer">Email Log</SelectItem>
              </SelectContent>

            </Select>
          </CardDescription>

          {!loading && (
            <div className="absolute top-6 right-6 text-lg text-primary px-4 font-semibold bg-muted px-2 py-1 rounded-md shadow">
              {filteredRules.length} rule{filteredRules.length !== 1 ? "s" : ""}
            </div>
          )}
        </CardHeader>

        <CardContent
            className={clsx(
              "relative space-y-4 max-h-[400px] overflow-y-auto px-6 pt-4",
              "scrollbar-thin scrollbar-thumb-primary scrollbar-track-transparent scroll-smooth",
              "border-t border-border"
            )}
          >
          {loading ? (
            <p className="text-sm text-muted-foreground">Loading...</p>
          ) : filteredRules.length === 0 ? (
            <p className="text-sm italic text-muted-foreground">
              No detection rules available for the selected log type.
            </p>
          ) : (
            filteredRules.map((rule) => (
              <div
                key={rule.id}
                className="border border-zinc-700 bg-gradient-to-l from-gray-900 to-zinc-950 rounded-xl p-4 space-y-2 shadow-md"
              >
                <div className="flex justify-between items-center">
                  <div>
                    <h4 className="font-semibold text-md">{rule.name}</h4>
                    <p className="text-sm text-muted-foreground">
                      {rule.description}
                    </p>
                  </div>
                  <div className="flex items-center space-x-4"> {/* Added a div for alignment */}
                    <Button
                      variant="ghost"
                      size="sm" // Changed from "icon"
                      onClick={() => handleEditClick(rule)}
                      className="inline-flex items-center px-3 py-1 space-x-1 bg-zinc-800 hover:bg-zinc-700 rounded-xl" // Added bg-zinc-800 and rounded-md
                      aria-label="Edit rule"
                    >
                      <span>Edit</span> <PencilIcon className="w-4 h-4" />
                    </Button>
                    <Switch
                      checked={rule.active}
                      onCheckedChange={(val) => onSwitchChange(rule, val)}
                    />
                  </div>
                </div>
                <div className="text-sm text-muted-foreground flex flex-wrap gap-2 mt-2">
                  <Badge variant="secondary">{rule.log_type}</Badge>
                  <Badge variant="outline">{rule.rule_type}</Badge>
                  <Badge variant="default">
                    Every {rule.interval_minutes} min
                  </Badge>
                </div>
              </div>
            ))
          )}
        </CardContent>
      </Card>

      {/* Confirmation Dialog for Disable */}
      <Dialog open={disableConfirm} onOpenChange={setDisableConfirm}>
        <DialogContent>
          <DialogHeader>
            <DialogTitle>Disable Detection Rule?</DialogTitle>
            <DialogDescription>
              Are you sure you want to disable "{pendingToggle?.name}"? It will
              stop monitoring this activity.
            </DialogDescription>
          </DialogHeader>
          <DialogFooter className="gap-2">
            <Button variant="outline" onClick={() => setDisableConfirm(false)}>
              Cancel
            </Button>
            <Button variant="destructive" onClick={confirmDisable}>
              Disable
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>

      {/* Edit Rule Dialog */}
      <Dialog open={editDialogOpen} onOpenChange={setEditDialogOpen}>
        <DialogContent className="max-w-[90vw] sm:max-w-[600px] max-h-[80vh] overflow-y-auto custom-scrollbar">
          <DialogHeader>
            <DialogTitle>Edit Detection Rule</DialogTitle>
            <DialogDescription>
              Make changes to the rule's parameters. Click save when you're done.
            </DialogDescription>
          </DialogHeader>

          {editingRule && (
            <div className="grid gap-4 py-4">
              <div className="grid grid-cols-4 items-center gap-4">
                <label htmlFor="name" className="text-right">Name</label>
                <Input id="name" defaultValue={editingRule.name} className="col-span-3" readOnly disabled />
              </div>

              <div className="grid grid-cols-4 items-center gap-4">
                <label htmlFor="description" className="text-right">Description</label>
                <Input id="description" defaultValue={editingRule.description} className="col-span-3" readOnly disabled />
              </div>

              <div className="grid grid-cols-4 items-center gap-4">
                <label htmlFor="rule_type" className="text-right">Rule Type</label>
                <Input id="rule_type" defaultValue={editingRule.rule_type} className="col-span-3" readOnly disabled />
              </div>

              <div className="grid grid-cols-4 items-center gap-4">
                <label htmlFor="log_type" className="text-right">Log Type</label>
                <Input id="log_type" defaultValue={editingRule.log_type} className="col-span-3" readOnly disabled />
              </div>

              <div className="grid grid-cols-4 items-center gap-4">
                <label htmlFor="condition" className="text-right">Condition</label>
                <Input id="condition" defaultValue={editingRule.condition} className="col-span-3" readOnly disabled />
              </div>

              <div className="grid grid-cols-4 items-center gap-4">
                <label htmlFor="threshold" className="text-right">Threshold</label>
                <Input
                  id="threshold"
                  type="number"
                  value={editedThreshold}
                  onChange={(e) => setEditedThreshold(parseInt(e.target.value))}
                  className="col-span-3"
                />
              </div>

              <div className="grid grid-cols-4 items-center gap-4">
                <label htmlFor="interval_minutes" className="text-right">Interval (min)</label>
                <Input
                  id="interval_minutes"
                  type="number"
                  value={editedIntervalMinutes}
                  onChange={(e) => setEditedIntervalMinutes(parseInt(e.target.value))}
                  className="col-span-3"
                />
              </div>
            </div>
          )}

          <DialogFooter className="gap-2">
            <Button variant="outline" onClick={() => setEditDialogOpen(false)}>
              Cancel
            </Button>
            <Button
              onClick={handleSaveEdit}
              disabled={
                !editingRule ||
                isNaN(editedThreshold) ||
                isNaN(editedIntervalMinutes) ||
                (editedThreshold === editingRule.threshold &&
                  editedIntervalMinutes === editingRule.interval_minutes)
              }
            >
              Save changes
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>

    </>
  )
}
