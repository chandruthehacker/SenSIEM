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
import { AlertCircle } from "lucide-react"
import axios from "axios"
import BackendConfig from "@/configs/config.json"
import {
  Dialog,
  DialogContent,
  DialogHeader,
  DialogTitle,
  DialogDescription,
  DialogFooter,
} from "@/components/ui/dialog"
import { Button } from "@/components/ui/button"
import clsx from "clsx"

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
  last_run: string | null
}

export default function DetectionRules() {
  const [rules, setRules] = useState<DetectionRule[]>([])
  const [loading, setLoading] = useState(true)
  const [disableConfirm, setDisableConfirm] = useState(false)
  const [pendingToggle, setPendingToggle] = useState<DetectionRule | null>(null)



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

  return (
    <>
      <Card className="shadow-md border border-border rounded-xl">
        <CardHeader className="relative">
          <CardTitle className="flex items-center gap-2 text-lg">
            <AlertCircle className="w-5 h-5 text-primary" />
            Detection Rules
          </CardTitle>
          <CardDescription>
            Enable or disable detection rules for different log types.
          </CardDescription>
          {!loading && (
            <div className="absolute top-6 right-6 text-lg text-primary px-4 font-semibold bg-muted px-2 py-1 rounded-md shadow">
              {rules.length} rule{rules.length !== 1 ? "s" : ""}
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
          ) : rules.length === 0 ? (
            <p className="text-sm italic text-muted-foreground">
              No detection rules available.
            </p>
          ) : (
            rules.map((rule) => (
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
                  <Switch
                    checked={rule.active}
                    onCheckedChange={(val) => onSwitchChange(rule, val)}
                  />
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

      {/* Confirmation Dialog */}
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
    </>
  )
}
