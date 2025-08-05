import { useEffect, useState } from "react";
import { FileText, Search, Filter, Eye, Download, RefreshCw } from "lucide-react";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import axios from "axios";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import Layout from "@/components/layout/Layout";

import backendConfig from "@/configs/config.json";

interface LogEntry {
  id?: string | number;
  timestamp: string;
  level: string;
  message: string;
  host?: string;
  file_path?: string;
  username?: string;
  process?: string;
  from_host?: string;
  type: string;
  raw_log: string;
  pid?: string | number;
  metadata?: Record<string, string | number>;
}


const Logs = () => {
  const [currentPage, setCurrentPage] = useState(1);
  const [searchTerm, setSearchTerm] = useState("");
  const [logs, setLogs] = useState<LogEntry[]>([]);
  const [selectedLog, setSelectedLog] = useState<LogEntry | null>(null);
  const [isRefreshing, setIsRefreshing] = useState(false);

  const itemsPerPage = 100;

  async function fetchLogs() {
    try {
      const res = await axios.get(`${backendConfig.apiUrl}/get-logs`);
      const logsWithMetadata = res.data.logs.map((log) => ({
        ...log,
        level: log.log_level ?? log.level ?? "INFO",
        metadata: {
          host: log.host,
          username: log.username,
          file_path: log.file_path,
          process: log.process,
          from_host: log.from_host,
          source_IP: log.src_ip,
          destination_IP: log.dest_ip,
          status_code: log.status_code,
          url: log.url,
          method: log.method,
          protocol: log.protocol,
          action: log.action,
          user_agent: log.user_agent,
          device: log.device,
          mail_subject: log.mail_subject,
          file_hash: log.file_hash,
          tags: log.tags
        },
      }));
      setLogs(logsWithMetadata);
    } catch (err) {
      console.error("Failed to fetch logs", err);
    }
  }

  useEffect(() => {
    fetchLogs();
  }, []);

  const filteredLogs = logs.filter((log) =>
    log.message.toLowerCase().includes(searchTerm.toLowerCase()) ||
    log.type.toLowerCase().includes(searchTerm.toLowerCase())
  );

  const totalPages = Math.ceil(filteredLogs.length / itemsPerPage);
  const startIndex = (currentPage - 1) * itemsPerPage;
  const currentLogs = filteredLogs.slice(startIndex, startIndex + itemsPerPage);

  const handleRefresh = async () => {
    setIsRefreshing(true);
    try {
      await fetchLogs();
      await new Promise((res) => setTimeout(res, 1000));
    } finally {
      setIsRefreshing(false);
    }
  };

  return (
    <Layout>
      <div className="p-6 space-y-6 animate-fade-in">
        {/* Header */}
        <div className="flex items-center justify-between">
          <div>
            <h1 className="text-3xl font-bold text-foreground">Log Viewer</h1>
            <p className="text-muted-foreground">Browse and analyze system logs in real-time</p>
          </div>
          <div className="flex gap-3">
            <Button variant="outline" size="sm">
              <Download className="w-4 h-4 mr-2" />
              Export
            </Button>
            <Button variant="outline" size="sm" onClick={handleRefresh}>
                <RefreshCw
                  className={`w-4 h-4 mr-2 transition-transform ${
                    isRefreshing ? "animate-spin" : ""
                  }`}
                />
                Refresh
              </Button>
          </div>
        </div>

        {/* Search and Filters */}
        <Card>
          <CardHeader>
            <CardTitle className="flex items-center gap-2">
              <Search className="w-5 h-5" />
              Search & Filter Logs
            </CardTitle>
          </CardHeader>
          <CardContent>
            <div className="flex gap-4">
              <div className="flex-1">
                <Input
                  placeholder="Search logs by message or source..."
                  value={searchTerm}
                  onChange={(e) => setSearchTerm(e.target.value)}
                />
              </div>
              {/* Future filters can go here */}
            </div>
          </CardContent>
        </Card>

        {/* Logs List */}
        <Card>
          <CardHeader>
            <CardTitle className="flex items-center justify-between">
              <div className="flex items-center gap-2">
                <FileText className="w-5 h-5" />
                Log Entries
              </div>
              <Badge variant="outline" className="flex text-primary border-primary text-sm px-5 gap-2">
                <span className="text-white text-lg font-bold font-mono">{filteredLogs.length}</span> total logs
              </Badge>
            </CardTitle>
          </CardHeader>
          <CardContent>
            <div className="space-y-4">
              {currentLogs.map((log) => (
                <div
                  key={log.id ?? `${log.timestamp}-${log.message.slice(0, 20)}`}
                  className="p-4 rounded-2xl border border-border bg-gradient-to-br from-muted/50 to-background hover:from-primary/10 hover:to-primary/30 transition-all duration-300 cursor-pointer group shadow-sm hover:shadow-md"
                  onClick={() => setSelectedLog(log)}
                >
                  <div className="flex items-start justify-between">
                    <div className="flex-1 space-y-3">
                      <div className="flex items-center gap-4 flex-wrap">
                        <Badge
                          className={`text-xs px-3 py-1 rounded-full font-semibold tracking-wide shadow-sm transition-colors duration-300
                            ${log.level === "ERROR"
                              ? "bg-red-600 text-white hover:bg-red-700"
                              : log.level === "WARNING"
                              ? "bg-yellow-400 text-black hover:bg-yellow-500"
                              : log.level === "CRITICAL"
                              ? "bg-purple-600 text-white hover:bg-purple-700"
                              : log.level === "ALERT"
                              ? "bg-orange-600 text-white hover:bg-orange-700"
                              : "bg-green-500 text-black hover:bg-green-600"}`}
                        >
                          {log.level}
                        </Badge>
                        <span className="text-xs text-muted-foreground font-mono group-hover:text-foreground transition-colors">
                          {new Date(log.timestamp).toLocaleString()}
                        </span>
                        {log.pid && (
                          <span className="text-xs text-muted-foreground group-hover:text-foreground transition-colors">
                            PID: {log.pid}
                          </span>
                        )}
                        <span className="text-xs text-primary group-hover:text-foreground transition-colors">
                          {log.type}
                        </span>

                        <span className="text-xs text-primary group-hover:text-foreground transition-colors">
                          Log ID: {log.id}
                        </span>
                      </div>
                      <p className="text-md font-mono text-foreground group-hover:text-white transition-colors line-clamp-3">
                        {log.message}
                      </p>
                    </div>
                    <Eye className="w-4 h-4 text-muted-foreground group-hover:text-foreground transition-colors" />
                  </div>
                </div>
              ))}
            </div>

            {/* Pagination */}
            <div className="flex items-center justify-between mt-6">
              <div className="text-sm text-muted-foreground">
                Showing {startIndex + 1} to {Math.min(startIndex + itemsPerPage, filteredLogs.length)} of {filteredLogs.length} logs
              </div>
              <div className="flex gap-2">
                <Button
                  variant="outline"
                  size="sm"
                  onClick={() => setCurrentPage((prev) => Math.max(1, prev - 1))}
                  disabled={currentPage === 1}
                >
                  Previous
                </Button>
                <Button
                  variant="outline"
                  size="sm"
                  onClick={() => setCurrentPage((prev) => Math.min(totalPages, prev + 1))}
                  disabled={currentPage === totalPages}
                >
                  Next
                </Button>
              </div>
            </div>
          </CardContent>
        </Card>

        {/* Log Detail Modal */}
        {selectedLog && (
          <Card className="fixed inset-0 z-50 m-6 max-h-[90vh] max-w-[95vw] mx-auto overflow-y-auto animate-fade-in bg-background shadow-xl">
            <CardHeader>
              <div className="flex items-center justify-between">
                <CardTitle className="flex items-center gap-2">
                  <FileText className="w-5 h-5" />
                  Log Details
                </CardTitle>
                <Button variant="outline" size="sm" onClick={() => setSelectedLog(null)} style={{ backgroundColor: "#9e0000ff" }}>
                  Close
                </Button>
              </div>
            </CardHeader>
            <CardContent className="space-y-6">
              <div className="grid grid-cols-2 gap-4">
                <div>
                  <h4 className="font-semibold text-foreground mb-2">Basic Information</h4>
                  <div className="space-y-2 text-sm">
                    <div className="flex justify-between">
                      <span className="text-muted-foreground">Timestamp:</span>
                      <span className="font-mono">{selectedLog.timestamp}</span>
                    </div>
                    <div className="flex justify-between">
                      <span className="text-muted-foreground">Level:</span>
                        <span
                          className={`text-xs px-3 py-1 rounded-full font-bold antialiased
                            ${
                              selectedLog.level === "ERROR"
                                ? "bg-red-600 text-white hover:bg-red-700"
                                : selectedLog.level  === "WARNING"
                                ? "bg-yellow-400 text-black hover:bg-yellow-500"
                                : selectedLog.level  === "CRITICAL"
                                ? "bg-purple-600 text-white hover:bg-purple-700"
                                : selectedLog.level  === "ALERT"
                                ? "bg-orange-600 text-white hover:bg-orange-700"
                                : "bg-green-500 text-black hover:bg-gray-400"
                            }`}
                        >
                          {selectedLog.level}
                        </span>
                    </div>
                    <div className="flex justify-between">
                      <span className="text-muted-foreground">Source:</span>
                      <span className="font-mono">{selectedLog.type}</span>
                    </div>
                    {selectedLog.pid && (
                      <div className="flex justify-between">
                        <span className="text-muted-foreground">PID:</span>
                        <span className="font-mono">{selectedLog.pid}</span>
                      </div>
                    )}
                  </div>
                </div>
                <div>
                  <h4 className="font-semibold text-foreground mb-2">Metadata</h4>
                  <div className="space-y-2 text-sm">
                    {selectedLog.metadata ? (
                      Object.entries(selectedLog.metadata).filter(([_, value]) => value != null).map(([key, value]) => (
                        <div key={key} className="flex justify-between">
                          <span className="text-muted-foreground capitalize">
                            {key.replace("_", " ")}:
                          </span>
                          <span className="font-mono">{String(value)}</span>
                        </div>
                      ))
                    ) : (
                      <p className="text-muted-foreground">No metadata available</p>
                    )}
                  </div>
                </div>
              </div>

              {/* Parsed Message */}
              <div>
                <h4 className="font-semibold text-foreground mb-2">Parsed Message</h4>
                <div className="p-3 rounded-lg bg-secondary/20 border border-border">
                  <p className="font-mono text-sm">{selectedLog.message}</p>
                </div>
              </div>

              {/* Raw Log */}
              <div>
                <h4 className="font-semibold text-foreground mb-2">Raw Log Entry</h4>
                <div className="p-3 rounded-lg bg-secondary/20 border border-border">
                  <p className="font-mono text-sm text-muted-foreground">{selectedLog.raw_log}</p>
                </div>
              </div>
            </CardContent>
          </Card>
        )}
      </div>
    </Layout>
  );
};

export default Logs;
