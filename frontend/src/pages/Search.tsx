import { useState, useEffect } from "react";
import {
  Search as SearchIcon,
  Loader2,
  FileText,
  AlertCircle,
  Download,
  RefreshCw,
  Save,
  Clock,
  Delete,
} from "lucide-react";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from "@/components/ui/card";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import { Badge } from "@/components/ui/badge";
import Layout from "@/components/layout/Layout";

import backendConfig from "@/configs/config.json";

const Search = () => {
  const [searchQuery, setSearchQuery] = useState("");
  const [filters, setFilters] = useState({
    dateRange: "all",
    logLevel: "all",
    source: "all",
  });
  const [filteredResults, setFilteredResults] = useState([]);
  const [savedSearches, setSavedSearches] = useState([]);
  const [isRefreshing, setIsRefreshing] = useState(false);
  const [isLoading, setIsLoading] = useState(false);
  const [searchFilter, setSearchFilter] = useState("");
  const [saveError, setSaveError] = useState("");
  


  useEffect(() => {
    const saved = JSON.parse(localStorage.getItem("savedSearches") || "[]");
    setSavedSearches(saved);
    handleSearch();
  }, []);

  const handleSearch = async () => {
    setIsLoading(true);
    setIsRefreshing(true);

    const parsed = parseSearchQuery(searchQuery);
    const body = {
      filters, // include your existing filters: dateRange, logLevel, etc.
      query: parsed,
    };

    setTimeout(async () => {
      try {
        const response = await fetch(`${backendConfig.apiUrl}/search-logs`, {
          method: "POST",
          headers: {
            "Content-Type": "application/json",
          },
          body: JSON.stringify(body),
        });

        if (!response.ok) throw new Error("Failed to fetch logs");

        const data = await response.json();
        setFilteredResults(data.logs || []);
      } catch (error) {
        console.error("Search failed:", error);
      } finally {
        setIsLoading(false);
        setIsRefreshing(false);
      }
    }, 500);
  };

const highlightText = (text, query) => {
  if (!query) return text;
  const parts = text.split(new RegExp(`(${query})`, "gi"));
  return parts.map((part, i) =>
    part.toLowerCase() === query.toLowerCase() ? (
      <span key={i} className="bg-yellow-300 px-1 rounded text-black">{part}</span>
    ) : (
      part
    )
  );
};


const handleSaveSearch = () => {
  if (!searchQuery.trim()) {
    setSaveError("Search query cannot be empty.");
    setTimeout(() => setSaveError(""), 2000);
    return;
  }

  const preset = { searchQuery, filters };
  const updated = [...savedSearches, preset];
  setSavedSearches(updated);
  localStorage.setItem("savedSearches", JSON.stringify(updated));
};

  const handleDeleteSearch = (index) => {
  const updated = [...savedSearches];
  updated.splice(index, 1);
  setSavedSearches(updated);
  localStorage.setItem("savedSearches", JSON.stringify(updated));
};

  const handleLoadSearch = (preset) => {
    setSearchQuery(preset.searchQuery);
    setFilters(preset.filters);
  };

  const handleExport = (format = "json") => {
    const filename = `export_logs_${Date.now()}.${format}`;
    const data =
      format === "csv"
        ? convertToCSV(filteredResults)
        : JSON.stringify(filteredResults, null, 2);

    const blob = new Blob([data], {
      type: format === "csv" ? "text/csv" : "application/json",
    });
    const link = document.createElement("a");
    link.href = URL.createObjectURL(blob);
    link.download = filename;
    link.click();
  };

  const convertToCSV = (logs) => {
    if (!logs.length) return "";
    const keys = Object.keys(logs[0]);
    const rows = logs.map((log) => keys.map((k) => JSON.stringify(log[k])));
    return [keys.join(","), ...rows.map((row) => row.join(","))].join("\n");
  };

  const visibleLogs = filteredResults.filter((log) =>
  log.message.toLowerCase().includes(searchFilter.toLowerCase())
);

function parseSearchQuery(query: string) {
  const kvRegex = /(\w+)=["']([^"']+)["']/g;
  const kv: Record<string, string> = {};
  const msg: string[] = [];

  let match;
  const kvMatches = [];
  while ((match = kvRegex.exec(query)) !== null) {
    kv[match[1].toLowerCase()] = match[2];
    kvMatches.push(match[0]);
  }

  let remaining = query;
  kvMatches.forEach(kvStr => {
    remaining = remaining.replace(kvStr, "");
  });

  remaining = remaining.replace(/\s+/g, " ").trim();

  const msgTerms = remaining
    .split(/\s+OR\s+/i)
    .map(term => term.trim())
    .filter(Boolean);

  msg.push(...msgTerms);

  return { kv, msgs: msg };
}

  return (
    <Layout>
      <div className="p-6 space-y-6 animate-fade-in">
        <div className="flex items-center justify-between">
          <div>
            <h1 className="text-3xl font-bold text-foreground">Log Search</h1>
            <p className="text-muted-foreground">
              Powerful log filtering and analysis.
            </p>
          </div>
          <Badge variant="outline" className="text-primary border-primary text-md p-1 px-4 flex items-center gap-2 font-normal hover:bg-primary hover:text-white">
            <div className="text-white font-semibold text-lg font-mono"> {filteredResults.length}</div> results found
          </Badge>
        </div>

        {/* SAVED PRESETS */}
        {savedSearches.length > 0 && (
          <div className="flex gap-4 flex-wrap">
            {savedSearches.map((preset, i) => (
              <div key={i} className="flex items-center gap-1">
                <Button
                  variant="outline"
                  size="sm"
                  className="text-xs max-w-[200px] truncate overflow-hidden"
                  onClick={() => handleLoadSearch(preset)}
                >
                  <Clock className="w-3 h-3 mr-1" />
                  <span className="truncate">{preset.searchQuery || "Empty Query"}</span>
                </Button>
                <Button
                  size="icon"
                  variant="ghost"
                  className="h-6 w-6 text-destructive"
                  onClick={() => handleDeleteSearch(i)}
                >
                  <Delete />
                </Button>
              </div>
            ))}
          </div>
        )}

        <Card>
          <CardHeader>
            <div className="flex flex-row w-full justify-between">
            <CardTitle className="flex items-center gap-2">
              <SearchIcon className="w-5 h-5" />
              Search Logs
            </CardTitle>
            <Button variant="default" className="gap-2 text-white font-semibold bg-blue-600 hover:bg-blue-700">
              <FileText className="w-4 h-4" />
              <a href="https://drive.google.com/file/d/10_nJT5EQVv-fLBIwk1TEr-sVAr5EEZ4S/view?usp=sharing" target="_blank" rel="noopener noreferrer">
                View Cheat Sheet
              </a>
            </Button>
            </div>
            <CardDescription>
              Use filters and search terms to find specific log entries
            </CardDescription>
          </CardHeader>
          <CardContent className="space-y-6">
          <div className="space-y-2">
            <Label htmlFor="search" className="text-lg font-bold text-white">
              Search Query
            </Label>

            <div className="relative group">
              <SearchIcon className="absolute left-3 top-1/2 transform -translate-y-1/2 w-4 h-4 text-gray-400 group-focus-within:text-blue-500 transition-colors" />

              <Input
                id="search"
                type="text"
                placeholder='e.g., index="Chandru" host="myhost" pid="8888" failed OR process'
                className="text-xl pl-10 pr-4 py-2 h-11 rounded-lg border border-gray-600 focus:border-none focus:ring-2 focus:ring-blue-200 shadow-sm text-sm placeholder:text-gray-400 transition-all duration-200"
                value={searchQuery}
                onChange={(e) => setSearchQuery(e.target.value)}
                onKeyDown={(e) => e.key === "Enter" && handleSearch()}
              />
            </div>
          </div>


            <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
              {/* Filters */}
              {[
                {
                  label: "Time Range",
                  value: filters.dateRange,
                  items: [
                    ["all", "All Time"],
                    ["1h", "Last Hour"],
                    ["24h", "Last 24 Hours"],
                    ["7d", "Last 7 Days"],
                    ["30d", "Last 30 Days"],
                  ],
                  key: "dateRange",
                },
                {
                  label: "Log Level",
                  value: filters.logLevel,
                  items: [
                    ["all", "All Levels"],
                    ["CRITICAL", "Critical"],
                    ["ALERT", "Alert"],
                    ["ERROR", "Error"],
                    ["WARNING", "Warning"],
                    ["INFO", "Info"],
                  ],
                  key: "logLevel",
                },
                {
                  label: "Source",
                  value: filters.source,
                  items: [
                    ["all", "All Sources"],
                    ["syslog", "Syslog"],
                    ["apache", "Apache Log"],
                    ["auth.log", "Auth Log"],
                    ["nginx", "Nginx Log"],
                    ["windows_event", "Windows Event Logs"],
                    ["firewall", "Firewall Logs"],
                    ["ids_ips", "IDS / IPS Logs"],
                    ["vpn", "VPN"],
                    ["cloud", "Cloud"],
                    ["dns", "DNS"],
                    ["antivirus", "Antivirus"],
                    ["zeek", "Zeek"],
                    ["email", "Email"],
                    ["waf", "WAF Logs"],
                    ["databse", "DATABASE"],
                    ["proxy", "Proxy"],
                    ["json", "JSON"],

                  ],
                  key: "source",
                },
              ].map((filter, idx) => (
                <div key={idx} className="space-y-2">
                  <Label>{filter.label}</Label>
                  <Select
                    value={filter.value}
                    onValueChange={(val) =>
                      setFilters((prev) => ({ ...prev, [filter.key]: val }))
                    }
                  >
                    <SelectTrigger>
                      <SelectValue />
                    </SelectTrigger>
                    <SelectContent>
                      {filter.items.map(([val, label]) => (
                        <SelectItem key={val} value={val}>
                          {label}
                        </SelectItem>
                      ))}
                    </SelectContent>
                  </Select>
                </div>
              ))}
            </div>

            <div className="flex gap-2 items-start">
              {/* Search Button */}
              <Button
                className="w-full bg-gradient-primary font-semibold"
                onClick={handleSearch}
                disabled={isLoading}
              >
                {isLoading ? (
                  <>
                    <Loader2 className="w-4 h-4 mr-2 animate-spin" />
                    Searching logs...
                  </>
                ) : (
                  <>
                    <SearchIcon className="w-4 h-4 mr-2" />
                    Search Logs
                  </>
                )}
              </Button>

              {/* Save Button with Tooltip Error */}
              <div className="relative">
                {saveError && (
                  <div className="absolute -top-16 left-1/8 -translate-x-1/2 animate-fade-down rounded">
                    {/* Error Box */}
                    <div className="text-white bg-red-500 border border-red-600 rounded-md px-4 py-2 text-sm font-medium shadow-md max-w-xs whitespace-nowrap">
                      {saveError}
                    </div>
                    {/* Arrow */}
                    <div className="absolute right-2 -bottom-2 -translate-x-1/2 w-3 h-3 rotate-45 text-white bg-red-500 border border-red-600 border-l border-t border-red-300 shadow-md z-[-1]"></div>
                  </div>
                )}

                {/* Save Button */}
                <Button
                  className="text-sm font-bold text-white bg-blue-600 hover:bg-blue-700 transition-all duration-200 shadow-md px-4 py-2 rounded-md"
                  onClick={handleSaveSearch}
                >
                  <Save className="w-4 h-4 mr-2" />
                  Save Search
                </Button>
              </div>
            </div>
          </CardContent>
        </Card>

        <Card>
          <CardHeader className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-4">
            <div className="flex flex-col sm:flex-row sm:items-center gap-4 w-full">
              <CardTitle className="flex items-center gap-2 text-xl font-semibold">
                <FileText className="w-5 h-5 text-muted-foreground" />
                <pre>Search Results</pre>
              </CardTitle>

              {/* Search Box */}
              <div className="relative group w-full">
                <SearchIcon className="absolute left-3 top-1/2 transform -translate-y-1/2 w-4 h-4 text-gray-400 group-focus-within:text-blue-500 transition-colors" />
              <Input
                type="text"
                placeholder="Instant filter logs..."
                value={searchFilter}
                onChange={(e) => setSearchFilter(e.target.value)}
                className="w-full h-10 rounded-xl border border-blue-300 bg-background focus:border-none px-4 py-2 text-sm text-foreground shadow-sm outline-none transition-all placeholder:text-muted-foreground focus:border-blue-400 focus:ring-2 focus:ring-blue-400 pl-10"
              />
              </div>
            </div>

            <div className="flex gap-2">
              <Button
                variant="outline"
                size="sm"
                onClick={() => handleExport("json")}
              >
                <Download className="w-4 h-4 mr-2" />
                Export JSON
              </Button>
              <Button
                variant="outline"
                size="sm"
                onClick={() => handleExport("csv")}
              >
                <Download className="w-4 h-4 mr-2" />
                Export CSV
              </Button>
              <Button variant="outline" size="sm" onClick={handleSearch}>
                <RefreshCw
                  className={`w-4 h-4 mr-2 transition-transform ${
                    isRefreshing ? "animate-spin" : ""
                  }`}
                />
                Refresh
              </Button>
            </div>
          </CardHeader>

          <CardContent>
            <div className="space-y-3">
              {visibleLogs.length > 0 ? (
                visibleLogs.map((result) => (
                  <div
                    key={result.id || result.timestamp + result.message}
                    className="p-4 rounded-lg border bg-card hover:bg-secondary/50 transition-colors"
                  >
                    <div className="flex flex-col gap-3">
                      {/* Header: Level + Timestamp */}
                      <div className="flex flex-wrap items-center gap-3">
                        <Badge
                          className={`text-xs px-3 py-1 rounded-full font-semibold tracking-wide shadow-sm transition-colors duration-300
                            ${result.log_level === "ERROR"
                              ? "bg-red-600 text-white hover:bg-red-700"
                              : result.log_level === "WARNING"
                              ? "bg-yellow-400 text-black hover:bg-yellow-500"
                              : result.log_level === "CRITICAL"
                              ? "bg-purple-600 text-white hover:bg-purple-700"
                              : result.log_level === "ALERT"
                              ? "bg-orange-600 text-white hover:bg-orange-700"
                              : "bg-green-500 text-black hover:bg-gray-400"}`}
                        >
                          {result.log_level}
                        </Badge>
                        <span className="text-xs text-muted-foreground">
                          {result.timestamp}
                        </span>
                      </div>

                      {/* Message */}
                      <p className="text-sm font-mono text-foreground">
                        {highlightText(result.message, searchFilter)}
                      </p>

                      {/* Log Path (new line) */}
                      {result.file_path && (
                        <div className="text-xs text-muted-foreground break-all">
                          <strong>Path:</strong>{" "}
                          {highlightText(result.file_path, searchFilter)}
                        </div>
                      )}

                      {/* Meta Info - Responsive Flex Wrap */}
                      <div className="flex flex-wrap gap-4 text-xs text-muted-foreground">
                        {[
                          { label: "Source", value: result.source },
                          { label: "From Hostname", value: result.from_host },
                          { label: "Process", value: result.process },
                          { label: "Hostname", value: result.host },
                          { label: "Process ID", value: result.pid },
                          { label: "Username", value: result.username },
                          { label: "Status Code", value: result.status_code },
                          { label: "URL", value: result.url },
                          { label: "Method", value: result.method },
                          { label: "Protocol", value: result.protocol },
                          { label: "Source IP", value: result.src_ip },
                          { label: "Destination IP", value: result.dest_ip },
                          { label: "Source Port", value: result.src_port },
                          { label: "Destination Port", value: result.dest_port },
                          { label: "Signature", value: result.signature },
                          { label: "Action", value: result.action },
                          { label: "User Agent", value: result.user_agent },
                          { label: "Device", value: result.device },
                          { label: "Mail Subject", value: result.mail_subject },
                          { label: "File Hash", value: result.file_hash },
                          { label: "Rule", value: result.rule },
                        ]
                          .filter((field) => field.value !== null && field.value !== undefined && field.value !== "")
                          .map((field, index) => (
                            <p key={index} className="min-w-[140px]">
                              <strong>{field.label}:</strong>{" "}
                              {highlightText(String(field.value), searchFilter)}
                            </p>
                          ))}
                      </div>
                    </div>
                  </div>
                ))
              ) : (
                <div className="text-center text-muted-foreground py-10">
                  <p>No logs found matching your criteria.</p>
                  <p>Try adjusting your search query or filters.</p>
                </div>
              )}
            </div>
          </CardContent>

        </Card>
      </div>
    </Layout>
  );
};

export default Search;
