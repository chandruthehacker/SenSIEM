"use client";
import { useState, useEffect, useCallback, useRef } from "react";
import {
  Settings as SettingsIcon,
  Server,
  Database,
  Save,
  Plus,
  Trash2,
  Bell,
  Mail,
  Slack,
  Send,
  Download,
  Upload,
  FileText,
  Loader2,
  Pencil,
  RotateCcw
} from "lucide-react";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Button } from "@/components/ui/button";
import Layout from "@/components/layout/Layout";
import { Separator } from "@/components/ui/separator";
import { Dialog, DialogContent, DialogHeader, DialogTitle, DialogDescription, DialogFooter, DialogTrigger } from "@/components/ui/dialog";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import axios from "axios";
import { Textarea } from "@/components/ui/textarea";

import {NotificationSettings} from "@/components/cards/NotificationSetting";
import {BackendSettings} from "@/components/cards/BackendSettings";
import DetectionRules from "@/components/cards/DetectionRules";

import { toast } from "sonner";

import backendConfig from "@/configs/config.json";

function Settings() {
  const [config, setConfig] = useState(null);
  const [originalConfig, setOriginalConfig] = useState(null);
  const [newSourcePath, setNewSourcePath] = useState('');
  const [newSourceType, setNewSourceType] = useState('auto');
  const [showAddSourceModal, setShowAddSourceModal] = useState(false);
  const [showConfirmDeleteModal, setShowConfirmDeleteModal] = useState(false);
  const [sourceToDeleteId, setSourceToDeleteId] = useState<{ type: string, path: string } | null>(null);
  const [fileToIngest, setFileToIngest] = useState<File | null>(null);

  const [showToast, setShowToast] = useState(false);
  const [toastMessage, setToastMessage] = useState('');

  const [showModal, setShowModal] = useState(false);
  const [modalMessage, setModalMessage] = useState('');
  const [modalTitle, setModalTitle] = useState('');

  const [backendStatus, setBackendStatus] = useState<"idle" | "loading" | "success" | "error">("idle");
  const [errorMessage, setErrorMessage] = useState("");
  const [canAddSource, setCanAddSource] = useState(false);
  const debounceTimerRef = useRef<NodeJS.Timeout | null>(null);

  const [logContent, setLogContent] = useState("");
  const [inputMode, setInputMode] = useState<"file" | "manual" | null>(null);
  const [isValidLog, setIsValidLog] = useState(false);
  const [checking, setChecking] = useState(false);
  const [errorMsg, setErrorMsg] = useState("");
  const [logType, setLogType] = useState("unknown");
  const [loading, setLoading] = useState(true);  // optional
  const [error, setError] = useState(false);



  const fetchAllSettings = useCallback(async () => {
    try {
      const response = await axios.get(`${backendConfig?.apiUrl}/get-settings`);
      const fetchedConfig = response.data;

      setConfig(fetchedConfig);
      setOriginalConfig(fetchedConfig);
      setError(false);
    } catch (error) {
      console.error("Error fetching all settings:", error);
      setError(true);
      setModalTitle("Connection Error");
      setModalMessage("Failed to fetch settings from backend. Please check your connection.");
      setShowModal(true);
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    fetchAllSettings();
  }, [fetchAllSettings]);


  const showSuccessToast = (message: string) => {
    setToastMessage(message);
    setShowToast(true);
    const timer = setTimeout(() => {
      setShowToast(false);
      setToastMessage('');
    }, 4000);
    return () => clearTimeout(timer);
  };

  const showErrorModal = (message: string, title: string = "Error!") => {
    setModalMessage(message);
    setModalTitle(title);
    setShowModal(true);
  };

  const closeModal = () => {
    setShowModal(false);
    setModalMessage('');
    setModalTitle('');
  };


  const handleExportConfig = async () => {
    const response = await axios.get(`${backendConfig?.apiUrl}/get-settings`);
    const fetchedConfig = response.data;
    const configJson = JSON.stringify(fetchedConfig, null, 2);
    const blob = new Blob([configJson], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `sensiem_config_${new Date().toISOString().slice(0, 10)}.json`;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
    showSuccessToast("Configuration exported as JSON!");
    setShowToast(true);
  };

  const handleImportConfig = (event: React.ChangeEvent<HTMLInputElement>) => {
    const file = event.target.files?.[0];
    if (file) {
      const reader = new FileReader();
      reader.onload = (e) => {
        try {
          const importedConfig = JSON.parse(e.target?.result as string);
          if (importedConfig && typeof importedConfig === 'object') {
            const mergedConfig = {
              ...importedConfig,
              logSources: typeof importedConfig.logSources === 'object' ? importedConfig.logSources : {},
            };
            setConfig(mergedConfig);
            showSuccessToast("Configuration imported successfully! Remember to save changes.");
            setShowToast(true);
          } else {
            showErrorModal("Invalid configuration file format.", "Invalid");
          }
        } catch (error) {
          showErrorModal("Error parsing configuration file.", "Error");
          console.error("Error importing config:", error);
        }
      };
      reader.readAsText(file);
    }
  };

const handleDeleteSource = async (type: string, path: string) => {
  setSourceToDeleteId({ type, path });
  setShowConfirmDeleteModal(true);
};

const confirmDeleteSource = async () => {
  setShowConfirmDeleteModal(false);
  if (!sourceToDeleteId) return;
  const { type, path } = sourceToDeleteId;

  try {
    await new Promise(resolve => setTimeout(resolve, 100));

    const response = await axios.post(`${backendConfig?.apiUrl}/delete-log-path`, {
      type,
      path,
    });

    if (response.status === 200) {
      showSuccessToast("Log source deleted successfully.");
      fetchAllSettings?.();
    } else {
      showErrorModal("Failed to delete log source. Please try again.", "Failed");
    }
  } catch (error: any) {
    console.error("Error deleting log source:", error);
    showErrorModal(
      `An error occurred while deleting the log source: ${
        error.response?.data?.detail?.error || error.message
      }`,
      "ERROR"
    );
  }
};

const validatePathDebounced = (path: string) => {
  if (debounceTimerRef.current) {
    clearTimeout(debounceTimerRef.current);
  }

  debounceTimerRef.current = setTimeout(async () => {
    if (!path.trim()) return;

    setBackendStatus("loading");
    setCanAddSource(false);
    setErrorMessage("");

    try {
      const res = await fetch(`${backendConfig?.apiUrl}/validate-path`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ path }),
      });

      const data = await res.json();

      if (res.ok && data.status === "ok") {
        setBackendStatus("success");
        setCanAddSource(true);

        if (data.type) {
          setNewSourceType(data.type);
        }
      } else {
        setBackendStatus("error");
        setErrorMessage(data.message || "Invalid log file");
      }
    } catch (err: any) {
      setBackendStatus("error");
      setErrorMessage("Server validation failed");
    }
  }, 3000);
};

useEffect(() => {
  if (showAddSourceModal) {
    setBackendStatus("idle");
    setErrorMessage("");
    setNewSourcePath("");
    setFileToIngest(null);
    setNewSourceType("auto");
    setCanAddSource(false);
  }
}, [showAddSourceModal]);

const handleAddSource = async () => {
  if (!newSourcePath || !newSourceType || !canAddSource) return;

  setBackendStatus("loading");
  setErrorMessage("");

  try {
    const res = await fetch(`${backendConfig?.apiUrl}/add-log-source`, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
      },
      body: JSON.stringify({
        path: newSourcePath,
        type: newSourceType,
      }),
    });

    const data = await res.json();

    if (res.ok && data.status === "ok") {
      setBackendStatus("success");
      setCanAddSource(true);

      if (data.type && data.type !== "unknown" && data.type !== newSourceType) {
        setNewSourceType(data.type);
      }

      showSuccessToast(`✅ ${data.message || "Log source added successfully"}`);

      // Close modal and refresh
      setShowAddSourceModal(false);
      fetchAllSettings?.();
    } else {
      const errorMsg = data?.message || "Failed to add log source. Check path and log type.";
      setBackendStatus("error");
      setErrorMessage(errorMsg);
      toast.error(`❌ ${errorMsg}`);
    }
  } catch (err) {
    console.error("Add Source Error:", err);
    setBackendStatus("error");
    const fallback = "Server validation failed. Try again later.";
    setErrorMessage(fallback);
    toast.error(`❌ ${fallback}`);
  }
};

  const handleReset = () => {
    setInputMode(null);
    setFileToIngest(null);
    setLogContent('');
    setIsValidLog(false);
    setLogType('unknown');
    setErrorMsg('');
    setChecking(false);
    const fileInput = document.getElementById('ingestFile') as HTMLInputElement;
    if (fileInput) {
      fileInput.value = '';
    }
  };

  const handleFileToIngestChange = async (
    e: React.ChangeEvent<HTMLInputElement>
  ) => {
    const file = e.target.files?.[0];
    setErrorMsg("");
    setFileToIngest(file);
    setIsValidLog(false);
    setLogType('unknown');
    setLogContent('');

    if (file) {
      setChecking(true);

      setTimeout(async () => {
        try {
          const formData = new FormData();
          formData.append("file", file);

          const res = await axios.post(`${backendConfig?.apiUrl}/check-log`, formData);

          if (res.data.result === "success") {
            setIsValidLog(true);
            setLogType(res.data.type || "unknown");
          } else {
            setErrorMsg(res.data.message || "Invalid log content.");
            setIsValidLog(false); // Ensure this is false on error
            setLogType('unknown');
          }
        } catch (err) {
          console.error("Error validating log file:", err);
          setErrorMsg("Error validating log file. Please ensure the backend is running.");
          setIsValidLog(false);
          setLogType('unknown');
        } finally {
          setChecking(false);
        }
      }, 2000);
    } else {
      setErrorMsg("No log file selected.");
      handleReset();
    }
  };

  const handleManualChange = async (e: React.ChangeEvent<HTMLTextAreaElement>) => {
    const value = e.target.value;
    setLogContent(value);
    setIsValidLog(false);
    setLogType('unknown');
    setErrorMsg("");
    setFileToIngest(null);

    const fileInput = document.getElementById('ingestFile') as HTMLInputElement;
    if (fileInput) {
      fileInput.value = '';
    }

    if (value.trim()) {
      setChecking(true);
      setTimeout(async () => {
        try {
          const formData = new FormData();
          formData.append("content", value);

          const res = await axios.post(`${backendConfig?.apiUrl}/check-log`, formData);
          if (res.data.result === "success") {
            setIsValidLog(true);
            setLogType(res.data.type || "unknown");
          } else {
            setErrorMsg(res.data.message || "Invalid log content.");
            setIsValidLog(false);
            setLogType('unknown');
          }
        } catch (err) {
          console.error("Error validating content:", err);
          setErrorMsg("Error validating content. Please ensure the backend is running.");
          setIsValidLog(false);
          setLogType('unknown');
        } finally {
          setChecking(false);
        }
      }, 2000);
    } else {
      setErrorMsg("Log content cannot be empty.");
      setIsValidLog(false);
      setLogType('unknown');
    }
  };

  const handleIngestFile = async () => {
    if (!logType || logType === "unknown") {
      setErrorMsg("Please validate the log before ingesting.");
      return;
    }

    try {
      const formData = new FormData();
      if (fileToIngest) {
        formData.append("file", fileToIngest);
      } else if (logContent.trim()) {
        formData.append("content", logContent);
      } else {
        setErrorMsg("No file or content to ingest.");
        return;
      }

      formData.append("type", logType);

      const res = await axios.post(`${backendConfig?.apiUrl}/ingest-log`, formData);

      if (res.data.status === "success") {
        fetchAllSettings();
        showSuccessToast(res.data.message);
        handleReset();
      } else {
        setErrorMsg(res.data.message || "Failed to ingest log.");
      }
    } catch (err) {
      console.error("Ingest error:", err);
      setErrorMsg("Error sending log to backend. Ensure it's running.");
    }
  };



  return (
    <Layout>
      {loading ? (
        <div className="flex flex-col items-center justify-center h-full w-ful text-gray-500 space-y-4 text-center">
          <div className="flex items-center gap-4 text-xl">
            <Loader2 className="w-10 h-10 animate-spin text-primary" />
            Loading settings...
          </div>
          {error && (
            <div className="text-red-600 font-semibold">
              ❌ Check backend connection and reload the page
            </div>
          )}
        </div>
      ) : error ? (
        <div className="flex items-center justify-center h-full w-full text-xl text-red-600 font-semibold text-center">
          ❌ Check backend connection and reload the page
        </div>
      ) : config && (
          <div className="p-6 space-y-6 animate-fade-in mt-6">
              <div>
                <h1 className="text-3xl font-bold text-foreground flex items-center gap-2">
                  <SettingsIcon className="w-7 h-7" /> Settings
                </h1>
              </div>

            <p className="text-muted-foreground">Manage backend, alert rules, log sources, and notifications</p>
          {showToast && (
            <div className="toast-notification-container">
              <div className="toast-notification">
                {toastMessage}
              </div>
            </div>
          )}

          {/* --- Modal Dialog (Error) --- */}
          {showModal && (
            <div
              className="modal-overlay"
              onClick={(e) => { // Click outside to close
                if (e.target === e.currentTarget) { // Ensure click is on overlay itself
                  closeModal();
                }
              }}
            >
              <div className="modal-content error"> {/* Added .error class */}
                <h3>{modalTitle}</h3>
                <p>{modalMessage}</p>
                <button onClick={closeModal}>OK</button>
              </div>
            </div>
          )}

            <Separator />

            <div className="grid gap-10">
              {/* Backend Configuration */}
              <BackendSettings
                config={config}
                setConfig={setConfig}
                originalConfig={originalConfig}
                setOriginalConfig={setOriginalConfig}
                toast={toast}
                showSuccessToast={showSuccessToast}
                showErrorModal={showErrorModal}
              />

              {/* Log Sources - List View */}
              <Card>
                <CardHeader>
                  <CardTitle className="flex items-center gap-2 text-lg">
                    <Database className="w-5 h-5" />
                    Monitoring Log Sources
                  </CardTitle>
                  <CardDescription>
                    Paths to log files monitored by the backend.
                  </CardDescription>
                </CardHeader>

                <CardContent className="space-y-4">
                <div className="max-h-[300px] overflow-y-auto pr-1 space-y-6 scrollbar-thin scrollbar-thumb-gray-500 scrollbar-track-transparent hover:scrollbar-thumb-gray-400 scrollbar-thumb-rounded-md">
                    {config.logSources && Object.keys(config.logSources).length === 0 ? (
                      <div className="text-sm text-muted-foreground italic">
                        No log sources configured yet.
                      </div>
                    ) : (
                      Object.entries(config.logSources as Record<string, string[]>).map(
                        ([type, paths]) => (
                          <div key={type} className="space-y-2">
                            <h4 className="text-sm font-semibold text-muted-foreground capitalize">
                              {type}
                            </h4>
                            <div className="flex flex-wrap gap-4">
                              {paths.map((path: string) => (
                                <div
                                  key={`${type}-${path}`}
                                  className="flex items-center justify-between gap-2 px-3 py-1 rounded-lg border border-border bg-secondary/40 text-sm"
                                >
                                  <p className="text-foreground">{path}</p>
                                  <Button
                                    variant="ghost"
                                    size="icon"
                                    onClick={() => handleDeleteSource(type, path)}
                                    className="text-destructive hover:bg-destructive/10"
                                  >
                                    <Trash2 className="w-4 h-4" />
                                  </Button>
                                </div>
                              ))}
                            </div>
                          </div>
                        )
                      )
                    )}
                  </div>

                  <Button
                    onClick={() => setShowAddSourceModal(true)}
                    className="w-full"
                    variant="default"
                  >
                    <Plus className="w-4 h-4 mr-2" />
                    Add Log File Path
                  </Button>
                </CardContent>
              </Card>



              {/* Ingest Single Log File or Log Content*/}
              <Card>
                <CardHeader className="relative">
                  <CardTitle className="flex items-center gap-2">
                    <FileText className="w-5 h-5" />
                    Ingest Log
                  </CardTitle>
                  <CardDescription>
                    Choose how you'd like to ingest logs — upload a file or paste content.
                  </CardDescription>


                  {inputMode && (
                        <Button
                          onClick={handleReset}
                          variant="ghost"
                          size="sm"
                          className="absolute top-2 right-4 text-black font-bold hover:text-foreground bg-red-600"
                        >
                          <RotateCcw className="w-4 h-4 mr-1" />
                          Reset
                        </Button>
                      )}
                </CardHeader>

                <CardContent className="space-y-5">
                  {!inputMode ? (
                    <Dialog>
                      <DialogTrigger asChild>
                        <Button variant="outline" className="w-full">
                          Choose Ingestion Method
                        </Button>
                      </DialogTrigger>
                      <DialogContent className="space-y-4">
                        <p className="text-lg font-semibold">Select Ingestion Type</p>
                        <div className="flex gap-4">
                          <Button
                            onClick={() => {
                              setInputMode("file");
                              document.getElementById("ingestFile")?.click();
                            }}
                            className="flex-1"
                          >
                            <FileText className="w-4 h-4 mr-2" />
                            Upload Log File
                          </Button>
                          <Button
                            onClick={() => setInputMode("manual")}
                            className="flex-1"
                            variant="secondary"
                          >
                            <Pencil className="w-4 h-4 mr-2" />
                            Enter Log Content
                          </Button>
                        </div>
                      </DialogContent>
                    </Dialog>
                  ) : inputMode === "file" ? (
                    <>
                      <div>
                        <Label htmlFor="ingestFile">Select Log File</Label>
                        <Input
                          id="ingestFile"
                          type="file"
                          accept="*"
                          onChange={handleFileToIngestChange}
                        />
                        {fileToIngest && (
                          <p className="text-sm text-muted-foreground mt-2">
                            Selected: {fileToIngest.name}
                          </p>
                        )}
                      </div>
                      {errorMsg && (
                        <p className="text-red-500 text-sm -mt-2">{errorMsg}</p>
                      )}
                      {isValidLog && (
                        <Card className="mt-6">
                          <CardHeader>
                            <CardTitle className="text-base">Detected Log Type</CardTitle>
                          </CardHeader>
                          <CardContent>
                            <p className="mb-2 text-muted-foreground">
                              We detected the log type as <strong>{logType}</strong>.
                            </p>
                            <Label>Select Log Type</Label>
                            <Select value={logType} onValueChange={setLogType}>
                              <SelectTrigger className="w-full mt-1">
                                <SelectValue placeholder="Select log type" />
                              </SelectTrigger>
                              <SelectContent>
                                <SelectItem value="auto" className="hover:bg-gray-700 hover:cursor-pointer">Auto-detect</SelectItem>
                                <SelectItem value="syslog" className="hover:bg-gray-700 hover:cursor-pointer">Syslog</SelectItem>
                                <SelectItem value="apache" className="hover:bg-gray-700 hover:cursor-pointer">Apache Log</SelectItem>
                                <SelectItem value="auth.log" className="hover:bg-gray-700 hover:cursor-pointer">Auth Log</SelectItem>
                                <SelectItem value="nginx" className="hover:bg-gray-700 hover:cursor-pointer">Nginx Log</SelectItem>
                                <SelectItem value="windows_event" className="hover:bg-gray-700 hover:cursor-pointer">Windows Event Logs</SelectItem>
                                <SelectItem value="firewall" className="hover:bg-gray-700 hover:cursor-pointer">Firewall Logs</SelectItem>
                                <SelectItem value="ids_ips" className="hover:bg-gray-700 hover:cursor-pointer">IDS/IPS Logs</SelectItem>
                                <SelectItem value="vpn" className="hover:bg-gray-700 hover:cursor-pointer">VPN Logs</SelectItem>
                                <SelectItem value="cloud" className="hover:bg-gray-700 hover:cursor-pointer">Cloud Logs</SelectItem>
                                <SelectItem value="dns" className="hover:bg-gray-700 hover:cursor-pointer">DNS Logs</SelectItem>
                                <SelectItem value="antivirus" className="hover:bg-gray-700 hover:cursor-pointer">Antivirus Logs</SelectItem>
                                <SelectItem value="zeek" className="hover:bg-gray-700 hover:cursor-pointer">Zeek Logs</SelectItem>
                                <SelectItem value="email" className="hover:bg-gray-700 hover:cursor-pointer">Email Logs</SelectItem>
                                <SelectItem value="waf" className="hover:bg-gray-700 hover:cursor-pointer">Web Application Firewall Logs</SelectItem>
                                <SelectItem value="database" className="hover:bg-gray-700 hover:cursor-pointer">Database Logs</SelectItem>
                                <SelectItem value="proxy" className="hover:bg-gray-700 hover:cursor-pointer">Proxy Logs</SelectItem>
                                <SelectItem value="json" className="hover:bg-gray-700 hover:cursor-pointer">JSON Log</SelectItem>
                              </SelectContent>
                            </Select>
                          </CardContent>
                        </Card>
                      )}
                      <Button
                        onClick={handleIngestFile}
                        disabled={!isValidLog || checking}
                        className="w-full"
                      >
                        {checking ? (
                          "Checking..."
                        ) : (
                          <>
                            <Upload className="w-4 h-4 mr-2" />
                            Ingest File
                          </>
                        )}
                      </Button>
                    </>
                  ) : (
                    <>
                      <div>
                        <Label htmlFor="logContent">Enter Log Content</Label>
                        <Textarea
                          id="logContent"
                          rows={6}
                          placeholder="Paste log content here..."
                          value={logContent}
                          onChange={handleManualChange}
                        />
                      </div>
                      {errorMsg && (
                        <p className="text-red-500 text-sm -mt-2">{errorMsg}</p>
                      )}
                      {isValidLog && (
                        <Card className="mt-6">
                          <CardHeader>
                            <CardTitle className="text-base">Detected Log Type</CardTitle>
                          </CardHeader>
                          <CardContent>
                            <p className="mb-2 text-muted-foreground">
                              We detected the log type as <strong>{logType}</strong>.
                            </p>
                            <Label>Select Log Type</Label>
                            <Select value={logType} onValueChange={setLogType}>
                              <SelectTrigger className="w-full mt-1">
                                <SelectValue placeholder="Select log type" />
                              </SelectTrigger>
                              <SelectContent>
                                <SelectItem value="auto" className="hover:bg-gray-700 hover:cursor-pointer">Auto-detect</SelectItem>
                                <SelectItem value="syslog" className="hover:bg-gray-700 hover:cursor-pointer">Syslog</SelectItem>
                                <SelectItem value="apache" className="hover:bg-gray-700 hover:cursor-pointer">Apache Log</SelectItem>
                                <SelectItem value="auth.log" className="hover:bg-gray-700 hover:cursor-pointer">Auth Log</SelectItem>
                                <SelectItem value="nginx" className="hover:bg-gray-700 hover:cursor-pointer">Nginx Log</SelectItem>
                                <SelectItem value="windows_event" className="hover:bg-gray-700 hover:cursor-pointer">Windows Event Logs</SelectItem>
                                <SelectItem value="firewall" className="hover:bg-gray-700 hover:cursor-pointer">Firewall Logs</SelectItem>
                                <SelectItem value="ids_ips" className="hover:bg-gray-700 hover:cursor-pointer">IDS/IPS Logs</SelectItem>
                                <SelectItem value="vpn" className="hover:bg-gray-700 hover:cursor-pointer">VPN Logs</SelectItem>
                                <SelectItem value="cloud" className="hover:bg-gray-700 hover:cursor-pointer">Cloud Logs</SelectItem>
                                <SelectItem value="dns" className="hover:bg-gray-700 hover:cursor-pointer">DNS Logs</SelectItem>
                                <SelectItem value="antivirus" className="hover:bg-gray-700 hover:cursor-pointer">Antivirus Logs</SelectItem>
                                <SelectItem value="zeek" className="hover:bg-gray-700 hover:cursor-pointer">Zeek Logs</SelectItem>
                                <SelectItem value="email" className="hover:bg-gray-700 hover:cursor-pointer">Email Logs</SelectItem>
                                <SelectItem value="waf" className="hover:bg-gray-700 hover:cursor-pointer">Web Application Firewall Logs</SelectItem>
                                <SelectItem value="database" className="hover:bg-gray-700 hover:cursor-pointer">Database Logs</SelectItem>
                                <SelectItem value="proxy" className="hover:bg-gray-700 hover:cursor-pointer">Proxy Logs</SelectItem>
                                <SelectItem value="json" className="hover:bg-gray-700 hover:cursor-pointer">JSON Log</SelectItem>
                              </SelectContent>
                            </Select>
                          </CardContent>
                        </Card>
                      )}
                      <Button
                        onClick={handleIngestFile}
                        disabled={!isValidLog || checking}
                        className="w-full"
                      >
                        {checking ? (
                          "Checking..."
                        ) : (
                          <>
                            <Upload className="w-4 h-4 mr-2" />
                            Ingest Content
                          </>
                        )}
                      </Button>
                    </>
                  )}
                </CardContent>
              </Card>

              <DetectionRules />  

              {/* Notification Settings */}
              <NotificationSettings
                config={config}
                setConfig={setConfig}
                originalConfig={originalConfig}
                setOriginalConfig={setOriginalConfig}
                toast={toast}
                showSuccessToast={showSuccessToast}
                showErrorModal={showErrorModal}
              />



              {/* Backup and Export Configuration */}
              <Card>
                <CardHeader>
                  <CardTitle className="flex items-center gap-2">
                    <Download className="w-5 h-5" />
                    Backup & Export
                  </CardTitle>
                </CardHeader>
                <CardContent className="space-y-4">
                  <p className="text-sm text-muted-foreground">Export your current configuration to a JSON file or import a previously saved configuration.</p>
                  <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                  {/* Export Button */}
                  <Button
                    onClick={handleExportConfig}
                    variant="outline"
                    className="group transition-all duration-200 border hover:border-blue-500 hover:bg-blue-50 hover:text-blue-600"
                  >
                    <Download className="w-4 h-4 mr-2 group-hover:animate-bounce" />
                    Export Config
                  </Button>

                  {/* Import Button with File Input */}
                  <div className="">
                    <Input
                      id="importFile"
                      type="file"
                      accept=".json"
                      onChange={handleImportConfig}
                      className="absolute inset-0 opacity-0 cursor-pointer"
                    />
                    <Button
                      asChild
                      variant="outline"
                      className="w-full group transition-all duration-200 border hover:border-green-500 hover:bg-green-50 hover:text-green-600"
                    >
                      <label
                        htmlFor="importFile"
                        className="flex items-center justify-center cursor-pointer"
                      >
                        <Upload className="w-4 h-4 mr-2 group-hover:animate-bounce" />
                        Import Config
                      </label>
                    </Button>
                  </div>
                </div>

                </CardContent>
              </Card>

            </div>
          </div>
      )}
      {/* Dialogs */}

      {/* Add Log Path Dialog */}
      <Dialog
        open={showAddSourceModal}
        onOpenChange={setShowAddSourceModal}
      >
        <DialogContent
          className="
            sm:max-w-lg md:max-w-xl lg:max-w-2xl xl:max-w-3xl {/* Responsive max-width */}
            max-h-[90vh] max-w-[90vw] overflow-y-auto {/* Max height and scroll if content overflows */}
            bg-gray-900 {/* Dark background */}
            shadow-xl rounded-lg border border-gray-700 {/* Prominent shadow, subtle border for definition */}
            p-6 sm:p-8 {/* Increased padding for spacious feel */}
            text-gray-100 {/* Default text color for the dialog content */}
            transition-all duration-300 ease-in-out {/* Smooth transition */}
            relative {/* For absolute positioning of dialog close button if needed */}
          "
        >
          <DialogHeader className="text-center sm:text-left">
            <DialogTitle className="text-2xl font-bold text-white mb-2">
              Add New Log Source
            </DialogTitle>
            <DialogDescription className="text-gray-400">
              Select a log file from your system to ingest and analyze.
            </DialogDescription>
          </DialogHeader>

          <div className="grid gap-6 py-6 border-t border-b border-gray-700 my-4">
            {/* File Path and Browse */}
            <div className="grid grid-cols-1 md:grid-cols-4 items-center gap-4">
          <Label htmlFor="newSourcePath" className="md:text-right text-base text-gray-300 font-medium">
            Log File Path
          </Label>

            <div className="md:col-span-3 flex flex-col gap-2">
              <div className="relative w-full">
                <Input
                  id="newSourcePath"
                  placeholder="/var/log/auth.log"
                  value={newSourcePath}
                  onChange={(e) => {
                    const value = e.target.value;

                    setNewSourcePath(value);
                    setBackendStatus("loading");
                    setCanAddSource(false);
                    validatePathDebounced(value);
                    if(value==""){
                      setBackendStatus("idle");
                    }
                  }}
                  className=""
                />
                {backendStatus === "loading" && (
                  <Loader2 className="absolute right-3 top-3 animate-spin text-gray-400 w-4 h-4" />
                )}
              </div>

              {backendStatus === "error" && (
                <p className="text-sm text-red-400">{errorMessage}</p>
              )}
              {backendStatus === "success" && (
                <p className="text-sm text-green-400">Valid log file path!</p>
              )}
            </div>
          </div>

            {/* Type Selection */}
            <div className="grid grid-cols-1 md:grid-cols-4 items-center gap-4">
              <Label htmlFor="newSourceType" className="md:text-right text-base text-gray-300 font-medium">
                Type
              </Label>
              <Select value={newSourceType} onValueChange={setNewSourceType}>
                <SelectTrigger className="md:col-span-3 border border-gray-700 bg-gray-900 text-gray-100 placeholder:text-gray-500 rounded-md px-3 py-2 focus:ring-blue-500 focus:border-blue-500">
                  <SelectValue placeholder="Select log type" />
                </SelectTrigger>
                <SelectContent className="bg-gray-900 border border-gray-700 text-gray-100">
                  <SelectItem value="auto" className="hover:bg-gray-700 hover:cursor-pointer">Auto-detect</SelectItem>
                  <SelectItem value="syslog" className="hover:bg-gray-700 hover:cursor-pointer">Syslog</SelectItem>
                  <SelectItem value="apache" className="hover:bg-gray-700 hover:cursor-pointer">Apache Log</SelectItem>
                  <SelectItem value="auth" className="hover:bg-gray-700 hover:cursor-pointer">Auth Log</SelectItem>
                  <SelectItem value="nginx" className="hover:bg-gray-700 hover:cursor-pointer">Nginx Log</SelectItem>
                  <SelectItem value="windows_event" className="hover:bg-gray-700 hover:cursor-pointer">Windows Event Logs</SelectItem>
                  <SelectItem value="firewall" className="hover:bg-gray-700 hover:cursor-pointer">Firewall Logs</SelectItem>
                  <SelectItem value="ids_ips" className="hover:bg-gray-700 hover:cursor-pointer">IDS/IPS Logs</SelectItem>
                  <SelectItem value="vpn" className="hover:bg-gray-700 hover:cursor-pointer">VPN Logs</SelectItem>
                  <SelectItem value="cloud" className="hover:bg-gray-700 hover:cursor-pointer">Cloud Logs</SelectItem>
                  <SelectItem value="dns" className="hover:bg-gray-700 hover:cursor-pointer">DNS Logs</SelectItem>
                  <SelectItem value="antivirus" className="hover:bg-gray-700 hover:cursor-pointer">Antivirus Logs</SelectItem>
                  <SelectItem value="zeek" className="hover:bg-gray-700 hover:cursor-pointer">Zeek Logs</SelectItem>
                  <SelectItem value="email" className="hover:bg-gray-700 hover:cursor-pointer">Email Logs</SelectItem>
                  <SelectItem value="waf" className="hover:bg-gray-700 hover:cursor-pointer">Web Application Firewall Logs</SelectItem>
                  <SelectItem value="database" className="hover:bg-gray-700 hover:cursor-pointer">Database Logs</SelectItem>
                  <SelectItem value="proxy" className="hover:bg-gray-700 hover:cursor-pointer">Proxy Logs</SelectItem>
                  <SelectItem value="json" className="hover:bg-gray-700 hover:cursor-pointer">JSON Log</SelectItem>
                </SelectContent>
              </Select>
            </div>
          </div>

      {/* Footer */}
          <DialogFooter className="mt-6 flex-col sm:flex-row sm:justify-end gap-3 pt-4 border-t border-gray-700">
            <Button
              variant="outline"
              onClick={() => setShowAddSourceModal(false)}
              className="w-full sm:w-auto
                border border-gray-600 text-gray-300 hover:bg-gray-700 hover:text-gray-100
                transition-colors duration-200
              "
            >
              Cancel
            </Button>
            <Button
              onClick={handleAddSource}
              disabled={!canAddSource || backendStatus === "loading"}
              className="w-full sm:w-auto
                bg-blue-600 text-white hover:bg-blue-700
                transition-colors duration-200 font-semibold
              "
            >
              {backendStatus === "loading" ? (
                <span className="flex items-center gap-2">
                  <Loader2 className="animate-spin w-4 h-4" /> Adding...
                </span>
              ) : (
                "Add Source"
              )}
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>


      {/* Confirm Delete Log Source Modal */}
      <Dialog open={showConfirmDeleteModal} onOpenChange={setShowConfirmDeleteModal}>
        <DialogContent>
          <DialogHeader>
            <DialogTitle>Confirm Deletion</DialogTitle>
            <DialogDescription>
              Are you sure you want to delete this log source? This action cannot be undone.
            </DialogDescription>
          </DialogHeader>
          <DialogFooter>
            <Button variant="outline" onClick={() => setShowConfirmDeleteModal(false)}>Cancel</Button>
            <Button variant="destructive" onClick={confirmDeleteSource}>Delete</Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>


    </Layout>
  );
};

export default Settings;


