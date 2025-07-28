// src/components/settings/BackendSettings.jsx
import React, { useCallback, useMemo, useState } from "react";
import {
  Card,
  CardHeader,
  CardTitle,
  CardContent,
} from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Label } from "@/components/ui/label";
import { Input } from "@/components/ui/input";
import { Server, Save, SearchCheck } from "lucide-react";
import axios from "axios";

import backendConfig from "../../configs/config.json";


export function BackendSettings({ config, setConfig, originalConfig, setOriginalConfig, toast, showSuccessToast, showErrorModal }) {

  const currentBackendConfig = useMemo(() => ({
    backendIP: config?.backendIP,
    backendPort: config?.backendPort,
    apiUrl: config?.apiUrl,
  }), [config?.backendIP, config?.backendPort, config?.apiUrl]);

  const originalBackendConfig = useMemo(() => ({
    backendIP: originalConfig?.backendIP,
    backendPort: originalConfig?.backendPort,
    apiUrl: originalConfig?.apiUrl,
  }), [originalConfig?.backendIP, originalConfig?.backendPort, originalConfig?.apiUrl]);

  const hasBackendChanges = JSON.stringify(currentBackendConfig) !== JSON.stringify(originalBackendConfig);


  const validateBackendFields = useCallback(() => {
    const errors = {};
    let isValid = true;

    if (!currentBackendConfig.backendIP) {
      errors.backendIP = "Backend IP Address is required.";
      isValid = false;
    }
    if (!currentBackendConfig.backendPort || isNaN(Number(currentBackendConfig.backendPort)) || Number(currentBackendConfig.backendPort) <= 0) {
      errors.backendPort = "Backend Port is required and must be a positive number.";
      isValid = false;
    }

    return { isValid, errors };
  }, [currentBackendConfig]);


  const handleSaveBackendSettings = async () => {
    const { isValid, errors } = validateBackendFields();

    if (!isValid) {
      console.error("Backend settings validation errors:", errors);
      toast.error("Please correct the errors in Backend Configuration.");
      return;
    }

    try {
      const response = await fetch(`${backendConfig?.apiUrl}/save-backend-settings`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify(currentBackendConfig),
      });

      if (!response.ok) {
        const errorData = await response.json();
        throw new Error(errorData.errors || 'Failed to save backend settings on server.');
      }

      setOriginalConfig(prev => ({
        ...prev,
        backendIP: currentBackendConfig.backendIP,
        backendPort: currentBackendConfig.backendPort,
        apiUrl: currentBackendConfig.apiUrl,
      }));
      showSuccessToast("Backend settings saved successfully!");
    } catch (error) {
      console.error("Error saving backend settings:", error);
      showErrorModal(`${error.message || "Unknown error"}`, "Error");
    }
  };

  const testAPI = async () => {
    try {
      const response = await axios.get(`${backendConfig?.apiUrl}/test`);

      if (response.status === 200) {
        showSuccessToast("✅ API is working fine.");
      } else {
        showErrorModal("⚠️ API responded, but not with status 200", "Unexpected Response");
      }
    } catch (error) {
      console.error("Error testing API:", error);
      showErrorModal("❌ API not working. Please check backend connection.", "Error");
    }
  };


  return (
    <Card className="!bg-zinc-900 text-white shadow-xl border border-zinc-800 rounded-xl">
      <CardHeader className="flex flex-wrap w-full flex-row justify-between items-center gap-5 border-b border-zinc-700 px-6 py-4">
        <CardTitle className="flex items-center gap-2 text-lg font-semibold text-white">
          <Server className="w-5 h-5 text-purple-400" /> {/* Changed color for visual distinction */}
          Backend Configuration
        </CardTitle>
        <Button
          onClick={handleSaveBackendSettings}
          disabled={!hasBackendChanges || !validateBackendFields().isValid}
          className={`flex items-center gap-2 px-4 py-2 rounded-md transition-all duration-300 text-white text-sm font-medium
            ${
              hasBackendChanges && validateBackendFields().isValid
                ? "bg-gradient-to-r from-purple-600 to-indigo-600 hover:shadow-cyber"
                : "!bg-zinc-700 cursor-not-allowed"
            }
          `}
        >
          <Save className="w-4 h-4" />
          Save Backend Settings
        </Button>
      </CardHeader>
      <CardContent className="space-y-4 p-6"> {/* Added p-6 for consistency */}
        <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
          <div className="flex flex-col justify-center w-full text-center">
            <Label htmlFor="backendIP" className="text-sm text-gray-300">Backend IP Address</Label>
            <Input
              id="backendIP"
              className="mt-1 !bg-zinc-900 !text-white placeholder:text-gray-400 focus:ring-2 focus:ring-purple-600 focus:border-purple-600 border border-zinc-600"
              placeholder="e.g., 127.0.0.1"
              value={config?.backendIP || ''}
              onChange={(e) => setConfig(prev => ({ ...prev, backendIP: e.target.value }))}
            />
            {/* You'd add error display here if you manage `fieldErrors` locally */}
          </div>
          <div className="flex flex-col justify-center w-full text-center">
            <Label htmlFor="backendPort" className="text-sm text-gray-300">Backend Port</Label>
            <Input
              id="backendPort"
              type="number"
              className="mt-1 !bg-zinc-900 !text-white placeholder:text-gray-400 focus:ring-2 focus:ring-purple-600 focus:border-purple-600 border border-zinc-600"
              placeholder="e.g., 8787"
              value={config?.backendPort || ''}
              onChange={(e) => setConfig(prev => ({ ...prev, backendPort: e.target.value }))}
            />

             {/* You'd add error display here if you manage `fieldErrors` locally */}
          </div>
        </div>
        <div className="flex gap-4 justify-center w-full flex-col text-center pt-6">
          <Label htmlFor="apiPath" className="text-sm text-gray-300">
            API Path (Optional)
          </Label>
          <div className="mt-1 flex rounded shadow-sm flex-wrap justify-center gap-4  ">
            <span className="inline-flex items-center px-3 rounded border border-r-0 border-zinc-600 !bg-zinc-800 text-gray-400 font-semibold text-md">
              {backendConfig?.apiUrl}
            </span>
            <Button className="font-semibold text-md flex" onClick={testAPI}>
              <SearchCheck className="w-10 h-10 text-lg font-bold"/> Test API
            </Button>
          </div>
        </div>
      </CardContent>
    </Card>
  );
}