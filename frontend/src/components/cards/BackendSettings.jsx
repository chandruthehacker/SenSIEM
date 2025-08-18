// src/components/settings/BackendSettings.jsx
import React, { useMemo } from "react";
import {
  Card,
  CardHeader,
  CardTitle,
  CardContent,
} from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Label } from "@/components/ui/label";
import { Input } from "@/components/ui/input";
import { Server, SearchCheck } from "lucide-react";
import axios from "axios";

import backendConfig from "../../configs/config.json";

export function BackendSettings({ config, toast, showSuccessToast, showErrorModal }) {
  const currentBackendConfig = useMemo(() => ({
    backendIP: config?.backendIP,
    backendPort: config?.backendPort,
    apiUrl: config?.apiUrl,
  }), [config?.backendIP, config?.backendPort, config?.apiUrl]);

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
          <Server className="w-5 h-5 text-purple-400" />
          Backend Configuration
        </CardTitle>
        {/* Removed Save button */}
      </CardHeader>

      <CardContent className="space-y-4 p-6">
        <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
          <div className="flex flex-col justify-center w-full text-center">
            <Label htmlFor="backendIP" className="text-sm text-gray-300">Backend IP Address</Label>
            <Input
              id="backendIP"
              readOnly
              className="mt-1 !bg-zinc-900 !text-white cursor-not-allowed placeholder:text-gray-400 border border-zinc-600"
              value={config?.backendIP || ''}
            />
          </div>
          <div className="flex flex-col justify-center w-full text-center">
            <Label htmlFor="backendPort" className="text-sm text-gray-300">Backend Port</Label>
            <Input
              id="backendPort"
              type="number"
              readOnly
              className="mt-1 !bg-zinc-900 !text-white cursor-not-allowed placeholder:text-gray-400 border border-zinc-600"
              value={config?.backendPort || ''}
            />
          </div>
        </div>
        <div className="flex gap-4 justify-center w-full flex-col text-center pt-6">
          <Label htmlFor="apiPath" className="text-sm text-gray-300">
            API Path (Optional)
          </Label>
          <div className="mt-1 flex rounded shadow-sm flex-wrap justify-center gap-4">
            <span className="inline-flex items-center px-3 rounded border border-r-0 border-zinc-600 !bg-zinc-800 text-gray-400 font-semibold text-md">
              {backendConfig?.apiUrl}
            </span>
            <Button className="font-semibold text-md flex" onClick={testAPI}>
              <SearchCheck className="w-10 h-10 text-lg font-bold" /> Test API
            </Button>
          </div>
        </div>
      </CardContent>
    </Card>
  );
}
