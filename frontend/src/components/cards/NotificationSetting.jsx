// src/components/settings/NotificationSettings.jsx
import React, { useState, useEffect, useCallback, useMemo } from "react";
import {
  Card,
  CardHeader,
  CardTitle,
  CardContent,
} from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Label } from "@/components/ui/label";
import { Input } from "@/components/ui/input";
import {
  Dialog,
  DialogContent,
  DialogHeader,
  DialogTitle,
  DialogDescription,
  DialogFooter,
} from "@/components/ui/dialog";
import { Bell, Mail, Slack, Send, Save } from "lucide-react";

import backendConfig from "../../configs/config.json";

export function NotificationSettings({ config, setConfig, originalConfig, setOriginalConfig, toast, showSuccessToast, showErrorModal }) {
  const [showConfirmDisableModal, setShowConfirmDisableModal] = useState(false);
  const [pendingDisableType, setPendingDisableType] = useState(null);
  const [fieldErrors, setFieldErrors] = useState({});
  const [fieldStatus, setFieldStatus] = useState({});

  if (!config || !config.notificationSettings) {
    return null;
  }

  const notificationSettings = config.notificationSettings;


  const hasNotificationChanges = useMemo(() => {
    if (!originalConfig || !originalConfig.notificationSettings) return false; // Ensure originalConfig is also ready
    return JSON.stringify(notificationSettings) !== JSON.stringify(originalConfig.notificationSettings);
  }, [notificationSettings, originalConfig?.notificationSettings]);


  const validateField = useCallback((name, value, currentConfig) => {
    let error = "";
    const currentNotificationSettings = currentConfig?.notificationSettings || {};

    switch (name) {
      case "emailRecipient":
        if (currentNotificationSettings.emailEnabled && !value) {
          error = "Recipient email is required.";
        } else if (currentNotificationSettings.emailEnabled && !/\S+@\S+\.\S+/.test(value)) {
          error = "Please enter a valid email address.";
        }
        break;
      case "emailSender":
        if (currentNotificationSettings.emailEnabled && !value) {
          error = "Sender email is required.";
        } else if (currentNotificationSettings.emailEnabled && !/\S+@\S+\.\S/.test(value)) {
          error = "Please enter a valid email address.";
        }
        break;
      case "emailSmtpServer":
        if (currentNotificationSettings.emailEnabled && !value) {
          error = "SMTP Server is required.";
        }
        break;
      case "emailSmtpPort":
        if (currentNotificationSettings.emailEnabled && (!value || isNaN(Number(value)) || Number(value) <= 0)) {
          error = "SMTP Port is required and must be a positive number.";
        }
        break;
      case "emailPassword":
        if (currentNotificationSettings.emailEnabled && !value) {
          error = "Email password is required.";
        }
        break;
      case "slackWebhookUrl":
        if (currentNotificationSettings.slackEnabled && !value) {
          error = "Slack Webhook URL is required.";
        } else if (currentNotificationSettings.slackEnabled && !/^https:\/\/hooks\.slack\.com\//.test(value)) {
          error = "Please enter a valid Slack Webhook URL.";
        }
        break;
      case "telegramBotToken":
        if (currentNotificationSettings.telegramEnabled && !value) {
          error = "Telegram Bot Token is required.";
        }
        break;
      case "telegramChatId":
        if (currentNotificationSettings.telegramEnabled && !value) {
          error = "Telegram Chat ID is required.";
        }
        break;
      default:
        break;
    }
    return error;
  }, []);

  const validateNotificationFields = useCallback(() => {
    const errors = {};
    let isValid = true;

    if (!config || !notificationSettings) return false;

    if (notificationSettings.emailEnabled) {
      const emailFields = ["emailRecipient", "emailSender", "emailSmtpServer", "emailSmtpPort", "emailPassword"];
      emailFields.forEach(field => {
        const value = notificationSettings[field];
        const error = validateField(field, value, config); // Pass full config for context
        if (error) {
          errors[field] = error;
          isValid = false;
        }
      });
    }


    if (notificationSettings.slackEnabled) {
      const slackWebhookUrlError = validateField(
        "slackWebhookUrl",
        notificationSettings.slackWebhookUrl,
        config
      );
      if (slackWebhookUrlError) {
        errors.slackWebhookUrl = slackWebhookUrlError;
        isValid = false;
      }
    }

    if (notificationSettings.telegramEnabled) {
      const telegramFields = ["telegramBotToken", "telegramChatId"];
      telegramFields.forEach(field => {
        const value = notificationSettings[field];
        const error = validateField(field, value, config);
        if (error) {
          errors[field] = error;
          isValid = false;
        }
      });
    }

    setFieldErrors(errors);
    return isValid;
  }, [config, notificationSettings, validateField]); // Add notificationSettings to dependencies

  const handleChange = useCallback(
    (key, value) => {
      setConfig((prev) => {
        const prevNotificationSettings = prev?.notificationSettings || {};
        const newConfig = {
          ...prev,
          notificationSettings: {
            ...prevNotificationSettings,
            [key]: value,
          },
        };
        const error = validateField(key, value, newConfig);
        setFieldErrors((prevErrors) => ({ ...prevErrors, [key]: error }));
        return newConfig;
      });
    },
    [setConfig, validateField]
  );

  const handleSaveNotifications = async () => {
    const isValid = validateNotificationFields();
    if (!isValid) {
      toast.error("Please correct the errors in your notification settings.");
      return;
    }

    try {
      const response = await fetch(`${backendConfig?.apiUrl}/save-notification-settings`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify(notificationSettings),
      });

      if (!response.ok) {
        const errorData = await response.json();
        throw new Error(errorData.message || 'Failed to save notification settings on server.');
      }

      setOriginalConfig(prev => ({
        ...prev,
        notificationSettings: { ...notificationSettings }
      }));
      toast.success("Notification settings saved successfully!");
    } catch (error) {
      console.error("Error saving notification settings:", error);
      toast.error(`Failed to save notification settings: ${error.message || "Unknown error"}`);
    }
  };

  const handleDisableConfirm = useCallback(() => {
    if (!pendingDisableType) return;

    const cleared = {
      email: {
        emailEnabled: false,
        emailRecipient: "",
        emailSender: "",
        emailSmtpServer: "",
        emailSmtpPort: "587", // Default port
        emailPassword: "",
      },
      slack: {
        slackEnabled: false,
        slackWebhookUrl: "",
      },
      telegram: {
        telegramEnabled: false,
        telegramBotToken: "",
        telegramChatId: "",
      },
    };

    setConfig((prev) => ({
      ...prev,
      notificationSettings: {
        ...prev.notificationSettings,
        ...cleared[pendingDisableType],
      },
    }));

    setFieldErrors((prev) => {
      const newErrors = { ...prev };
      // Clear errors related to the disabled type
      if (pendingDisableType === "email") {
        delete newErrors.emailRecipient;
        delete newErrors.emailSender;
        delete newErrors.emailSmtpServer;
        delete newErrors.emailSmtpPort;
        delete newErrors.emailPassword;
      } else if (pendingDisableType === "slack") {
        delete newErrors.slackWebhookUrl;
      } else if (pendingDisableType === "telegram") {
        delete newErrors.telegramBotToken;
        delete newErrors.telegramChatId;
      }
      return newErrors;
    });

    setShowConfirmDisableModal(false);
    setPendingDisableType(null);
  }, [pendingDisableType, setConfig]);

  return (
    <>
      <Card className="!bg-zinc-900 text-white shadow-xl border border-zinc-800 rounded-xl">
        <CardHeader className="flex flex-wrap w-full flex-row justify-between items-center gap-5 border-b border-zinc-700 px-6 py-4">
          <CardTitle className="flex items-center gap-2 text-lg font-semibold text-white">
            <Bell className="w-5 h-5 text-primary" />
            Notification Settings
          </CardTitle>
          <Button
            onClick={handleSaveNotifications}
            disabled={!hasNotificationChanges || Object.values(fieldErrors).some(error => error)}
            className={`flex items-center gap-2 px-4 py-2 rounded-md transition-all duration-300 text-white text-sm font-medium
              ${
                hasNotificationChanges && !Object.values(fieldErrors).some(error => error)
                  ? "bg-gradient-to-r from-purple-600 to-indigo-600 hover:shadow-cyber"
                  : "!bg-zinc-700 cursor-not-allowed"
              }
            `}
          >
            <Save className="w-4 h-4" />
            Save Notification Settings
          </Button>
        </CardHeader>

        <CardContent className="space-y-6 p-6">
          {/* Email Notifications */}
          <div className="space-y-4 border border-zinc-700 !bg-zinc-800 p-5 rounded-lg shadow-sm">
            <div className="flex items-center justify-between p-4">
              <div className="flex items-center gap-2 text-white">
                <Mail className="w-5 h-5 text-cyan-400" />
                <Label htmlFor="emailEnabled" className="font-medium text-white hover:cursor-pointer">
                  Email Notifications
                </Label>
              </div>
              <Input
                id="emailEnabled"
                type="checkbox"
                checked={notificationSettings.emailEnabled}
                onChange={(e) => {
                  const checked = e.target.checked;
                  if (!checked) {
                    setPendingDisableType("email");
                    setShowConfirmDisableModal(true);
                  } else {
                    handleChange("emailEnabled", true); // Use handleChange for consistency
                  }
                }}
                className="w-5 h-5 accent-cyan-500 hover:cursor-pointer"
              />
            </div>

            {/* Content for email notifications - conditionally rendered but with a min-height for consistent spacing when empty */}
            {notificationSettings.emailEnabled && (
              <div className="space-y-3 p-4">
                <div>
                  <Label htmlFor="emailRecipient" className="text-sm text-gray-300">
                    Recipient Email
                  </Label>
                  <Input
                    id="emailRecipient"
                    type="email"
                    placeholder="recipient@example.com"
                    value={notificationSettings.emailRecipient || ''}
                    onChange={(e) => handleChange("emailRecipient", e.target.value)}
                    className={`mt-1 !bg-zinc-900 border text-white ${
                      fieldErrors["emailRecipient"] ? "border-red-500" : "border-zinc-600"
                    }`}
                  />
                  {fieldStatus["emailRecipient"] === "checking" && (
                    <p className="text-xs text-blue-400 mt-1">Checking...</p>
                  )}
                  {fieldErrors["emailRecipient"] && (
                    <p className="text-xs text-red-500 mt-1">
                      {fieldErrors["emailRecipient"]}
                    </p>
                  )}
                </div>

                <div>
                  <Label htmlFor="emailSender" className="text-sm text-gray-300">
                    Sender Email
                  </Label>
                  <Input
                    id="emailSender"
                    type="email"
                    placeholder="sender@example.com"
                    className={`mt-1 !bg-zinc-900 border text-white ${
                      fieldErrors["emailSender"] ? "border-red-500" : "border-zinc-600"
                    }`}
                    value={notificationSettings.emailSender || ''}
                    onChange={(e) => handleChange("emailSender", e.target.value)}
                  />
                  {fieldErrors["emailSender"] && (
                    <p className="text-xs text-red-500 mt-1">
                      {fieldErrors["emailSender"]}
                    </p>
                  )}
                </div>

                <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                  <div>
                    <Label htmlFor="emailSmtpServer" className="text-sm text-gray-300">
                      SMTP Server
                    </Label>
                    <Input
                      id="emailSmtpServer"
                      placeholder="smtp.example.com"
                      className={`mt-1 !bg-zinc-900 border text-white ${
                        fieldErrors["emailSmtpServer"] ? "border-red-500" : "border-zinc-600"
                      }`}
                      value={notificationSettings.emailSmtpServer || ''}
                      onChange={(e) => handleChange("emailSmtpServer", e.target.value)}
                    />
                    {fieldErrors["emailSmtpServer"] && (
                      <p className="text-xs text-red-500 mt-1">
                        {fieldErrors["emailSmtpServer"]}
                      </p>
                    )}
                  </div>
                  <div>
                    <Label htmlFor="emailSmtpPort" className="text-sm text-gray-300">
                      SMTP Port
                    </Label>
                    <Input
                      id="emailSmtpPort"
                      type="number"
                      placeholder="587"
                      className={`mt-1 !bg-zinc-900 border text-white ${
                        fieldErrors["emailSmtpPort"] ? "border-red-500" : "border-zinc-600"
                      }`}
                      value={notificationSettings.emailSmtpPort || ''}
                      onChange={(e) => handleChange("emailSmtpPort", e.target.value)}
                    />
                    {fieldErrors["emailSmtpPort"] && (
                      <p className="text-xs text-red-500 mt-1">
                        {fieldErrors["emailSmtpPort"]}
                      </p>
                    )}
                  </div>
                </div>

                <div>
                  <Label htmlFor="emailPassword" className="text-sm text-gray-300">
                    Email Password (App Password Recommended)
                  </Label>
                  <Input
                    id="emailPassword"
                    type="password"
                    placeholder="********"
                    className={`mt-1 !bg-zinc-900 border text-white ${
                      fieldErrors["emailPassword"] ? "border-red-500" : "border-zinc-600"
                    }`}
                    value={notificationSettings.emailPassword || ''}
                    onChange={(e) => handleChange("emailPassword", e.target.value)}
                  />
                  {fieldErrors["emailPassword"] && (
                    <p className="text-xs text-red-500 mt-1">
                      {fieldErrors["emailPassword"]}
                    </p>
                  )}
                </div>
              </div>
            )}
          </div>

          {/* Slack Notifications */}
          <div className="space-y-4 border border-zinc-700 !bg-zinc-800 p-5 rounded-lg shadow-sm">
            <div className="flex items-center justify-between p-4">
              <div className="flex items-center gap-2 text-white">
                <Slack className="w-5 h-5 text-green-400" />
                <Label htmlFor="slackEnabled" className="font-medium text-white hover:cursor-pointer">
                  Slack Notifications
                </Label>
              </div>
              <Input
                id="slackEnabled"
                type="checkbox"
                checked={notificationSettings.slackEnabled}
                onChange={(e) => {
                  const checked = e.target.checked;
                  if (!checked) {
                    setPendingDisableType("slack");
                    setShowConfirmDisableModal(true);
                  } else {
                    handleChange("slackEnabled", true); // Use handleChange for consistency
                  }
                }}
                className="w-5 h-5 accent-green-500 hover:cursor-pointer"
              />
            </div>

            {notificationSettings.slackEnabled && (
              <div className="p-4">
                <Label htmlFor="slackWebhookUrl" className="text-sm text-gray-300">
                  Slack Webhook URL
                </Label>
                <Input
                  id="slackWebhookUrl"
                  type="url"
                  className={`mt-1 !bg-zinc-900 border text-white ${
                    fieldErrors["slackWebhookUrl"] ? "border-red-500" : "border-zinc-600"
                  }`}
                  placeholder="https://hooks.slack.com/services/T00000000/B00000000/XXXXXXXXXXXXXXXXXXXXXXXX"
                  value={notificationSettings.slackWebhookUrl || ''}
                  onChange={(e) => handleChange("slackWebhookUrl", e.target.value)}
                />
                {fieldStatus["slackWebhookUrl"] === "checking" && (
                  <p className="text-xs text-blue-400 mt-1">Checking...</p>
                )}
                {fieldErrors["slackWebhookUrl"] && (
                  <p className="text-xs text-red-500 mt-1">
                    {fieldErrors["slackWebhookUrl"]}
                  </p>
                )}
              </div>
            )}
          </div>

          {/* Telegram Notifications */}
          <div className="space-y-4 border border-zinc-700 !bg-zinc-800 p-5 rounded-lg shadow-sm">
            <div className="flex items-center justify-between p-4">
              <div className="flex items-center gap-2 text-white">
                <Send className="w-5 h-5 text-indigo-400" />
                <Label htmlFor="telegramEnabled" className="font-medium text-white hover:cursor-pointer">
                  Telegram Notifications
                </Label>
              </div>
              <Input
                id="telegramEnabled"
                type="checkbox"
                checked={notificationSettings.telegramEnabled}
                onChange={(e) => {
                  const checked = e.target.checked;
                  if (!checked) {
                    setPendingDisableType("telegram");
                    setShowConfirmDisableModal(true);
                  } else {
                    handleChange("telegramEnabled", true); // Use handleChange for consistency
                  }
                }}
                className="w-5 h-5 accent-indigo-500 hover:cursor-pointer"
              />
            </div>

            {notificationSettings.telegramEnabled && (
              <div className="space-y-3  p-4">
                <div>
                  <Label htmlFor="telegramBotToken" className="text-sm text-gray-300">
                    Telegram Bot Token
                  </Label>
                  <Input
                    id="telegramBotToken"
                    placeholder="Enter bot token"
                    value={notificationSettings.telegramBotToken || ''}
                    onChange={(e) => handleChange("telegramBotToken", e.target.value)}
                    className={`mt-1 !bg-zinc-900 border text-white ${
                      fieldErrors["telegramBotToken"] ? "border-red-500" : "border-zinc-600"
                    }`}
                  />
                  {fieldErrors["telegramBotToken"] && (
                    <p className="text-xs text-red-500 mt-1">
                      {fieldErrors["telegramBotToken"]}
                    </p>
                  )}
                </div>

                <div>
                  <Label htmlFor="telegramChatId" className="text-sm text-gray-300">
                    Telegram Chat ID
                  </Label>
                  <Input
                    id="telegramChatId"
                    placeholder="Enter chat ID"
                    value={notificationSettings.telegramChatId || ''}
                    onChange={(e) => handleChange("telegramChatId", e.target.value)}
                    className={`mt-1 !bg-zinc-900 border text-white ${
                      fieldErrors["telegramChatId"] ? "border-red-500" : "border-zinc-600"
                    }`}
                  />
                  {fieldErrors["telegramChatId"] && (
                    <p className="text-xs text-red-500 mt-1">
                      {fieldErrors["telegramChatId"]}
                    </p>
                  )}
                </div>
              </div>
            )}
          </div>
        </CardContent>
      </Card>

      <Dialog open={showConfirmDisableModal} onOpenChange={setShowConfirmDisableModal}>
        <DialogContent>
          <DialogHeader>
            <DialogTitle>Disable Notification</DialogTitle>
            <DialogDescription>
              Are you sure you want to disable{" "}
              <span className="capitalize font-medium">{pendingDisableType}</span>{" "}
              notifications? All related fields will be cleared.
            </DialogDescription>
          </DialogHeader>
          <DialogFooter>
            <Button variant="outline" onClick={() => setShowConfirmDisableModal(false)}>
              Cancel
            </Button>
            <Button
              variant="destructive"
              onClick={handleDisableConfirm} // Use the new useCallback for clarity
            >
              Disable
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </>
  );
}