using LocalSentinel.Models;
using System;
using System.Collections.Generic;
using System.Management;

namespace LocalSentinel.Services
{
    public static class UsbDeviceService
    {
        public static List<UsbEventRecord> GetConnectedUsbStorageDevices()
        {
            var devices = new List<UsbEventRecord>();

            try
            {
                const string query = "SELECT Model, SerialNumber, PNPDeviceID FROM Win32_DiskDrive WHERE InterfaceType='USB'";
                using var searcher = new ManagementObjectSearcher(query);
                using var results = searcher.Get();

                foreach (ManagementObject device in results)
                {
                    try
                    {
                        devices.Add(new UsbEventRecord
                        {
                            DeviceName = device["Model"]?.ToString()?.Trim() ?? "USB storage device",
                            SerialNumber = device["SerialNumber"]?.ToString()?.Trim(),
                            PnpDeviceId = device["PNPDeviceID"]?.ToString()?.Trim()
                        });
                    }
                    catch
                    {
                        // Ignore individual device property read errors
                    }
                }
            }
            catch
            {
                // WMI service may be stopped or query permissions restricted
            }

            return devices;
        }

        public static string GetDeviceKey(UsbEventRecord device)
        {
            if (device == null)
            {
                return string.Empty;
            }

            if (!string.IsNullOrWhiteSpace(device.PnpDeviceId))
            {
                return device.PnpDeviceId;
            }

            if (!string.IsNullOrWhiteSpace(device.SerialNumber))
            {
                return $"{device.DeviceName}|{device.SerialNumber}";
            }

            return device.DeviceName;
        }
    }
}
