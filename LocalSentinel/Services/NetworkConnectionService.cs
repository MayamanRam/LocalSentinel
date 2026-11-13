using LocalSentinel.Models;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Net;
using System.Net.NetworkInformation;
using System.Runtime.InteropServices;

namespace LocalSentinel.Services
{
    public static class NetworkConnectionService
    {
        private const int AfInet = 2;
        private const int AfInet6 = 23;
        private const uint ErrorInsufficientBuffer = 122;

        private enum TcpTableClass
        {
            OwnerPidAll = 5
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct MibTcpRowOwnerPid
        {
            public uint State;
            public uint LocalAddress;
            public uint LocalPort;
            public uint RemoteAddress;
            public uint RemotePort;
            public uint OwningPid;
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct MibTcp6RowOwnerPid
        {
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 16)]
            public byte[] LocalAddress;
            public uint LocalScopeId;
            public uint LocalPort;
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 16)]
            public byte[] RemoteAddress;
            public uint RemoteScopeId;
            public uint RemotePort;
            public uint State;
            public uint OwningPid;
        }

        [DllImport("iphlpapi.dll", SetLastError = true)]
        private static extern uint GetExtendedTcpTable(
            IntPtr tcpTable,
            ref int size,
            bool order,
            int ipVersion,
            TcpTableClass tableClass,
            uint reserved
        );

        public static List<NetworkEventRecord> GetActiveTcpConnections()
        {
            var results = new List<NetworkEventRecord>();

            try
            {
                ReadIpv4Connections(results);
            }
            catch
            {
                // Fallback gracefully on platform inspection errors
            }

            try
            {
                ReadIpv6Connections(results);
            }
            catch
            {
                // Fallback gracefully
            }

            return results;
        }

        public static string GetConnectionKey(NetworkEventRecord record)
        {
            if (record == null)
            {
                return string.Empty;
            }

            return $"{record.Protocol}|{record.LocalAddress}|{record.LocalPort}|{record.RemoteAddress}|{record.RemotePort}|{record.ProcessId}";
        }

        private static void ReadIpv4Connections(List<NetworkEventRecord> results)
        {
            int size = 0;
            uint firstResult = GetExtendedTcpTable(IntPtr.Zero, ref size, true, AfInet, TcpTableClass.OwnerPidAll, 0);

            if (firstResult != ErrorInsufficientBuffer || size <= 0)
            {
                return;
            }

            IntPtr buffer = Marshal.AllocHGlobal(size);
            try
            {
                uint result = GetExtendedTcpTable(buffer, ref size, true, AfInet, TcpTableClass.OwnerPidAll, 0);
                if (result != 0)
                {
                    return;
                }

                int rowCount = Marshal.ReadInt32(buffer);
                int rowSize = Marshal.SizeOf<MibTcpRowOwnerPid>();
                IntPtr rowPointer = IntPtr.Add(buffer, sizeof(int));

                for (int i = 0; i < rowCount; i++)
                {
                    var row = Marshal.PtrToStructure<MibTcpRowOwnerPid>(rowPointer);
                    AddIpv4Row(results, row);
                    rowPointer = IntPtr.Add(rowPointer, rowSize);
                }
            }
            finally
            {
                Marshal.FreeHGlobal(buffer);
            }
        }

        private static void AddIpv4Row(List<NetworkEventRecord> results, MibTcpRowOwnerPid row)
        {
            var state = (TcpState)row.State;
            int remotePort = ConvertPort(row.RemotePort);

            if (state == TcpState.Listen || remotePort == 0)
            {
                return;
            }

            int processId = unchecked((int)row.OwningPid);
            string localIp = new IPAddress(BitConverter.GetBytes(row.LocalAddress)).ToString();
            string remoteIp = new IPAddress(BitConverter.GetBytes(row.RemoteAddress)).ToString();

            results.Add(new NetworkEventRecord
            {
                Timestamp = DateTime.Now,
                Protocol = "TCPv4",
                LocalAddress = localIp,
                LocalPort = ConvertPort(row.LocalPort),
                RemoteAddress = remoteIp,
                RemotePort = remotePort,
                ConnectionState = state.ToString(),
                ProcessId = processId,
                ProcessName = GetProcessName(processId)
            });
        }

        private static void ReadIpv6Connections(List<NetworkEventRecord> results)
        {
            int size = 0;
            uint firstResult = GetExtendedTcpTable(IntPtr.Zero, ref size, true, AfInet6, TcpTableClass.OwnerPidAll, 0);

            if (firstResult != ErrorInsufficientBuffer || size <= 0)
            {
                return;
            }

            IntPtr buffer = Marshal.AllocHGlobal(size);
            try
            {
                uint result = GetExtendedTcpTable(buffer, ref size, true, AfInet6, TcpTableClass.OwnerPidAll, 0);
                if (result != 0)
                {
                    return;
                }

                int rowCount = Marshal.ReadInt32(buffer);
                int rowSize = Marshal.SizeOf<MibTcp6RowOwnerPid>();
                IntPtr rowPointer = IntPtr.Add(buffer, sizeof(int));

                for (int i = 0; i < rowCount; i++)
                {
                    var row = Marshal.PtrToStructure<MibTcp6RowOwnerPid>(rowPointer);
                    AddIpv6Row(results, row);
                    rowPointer = IntPtr.Add(rowPointer, rowSize);
                }
            }
            finally
            {
                Marshal.FreeHGlobal(buffer);
            }
        }

        private static void AddIpv6Row(List<NetworkEventRecord> results, MibTcp6RowOwnerPid row)
        {
            var state = (TcpState)row.State;
            int remotePort = ConvertPort(row.RemotePort);

            if (state == TcpState.Listen || remotePort == 0 || row.LocalAddress == null || row.RemoteAddress == null)
            {
                return;
            }

            int processId = unchecked((int)row.OwningPid);
            string localIp = new IPAddress(row.LocalAddress, row.LocalScopeId).ToString();
            string remoteIp = new IPAddress(row.RemoteAddress, row.RemoteScopeId).ToString();

            results.Add(new NetworkEventRecord
            {
                Timestamp = DateTime.Now,
                Protocol = "TCPv6",
                LocalAddress = localIp,
                LocalPort = ConvertPort(row.LocalPort),
                RemoteAddress = remoteIp,
                RemotePort = remotePort,
                ConnectionState = state.ToString(),
                ProcessId = processId,
                ProcessName = GetProcessName(processId)
            });
        }

        public static int ConvertPort(uint port)
        {
            return (int)(((port & 0x000000FF) << 8) | ((port & 0x0000FF00) >> 8));
        }

        public static string? GetProcessName(int processId)
        {
            try
            {
                using var process = Process.GetProcessById(processId);
                return process.ProcessName;
            }
            catch
            {
                return null;
            }
        }
    }
}
