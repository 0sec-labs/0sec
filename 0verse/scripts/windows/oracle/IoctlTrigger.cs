// IoctlTrigger.cs — 0verse Windows kernel-oracle trigger (defensive bug-detection harness).
//
// Drives ONE directed DeviceIoControl (code + flat buffer) at a statically-located
// sink and reports the outcome as a single machine-parseable marker line
// (0VERSE-TRIGGER-JSON:{...}). No fuzzing, no loops, no exploitation primitives:
// one open, one IOCTL, one report. Compiled in-guest with the in-box
// C:\Windows\Microsoft.NET\Framework64\v4.0.30319\csc.exe (no toolchain dependency);
// keep the source C# 5-compatible (no interpolation, no out-var, no tuples).
//
// Buffer shapes come from the static triage record (see
// benchmarks/windows_driver_corpus/iqvw64e-ioctl-map.json). For METHOD_NEITHER
// drivers (iqvw64e) the kernel reads lpInBuffer raw AND writes results back into
// lpInBuffer, so the post-call in-buffer bytes are reported too.
using System;
using System.Globalization;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;

internal static class IoctlTrigger
{
    private const uint GenericRead = 0x80000000;
    private const uint GenericWrite = 0x40000000;
    private const uint FileShareReadWrite = 0x3;
    private const uint OpenExisting = 3;

    [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    private static extern IntPtr CreateFile(
        string lpFileName, uint dwDesiredAccess, uint dwShareMode,
        IntPtr lpSecurityAttributes, uint dwCreationDisposition,
        uint dwFlagsAndAttributes, IntPtr hTemplateFile);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool DeviceIoControl(
        IntPtr hDevice, uint dwIoControlCode,
        byte[] lpInBuffer, uint nInBufferSize,
        byte[] lpOutBuffer, uint nOutBufferSize,
        out uint lpBytesReturned, IntPtr lpOverlapped);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool CloseHandle(IntPtr hObject);

    private static string Sha256Hex(byte[] data)
    {
        using (SHA256 sha = SHA256.Create())
        {
            byte[] hash = sha.ComputeHash(data);
            StringBuilder sb = new StringBuilder(hash.Length * 2);
            for (int i = 0; i < hash.Length; i++) sb.Append(hash[i].ToString("x2"));
            return sb.ToString();
        }
    }

    private static string HexPrefix(byte[] data, int max)
    {
        int n = Math.Min(data.Length, max);
        StringBuilder sb = new StringBuilder(n * 2);
        for (int i = 0; i < n; i++) sb.Append(data[i].ToString("x2"));
        return sb.ToString();
    }

    private static byte[] ParseHex(string hex)
    {
        string clean = hex.Replace(" ", string.Empty).Replace("0x", string.Empty);
        if (clean.Length % 2 != 0) throw new ArgumentException("odd-length hex input");
        byte[] bytes = new byte[clean.Length / 2];
        for (int i = 0; i < bytes.Length; i++)
            bytes[i] = byte.Parse(clean.Substring(i * 2, 2), NumberStyles.HexNumber);
        return bytes;
    }

    private static uint ParseUInt(string s)
    {
        s = s.Trim();
        if (s.StartsWith("0x", StringComparison.OrdinalIgnoreCase))
            return Convert.ToUInt32(s.Substring(2), 16);
        return Convert.ToUInt32(s, 10);
    }

    // usage: ioctl_trigger.exe <device> <ioctl> <hex:<hexbytes> | -> [outLen]
    private static int Main(string[] args)
    {
        if (args.Length < 3)
        {
            Console.Error.WriteLine("usage: ioctl_trigger.exe <device> <ioctl> <hex:<hex>|-> [outLen]");
            return 3;
        }
        string device = args[0];
        uint ioctl = ParseUInt(args[1]);
        byte[] inBuf;
        if (args[2] == "-") inBuf = new byte[0];
        else if (args[2].StartsWith("hex:", StringComparison.OrdinalIgnoreCase)) inBuf = ParseHex(args[2].Substring(4));
        else throw new ArgumentException("input must be '-' or an inline hex: payload");
        uint outLen = args.Length > 3 ? ParseUInt(args[3]) : 0;

        IntPtr h = CreateFile(device, GenericRead | GenericWrite, FileShareReadWrite,
            IntPtr.Zero, OpenExisting, 0, IntPtr.Zero);
        if (h == new IntPtr(-1))
        {
            int openErr = Marshal.GetLastWin32Error();
            Console.WriteLine("0VERSE-TRIGGER-JSON:{\"device\":" + JsonStr(device)
                + ",\"open_error\":" + openErr + "}");
            return 2;
        }

        byte[] outBuf = new byte[outLen];
        uint returned = 0;
        // Hash the DRIVEN bytes BEFORE the call: METHOD_NEITHER drivers write
        // results back into lpInBuffer, so a post-call hash binds the mutated
        // buffer, not the driven one (measured on the first M0 run).
        string inSha256Pre = Sha256Hex(inBuf);
        bool ok = DeviceIoControl(h, ioctl, inBuf, (uint)inBuf.Length, outBuf, outLen, out returned, IntPtr.Zero);
        int err = ok ? 0 : Marshal.GetLastWin32Error();
        CloseHandle(h);

        StringBuilder json = new StringBuilder();
        json.Append("{\"device\":").Append(JsonStr(device));
        json.Append(",\"ioctl\":\"0x").Append(ioctl.ToString("x8")).Append("\"");
        json.Append(",\"in_sha256\":\"").Append(inSha256Pre).Append("\"");
        json.Append(",\"in_len\":").Append(inBuf.Length);
        json.Append(",\"call_ok\":").Append(ok ? "true" : "false");
        json.Append(",\"win32_error\":").Append(err);
        json.Append(",\"bytes_returned\":").Append(returned);
        json.Append(",\"in_post_hex\":\"").Append(HexPrefix(inBuf, 64)).Append("\"");
        json.Append(",\"out_sha256\":\"").Append(outLen > 0 ? Sha256Hex(outBuf) : "").Append("\"");
        json.Append(",\"out_post_hex\":\"").Append(HexPrefix(outBuf, 64)).Append("\"");
        json.Append("}");
        Console.WriteLine("0VERSE-TRIGGER-JSON:" + json);
        return ok ? 0 : 2;
    }

    private static string JsonStr(string s)
    {
        return "\"" + s.Replace("\\", "\\\\").Replace("\"", "\\\"") + "\"";
    }
}
