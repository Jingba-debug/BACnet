/**************************************************************************
* .NET 8 port of BACnetTransportSecureConnect
* Original logic by Frederic Chaxel / Yabe BACnet stack
**************************************************************************/

using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.IO.BACnet.Transport;
using System.Net.Security;
using System.Net.WebSockets;
using System.Security.Authentication;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using System.Xml.Serialization;
using System.Security.Cryptography;

namespace System.IO.BACnet
{
    public enum BACnetSCState
    {
        IDLE,
        AWAITING_WEBSOCKET,
        AWAITING_REQUEST,
        AWAITING_ACCEPT,
        CONNECTED,
        DISCONNECTING
    }

    public sealed class BACnetTransportSecureConnect : IBacnetTransport, IDisposable
    {
        private readonly object _sync = new();
        private BACnetSCState state = BACnetSCState.IDLE;
        public BACnetSCState State => state;

        private ClientWebSocket? _webSocket;
        private CancellationTokenSource? _cts;
        private Task? _receiveTask;
        private Task? _connectTask;

        private readonly BACnetSCConfigChannel configuration;

        private readonly byte[] myVMAC = new byte[6];
        private readonly byte[] RemoteVMAC = new byte[6];
        private int DuplicateVMACCount = 0;

        public int HeaderLength => BVLC_HEADER_LENGTH;
        public const byte BVLC_HEADER_LENGTH = 10;
        public const BacnetMaxAdpu BVLC_MAX_APDU = BacnetMaxAdpu.MAX_APDU1476;

        public BacnetMaxAdpu MaxAdpuLength => BVLC_MAX_APDU;
        public byte MaxInfoFrames { get => 0xff; set { } }
        public int MaxBufferLength => m_max_payload;
        public BacnetAddressTypes Type => BacnetAddressTypes.SC;

        private int m_max_payload = 1500;
        private readonly List<byte[]> AwaitingFrames = new();
        private bool ConfigOK = false;

        private X509Chain CertValidationChain = new();

        public event MessageRecievedHandler? MessageRecieved;
        public event EventHandler? OnChannelConnected;
        public event EventHandler? OnChannelDisconnected;

        public BACnetTransportSecureConnect(BACnetSCConfigChannel config)
        {
            configuration = config;

            if (configuration.VMAC == null || configuration.VMAC.Length != 6)
            {
                FillRandomBytes(myVMAC);
                myVMAC[0] = (byte)((myVMAC[0] & 0xF0) | 0x02);
            }
            else
            {
                Array.Copy(configuration.VMAC, myVMAC, 6);
            }

            if (configuration.UseTLS)
            {
                if (!string.IsNullOrWhiteSpace(configuration.OwnCertificateFile) && configuration.OwnCertificate == null)
                {
                    try
                    {
                        configuration.OwnCertificate = new X509Certificate2(
                            configuration.OwnCertificateFile,
                            configuration.OwnCertificateFilePassword);
                    }
                    catch (Exception e)
                    {
                        Trace.TraceError("Error with app own certificate file: " + e.Message);
                    }
                }

                if (configuration.OwnCertificate == null)
                    Trace.TraceWarning("BACnet/SC: Warning app without certificate");

                if (configuration.OwnCertificate != null && !configuration.OwnCertificate.HasPrivateKey)
                    Trace.TraceWarning("BACnet/SC: Warning the app own certificate is without a private key");

                if (configuration.ValidateHubCertificate && configuration.ThrustedCertificates == null)
                {
                    try
                    {
                        if (!string.IsNullOrWhiteSpace(configuration.ThrustedCertificatesFile))
                        {
                            configuration.ThrustedCertificates = new X509Certificate2Collection();

                            try
                            {
                                configuration.ThrustedCertificates.Import(configuration.ThrustedCertificatesFile);
                            }
                            catch
                            {
                                // ignore: multi-cert PEM often fails here, manual parse below
                            }

                            StringBuilder sb = new();
                            using StreamReader sr = new(configuration.ThrustedCertificatesFile);
                            string? l;
                            bool begin = false;

                            do
                            {
                                l = sr.ReadLine();

                                if (l != null && l.Contains("-----BEGIN CERTIFICATE-----"))
                                {
                                    begin = true;
                                }
                                else if (l != null && l.Contains("-----END CERTIFICATE-----"))
                                {
                                    try
                                    {
                                        X509Certificate2 cert = new(Convert.FromBase64String(sb.ToString()));
                                        if (!configuration.ThrustedCertificates.Contains(cert))
                                            configuration.ThrustedCertificates.Add(cert);
                                    }
                                    catch
                                    {
                                    }

                                    sb.Clear();
                                    begin = false;
                                }
                                else if (!string.IsNullOrWhiteSpace(l) && l.Length % 4 == 0 && begin)
                                {
                                    sb.Append(l);
                                }

                            } while (l != null);
                        }
                    }
                    catch
                    {
                    }
                }

                if (configuration.ValidateHubCertificate)
                {
                    CertValidationChain = new X509Chain();
                    CertValidationChain.ChainPolicy.RevocationMode = X509RevocationMode.NoCheck;
                    CertValidationChain.ChainPolicy.VerificationFlags = X509VerificationFlags.AllowUnknownCertificateAuthority;

                    if (!string.IsNullOrWhiteSpace(configuration.OwnCertificateFile))
                    {
                        try
                        {
                            X509Certificate2Collection validationCollection = new();
                            validationCollection.Import(
                                configuration.OwnCertificateFile,
                                configuration.OwnCertificateFilePassword,
                                X509KeyStorageFlags.DefaultKeySet);

                            if (configuration.OwnCertificate != null)
                            {
                                foreach (X509Certificate2 cert in validationCollection)
                                {
                                    if (cert.Subject == configuration.OwnCertificate.Issuer)
                                        CertValidationChain.ChainPolicy.ExtraStore.Add(cert);
                                }

                                CertValidationChain.ChainPolicy.ExtraStore.Add(configuration.OwnCertificate);
                            }
                        }
                        catch (Exception ex)
                        {
                            Trace.TraceWarning("BACnet/SC: certificate validation setup warning: " + ex.Message);
                        }
                    }

                    if (configuration.ThrustedCertificates != null)
                        CertValidationChain.ChainPolicy.ExtraStore.AddRange(configuration.ThrustedCertificates);
                }
            }

            ConfigOK = true;
        }

        public override int GetHashCode() => configuration.primaryHubURI.GetHashCode();

        public override string ToString() => "Secure Connect : " + configuration.primaryHubURI;

        public void Start()
        {
            Open();
        }

        private void Open()
        {
            if (!ConfigOK)
                return;

            lock (_sync)
            {
                if (_connectTask != null && !_connectTask.IsCompleted)
                    return;

                _cts = new CancellationTokenSource();
                _connectTask = Task.Run(() => ConnectAndReceiveLoopAsync(_cts.Token));
            }
        }

        private async Task ConnectAndReceiveLoopAsync(CancellationToken cancellationToken)
        {
            while (!cancellationToken.IsCancellationRequested)
            {
                try
                {
                    state = BACnetSCState.AWAITING_WEBSOCKET;

                    _webSocket?.Dispose();
                    _webSocket = BuildWebSocket();

                    Uri uri = new(configuration.primaryHubURI.Trim());

                    await _webSocket.ConnectAsync(uri, cancellationToken).ConfigureAwait(false);

                    Websocket_OnOpen();
                    _receiveTask = ReceiveLoopAsync(_webSocket, cancellationToken);
                    await _receiveTask.ConfigureAwait(false);
                }
                catch (OperationCanceledException)
                {
                    break;
                }
                catch (Exception ex)
                {
                    Websocket_OnError(ex);
                }

                Websocket_OnClose();

                if (cancellationToken.IsCancellationRequested)
                    break;

                if (configuration.AutoReconnectDelay > -1)
                {
                    state = BACnetSCState.AWAITING_WEBSOCKET;
                    try
                    {
                        await Task.Delay(TimeSpan.FromSeconds(configuration.AutoReconnectDelay), cancellationToken)
                            .ConfigureAwait(false);
                    }
                    catch (OperationCanceledException)
                    {
                        break;
                    }
                }
                else if (DuplicateVMACCount > 0 && DuplicateVMACCount < 3)
                {
                    Trace.TraceInformation("BACnet/SC Duplicate VMAC: trying with a random one");
                    state = BACnetSCState.AWAITING_WEBSOCKET;
                    await Task.Delay(250, cancellationToken).ConfigureAwait(false);
                }
                else
                {
                    state = BACnetSCState.IDLE;
                    break;
                }
            }
        }

        private ClientWebSocket BuildWebSocket()
        {
            ClientWebSocket ws = new();

            ws.Options.AddSubProtocol(configuration.DirectConnect
                ? "dc.bsc.bacnet.org"
                : "hub.bsc.bacnet.org");

            if (configuration.UseTLS)
            {
                if (configuration.OwnCertificate != null)
                    ws.Options.ClientCertificates ??= new X509Certificate2Collection();

                if (configuration.OwnCertificate != null)
                    ws.Options.ClientCertificates.Add(configuration.OwnCertificate);

                #if NET5_0_OR_GREATER
                ws.Options.RemoteCertificateValidationCallback = RemoteCertificateValidationCallback;
                #endif
            }

            return ws;
        }

        private async Task ReceiveLoopAsync(ClientWebSocket ws, CancellationToken cancellationToken)
        {
            byte[] buffer = new byte[65535];
            using MemoryStream ms = new();

            while (ws.State == WebSocketState.Open && !cancellationToken.IsCancellationRequested)
            {
                ms.SetLength(0);

                WebSocketReceiveResult result;
                do
                {
                    result = await ws.ReceiveAsync(new ArraySegment<byte>(buffer), cancellationToken).ConfigureAwait(false);

                    if (result.MessageType == WebSocketMessageType.Close)
                    {
                        try
                        {
                            if (ws.State == WebSocketState.Open || ws.State == WebSocketState.CloseReceived)
                            {
                                await ws.CloseAsync(
                                    WebSocketCloseStatus.NormalClosure,
                                    "Closing",
                                    cancellationToken).ConfigureAwait(false);
                            }
                        }
                        catch
                        {
                        }

                        return;
                    }

                    ms.Write(buffer, 0, result.Count);

                } while (!result.EndOfMessage);

                OnReceiveData(ms.ToArray());
            }
        }

        private bool RemoteCertificateValidationCallback(
            object? sender,
            X509Certificate? certificate,
            X509Chain? chain,
            SslPolicyErrors sslPolicyErrors)
        {
            if (!configuration.ValidateHubCertificate)
                return true;

            if (certificate == null)
                return false;

            if (configuration.ThrustedCertificates != null && configuration.ThrustedCertificates.Contains(certificate))
                return true;

            if (CertValidationChain != null && certificate is X509Certificate2 x509)
            {
                if (CertValidationChain.Build(x509))
                {
                    if (CertValidationChain.ChainElements.Count > 1)
                    {
                        X509Certificate2 root =
                            CertValidationChain.ChainElements[CertValidationChain.ChainElements.Count - 1].Certificate;

                        if (CertValidationChain.ChainPolicy.ExtraStore.Contains(root))
                            return true;
                    }
                }
            }

            Trace.TraceInformation("BACnet/SC: Remote certificate rejected");
            return false;
        }

        private void Websocket_OnOpen()
        {
            state = BACnetSCState.AWAITING_ACCEPT;
            Trace.TraceInformation("BACnet/SC WebSocket established");
            BVLC_SC_SendConnectRequest();
        }

        private void Websocket_OnError(Exception ex)
        {
            if (DuplicateVMACCount == 0)
            {
                Trace.TraceError("BACnet/SC Error: " + ex.Message);
                state = BACnetSCState.IDLE;
            }
        }

        private void Websocket_OnClose()
        {
            Trace.TraceInformation("BACnet/SC Close");
            OnChannelDisconnected?.Invoke(this, EventArgs.Empty);
        }

        private void Close()
        {
            if (state == BACnetSCState.IDLE)
                return;

            state = BACnetSCState.DISCONNECTING;

            try
            {
                BVLC_SC_SendSimpleBVLCMsg(BacnetBvlcSCMessage.BVLC_DISCONNECT_REQUEST, 0, 0);
            }
            catch
            {
            }

            Task.Run(async () =>
            {
                try
                {
                    await Task.Delay(2000).ConfigureAwait(false);

                    if (_webSocket != null &&
                        (_webSocket.State == WebSocketState.Open || _webSocket.State == WebSocketState.CloseReceived))
                    {
                        await _webSocket.CloseAsync(
                            WebSocketCloseStatus.NormalClosure,
                            "Disconnect",
                            CancellationToken.None).ConfigureAwait(false);
                    }
                }
                catch
                {
                }
                finally
                {
                    try { _cts?.Cancel(); } catch { }
                    try { _webSocket?.Dispose(); } catch { }
                    state = BACnetSCState.IDLE;
                }
            });
        }

        public void Dispose()
        {
            try
            {
                ConfigOK = false;
                configuration.AutoReconnectDelay = -1;
                Close();
                _cts?.Dispose();
                _webSocket?.Dispose();
            }
            catch
            {
            }
        }

        private void OnReceiveData(byte[] local_buffer)
        {
            try
            {
                int rx = local_buffer.Length;

                if (rx < 4)
                {
                    Trace.WriteLine("Unknown BVLC header");
                    return;
                }

                try
                {
                    BacnetAddress remote_address = new(BacnetAddressTypes.SC, null);
                    int headerLength = BVLC_SC_Decode(
                        local_buffer,
                        0,
                        out BacnetBvlcSCMessage function,
                        out int msg_length,
                        remote_address);

                    if (function == BacnetBvlcSCMessage.BVLC_CONNECT_ACCEPT)
                    {
                        Trace.TraceInformation("BACnet/SC connected");
                        state = BACnetSCState.CONNECTED;
                        OnChannelConnected?.Invoke(this, EventArgs.Empty);
                    }

                    if (headerLength == 0)
                        return;

                    if (headerLength == -1)
                    {
                        Trace.WriteLine("Unknown BVLC header");
                        return;
                    }

                    if (function == BacnetBvlcSCMessage.BVLC_ENCASULATED_NPDU)
                    {
                        if (configuration.DirectConnect)
                        {
                            Array.Copy(RemoteVMAC, remote_address.VMac, 6);
                            remote_address.adr = remote_address.VMac;
                        }

                        if (MessageRecieved != null && rx > headerLength)
                            MessageRecieved(this, local_buffer, headerLength, rx - headerLength, remote_address);
                    }
                }
                catch (Exception ex)
                {
                    Trace.TraceError("Exception in WebSocket OnReceiveData: " + ex.Message);
                }
            }
            catch (Exception ex)
            {
                Trace.TraceError("Exception in WebSocket OnReceiveData: " + ex.Message);
            }
        }

        public bool WaitForAllTransmits(int timeout)
        {
            return true;
        }

        private int Send(byte[] buffer)
        {
            try
            {
                if (_webSocket == null || _webSocket.State != WebSocketState.Open)
                    return 0;

                var segment = new ArraySegment<byte>(buffer);

                _webSocket.SendAsync(segment, WebSocketMessageType.Binary, true, CancellationToken.None)
                    .GetAwaiter()
                    .GetResult();

                return buffer.Length;
            }
            catch
            {
                return 0;
            }
        }
        public int Send(byte[] buffer, int offset, int data_length, BacnetAddress address, bool wait_for_transmission, int timeout)
        {
            if (state == BACnetSCState.IDLE || state == BACnetSCState.DISCONNECTING)
                return -1;

            int full_length = data_length + HeaderLength;
            BVLC_SC_Encode(buffer, offset - BVLC_HEADER_LENGTH, BacnetBvlcSCMessage.BVLC_ENCASULATED_NPDU, ref full_length, address);

            if (state == BACnetSCState.CONNECTED)
            {
                Array.Resize(ref buffer, full_length);
                return Send(buffer);
            }
            else
            {
                byte[] cpy = new byte[full_length];
                Array.Copy(buffer, cpy, full_length);

                lock (AwaitingFrames)
                {
                    Trace.TraceInformation("BACnet/SC: Request pushed in delay queue");
                    AwaitingFrames.Add(cpy);

                    if (AwaitingFrames.Count == 1)
                        ThreadPool.QueueUserWorkItem(SendLaterAwaitingFrames);
                }
            }

            return 0;
        }

        private void SendLaterAwaitingFrames(object? _)
        {
            do
            {
                Thread.Sleep(200);

                if (state == BACnetSCState.IDLE)
                {
                    lock (AwaitingFrames)
                        AwaitingFrames.Clear();

                    return;
                }
            }
            while (state != BACnetSCState.CONNECTED);

            lock (AwaitingFrames)
            {
                foreach (var frame in AwaitingFrames)
                {
                    Send(frame);
                    Trace.TraceInformation("BACnet/SC: Request pulled from queue");
                }

                AwaitingFrames.Clear();
            }
        }

        private void BVLC_SC_SendConnectRequest()
        {
            byte[] b = new byte[4 + 6 + 16 + 2 + 2];
            b[0] = (byte)BacnetBvlcSCMessage.BVLC_CONNECT_REQUEST;
            b[1] = 0;
            b[2] = 0;
            b[3] = 0;

            Array.Copy(myVMAC, 0, b, 4, 6);

            byte[] bUUID;
            if (Guid.TryParse(configuration.UUID, out Guid uuid))
                bUUID = uuid.ToByteArray();
            else
                bUUID = Guid.NewGuid().ToByteArray();

            Array.Copy(bUUID, 0, b, 10, 16);

            b[26] = 0x06;
            b[27] = 0x40;

            b[28] = 0x05;
            b[29] = 0xD9;

            Send(b);
        }

        private void BVLC_SC_SendBvlcError(byte[] DestVmac, byte MsgId1, byte MsgId2, BacnetErrorClasses classe, BacnetErrorCodes code)
        {
            byte[] b = new byte[10 + (configuration.DirectConnect ? 0 : 6)];

            b[0] = (byte)BacnetBvlcSCMessage.BVLC_RESULT;
            b[1] = (byte)(configuration.DirectConnect ? 0 : 4);
            b[2] = MsgId1;
            b[3] = MsgId2;

            int offset = 0;
            if (!configuration.DirectConnect)
            {
                Array.Copy(DestVmac, 0, b, 4, 6);
                offset = 6;
            }

            b[4 + offset] = 0;
            b[5 + offset] = 0x01;
            b[6 + offset] = 0;
            b[7 + offset] = (byte)BacnetErrorClasses.ERROR_CLASS_SERVICES;
            b[8 + offset] = 0;
            b[9 + offset] = (byte)BacnetErrorCodes.ERROR_CODE_BVLC_FUNCTION_UNKNOWN;

            Send(b);
        }

        private void BVLC_SC_SendSimpleBVLCMsg(BacnetBvlcSCMessage Msg, byte MsgId1, byte MsgId2)
        {
            byte[] b = new byte[4];
            b[0] = (byte)Msg;
            b[1] = 0;
            b[2] = MsgId1;
            b[3] = MsgId2;
            Send(b);
        }

        private int BVLC_SC_Encode(byte[] buffer, int offset, BacnetBvlcSCMessage function, ref int msg_length, BacnetAddress address)
        {
            if (!configuration.DirectConnect)
            {
                buffer[0] = (byte)function;
                buffer[1] = 4;
                buffer[2] = 0xBA;
                buffer[3] = 0xC0;
                Array.Copy(address.VMac, 0, buffer, 4, 6);
                return 10;
            }
            else
            {
                Array.Copy(buffer, 10, buffer, 4, msg_length - 6);
                buffer[0] = (byte)function;
                buffer[1] = 0;
                buffer[2] = 0xBA;
                buffer[3] = 0xC0;

                msg_length -= 6;
                return 4;
            }
        }

        private int BVLC_SC_Decode(byte[] buffer, int offset, out BacnetBvlcSCMessage function, out int msg_length, BacnetAddress remote_address)
        {
            msg_length = -1;

            function = (BacnetBvlcSCMessage)buffer[0];
            byte controlFlag = buffer[1];

            offset = 4;

            if ((controlFlag & 8) != 0)
            {
                Array.Copy(buffer, offset, remote_address.VMac, 0, 6);
                remote_address.adr = remote_address.VMac;
                offset += 6;
            }

            if ((controlFlag & 4) != 0)
            {
                offset += 6;
            }

            if ((controlFlag & 2) != 0)
            {
                bool moreOption = true;
                while (moreOption)
                {
                    moreOption = (buffer[offset] & 0x80) != 0;
                    bool headerDataPresent = (buffer[offset] & 0x20) != 0;
                    offset++;
                    if (headerDataPresent)
                        offset += 2 + (buffer[offset] << 8) + buffer[offset + 1];
                }
            }

            if ((controlFlag & 1) != 0)
            {
                bool moreOption = true;
                while (moreOption)
                {
                    moreOption = (buffer[offset] & 0x80) != 0;
                    bool headerDataPresent = (buffer[offset] & 0x20) != 0;
                    offset++;
                    if (headerDataPresent)
                        offset += 2 + (buffer[offset] << 8) + buffer[offset + 1];
                }
            }

            msg_length = offset;

            switch (function)
            {
                case BacnetBvlcSCMessage.BVLC_RESULT:
                    if (buffer[offset] == (byte)BacnetBvlcSCMessage.BVLC_CONNECT_REQUEST &&
                        buffer[offset + 1] == 0x01 &&
                        buffer[offset + 2] == 0)
                    {
                        ushort ErrorClass = (ushort)((buffer[offset + 3] << 8) | buffer[offset + 4]);
                        ushort ErrorCode = (ushort)((buffer[offset + 5] << 8) | buffer[offset + 6]);

                        if (ErrorClass == (byte)BacnetErrorClasses.ERROR_CLASS_COMMUNICATION &&
                            ErrorCode == (byte)BacnetErrorCodes.ERROR_CODE_NODE_DUPLICATE_VMAC)
                        {
                            FillRandomBytes(myVMAC);
                            myVMAC[0] = (byte)((myVMAC[0] & 0xF0) | 0x02);
                            DuplicateVMACCount++;

                            try
                            {
                                _cts?.Cancel();
                                _webSocket?.Abort();
                            }
                            catch
                            {
                            }
                        }
                    }
                    return 0;

                case BacnetBvlcSCMessage.BVLC_ENCASULATED_NPDU:
                    return offset;

                case BacnetBvlcSCMessage.BVLC_CONNECT_ACCEPT:
                    Array.Copy(buffer, 4, RemoteVMAC, 0, 6);
                    return 0;

                case BacnetBvlcSCMessage.BVLC_DISCONNECT_REQUEST:
                    BVLC_SC_SendSimpleBVLCMsg(BacnetBvlcSCMessage.BVLC_DISCONNECT_ACK, buffer[2], buffer[3]);
                    state = BACnetSCState.IDLE;
                    return 0;

                case BacnetBvlcSCMessage.BVLC_DISCONNECT_ACK:
                    return 0;

                case BacnetBvlcSCMessage.BVLC_HEARTBEAT_REQUEST:
                    BVLC_SC_SendSimpleBVLCMsg(BacnetBvlcSCMessage.BVLC_HEARTBEAT_ACK, buffer[2], buffer[3]);
                    return 0;

                case BacnetBvlcSCMessage.BVLC_ADDRESS_RESOLUTION:
                    BVLC_SC_SendBvlcError(
                        remote_address.VMac,
                        buffer[2],
                        buffer[3],
                        BacnetErrorClasses.ERROR_CLASS_COMMUNICATION,
                        BacnetErrorCodes.ERROR_CODE_OPTIONAL_FUNCTIONALITY_NOT_SUPPORTED);
                    return 0;

                case BacnetBvlcSCMessage.BVLC_PROPRIETARY_MESSAGE:
                    BVLC_SC_SendBvlcError(
                        remote_address.VMac,
                        buffer[2],
                        buffer[3],
                        BacnetErrorClasses.ERROR_CLASS_COMMUNICATION,
                        BacnetErrorCodes.ERROR_CODE_BVLC_PROPRIETARY_FUNCTION_UNKNOWN);
                    return 0;

                case BacnetBvlcSCMessage.BVLC_ADVERTISEMENT_SOLICITATION:
                default:
                    BVLC_SC_SendBvlcError(
                        remote_address.VMac,
                        buffer[2],
                        buffer[3],
                        BacnetErrorClasses.ERROR_CLASS_COMMUNICATION,
                        BacnetErrorCodes.ERROR_CODE_BVLC_FUNCTION_UNKNOWN);
                    return 0;
            }
        }

        public BacnetAddress GetBroadcastAddress()
        {
            var ret = new BacnetAddress(BacnetAddressTypes.SC, 0xFFFF, null);
            ret.VMac = new byte[] { 255, 255, 255, 255, 255, 255 };
            ret.adr = ret.VMac;
            return ret;
        }

        private enum BacnetBvlcSCMessage : byte
        {
            BVLC_RESULT = 0,
            BVLC_ENCASULATED_NPDU = 1,
            BVLC_ADDRESS_RESOLUTION = 2,
            BVLC_ADDRESS_RESOLUTION_ACK = 3,
            BVLC_ADVERTISEMENT = 4,
            BVLC_ADVERTISEMENT_SOLICITATION = 5,
            BVLC_CONNECT_REQUEST = 6,
            BVLC_CONNECT_ACCEPT = 7,
            BVLC_DISCONNECT_REQUEST = 8,
            BVLC_DISCONNECT_ACK = 9,
            BVLC_HEARTBEAT_REQUEST = 0xA,
            BVLC_HEARTBEAT_ACK = 0xB,
            BVLC_PROPRIETARY_MESSAGE = 0xC
        };
        private static void FillRandomBytes(byte[] buffer)
        {
#if NET8_0_OR_GREATER
    Random.Shared.NextBytes(buffer);
#else
            using (RandomNumberGenerator rng = RandomNumberGenerator.Create())
            {
                rng.GetBytes(buffer);
            }
#endif
        }   

    }
}