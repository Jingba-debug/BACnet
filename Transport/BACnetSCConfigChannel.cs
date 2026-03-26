using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Threading.Tasks;

namespace System.IO.BACnet.Transport
{
    public class BACnetSCConfigChannel
    {
        public string primaryHubURI = "";
        public string? failoverHubURI;

        public string? UUID;

        public string? OwnCertificateFile;
        public string? ThrustedCertificatesFile;

        public bool ValidateHubCertificate = false;
        public bool DirectConnect = false;

        public bool OnlyAllowsTLS13 = false;
        public bool UseTLS => !string.IsNullOrEmpty(primaryHubURI) &&
            primaryHubURI.StartsWith("wss://", StringComparison.OrdinalIgnoreCase);

        private int _AutoReconnectDelay = -1;

        public byte[]? VMAC;

        public int AutoReconnectDelay
        {
            get => _AutoReconnectDelay;
            set
            {
                _AutoReconnectDelay = value;
                if (_AutoReconnectDelay >= 0)
                    _AutoReconnectDelay = Math.Min(30, Math.Max(2, _AutoReconnectDelay));
            }
        }

        [XmlIgnore]
        public string? OwnCertificateFilePassword;

        [XmlIgnore]
        public X509Certificate2? OwnCertificate;

        [XmlIgnore]
        public X509Certificate2Collection? ThrustedCertificates;

        public int WiresharkCapturePort = -1;
    }
}
