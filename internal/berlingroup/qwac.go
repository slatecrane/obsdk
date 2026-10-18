package berlingroup

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/asn1"
	"fmt"
	"net/http"
	"time"
)

// QWACClient returns an HTTP client that presents the QWAC, for banks whose
// servers use certificates from a public CA (the system roots apply).
func QWACClient(qwac tls.Certificate) *http.Client {
	t := http.DefaultTransport.(*http.Transport).Clone()
	t.TLSClientConfig = &tls.Config{Certificates: []tls.Certificate{qwac}, MinVersion: tls.VersionTLS12}
	return &http.Client{Timeout: 30 * time.Second, Transport: t}
}

// oidOrganizationIdentifier is the X.520 organizationIdentifier (2.5.4.97)
// that carries the PSD2 authorisation number in eIDAS certificates.
var oidOrganizationIdentifier = asn1.ObjectIdentifier{2, 5, 4, 97}

// OrganizationIdentifier returns a QWAC's organizationIdentifier (e.g.
// PSDDE-BAFIN-123456), which OAuth SCA banks expect as the client id.
func OrganizationIdentifier(qwac *x509.Certificate) (string, error) {
	for _, n := range qwac.Subject.Names {
		if n.Type.Equal(oidOrganizationIdentifier) {
			if s, ok := n.Value.(string); ok && s != "" {
				return s, nil
			}
		}
	}
	return "", fmt.Errorf("berlingroup: certificate %q has no organizationIdentifier", qwac.Subject.CommonName)
}
