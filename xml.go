package sslscan

import "encoding/xml"

type Run struct {
	// XMLName xml.Name `xml:"document" json:"document"`

	Title   string   `xml:"title,attr" json:"title"`
	Version string   `xml:"version,attr" json:"version"`
	SSLTest *SSLTest `xml:"ssltest" json:"ssltest"`

	rawXML []byte
}

type SSLTest struct {
	Host            string        `xml:"host,attr" json:"host"`
	SNIName         string        `xml:"sniname,attr" json:"sniname="`
	Port            string        `xml:"port,attr" json:"port"`
	SSLTLSprotocols []Protocol    `xml:"protocol" json:"SSLTLSProtocols"`
	TLSFallbackSCSV Fallback      `xml:"fallback" json:"TLSFallbackSCSV"`
	Renegotiation   Renegotiation `xml:"renegotiation" json:"Renegotiation"`
	Heartbleeds     []Heartbleed  `xml:"heartbleed" json:"Heartbleeds"`
	Cyphers         []Cypher      `xml:"cipher" json:"Cyphers"`
	Groups          []Cypher      `xml:"group" json:"Groups"`
	Certificates    Certificates  `xml:"certificates" json:"Certificates"`
}

type Protocol struct {
	Type    string `xml:"type,attr" json:"type"`
	Version string `xml:"version,attr" json:"version"`
	Enabled string `xml:"enabled,attr" json:"enabled"`
}

type Fallback struct {
	Supported string `xml:"supported,attr" json:"supported"`
}

type Renegotiation struct {
	Supported string `xml:"supported,attr" json:"supported"`
	Secure    string `xml:"secure,attr" json:"secure"`
}

type Heartbleed struct {
	SSLVersion string `xml:"sslversion,attr" json:"sslVersion"`
	Vulnerable string `xml:"vulnerable,attr" json:"vulnerable"`
}

type Cypher struct {
	Status     string `xml:"status,attr" json:"status"`
	SSLVersion string `xml:"sslversion,attr" json:"sslVersion"`
	Bits       string `xml:"bits,attr" json:"bits"`
	Value      string `xml:"cipher,attr" json:"value"`
	ID         string `xml:"id,attr" json:"id"`
	Strength   string `xml:"strength,attr" json:"strength"`
	Curve      string `xml:"curve,attr" json:"curve"`
	Ecdhebits  string `xml:"ecdhebits,attr" json:"ecdhebits"`
}

type Group struct {
	SSLVersion string `xml:"sslversion,attr" json:"sslVersion"`
	Bits       string `xml:"bits,attr" json:"bits"`
	Name       string `xml:"name,attr" json:"name"`
	ID         string `xml:"id,attr" json:"id"`
}

type Certificates struct {
	Certificate []Certificate `xml:"certificate" json:"certificate"`
}

type Certificate struct {
	Type               string `xml:"type,attr" json:"type"`
	SignatureAlgorithm string `xml:"signature-algorithm" json:"signatureAlgorithm"`
	PK                 PK     `xml:"pk" json:"pk"`
	Subject            string `xml:"subject" json:"subject"`
	AltNames           string `xml:"altnames" json:"altNames"`
	Issuer             string `xml:"issuer" json:"issuer"`
	NotValidBefore     string `xml:"not-valid-before" json:"notValidBefore"`
	NotValidAfter      string `xml:"not-valid-after" json:"notValidAfter"`
	Expired            string `xml:"expired" json:"expired"`
}

type PK struct {
	Error string `xml:"error,attr" json:"error"`
	Type  string `xml:"type,attr" json:"type"`
	Bits  string `xml:"bits,attr" json:"bits"`
}

// Parse takes a byte array of nmap xml data and unmarshals it into a
// Run struct.
func Parse(content []byte) (*Run, error) {
	r := &Run{
		rawXML: content,
	}

	err := xml.Unmarshal(content, r)

	return r, err
}
