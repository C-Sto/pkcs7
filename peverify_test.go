package pkcs7

import (
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"testing"
)

type WinCert struct {
	Length   uint32
	Revision uint16
	Type     uint16
	Cert     []byte
}

func NewWinCert(b []byte) WinCert {
	r := WinCert{}
	ctr := 0
	r.Length = binary.LittleEndian.Uint32(b[ctr : ctr+4])
	ctr += 4
	r.Revision = binary.LittleEndian.Uint16(b[ctr : ctr+2])
	ctr += 2
	r.Type = binary.LittleEndian.Uint16(b[ctr : ctr+2])
	ctr += 2
	r.Cert = make([]byte, r.Length)
	copy(r.Cert, b[ctr:r.Length])
	return r
}
func TestPEVerify(t *testing.T) {
	/*
			Got embedded like this:

		loc := `D:\vm\vagrant\win10sec\ok\signme.exe`
		p, err := pe.Open(loc)
		bb, err := ioutil.ReadFile(loc)

		certTableOffset := p.OptionalHeader.(*pe.OptionalHeader64).DataDirectory[pe.CERTIFICATE_TABLE].VirtualAddress
		certTableSize := p.OptionalHeader.(*pe.OptionalHeader64).DataDirectory[pe.CERTIFICATE_TABLE].Size

		fmt.Println(base64.StdEncoding.EncodeToString(bb[certTableOffset : certTableOffset+certTableSize]))

		//p7data := NewWinCert(bb[certTableOffset : certTableOffset+certTableSize])

	*/
	data, e := base64.StdEncoding.DecodeString(peEmbedBlob)
	if e != nil {
		t.Fatalf("Bad decode somehow: %s", e)
	}

	p7data := NewWinCert(data)

	p7, err := Parse(p7data.Cert)
	if err != nil {
		panic(err)
	}

	msSpecificStruct := &SpcIndirectDataContent{}
	d := SpcAttributeTypeAndOptionalValue{}
	r, _ := asn1.Unmarshal(p7.Content, &d)
	msSpecificStruct.Data = d
	r, _ = asn1.Unmarshal(r, &msSpecificStruct.MessageDigest)
	fmt.Printf("PE hash to verify: %x", msSpecificStruct.MessageDigest.Digest)

	if err := p7.Verify(); err != nil {
		t.Errorf("Verify failed with error: %v", err)
	}

	//get from bananaphone/example/participationcertificate
	expected := "8e48f0f91f286bcffa90bd61560d3de108a501b2"

	if expected != hex.EncodeToString(msSpecificStruct.MessageDigest.Digest) {
		t.Errorf("did not get expected string")
	}

}

type SpcAttributeTypeAndOptionalValue struct {
	Type  asn1.ObjectIdentifier
	Value SpcPeImageData `asn1:"explicit,optional,tag:0"`
}

type DigestInfo struct {
	DigestAlgorithm pkix.AlgorithmIdentifier
	Digest          []byte
}

type SpcIndirectDataContent struct {
	Data          SpcAttributeTypeAndOptionalValue
	MessageDigest DigestInfo
}

type SpcPeImageData struct {
	Flags asn1.BitString
	File  SpcLink
}

type SpcLink struct {
	Url     []byte    `asn1:"implicit,tag:0"`
	Monkier []byte    `asn1:"implicit,tag:1"`
	File    SpcString `asn1:"explicit,tag:2"`
}

type SpcString struct {
	Unicode []byte `asn1:"implicit,tag:0"`
	Ascii   []byte `asn1:"implicit,tag:1"`
}

type SpcPeImageFlags asn1.BitString

var SPC_INDIRECT_DATA_OBJID = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 311, 2, 1, 15}

const peEmbedBlob = `WAUAAAACAgAwggVHBgkqhkiG9w0BBwKgggU4MIIFNAIBATELMAkGBSsOAwIaBQAwTAYKKwYBBAGCNwIBBKA+MDwwFwYKKwYBBAGCNwIBDzAJAwEAoASiAoAAMCEwCQYFKw4DAhoFAAQUjkjw+R8oa8/6kL1hVg094QilAbKgggMCMIIC/jCCAeagAwIBAgIQQ790mTBeaIVEKkFbB0ti5DANBgkqhkiG9w0BAQsFADAXMRUwEwYDVQQDDAxDb2RlIFNpZ25pbmcwHhcNMjAwNzA1MDU0MDEyWhcNMjEwNzA1MDYwMDEyWjAXMRUwEwYDVQQDDAxDb2RlIFNpZ25pbmcwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQDU+J/s5a9HlVfoouTLK9MjY43fpPClFC0i+1EnmsRy5atcvSOfvxc+fhZGk3OK3Fd+bszNWNhrIzfmdCcHGxhTUGzrNoJUa4RgIkA5XJo05PdvbEedQnffIwhjzvOvY/YCyGobAQ0meWqVSq6ER9Kec00aLDScnb5cjCBScBs9d4JstCjVmVOWWZPDBXJna7D1+8sUtRFGWOB0G+BTd1Mum/gGsLfxImjzFPGF+M1C1/YI6VsCW48VyDjD2jkyVBRtwD0y4vRtgTmkd510PLqndV92a/Mh/aAd81ptbiesEahN0AznU7ig4AYKS3RmGOsp+Ys/Y1TnBXQTGCkD9TjJAgMBAAGjRjBEMA4GA1UdDwEB/wQEAwIHgDATBgNVHSUEDDAKBggrBgEFBQcDAzAdBgNVHQ4EFgQUzLUTjxULKe4ooELaWn032gp5hOswDQYJKoZIhvcNAQELBQADggEBALbigFW4b0L0xzKBq3t7T2VpiY2LaSB8NJ3snanzF/rTgv//tt0qQLg+vgAbiuOtOG4zapP8z4jaNv2xTs58pPEu3+B8Hy4ECmOnieSP/s1Q65p+ZKZrD/8+iEbyg8jFRBsxfgSF8usbRWJCdYD27wepsNNtPG0wEMqquGIUVDFhSFvnrgfi3q4GhYIcKsjmewFf4eHv4RGYNbQ7H46+TLR87Vj9AqIHGxzipM2uyueIICtJWKQ76tScKHxCBg369oDTAwE2+EahW9mSEeSI5lC6x+YbTXuJq1rclcKFp1VeG0XrdzMQ+1P3kjmjr18JzNIP2H50hFazJHutC4/PaqMxggHMMIIByAIBATArMBcxFTATBgNVBAMMDENvZGUgU2lnbmluZwIQQ790mTBeaIVEKkFbB0ti5DAJBgUrDgMCGgUAoHgwGAYKKwYBBAGCNwIBDDEKMAigAoAAoQKAADAZBgkqhkiG9w0BCQMxDAYKKwYBBAGCNwIBBDAcBgorBgEEAYI3AgELMQ4wDAYKKwYBBAGCNwIBFTAjBgkqhkiG9w0BCQQxFgQUaTBvdOK2yIi4CEnK93JzCCblkQ4wDQYJKoZIhvcNAQEBBQAEggEANL12Ac3TTHgHxmmGp+xPZ/FQx+J2Sq+zFrefGAHm5MGiO3qEQigsKk+DqgYtnSxVSYaZsyLYiEQjRXuJvPjq5oeVgjRxScG9vS003mrufBL76ziNyGXpKYR/kv6I/IhnMtvoF5oAnporORgpRBFMEiCK42Gp5BPM2Q7I+1zrAiD/8rk3dENQi1ybVkbQyYsFB5Hd71X1mFv7atujOjgBOYE/cf61HI8Ymf+IbAtOu/oNj+aizgYQ3iuboa4/Vhiy6RLAwUCl+XwgdxwhvxBmLLUavfkb2H5gPOLPt4wHWMFKKtZOjI8MgcHcCDWo6VMXignk/OZoAQDO0N6IrdC4+AAAAAAA`
