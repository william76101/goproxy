package main

import (
	"crypto/tls"
	"crypto/x509"

	"github.com/EnableSecurity/goproxy"
)

var caCert = []byte(`-----BEGIN CERTIFICATE-----
MIIDkzCCAnugAwIBAgIJAKe/ZGdfcHdPMA0GCSqGSIb3DQEBCwUAMGAxCzAJBgNV
BAYTAkFVMRMwEQYDVQQIDApTb21lLVN0YXRlMSEwHwYDVQQKDBhJbnRlcm5ldCBX
aWRnaXRzIFB0eSBMdGQxGTAXBgNVBAMMEGRlbW8gZm9yIGdvcHJveHkwHhcNMTYw
OTI3MTQzNzQ3WhcNMTkwOTI3MTQzNzQ3WjBgMQswCQYDVQQGEwJBVTETMBEGA1UE
CAwKU29tZS1TdGF0ZTEhMB8GA1UECgwYSW50ZXJuZXQgV2lkZ2l0cyBQdHkgTHRk
MRkwFwYDVQQDDBBkZW1vIGZvciBnb3Byb3h5MIIBIjANBgkqhkiG9w0BAQEFAAOC
AQ8AMIIBCgKCAQEA2+W48YZoch72zj0a+ZlyFVY2q2MWmqsEY9f/u53fAeTxvPE6
1/DnqsydnA3FnGvxw9Dz0oZO6xG+PZvp+lhN07NZbuXK1nie8IpxCa342axpu4C0
69lZwxikpGyJO4IL5ywp/qfb5a2DxPTAyQOQ8ROAaydoEmktRp25yicnQ2yeZW//
1SIQxt7gRxQIGmuOQ/Gqr/XN/z2cZdbGJVRUvQXk7N6NhQiCX1zlmp1hzUW9jwC+
JEKKF1XVpQbc94Bo5supxhkKJ70CREPy8TH9mAUcQUZQRohnPvvt/lKneYAGhjHK
vhpajwlbMMSocVXFvY7o/IqIE/+ZUeQTs1SUwQIDAQABo1AwTjAdBgNVHQ4EFgQU
GnlWcIbfsWJW7GId+6xZIK8YlFEwHwYDVR0jBBgwFoAUGnlWcIbfsWJW7GId+6xZ
IK8YlFEwDAYDVR0TBAUwAwEB/zANBgkqhkiG9w0BAQsFAAOCAQEAoFUjSD15rKlY
xudzyVlr6n0fRNhITkiZMX3JlFOvtHNYif8RfK4TH/oHNBTmle69AgixjMgy8GGd
H90prytGQ5zCs1tKcCFsN5gRSgdAkc2PpRFOK6u8HwOITV5lV7sjucsddXJcOJbQ
4fyVe47V9TTxI+A7lRnUP2HYTR1Bd0R/IgRAH57d1ZHs7omHIuQ+Ea8ph2ppXMnP
DXVOlZ9zfczSnPnQoomqULOU9Fq2ycyi8Y/ROtAHP6O7wCFbYHXhxojdaHSdhkcd
troTflFMD2/4O6MtBKbHxSmEG6H0FBYz5xUZhZq7WUH24V3xYsfge29/lOCd5/Xf
A+j0RJc/lQ==
-----END CERTIFICATE-----`)

var caKey = []byte(`-----BEGIN RSA PRIVATE KEY-----
MIIEowIBAAKCAQEA2+W48YZoch72zj0a+ZlyFVY2q2MWmqsEY9f/u53fAeTxvPE6
1/DnqsydnA3FnGvxw9Dz0oZO6xG+PZvp+lhN07NZbuXK1nie8IpxCa342axpu4C0
69lZwxikpGyJO4IL5ywp/qfb5a2DxPTAyQOQ8ROAaydoEmktRp25yicnQ2yeZW//
1SIQxt7gRxQIGmuOQ/Gqr/XN/z2cZdbGJVRUvQXk7N6NhQiCX1zlmp1hzUW9jwC+
JEKKF1XVpQbc94Bo5supxhkKJ70CREPy8TH9mAUcQUZQRohnPvvt/lKneYAGhjHK
vhpajwlbMMSocVXFvY7o/IqIE/+ZUeQTs1SUwQIDAQABAoIBAHK94ww8W0G5QIWL
Qwkc9XeGvg4eLUxVknva2Ll4fkZJxY4WveKx9OCd1lv4n7WoacYIwUGIDaQBZShW
s/eKnkmqGy+PvpC87gqL4sHvQpuqqJ1LYpxylLEFqduWOuGPUVC2Lc+QnWCycsCS
CgqZzsbMq0S+kkKRGSvw32JJneZCzqLgLNssQNVk+Gm6SI3s4jJsGPesjhnvoPaa
xZK14uFpltaA05GSTDaQeZJFEdnnb3f/eNPc2xMEfi0S2ZlJ6Q92WJEOepAetDlR
cRFi004bNyTb4Bphg8s4+9Cti5is199aFkGCRDWxeqEnc6aMY3Ezu9Qg3uttLVUd
uy830GUCgYEA7qS0X+9UH1R02L3aoANyADVbFt2ZpUwQGauw9WM92pH52xeHAw1S
ohus6FI3OC8xQq2CN525tGLUbFDZnNZ3YQHqFsfgevfnTs1//gbKXomitev0oFKh
VT+WYS4lkgYtPlXzhdGuk32q99T/wIocAguvCUY3PiA7yBz93ReyausCgYEA6+P8
bugMqT8qjoiz1q/YCfxsw9bAGWjlVqme2xmp256AKtxvCf1BPsToAaJU3nFi3vkw
ICLxUWAYoMBODJ3YnbOsIZOavdXZwYHv54JqwqFealC3DG0Du6fZYZdiY8pK+E6m
3fiYzP1WoVK5tU4bH8ibuIQvpcI8j7Gy0cV6/AMCgYBHl7fZNAZro72uLD7DVGVF
9LvP/0kR0uDdoqli5JPw12w6szM40i1hHqZfyBJy042WsFDpeHL2z9Nkb1jpeVm1
C4r7rJkGqwqElJf6UHUzqVzb8N6hnkhyN7JYkyyIQzwdgFGfaslRzBiXYxoa3BQM
9Q5c3OjDxY3JuhDa3DoVYwKBgDNqrWJLSD832oHZAEIicBe1IswJKjQfriWWsV6W
mHSbdtpg0/88aZVR/DQm+xLFakSp0jifBTS0momngRu06Dtvp2xmLQuF6oIIXY97
2ON1owvPbibSOEcWDgb8pWCU/oRjOHIXts6vxctCKeKAFN93raGphm0+Ck9T72NU
BTubAoGBAMEhI/Wy9wAETuXwN84AhmPdQsyCyp37YKt2ZKaqu37x9v2iL8JTbPEz
pdBzkA2Gc0Wdb6ekIzRrTsJQl+c/0m9byFHsRsxXW2HnezfOFX1H4qAmF6KWP0ub
M8aIn6Rab4sNPSrvKGrU6rFpv/6M33eegzldVnV9ku6uPJI1fFTC
-----END RSA PRIVATE KEY-----`)

var ucaCert = []byte(`-----BEGIN CERTIFICATE-----
MIICSjCCAbWgAwIBAgIBADALBgkqhkiG9w0BAQUwSjEjMCEGA1UEChMaZ2l0aHVi
LmNvbS9lbGF6YXJsL2dvcHJveHkxIzAhBgNVBAMTGmdpdGh1Yi5jb20vZWxhemFy
bC9nb3Byb3h5MB4XDTAwMDEwMTAwMDAwMFoXDTQ5MTIzMTIzNTk1OVowSjEjMCEG
A1UEChMaZ2l0aHViLmNvbS9lbGF6YXJsL2dvcHJveHkxIzAhBgNVBAMTGmdpdGh1
Yi5jb20vZWxhemFybC9nb3Byb3h5MIGdMAsGCSqGSIb3DQEBAQOBjQAwgYkCgYEA
vz9BbCaJjxs73Tvcq3leP32hAGerQ1RgvlZ68Z4nZmoVHfl+2Nr/m0dmW+GdOfpT
cs/KzfJjYGr/84x524fiuR8GdZ0HOtXJzyF5seoWnbBIuyr1PbEpgRhGQMqqOUuj
YExeLbfNHPIoJ8XZ1Vzyv3YxjbmjWA+S/uOe9HWtDbMCAwEAAaNGMEQwDgYDVR0P
AQH/BAQDAgCkMBMGA1UdJQQMMAoGCCsGAQUFBwMBMA8GA1UdEwEB/wQFMAMBAf8w
DAYDVR0RBAUwA4IBKjALBgkqhkiG9w0BAQUDgYEAIcL8huSmGMompNujsvePTUnM
oEUKtX4Eh/+s+DSfV/TyI0I+3GiPpLplEgFWuoBIJGios0r1dKh5N0TGjxX/RmGm
qo7E4jjJuo8Gs5U8/fgThZmshax2lwLtbRNwhvUVr65GdahLsZz8I+hySLuatVvR
qHHq/FQORIiNyNpq/Hg=
-----END CERTIFICATE-----`)

var ucaKey = []byte(`-----BEGIN RSA PRIVATE KEY-----
MIICXQIBAAKBgQC/P0FsJomPGzvdO9yreV4/faEAZ6tDVGC+VnrxnidmahUd+X7Y
2v+bR2Zb4Z05+lNyz8rN8mNgav/zjHnbh+K5HwZ1nQc61cnPIXmx6hadsEi7KvU9
sSmBGEZAyqo5S6NgTF4tt80c8ignxdnVXPK/djGNuaNYD5L+4570da0NswIDAQAB
AoGBALzIv1b4D7ARTR3NOr6V9wArjiOtMjUrdLhO+9vIp9IEA8ZsA9gjDlCEwbkP
VDnoLjnWfraff5Os6+3JjHy1fYpUiCdnk2XA6iJSL1XWKQZPt3wOunxP4lalDgED
QTRReFbA/y/Z4kSfTXpVj68ytcvSRW/N7q5/qRtbN9804jpBAkEA0s6lvH2btSLA
mcEdwhs7zAslLbdld7rvfUeP82gPPk0S6yUqTNyikqshM9AwAktHY7WvYdKl+ghZ
HTxKVC4DoQJBAOg/IAW5RbXknP+Lf7AVtBgw3E+Yfa3mcdLySe8hjxxyZq825Zmu
Rt5Qj4Lw6ifSFNy4kiiSpE/ZCukYvUXGENMCQFkPxSWlS6tzSzuqQxBGwTSrYMG3
wb6b06JyIXcMd6Qym9OMmBpw/J5KfnSNeDr/4uFVWQtTG5xO+pdHaX+3EQECQQDl
qcbY4iX1gWVfr2tNjajSYz751yoxVbkpiT9joiQLVXYFvpu+JYEfRzsjmWl0h2Lq
AftG8/xYmaEYcMZ6wSrRAkBUwiom98/8wZVlB6qbwhU1EKDFANvICGSWMIhPx3v7
MJqTIj4uJhte2/uyVvZ6DC6noWYgy+kLgqG0S97tUEG8
-----END RSA PRIVATE KEY-----`)

func setCA(caCert, caKey []byte) error {
	goproxyCa, err := tls.X509KeyPair(caCert, caKey)
	if err != nil {
		return err
	}
	if goproxyCa.Leaf, err = x509.ParseCertificate(goproxyCa.Certificate[0]); err != nil {
		return err
	}
	ugoproxyCa, err := tls.X509KeyPair(ucaCert, ucaKey)
	if err != nil {
		return err
	}
	if ugoproxyCa.Leaf, err = x509.ParseCertificate(ugoproxyCa.Certificate[0]); err != nil {
		return err
	}

	goproxy.GoproxyCa = goproxyCa
	goproxy.OkConnect = &goproxy.ConnectAction{Action: goproxy.ConnectAccept, TLSConfig: goproxy.TLSConfigFromCA(&goproxyCa, &ugoproxyCa)}
	goproxy.MitmConnect = &goproxy.ConnectAction{Action: goproxy.ConnectMitm, TLSConfig: goproxy.TLSConfigFromCA(&goproxyCa, &ugoproxyCa)}
	goproxy.HTTPMitmConnect = &goproxy.ConnectAction{Action: goproxy.ConnectHTTPMitm, TLSConfig: goproxy.TLSConfigFromCA(&goproxyCa, &ugoproxyCa)}
	goproxy.RejectConnect = &goproxy.ConnectAction{Action: goproxy.ConnectReject, TLSConfig: goproxy.TLSConfigFromCA(&goproxyCa, &ugoproxyCa)}
	return nil
}
