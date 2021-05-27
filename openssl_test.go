package phpToGO

import (
	"encoding/base64"
	"github.com/stretchr/testify/require"
	"testing"
)

var privateKey = `
-----BEGIN RSA PRIVATE KEY-----
MIICXgIBAAKBgQC6CQQb5c4BF7DgorQMgdaftR8UYwTeFmS3KW98bQ+l6NcFPM4k
E14rgHT6mSnCRQjTdc9NQ41deNz/50aC0wegko9oixFlU8eR8kL1yLetL89/oksg
hmssbxhjJmThQGnAs56GudllOCC71TV1FZxEiAHZwrvWOmHi9RhqNm2K9wIDAQAB
AoGBALkPwwCliFpZ4OB1ujo+5uwU1wgGwI7VI/d4xqi2LTzT9SIGrOICSkloDfZE
auAQoIkKxt+LdZMoamA/B0uY9hm5g7sMseAFI1EKNfvmVC/5OgDiWeYtGFxX9G3s
mwLgUbp9EU2WIzo8puQVIqhmTSqi42IgNpymaz5W74xzf1gRAkEA4a9PiVfmCkwK
lzSErpuJ5jpr1tnLFn7RxmP+KXnCPvk925vNB384eDGwA2qLVdwovvdfqbb6IIE7
nfkggIVWawJBANMGQ235L6gWlFDXxfUor7/RDc8XbMwjAjxCv0iDLKhY4nj39qpc
r7sJYEKS104myAMR+xvFzP6qaBx5DDy8iKUCQQCwGn9C2a7sjAebk2SRZ1dEqoOp
pEsf45fHahFSxer3/r7xFXL4jaI/z+3bzJCrT98PnLIuGVS2doFRtKtS/ji/AkBf
MaghaBOzg9wMTAok+eGuaiQMk8iknfZYMNQRZfszRkWDxHgligJMIYKnBY7S1nPL
zsS0VpqPF1g33/NBQttxAkEAw4UKea5WHmWl7HGNDc8I//eEi75k5Emboj9jTKmC
HtaS2DjliKDNRKe1xdMGhTkYNC6B7/KduwQ8fXDXWHBU0w==
-----END RSA PRIVATE KEY-----
`
var publicKey = `
-----BEGIN PUBLIC KEY-----
MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQC6CQQb5c4BF7DgorQMgdaftR8U
YwTeFmS3KW98bQ+l6NcFPM4kE14rgHT6mSnCRQjTdc9NQ41deNz/50aC0wegko9o
ixFlU8eR8kL1yLetL89/oksghmssbxhjJmThQGnAs56GudllOCC71TV1FZxEiAHZ
wrvWOmHi9RhqNm2K9wIDAQAB
-----END PUBLIC KEY-----
`

func TestOpensslVerify(t *testing.T) {
	// base64 of sign
	signEnc := "JUM7R1XeXZQT3mz/Ud7O61L+zzMOjyktnt8YlcP2E3GXnDqkVmfyDZxr9x/pQbpB7ufudKBRDl7NGkS2S2t68gGwM/HgJrMYr9CI0AYSZ1bde9tleqAvN77sVwNgh6Yu6/T2orKtdAMoX1fAYAJJ8V7DU5Ji13dH50Kr8d0jzQ8="

	data := "test"

	sign, err := base64.StdEncoding.DecodeString(signEnc)
	require.NoError(t, err)

	err = opensslVerify([]byte(data), sign, publicKey)
	require.NoError(t, err)
}

func TestOpensslSign(t *testing.T) {
	data := []byte("test")

	sign, err := opensslSign(data, []byte(privateKey))
	require.NoError(t, err)

	err = opensslVerify(data, sign, publicKey)
	require.NoError(t, err)
}
