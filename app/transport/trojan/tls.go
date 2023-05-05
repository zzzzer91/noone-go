package trojan

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"log"
	"math"
	"math/big"
	"time"
)

func randInt() *big.Int {
	n, err := rand.Int(rand.Reader, big.NewInt(math.MaxInt64))
	if err != nil {
		log.Fatal(err)
	}
	return n
}

func generateTLSConfig(cn string, alpn []string) *tls.Config {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		log.Fatal(err)
	}

	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		log.Fatal(err)
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})

	t := time.Now().AddDate(0, -1, 0)
	template := x509.Certificate{
		SerialNumber: randInt(),
		Subject:      pkix.Name{CommonName: cn},
		NotBefore:    t,
		NotAfter:     t.AddDate(1, 0, 0),
	}
	certDER, err := x509.CreateCertificate(rand.Reader, &template, &template, &key.PublicKey, key)
	if err != nil {
		log.Fatal(err)
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})

	tlsCert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		log.Fatal(err)
	}
	return &tls.Config{
		Certificates: []tls.Certificate{tlsCert},
		NextProtos:   alpn,
	}
}
