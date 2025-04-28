package lib

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"log"
	"math/big"
	"net"
	"os"
	"time"
)

const path string = "./certs/"

func createCA(subject *pkix.Name) (*x509.Certificate, *rsa.PrivateKey, error) {
	// creating a CA which will be used to sign all of our certificates using the x509 package from the Go Standard Library
	caCert := &x509.Certificate{
		SerialNumber:          big.NewInt(2019),
		Subject:               *subject,
		NotBefore:             time.Now(),
		NotAfter:              time.Now().AddDate(10*365, 0, 0),
		IsCA:                  true, // <- indicating this certificate is a CA certificate.
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
	}

	ip := net.ParseIP(GetServerIP())
	if ip != nil {
		caCert.IPAddresses = append(caCert.IPAddresses, ip)
	}

	// generate a private key for the CA
	caKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		log.Printf("Generate the CA Private Key error: %v\n", err)
		return nil, nil, err
	}

	// create the CA certificate
	caBytes, err := x509.CreateCertificate(rand.Reader, caCert, caCert, &caKey.PublicKey, caKey)
	if err != nil {
		log.Printf("Create the CA Certificate error: %v\n", err)
		return nil, nil, err
	}

	// Create the CA PEM files
	caPEM := new(bytes.Buffer)
	pem.Encode(caPEM, &pem.Block{
		Type:  "CERTIFICATE",
		Bytes: caBytes,
	})
	caDirPath := path + "ca/"
	if err := os.WriteFile(caDirPath+"ca.crt", caPEM.Bytes(), 0644); err != nil {
		log.Printf("Write the CA certificate file error: %v\n", err)
		return nil, nil, err
	}

	caPrivKeyPEM := new(bytes.Buffer)
	pem.Encode(caPrivKeyPEM, &pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(caKey),
	})
	if err := os.WriteFile(caDirPath+"ca.key", caPrivKeyPEM.Bytes(), 0644); err != nil {
		log.Printf("Write the CA certificate file error: %v\n", err)
		return nil, nil, err
	}
	return caCert, caKey, nil
}

func makeCert(caCert *x509.Certificate, caKey *rsa.PrivateKey, subject *pkix.Name, name string) error {
	cert := &x509.Certificate{
		SerialNumber: big.NewInt(1658),
		Subject:      *subject,
		DNSNames:     []string{"localhost"},
		NotBefore:    time.Now(),
		NotAfter:     time.Now().AddDate(10, 0, 0),
		SubjectKeyId: []byte{1, 2, 3, 4, 6},
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
		KeyUsage:     x509.KeyUsageDigitalSignature,
	}

	ip := net.ParseIP(GetServerIP())
	if ip != nil {
		cert.IPAddresses = append(cert.IPAddresses, ip)
	}

	certKey, err := rsa.GenerateKey(rand.Reader, 4096)
	if err != nil {
		log.Printf("Generate the Key error: %v\n", err)
		return err
	}
	certBytes, err := x509.CreateCertificate(rand.Reader, cert, caCert, &certKey.PublicKey, caKey)
	if err != nil {
		log.Printf("Generate the certificate error: %v\n", err)
		return err
	}

	certPEM := new(bytes.Buffer)
	pem.Encode(certPEM, &pem.Block{
		Type:  "CERTIFICATE",
		Bytes: certBytes,
	})

	certDir := path + name + "/"
	if err := os.WriteFile(certDir+name+".crt", certPEM.Bytes(), 0644); err != nil {
		log.Printf("Write the CA certificate file error: %v\n", err)
		return err
	}

	certKeyPEM := new(bytes.Buffer)
	pem.Encode(certKeyPEM, &pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(certKey),
	})
	if err := os.WriteFile(certDir+name+".key", certKeyPEM.Bytes(), 0644); err != nil {
		log.Printf("Write the CA certificate file error: %v\n", err)
		return err
	}
	return nil
}

func baseSubject() *pkix.Name {
	return &pkix.Name{
		Country:            []string{"Earth"},
		Organization:       []string{"CA Company"},
		OrganizationalUnit: []string{"Engineering"},
		Locality:           []string{"Mountain"},
		Province:           []string{"Asia"},
		StreetAddress:      []string{"Bridge"},
		PostalCode:         []string{"123456"},
		SerialNumber:       "",
		CommonName:         "ROOTCA",
		Names:              []pkix.AttributeTypeAndValue{},
		ExtraNames:         []pkix.AttributeTypeAndValue{},
	}
}

func (ca *CA) genCaCert() {
	caCert, caKey, err := createCA(ca.subject)
	if err != nil {
		log.Fatalf("make CA Certificate error!")
	}
	log.Println("Create the CA certificate successfully.")
	ca.cert = caCert
	ca.key = caKey
}

func (ca *CA) createCert(cn string, org string) {
	ca.subject.CommonName = cn
	ca.subject.Organization = []string{org}
	if err := makeCert(ca.cert, ca.key, ca.subject, cn); err != nil {
		log.Fatalf("make %s Certificate error!", cn)
	}
	log.Printf("Create and Sign the %s certificate successfully.\n", cn)

}

type CA struct {
	cert    *x509.Certificate
	key     *rsa.PrivateKey
	subject *pkix.Name
}

func GenClient() {
	cert, err := tls.LoadX509KeyPair("./certs/ca/ca.crt", "./certs/ca/ca.key")
	if err != nil {
		// Handle error
		fmt.Println(err)
	}
	log.Println("Priv Key: ", cert.PrivateKey)

	CA := &CA{
		cert: &x509.Certificate{
			Raw: cert.Leaf.Raw,
		},
		key:     cert.PrivateKey.(*rsa.PrivateKey),
		subject: &cert.Leaf.Subject,
	}

	CA.createCert("client", "pottery")
}

func GenServer() {
	cert, err := tls.LoadX509KeyPair("./certs/ca/ca.crt", "./certs/ca/ca.key")
	if err != nil {
		// Handle error
		fmt.Println(err)
	}

	CA := &CA{
		cert: &x509.Certificate{
			Raw: cert.Leaf.Raw,
		},
		key:     cert.PrivateKey.(*rsa.PrivateKey),
		subject: &cert.Leaf.Subject,
	}

	CA.createCert("server", "pottery")
}

func GenAll() {

	CA := &CA{}
	CA.subject = baseSubject()
	CA.genCaCert()

	CA.createCert("server", "pottery")
	CA.createCert("client", "pottery")
}
