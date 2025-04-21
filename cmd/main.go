package main

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"log"
	"os"

	"certgen/cert"
)

func main() {

	if len(os.Args) < 2 {
		showHelp()
		return
	}

	args := os.Args[1:]

	switch args[0] {
	case "ca":
		if len(args) < 2 {
			log.Printf("ca option requires a common name, see help for details")
			return
		}

		name := args[1]

		err := generateCA(name)
		if err != nil {
			log.Println(err)
		}

	case "site-cert":
		if len(args) < 2 {
			log.Printf("site-cert option requires a host name, see help for details")
			return
		}

		if len(args) == 3 || len(args) > 4 {
			log.Println("Usage: site-cert <hostname> [<ca-cert> <ca-key>]")
			return
		}

		name := args[1]
		caCertFilePath := ""
		caKeyFilePath := ""

		if len(args) > 2 {
			caCertFilePath = args[2]
			caKeyFilePath = args[3]
		}

		err := generateSiteCert(name, caCertFilePath, caKeyFilePath)
		if err != nil {
			log.Println(err)
			return
		}

	case "install":
		if len(args) < 2 {
			log.Println("install command requires absolute file path to certificate file")
			return
		}

		path := args[1]
		err := cert.InstallCertificate(path)
		if err != nil {
			log.Println(err)
			return
		}

	default:
		log.Println("Unknown Command")
		showHelp()
	}
}

func showHelp() {
	fmt.Printf(`
Usage: %s [command] <options>
  commands:
    ca: Generate a certificate authority certificate
      required:
        name: <name> : Common name of certificate authority certificate
    site-cert: Generate a site certificate
      required:
        hostname: <name> : Host name of site certificate
      optional:
        ca-cert: <filepath> : Absolute filepath to CA certificate
        ca-key: <filepath> : Absolute path to CA Key file
    install: Install certificate in OS's certificate store'
      required:
        certFilePath: <filepath> : absolute filepath or certificate to be installed 
    help: show help
`, os.Args[0])
}

func generateCA(name string) error {
	caCert, caKey, err := cert.GenerateCA(name, nil)
	if err != nil {
		return fmt.Errorf("Failed to create certificate authority: %v\n", err)
	}

	err = cert.WriteKeyFiles("ca_cert.pem", "ca_key.pem", caCert, caKey)
	if err != nil {
		return fmt.Errorf("Failed to write certificate files: %v\n", err)
	}

	return nil
}

func generateSiteCert(hostname, caCertFilePath, caKeyFilePath string) error {
	if caCertFilePath == "" || caKeyFilePath == "" {
		fmt.Println("No certificate authority files specified")
		fmt.Println("Generating new ones . . . . ")

		err := generateCA("certgen")
		if err != nil {
			return err
		}

		fmt.Println("Certificate authority files generated successfully")
		fmt.Printf("Please install them with %s install ca_cert.pem ca_key.pem\n", os.Args[0])

		caCertFilePath = "ca_cert.pem"
		caKeyFilePath = "ca_key.pem"
	}

	caCert, err := loadCACert(caCertFilePath)
	if err != nil {
		return fmt.Errorf("Failed to load ca cert file: %v\n", err)
	}

	caKey, err := loadCAKey(caKeyFilePath)
	if err != nil {
		return fmt.Errorf("Failed to load ca key file: %v\n", err)
	}

	siteCert, siteKey, err := cert.GenerateSignedCertificate(hostname, caCert, caKey)
	if err != nil {
		return fmt.Errorf("Failed to generate site certificate files: %v\n", err)
	}

	return cert.WriteKeyFiles(fmt.Sprintf("%s_cert.pem", hostname), fmt.Sprintf("%s_key.pem", hostname), siteCert, siteKey)
}

func loadCACert(path string) (*x509.Certificate, error) {
	certPEM, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	block, _ := pem.Decode(certPEM)
	if block == nil || block.Type != "CERTIFICATE" {
		return nil, errors.New("failed to decode PEM block containing certificate")
	}

	certificate, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, err
	}

	return certificate, nil
}

func loadCAKey(path string) (*rsa.PrivateKey, error) {
	keyPEM, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	block, _ := pem.Decode(keyPEM)
	if block == nil {
		return nil, errors.New("failed to decode PEM block containing private key")
	}

	key, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		return nil, err
	}

	return key, nil
}
