package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	crypto_rand "crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
    "database/sql"
	"encoding/pem"
	"expvar"
    "encoding/json"
	"flag"
    _ "fmt"
    "io"
	"math/big"
	"math/rand"
	"net/http"
	"os"
    "os/user"
	"time"

	"github.com/pinterest/knox"
	"github.com/pinterest/knox/log"
	"github.com/pinterest/knox/server"
	"github.com/pinterest/knox/server/auth"
	"github.com/pinterest/knox/server/keydb"
    
    _ "github.com/lib/pq"
)

const caCert = `-----BEGIN CERTIFICATE-----
MIIB5jCCAYygAwIBAgIUD/1LTTQNvk3Rp9399flLlimbgngwCgYIKoZIzj0EAwIw
UTELMAkGA1UEBhMCVVMxCzAJBgNVBAgTAkNBMRgwFgYDVQQKEw9NeSBDb21wYW55
IE5hbWUxGzAZBgNVBAMTEnVzZU9ubHlJbkRldk9yVGVzdDAeFw0xODAzMDIwMTU5
MDBaFw0yMzAzMDEwMTU5MDBaMFExCzAJBgNVBAYTAlVTMQswCQYDVQQIEwJDQTEY
MBYGA1UEChMPTXkgQ29tcGFueSBOYW1lMRswGQYDVQQDExJ1c2VPbmx5SW5EZXZP
clRlc3QwWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAARbSovOAo4ZimGBOn+tyftX
+GXShKsy2eFdvX9WfYx2NvYnw+RSM/JjRSBhUsCPXuEh/E5lhwRVfUxIlHry1CkS
o0IwQDAOBgNVHQ8BAf8EBAMCAQYwDwYDVR0TAQH/BAUwAwEB/zAdBgNVHQ4EFgQU
jjNCAZxA5kjDK1ogrwkdziFiDgkwCgYIKoZIzj0EAwIDSAAwRQIgLXo9amyNn1Y3
qLpqrzVF7N7UQ3mxTl01MvnsqvahI08CIQCArwO8KmbPbN5XZrQ2h9zUgbsebwSG
dfOY505yMqiXig==
-----END CERTIFICATE-----`

var gitSha = expvar.NewString("version")
var service = expvar.NewString("service")

var (
	flagAddr = flag.String("http", ":9000", "HTTP port to listen on")
)

const (
	authTimeout = 10 * time.Second // Calls to auth timeout after 10 seconds
	serviceName = "knox_prod"
)

type KeyConfig struct {
    EncKey []byte `json:"encKey"`
}

func main() {
	rand.Seed(time.Now().UTC().UnixNano())
	flag.Parse()
	accLogger, errLogger := setupLogging("prod", serviceName)

    u, err := user.Current()
	if err != nil {
        os.Exit(1)
	}

    keyFile, err := os.Open(u.HomeDir + "/.knox_server_config.json")
    if err != nil {
        keyFile.Close()
        cwd, _ := os.Getwd()
        keyFile, err = os.Open(cwd + "/.knox_server_config.json")
        defer keyFile.Close()
        if (err != nil) {
            errLogger.Fatal("Failed to read knox_server_config.json: ", err)
        }
    }
    keyConfig := KeyConfig{}
    decoder := json.NewDecoder(keyFile) 
    err = decoder.Decode(&keyConfig) 
    if err != io.EOF && err != nil {
        errLogger.Fatal("Could not decode knox_server_config.json: ", err)
    }
	dbEncryptionKey := []byte(keyConfig.EncKey)
    if len(keyConfig.EncKey) != 32 {
        errLogger.Fatal("Incorect key size, must be 32 byte, now: ", len(keyConfig.EncKey))
    }
	cryptor := keydb.NewAESGCMCryptor(0, dbEncryptionKey)

	tlsCert, tlsKey, err := buildCert()
	if err != nil {
		errLogger.Fatal("Failed to make TLS key or cert: ", err)
	}

    d, err := sql.Open("postgres", "user=postgres dbname=athena sslmode=disable")
    if err != nil {
        errLogger.Fatal("db: ", err)
    }
    db, err := keydb.NewPostgreSQLDB(d)
    if err != nil {
        errLogger.Fatal("db: ", err)
    }
	//db := keydb.NewTempDB()

	server.AddDefaultAccess(&knox.Access{
		Type:       knox.UserGroup,
		ID:         "security-team",
		AccessType: knox.Admin,
	})

	certPool := x509.NewCertPool()
	certPool.AppendCertsFromPEM([]byte(caCert))

	decorators := [](func(http.HandlerFunc) http.HandlerFunc){
		server.Logger(accLogger),
		server.AddHeader("Content-Type", "application/json"),
		server.AddHeader("X-Content-Type-Options", "nosniff"),
		server.Authentication([]auth.Provider{
			//auth.NewMTLSAuthProvider(certPool),
			//auth.NewGitHubProvider(authTimeout),
			//auth.NewSpiffeAuthProvider(certPool),
            auth.NewSSHAuthorizationProvider(),
		}),
	}

	r := server.GetRouter(cryptor, db, decorators)

	http.Handle("/", r)

	errLogger.Fatal(serveTLS(tlsCert, tlsKey, *flagAddr))
}

func setupLogging(gitSha, service string) (*log.Logger, *log.Logger) {
	accLogger := log.New(os.Stderr, "", 0)
	accLogger.SetVersion(gitSha)
	accLogger.SetService(service)

	errLogger := log.New(os.Stderr, "", 0)
	errLogger.SetVersion(gitSha)
	errLogger.SetService(service)
	return accLogger, errLogger
}

func buildCert() (certPEMBlock, keyPEMBlock []byte, err error) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), crypto_rand.Reader)
	if err != nil {
		return nil, nil, err
	}

	notBefore := time.Now()
	notAfter := notBefore.Add(24 * time.Hour)
	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNumber, err := crypto_rand.Int(crypto_rand.Reader, serialNumberLimit)
	if err != nil {
		return nil, nil, err
	}

	template := x509.Certificate{
		SerialNumber: serialNumber,
		Subject:      pkix.Name{Organization: []string{"Acme Co"}},
		NotBefore:    notBefore,
		NotAfter:     notAfter,

		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}

	template.DNSNames = []string{"localhost"}

	derBytes, err := x509.CreateCertificate(crypto_rand.Reader, &template, &template, &priv.PublicKey, priv)
	if err != nil {
		return nil, nil, err
	}
	b, err := x509.MarshalECPrivateKey(priv)
	if err != nil {
		return nil, nil, err
	}

	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: derBytes}), pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: b}), nil
}

// serveTLS sets up TLS using Mozilla reccommendations and then serves http
func serveTLS(certPEMBlock, keyPEMBlock []byte, httpPort string) error {
	// This TLS config disables RC4 and SSLv3.
	tlsConfig := &tls.Config{
		NextProtos:               []string{"http/1.1"},
		MinVersion:               tls.VersionTLS12,
		PreferServerCipherSuites: true,
		ClientAuth:               tls.RequestClientCert,
		CipherSuites: []uint16{
			tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
		},
	}

	tlsConfig.Certificates = make([]tls.Certificate, 1)
	var err error
	tlsConfig.Certificates[0], err = tls.X509KeyPair(certPEMBlock, keyPEMBlock)
	if err != nil {
		return err
	}
	server := &http.Server{Addr: httpPort, Handler: nil, TLSConfig: tlsConfig}

	return server.ListenAndServeTLS("", "")
}
