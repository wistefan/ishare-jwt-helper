package main

import (
	"crypto/rsa"
	"encoding/base64"
	"encoding/pem"
	"io/ioutil"
	"os"
	"time"

	"github.com/golang-jwt/jwt"
	"github.com/google/uuid"
	log "github.com/sirupsen/logrus"
)

func main() {

	iShareClientID := os.Getenv("I_SHARE_CLIENT_ID")
	iShareIdpID := os.Getenv("I_SHARE_IDP_ID")
	if iShareClientID == "" {
		log.Error("No I_SHARE_CLIENT_ID provided")
		return
	}
	if iShareIdpID == "" {
		log.Error("No I_SHARE_IDP_ID provided")
		return
	}
	// the files are stored in folders namend by the clientId
	credentialsFolderPath := "/certificates"

	log.Info("CredentialsFolderPath: " + credentialsFolderPath)

	randomUuid, err := uuid.NewRandom()

	if err != nil {
		log.Warn("Was not able to generate a uuid.", err)
		return
	}

	// prepare token headers
	now := time.Now().Unix()
	jwtToken := jwt.NewWithClaims(jwt.SigningMethodRS256, jwt.MapClaims{
		"jti": randomUuid.String(),
		"iss": iShareClientID,
		"sub": iShareClientID,
		"aud": iShareIdpID,
		"iat": now,
		"exp": now + 30,
	})

	key, err := getSigningKey(credentialsFolderPath)
	if err != nil {
		log.Warn("Was not able to read the signing key.")
		return
	}
	if key == nil {
		log.Warn("Was not able to read a valid signing key.")
		return
	}

	cert, err := getEncodedCertificate(credentialsFolderPath)
	if err != nil {
		log.Warn("Was not able to read the certificate.")
		return
	}

	x5cCerts := [1]string{cert}
	jwtToken.Header["x5c"] = x5cCerts

	// sign the token
	signedToken, err := jwtToken.SignedString(key)
	if err != nil {
		log.Warn("Was not able to sign the jwt.", err)
		return
	}

	log.Infof("Token: %s", signedToken)
}

/**
* Read siging key from local filesystem
 */
func getSigningKey(credentialsFolderPath string) (key *rsa.PrivateKey, err error) {
	// read key file
	priv, err := readFile(credentialsFolderPath + "/key.pem")
	if err != nil {
		log.Warn("Was not able to read the key file. ", err)
		return key, err
	}

	// parse key file
	key, err = jwt.ParseRSAPrivateKeyFromPEM(priv)
	if err != nil {
		log.Warn("Was not able to parse the key.", err)
		return key, err
	}

	return key, err
}

/**
* Read and encode(base64) certificate from file system
 */
func getEncodedCertificate(credentialsFolderPath string) (encodedCert string, err error) {
	// read certificate file and set it in the token header
	cert, err := readFile(credentialsFolderPath + "/certificate.pem")
	if err != nil {
		log.Warn("Was not able to read the certificateChain file.", err)
		return encodedCert, err
	}
	certCer, _ := pem.Decode(cert)
	if certCer == nil {
		log.Warn("Was not able to decode certificate.")
		return encodedCert, err
	}
	encodedCert = base64.StdEncoding.EncodeToString(certCer.Bytes)
	return encodedCert, err
}

func readFile(filename string) ([]byte, error) {
	return ioutil.ReadFile(filename)
}
