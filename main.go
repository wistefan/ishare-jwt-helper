package main

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"
	"io/ioutil"
	"net/http"
	"os"
	"strconv"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt"
	"github.com/google/uuid"
	log "github.com/sirupsen/logrus"
	"gopkg.in/yaml.v2"
)

var runServer bool = false

var defaultConfigPath string = "/config.yaml"
var credentials map[string]Credential = map[string]Credential{}
var serverPort int = 8080

var defaultIShareClientID string
var defaultIShareIdpID string

func init() {

	serverEnabled, err := strconv.ParseBool(os.Getenv("RUN_SERVER"))
	if err == nil && serverEnabled {
		runServer = serverEnabled
	}

	serverPortEnvVar := os.Getenv("SERVER_PORT")
	serverPort, err := strconv.Atoi(serverPortEnvVar)
	if err != nil {
		log.Warnf("No valid server port was provided, run on default %s.", serverPort)
	}

	configPath := os.Getenv("CONFIG_PATH")
	if configPath == "" {
		configPath = defaultConfigPath
	}

	configBytes, err := readFile(configPath)

	if err != nil {
		log.Fatalf("Was not able to read the config %s.", configPath, err)
	}

	err = yaml.Unmarshal(configBytes, credentials)
	if err != nil {
		log.Fatalf("Was not able to unmarshal config %s.", configPath, err)
	}

	log.Infof("Config is: %v", credentials)

	defaultIShareClientID = os.Getenv("I_SHARE_CLIENT_ID")
	defaultIShareIdpID = os.Getenv("I_SHARE_IDP_ID")
}

func main() {

	if runServer {

		router := gin.Default()

		router.GET("/token", token)

		router.Run(fmt.Sprintf("0.0.0.0:%v", serverPort))
		log.Infof("Started router at %v", serverPort)
	} else {
		token, _ := generateToken(defaultIShareClientID, defaultIShareIdpID)
		log.Infof("Token: %s", token)
	}

}

type Token struct {
	Token string `json:"token"`
}

func token(c *gin.Context) {
	clientId := c.Query("clientId")
	idpId := c.Query("idpId")

	if clientId == "" {
		clientId = defaultIShareClientID
	}
	if idpId == "" {
		idpId = defaultIShareIdpID
	}
	log.Infof("Creating token for %s - %s", clientId, idpId)

	token, err := generateToken(clientId, idpId)

	if err != nil {
		c.AbortWithError(http.StatusInternalServerError, err)
		return
	}
	c.AbortWithStatusJSON(http.StatusOK, Token{token})
}

func generateToken(clientId string, idpId string) (token string, err error) {
	randomUuid, err := uuid.NewRandom()

	if err != nil {
		log.Warn("Was not able to generate a uuid.", err)
		return
	}

	// prepare token headers
	now := time.Now().Unix()
	jwtToken := jwt.NewWithClaims(jwt.SigningMethodRS256, jwt.MapClaims{
		"jti": randomUuid.String(),
		"iss": clientId,
		"sub": clientId,
		"aud": idpId,
		"iat": now,
		"exp": now + 30,
	})

	credential := credentials[clientId]

	if credential == (Credential{}) {
		log.Errorf("No credentials for %s exist.", clientId)
		return token, errors.New("no_such_credentials")
	}

	key, err := getSigningKey(credential.Key)
	if err != nil {
		log.Warn("Was not able to read the signing key.")
		return
	}
	if key == nil {
		log.Warn("Was not able to read a valid signing key.")
		return
	}

	cert, err := getEncodedCertificate(credential.Certificate)
	if err != nil {
		log.Warn("Was not able to read the certificate.")
		return
	}

	x5cCerts := cert
	jwtToken.Header["x5c"] = x5cCerts

	// sign the token
	signedToken, err := jwtToken.SignedString(key)
	if err != nil {
		log.Warn("Was not able to sign the jwt.", err)
		return
	}

	log.Infof("Token: %s", signedToken)
	return signedToken, err
}

/**
* Read siging key from local filesystem
 */
func getSigningKey(keyPath string) (key *rsa.PrivateKey, err error) {
	// read key file
	priv, err := readFile(keyPath)
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
func getEncodedCertificate(certificatePath string) (encodedCert []string, err error) {
	// read certificate file
	cert, err := readFile(certificatePath)
	if err != nil {
		log.Warnf("Was not able to read the certificate file from %s.", certificatePath, err)
		return encodedCert, err
	}
	derArray := []string{}

	for block, rest := pem.Decode(cert); block != nil; block, rest = pem.Decode(rest) {
		switch block.Type {
		case "CERTIFICATE":
			// check that its a parsable certificate, only done on startup e.g. not performance critical
			_, err := x509.ParseCertificate(block.Bytes)
			if err != nil {
				log.Warnf("Was not able to parse the certificat from %s.", certificatePath, err)
				return encodedCert, err
			}
			derArray = append(derArray, base64.StdEncoding.EncodeToString(block.Bytes))
		default:
			log.Infof("Received unexpected block %s.", block.Type)
			return encodedCert, fmt.Errorf("unexpected-block")
		}
	}

	return derArray, err
}

func readFile(filename string) ([]byte, error) {
	return ioutil.ReadFile(filename)
}
