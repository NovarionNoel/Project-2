package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"log"
	"math/big"
	"net/http"
	"strconv"
	"time"

	"github.com/golang-jwt/jwt/v5"
	_ "github.com/mattn/go-sqlite3"
)

type AuthHandler struct {
	DB *sql.DB
}
type JWKSHandler struct {
	DB *sql.DB
}

var (
	goodPrivKey    *rsa.PrivateKey
	expiredPrivKey *rsa.PrivateKey
)

func main() {
	//open database
	db, err := sql.Open("sqlite3", "./totally_not_my_privateKeys.db")
	if err != nil {
		log.Fatal(err)
	}
	defer db.Close()
	initializeTable(db)
	genKeys()
	//store the keys
	storeKey(db, goodPrivKey, false)
	storeKey(db, expiredPrivKey, true)
	//handler structures so I can pass parameters
	authHandler := &AuthHandler{DB: db}
	jwksHandler := &JWKSHandler{DB: db}
	http.Handle("/.well-known/jwks.json", jwksHandler)
	http.Handle("/auth", authHandler)
	log.Fatal(http.ListenAndServe(":8080", nil))
}

// take rsa private key, convert to PEM, and store it in the database
func storeKey(db *sql.DB, key *rsa.PrivateKey, expired bool) {
	privDER := x509.MarshalPKCS1PrivateKey(key)
	privBlock := pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: privDER,
	}
	pemStr := string(pem.EncodeToMemory(&privBlock))

	exp := time.Now().Add(-1 * time.Hour).Unix()
	if !expired {
		exp = time.Now().Add(1 * time.Hour).Unix()
	}

	//put keys in database
	insertQuery := `INSERT INTO keys (key, exp) VALUES (?, ?)`
	stmt, err := db.Prepare(insertQuery)
	if err != nil {
		log.Fatal(err)
	}
	defer stmt.Close()

	_, err = stmt.Exec(pemStr, exp)
	if err != nil {
		log.Fatal(err)
	}

}

// fetch key from the database and return the key in *rsa.PrivateKey format.
func getKey(db *sql.DB, expired bool) *rsa.PrivateKey {
	var pemKey string
	var err error
	currentTime := time.Now().Unix()

	if expired {
		err = db.QueryRow("SELECT key FROM keys WHERE exp <= ? LIMIT 1", currentTime).Scan(&pemKey)
	} else {
		err = db.QueryRow("SELECT key FROM keys WHERE exp > ? LIMIT 1", currentTime).Scan(&pemKey)
	}

	if err != nil {
		if err == sql.ErrNoRows {

			log.Println("No matching key found")
		} else {
			log.Fatal(err)
		}
	}
	block, _ := pem.Decode([]byte(pemKey))
	if block == nil {

		return nil
	}

	privKey, err2 := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err2 != nil {
		return nil
	}
	return privKey
}

func genKeys() {
	// generate global key pair
	var err error
	goodPrivKey, err = rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		log.Fatalf("Error generating RSA keys: %v", err)
	}

	// Generate an expired key pair for demonstration purposes

	expiredPrivKey, err = rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		log.Fatalf("Error generating expired RSA keys: %v", err)
	}
}

const goodKID = "aRandomKeyID"

func (h *AuthHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	var (
		signingKey *rsa.PrivateKey
		keyID      string
		exp        int64
	)

	// Default to the good key
	signingKey = getKey(h.DB, false)
	keyID = goodKID
	exp = time.Now().Add(1 * time.Hour).Unix()

	// If the expired query parameter is set, use the expired key
	if expired, _ := strconv.ParseBool(r.URL.Query().Get("expired")); expired {
		signingKey = getKey(h.DB, true)
		keyID = "expiredKeyId"
		exp = time.Now().Add(-1 * time.Hour).Unix()
	}

	// Create the token with the expiry
	token := jwt.NewWithClaims(jwt.SigningMethodRS256, jwt.MapClaims{
		"exp": exp,
	})
	// Set the key ID header
	token.Header["kid"] = keyID
	// Sign the token with the private key
	signedToken, err := token.SignedString(signingKey)
	if err != nil {
		http.Error(w, "failed to sign token", http.StatusInternalServerError)
		return
	}

	_, _ = w.Write([]byte(signedToken))
}

// outline for JWKS key
type (
	JWKS struct {
		Keys []JWK `json:"keys"`
	}
	JWK struct {
		KID       string `json:"kid"`
		Algorithm string `json:"alg"`
		KeyType   string `json:"kty"`
		Use       string `json:"use"`
		N         string `json:"n"`
		E         string `json:"e"`
	}
)

func (h *JWKSHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	base64URLEncode := func(b *big.Int) string {
		return base64.RawURLEncoding.EncodeToString(b.Bytes())
	}

	publicKey := getKey(h.DB, false)
	resp := JWKS{
		Keys: []JWK{
			{
				KID:       goodKID,
				Algorithm: "RS256",
				KeyType:   "RSA",
				Use:       "sig",
				N:         base64URLEncode(publicKey.N),
				E:         base64URLEncode(big.NewInt(int64(publicKey.E))),
			},
		},
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(resp)
}

// check what needs to be done with the table
func initializeTable(db *sql.DB) {
	var name string

	err := db.QueryRow("SELECT name FROM sqlite_master WHERE type='table' AND name='keys'").Scan(&name)

	switch {
	case err == sql.ErrNoRows:

		createTable(db)
	case err != nil:
		log.Fatalf("Failed to check for table existence: %v", err)
	default:
		// Table exists. Drop and recreate.
		_, err = db.Exec("DROP TABLE keys")
		if err != nil {
			log.Fatalf("Failed to drop table: %v", err)
		}
		createTable(db)
	}

}

// create the table in the datbase
func createTable(db *sql.DB) {
	_, err := db.Exec(`CREATE TABLE keys (
		kid INTEGER PRIMARY KEY AUTOINCREMENT,
		key BLOB NOT NULL,
		exp INTEGER NOT NULL
	);
`)
	if err != nil {
		log.Fatalf("Failed to create table: %v", err)
	}
}
