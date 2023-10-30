package main

import (
	"bytes"
	"database/sql"
	"encoding/json"
	"io/ioutil"
	"log"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/golang-jwt/jwt/v5"
)

// tests if table is createdB
func TestCreateTable(t *testing.T) {
	var name string
	db, err := sql.Open("sqlite3", "./test_database.db")
	if err != nil {
		t.Fatalf("Failed to open test database: %v", err)
	}

	defer db.Close()

	err1 := db.QueryRow("SELECT name FROM sqlite_master WHERE type='table' AND name='keys'").Scan(&name)

	//if table already exists, drop it
	switch {
	case err1 == sql.ErrNoRows:
		break
	case err1 != nil:
		log.Fatalf("Failed to check for table existence: %v", err1)
	default:
		_, err = db.Exec("DROP TABLE keys")
		if err1 != nil {
			log.Fatalf("Failed to drop table: %v", err1)
		}
	}

	createTable(db)

	err2 := db.QueryRow("SELECT name FROM sqlite_master WHERE type='table' AND name='keys'").Scan(&name)
	if err2 == sql.ErrNoRows {
		t.Fatalf("Failed to create table: %v ", err2)
	}
}

// tests if keys generate
func TestGenKeys(t *testing.T) {
	genKeys()
	if goodPrivKey == nil {
		t.Fatalf("Failed to generate good key")
	}
	if expiredPrivKey == nil {
		t.Fatalf("Failed to generate expired key")
	}
}

// tests if getting keys works as expected
func TestRetrieveKeys(t *testing.T) {

}

// tests if db can insert
func TestStoreKeys(t *testing.T) {
	var pemKey string
	db, err := sql.Open("sqlite3", "./test_database.db")
	if err != nil {
		t.Fatalf("Failed to open test database: %v", err)
	}

	defer db.Close()
	storeKey(db, goodPrivKey, false)
	err = db.QueryRow("SELECT key FROM keys WHERE kid = ?", 1).Scan(&pemKey)

	if err != nil {
		if err == sql.ErrNoRows {
			t.Fatalf("Failed to store key: %v", err)
		} else {
			log.Fatal(err)
		}
	}

	storeKey(db, expiredPrivKey, true)
	err = db.QueryRow("SELECT key FROM keys WHERE kid = ?", 2).Scan(&pemKey)
	if err != nil {
		if err == sql.ErrNoRows {

			t.Fatalf("Failed to store key: %v", err)
		} else {
			log.Fatal(err)
		}
	}
}

// tests if auth returns expected responses
func TestExpectedAuthResponses(t *testing.T) {
	db, err := sql.Open("sqlite3", "./test_database.db")
	if err != nil {
		t.Fatalf("Failed to open test database: %v", err)
	}
	defer db.Close()
	authHandler := &AuthHandler{DB: db}

	tests := []struct {
		method string
		status int
	}{
		{"GET", http.StatusMethodNotAllowed},
		{"PUT", http.StatusMethodNotAllowed},
		{"DELETE", http.StatusMethodNotAllowed},
		{"PATCH", http.StatusMethodNotAllowed},
		{"POST", http.StatusOK},
	}

	for _, tt := range tests {
		req, err := http.NewRequest(tt.method, "/auth", nil)
		if err != nil {
			t.Fatalf("Failed to create request: %v", err)
		}

		// Record the response
		rr := httptest.NewRecorder()
		authHandler.ServeHTTP(rr, req)

		// Check the status code
		if status := rr.Code; status != tt.status {
			t.Errorf("handler returned wrong status code: got %v want %v", status, tt.status)
		}
	}
}

// tests if well-known/jwks.json returns expected reponses
func TestExpectedWKJWKSResponses(t *testing.T) {

	db, err := sql.Open("sqlite3", "./test_database.db")
	if err != nil {
		t.Fatalf("Failed to open test database: %v", err)
	}
	defer db.Close()
	jwksHandler := &JWKSHandler{DB: db}
	tests := []struct {
		method string
		status int
	}{
		{"POST", http.StatusMethodNotAllowed},
		{"PUT", http.StatusMethodNotAllowed},
		{"DELETE", http.StatusMethodNotAllowed},
		{"PATCH", http.StatusMethodNotAllowed},
		{"GET", http.StatusOK},
	}

	for _, tt := range tests {
		req, err := http.NewRequest(tt.method, "/.well-known/jwks.json", nil)
		if err != nil {
			t.Fatalf("Failed to create request: %v", err)
		}

		// Record the response
		rr := httptest.NewRecorder()
		jwksHandler.ServeHTTP(rr, req)

		// Check the status code
		if status := rr.Code; status != tt.status {
			t.Errorf("handler returned wrong status code: got %v want %v", status, tt.status)
		}
	}
}

// tests if well-known/jwks.json response is in jwks format
func TestJWKSFormat(t *testing.T) {
	db, err := sql.Open("sqlite3", "./test_database.db")
	if err != nil {
		t.Fatalf("Failed to open test database: %v", err)
	}
	defer db.Close()

	jwksHandler := &JWKSHandler{DB: db}
	server := httptest.NewServer(jwksHandler)
	defer server.Close()

	// Make a request to the test server's .well-known/jwks.json endpoint
	resp, err := http.Get(server.URL + "/.well-known/jwks.json")
	if err != nil {
		t.Fatalf("Failed to make GET request: %v", err)
	}
	defer resp.Body.Close()

	// Decode the response
	var jwks JWKS
	if err := json.NewDecoder(resp.Body).Decode(&jwks); err != nil {
		t.Fatalf("Failed to decode response: %v", err)
	}

	// Validate the response
	// This is a basic check to ensure the response isn't empty.
	// You might want to add more detailed checks based on your expectations.
	if len(jwks.Keys) == 0 {
		t.Errorf("No keys found in JWKS response")
	}
	for _, key := range jwks.Keys {
		if key.KID == "" {
			t.Errorf("KID should not be empty")
		}
		if key.Algorithm == "" {
			t.Errorf("Algorithm should not be empty")
		}
		if key.KeyType == "" {
			t.Errorf("KeyType should not be empty")
		}
		if key.E == "" {
			t.Errorf("Exponent should not be empty")
		}
		if key.N == "" {
			t.Errorf("N should not be empty")
		}
		if key.Use == "" {
			t.Errorf("Use should not be empty")
		}
	}

}

// test that auth returns a JWT
func TestAuthResponse(t *testing.T) {
	db, err := sql.Open("sqlite3", "./test_database.db") // Use a test database if possible
	if err != nil {
		t.Fatalf("Failed to open test database: %v", err)
	}
	defer db.Close()

	authHandler := &AuthHandler{DB: db}
	server := httptest.NewServer(authHandler)
	defer server.Close()

	reqData := map[string]string{
		"username": "dummyUser",
		"password": "dummyPass",
	}
	reqBody, _ := json.Marshal(reqData)

	resp, err := http.Post(server.URL+"/auth", "application/json", bytes.NewBuffer(reqBody))
	if err != nil {
		t.Fatalf("Failed to make POST request: %v", err)
	}
	defer resp.Body.Close()

	// Read response
	tokenBytes, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("Failed to read response body: %v", err)
	}
	tokenStr := string(tokenBytes)

	// Parse JWT without validating the signature
	token, _, err := new(jwt.Parser).ParseUnverified(tokenStr, &jwt.MapClaims{})

	if err != nil {
		t.Fatalf("Failed to parse token: %v", err)
	}
	if token == nil {
		t.Fatalf("Failed to parse token: token empty")
	}

}
