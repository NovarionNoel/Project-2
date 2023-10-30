Nova Lader - Fall 2023
CSCE 3550 - Jacob Hochstetler

# JWKS Server with SQLite Database

This server is built in Go, using a mix of provided source code and modifcations to add an SQLite database to the website. Screenshots of Gradebot and testing suite are in the Screenshots directory.

Code stores the private keys in a database, and fetches them. Proper parameters are used to prevent injection.

## Running the Program

To simply run the server, you can enter
`go run main.go`
and navigate to the (host)[http://localhost:8080/] in your browser.

## Test Suite

Run tests with
`go test`
use -v for verbose output, and/or -cover for code coverage.
