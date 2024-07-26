package main

import (
	"fmt"
	"golang.org/x/crypto/bcrypt"
)

// HashPassword hashes a plain text password using bcrypt.
func HashPassword(password string) (string, error) {
	// Generate hashed password with default cost.
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return "", err
	}
	return string(hashedPassword), nil
}

// CheckPasswordHash compares a bcrypt hashed password with its possible plaintext equivalent.
func CheckPasswordHash(password, hashedPassword string) bool {
	err := bcrypt.CompareHashAndPassword([]byte(hashedPassword), []byte(password))
	return err == nil
}

func main() {
	password := "mySuperSecretPassword"

	// Generate hashed password
	hashedPassword, err := HashPassword(password)
	if err != nil {
		fmt.Println("Error hashing password:", err)
		return
	}

	fmt.Printf("Original password: %s\n", password)
	fmt.Printf("Hashed password: %s\n", hashedPassword)

	// Validate password
	isValid := CheckPasswordHash(password, hashedPassword)
	fmt.Printf("Password is valid: %v\n", isValid)

	// Check with a wrong password
	wrongPassword := "wrongPassword"
	isValid = CheckPasswordHash(wrongPassword, hashedPassword)
	fmt.Printf("Wrong password is valid: %v\n", isValid)
}
