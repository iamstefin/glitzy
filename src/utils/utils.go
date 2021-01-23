package utils

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"log"
	"os"

	"github.com/iamstefin/glitzy/src/models"
	"github.com/manifoldco/promptui"
	"golang.org/x/crypto/scrypt"
	"gorm.io/gorm"
)

// GetInfo input the user info from terminal
func GetInfo(db *gorm.DB) *models.User {
	MainPassword := AddOrCheckMainPassword(db)
	ServiceName := GetNormalString("Service Name ")
	Username := GetNormalString("Username ")
	Password := getProtectedString("Password")
	cipherUsername, err := Encrypt([]byte(MainPassword), []byte(Username))
	if err != nil {
		log.Fatalf("%v", err)
	}
	cipherPassword, err := Encrypt([]byte(MainPassword), []byte(Password))
	if err != nil {
		log.Fatalf("%v", err)
	}
	return &models.User{Name: ServiceName, Username: hex.EncodeToString(cipherUsername), Password: hex.EncodeToString(cipherPassword)}
}

// GetNormalString input normal text from terminal
func GetNormalString(promptText string) string {
	validate := func(input string) error {
		if len(input) < 4 {
			return errors.New("Must be more than 4 characters")
		}
		return nil
	}
	prompt := promptui.Prompt{
		Label:    promptText,
		Validate: validate,
	}
	result, err := prompt.Run()

	if err != nil {
		log.Fatalf("%v", err)
	}
	return result
}

// getProtectedString input protected text from terminal
func getProtectedString(promptText string) string {
	validate := func(input string) error {
		if len(input) < 6 {
			return errors.New("Password must have more than 6 characters")
		}
		return nil
	}

	prompt := promptui.Prompt{
		Label:    promptText,
		Validate: validate,
		Mask:     '.',
	}
	result, err := prompt.Run()
	if err != nil {
		log.Fatalf("%v", err)
	}

	return result
}

// AddOrCheckMainPassword add a main password to the application
func AddOrCheckMainPassword(db *gorm.DB) string {
	if (db.Find(&models.Main{}).RowsAffected == 0) {
		fmt.Println("Main Password not configured!")
		mainPass := getProtectedString("Enter the Main Password")
		mainPassRe := getProtectedString("Enter the Main Password again")
		if mainPass != mainPassRe {
			log.Fatalf("Password Mismatch!")
		}
		hash := sha256.New()
		hash.Write([]byte(mainPass))
		err := db.Create(&models.Main{PasswordHash: hex.EncodeToString(hash.Sum(nil))}).Error
		if err != nil {
			log.Fatalf("%v", err)
		}
		return mainPassRe
	} else {
		var dbInfo models.Main
		db.First(&dbInfo)
		userInputMainPass := getProtectedString("Enter the Main Password")
		hash := sha256.New()
		hash.Write([]byte(userInputMainPass))
		if dbInfo.PasswordHash == hex.EncodeToString(hash.Sum(nil)) {
			fmt.Println("Authenticated with Main Password")
		} else {
			fmt.Println("Invalid Password!")
			os.Exit(0)
		}
		return userInputMainPass
	}
}

// Encrypt is used to encrypt the clear text password
func Encrypt(key, data []byte) ([]byte, error) {
	key, salt, err := DeriveKey(key, nil)
	if err != nil {
		return nil, err
	}
	blockCipher, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(blockCipher)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err = rand.Read(nonce); err != nil {
		return nil, err
	}
	ciphertext := gcm.Seal(nonce, nonce, data, nil)
	ciphertext = append(ciphertext, salt...)
	return ciphertext, nil
}

// Decrypt is used to decrypt the cipher with the password
func Decrypt(key, data []byte) ([]byte, error) {
	salt, data := data[len(data)-32:], data[:len(data)-32]
	key, _, err := DeriveKey(key, salt)
	if err != nil {
		return nil, err
	}
	blockCipher, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(blockCipher)
	if err != nil {
		return nil, err
	}
	nonce, ciphertext := data[:gcm.NonceSize()], data[gcm.NonceSize():]
	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, err
	}
	return plaintext, nil
}

// DeriveKey derive a key with the password
func DeriveKey(password, salt []byte) ([]byte, []byte, error) {
	if salt == nil {
		salt = make([]byte, 32)
		if _, err := rand.Read(salt); err != nil {
			return nil, nil, err
		}
	}
	key, err := scrypt.Key(password, salt, 32768, 8, 1, 32)
	if err != nil {
		return nil, nil, err
	}
	return key, salt, nil
}

// AddOrCreateConfigDir creates the .glitzy folder in the home directory
func AddOrCreateConfigDir() error {
	var HOME = os.Getenv("HOME")
	if _, err := os.Stat(HOME + "/.glitzy"); err != nil {
		if os.IsNotExist(err) {
			err := os.Mkdir(HOME+"/.glitzy", 0755)
			if err != nil {
				return err
			}
		}
	}
	return nil
}
