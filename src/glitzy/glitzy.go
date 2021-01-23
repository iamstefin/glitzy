package glitzy

import (
	"encoding/hex"
	"fmt"
	"log"
	"os"

	"github.com/iamstefin/glitzy/src/models"
	"github.com/iamstefin/glitzy/src/utils"
	"github.com/manifoldco/promptui"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
)

// Add will add a new password to the database
func Add() (err error) {
	db, err := initDB()
	if err != nil {
		log.Fatalf("%v", err)
	}
	err = db.Create(utils.GetInfo(db)).Error
	if err != nil {
		log.Fatalf("Failed to add password!")
	}
	fmt.Println("Data added!")
	return
}

// Search will search for the passwords
func Search() (err error) {
	db, err := initDB()
	if err != nil {
		log.Fatalf("%v", err)
	}
	passwd := utils.AddOrCheckMainPassword(db)
	searchTerm := utils.GetNormalString("Enter the search term")
	var rtrmdl []models.User
	if db.Where("name LIKE ?", "%"+searchTerm+"%").Find(&rtrmdl).RowsAffected == 0 {
		fmt.Println("Password not found!")
		os.Exit(0)
	}
	templates := &promptui.SelectTemplates{
		Active:   " \U00002705 {{ .Name | cyan }} ({{ .Username }})",
		Inactive: " {{ .Name | cyan }} ({{ .Username }})",
		Selected: " \U00002705 {{ .Name }} ({{ .Username }})",
	}
	prompt := promptui.Select{
		Label:     "Select",
		Items:     rtrmdl,
		HideHelp:  true,
		Templates: templates,
	}
	i, _, err := prompt.Run()

	if err != nil {
		fmt.Printf("Prompt failed %v\n", err)
		return
	}
	cipherTextUsername, err := hex.DecodeString(rtrmdl[i].Username)
	if err != nil {
		log.Fatalf("%v", err)
	}
	cipherTextPassword, err := hex.DecodeString(rtrmdl[i].Password)
	if err != nil {
		log.Fatalf("%v", err)
	}
	plainUsername, err := utils.Decrypt([]byte(passwd), cipherTextUsername)
	if err != nil {
		log.Fatalf("%v", err)
	}
	plainPassword, err := utils.Decrypt([]byte(passwd), cipherTextPassword)
	if err != nil {
		log.Fatalf("%v", err)
	}
	fmt.Printf("The Password for %v Is %v\n", string(plainUsername), string(plainPassword))
	return nil
}

// Wipe will remove all the passwords
func Wipe() (err error) {
	db, err := initDB()
	if err != nil {
		log.Fatalf("%v", err)
	}
	utils.AddOrCheckMainPassword(db)
	fmt.Printf("%v Records Deleted \n", db.Exec("DELETE FROM users").RowsAffected)
	var HOME = os.Getenv("HOME")
	os.Remove(HOME + "/.glitzy/password.db")
	return
}

func initDB() (*gorm.DB, error) {
	if err := utils.AddOrCreateConfigDir(); err != nil {
		log.Fatalf("%v", err)
	}
	var HOME = os.Getenv("HOME")
	db, err := gorm.Open(sqlite.Open(HOME+"/.glitzy/password.db"), &gorm.Config{})
	if err != nil {
		return nil, err
	}
	db.AutoMigrate(&models.User{})
	db.AutoMigrate(&models.Main{})
	return db, nil
}
