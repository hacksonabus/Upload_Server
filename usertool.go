// usertool.go
//
// External user file manager for upload.go.
// 
// - Add user
// - Update password
// - Delete user
// - List users
// - bcrypt password hashing
// 
// Build:
//     go build usertool.go
// 
// Usage Examples:
//     ./usertool -file users.txt -add admin -password secret
//     ./usertool -file users.txt -update admin -password newpass
//     ./usertool -file users.txt -delete admin
//     ./usertool -file users.txt -list
// 
// User File Format:
//     username:bcrypt_hash
// 

package main

import (
	"bufio"
	"flag"
	"fmt"
	"log"
	"os"
	"strings"

	"golang.org/x/crypto/bcrypt"
)

func loadUsers(path string) (map[string]string, error) {
	users := make(map[string]string)

	file, err := os.Open(path)
	if err != nil {
		if os.IsNotExist(err) {
			return users, nil
		}
		return nil, err
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		parts := strings.SplitN(line, ":", 2)
		if len(parts) == 2 {
			users[parts[0]] = parts[1]
		}
	}
	return users, scanner.Err()
}

func saveUsers(path string, users map[string]string) error {
	file, err := os.Create(path)
	if err != nil {
		return err
	}
	defer file.Close()

	for u, h := range users {
		fmt.Fprintf(file, "%s:%s\n", u, h)
	}
	return nil
}

func hashPassword(p string) (string, error) {
	hash, err := bcrypt.GenerateFromPassword([]byte(p), bcrypt.DefaultCost)
	return string(hash), err
}

func main() {

	filePath := flag.String("file", "users.txt", "User file")
	addUser := flag.String("add", "", "Add user")
	updateUser := flag.String("update", "", "Update password")
	deleteUser := flag.String("delete", "", "Delete user")
	password := flag.String("password", "", "Password")
	listUsers := flag.Bool("list", false, "List users")

	flag.Parse()

	users, err := loadUsers(*filePath)
	if err != nil {
		log.Fatal(err)
	}

	switch {
	case *listUsers:
		fmt.Println("Users:")
		for u := range users {
			fmt.Println(" -", u)
		}
		return

	case *addUser != "":
		if *password == "" {
			log.Fatal("Password required")
		}
		if _, exists := users[*addUser]; exists {
			log.Fatal("User exists")
		}
		hash, _ := hashPassword(*password)
		users[*addUser] = hash
		fmt.Println("User added")

	case *updateUser != "":
		if *password == "" {
			log.Fatal("Password required")
		}
		hash, _ := hashPassword(*password)
		users[*updateUser] = hash
		fmt.Println("User updated")

	case *deleteUser != "":
		delete(users, *deleteUser)
		fmt.Println("User deleted")

	default:
		flag.PrintDefaults()
		return
	}

	if err := saveUsers(*filePath, users); err != nil {
		log.Fatal(err)
	}
}
