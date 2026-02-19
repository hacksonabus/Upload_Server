// upload.go
//
// Secure file upload server with:
//
// - File upload + download
// - Directory listing
// - HTTP Basic Authentication (users stored in external file)
// - bcrypt password hashes
// - Inactivity-based shutdown (default 5 minutes from last completed request)
// - Optional HTTPS with self-signed certificate generation
//
// Build:
//   go mod init upload
//   go get golang.org/x/crypto/bcrypt
//   go build upload.go
//
// Usage Examples:
//  ./upload
//  ./upload -https -port 8888 -timeout 10 -cert server.crt -key server.key -users users.txt
//
// Generate/manage users:
//  go build usertool.go
//  ./usertool -add alice
//

package main

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"embed"
	"encoding/pem"
	"flag"
	"fmt"
	"html/template"
	"io"
	"log"
	"math/big"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/bcrypt"
)

// =====================
// Embedded assets
// =====================

//go:embed favicon.svg favicon.ico
var faviconFS embed.FS

// =====================
// Globals
// =====================

var (
	userFile   string
	users      map[string]string
	usersMutex sync.RWMutex

	lastActivity time.Time
	activityLock sync.Mutex
	timeoutMin   int
)

// =====================
// Data structures
// =====================

type FileInfo struct {
	Name     string
	Size     int64
	Modified string
}

type PageData struct {
	Files []FileInfo
}

// =====================
// Template
// =====================

const htmlPage = `
<!doctype html>
<html>
<head>
<meta charset="utf-8">
<title>Secure Upload</title>
<link rel="icon" type="image/svg+xml" href="/favicon.svg">
<link rel="icon" type="image/x-icon" href="/favicon.ico">
</head>
<body>
<h2>Upload a file</h2>
<form method="POST" enctype="multipart/form-data">
<input type="file" name="file">
<input type="submit" value="Upload">
</form>

<h2>Files</h2>
<table border="1" cellpadding="6">
<tr><th>Name</th><th>Size</th><th>Modified</th></tr>
{{- if .Files }}
{{- range .Files }}
<tr>
<td><a href="/download?file={{ .Name }}">{{ .Name }}</a></td>
<td>{{ .Size }} bytes</td>
<td>{{ .Modified }}</td>
</tr>
{{- end }}
{{- else }}
<tr><td colspan="3"><em>No files</em></td></tr>
{{- end }}
</table>
</body>
</html>
`

// =====================
// Activity Tracking
// =====================

func updateActivity() {
	activityLock.Lock()
	lastActivity = time.Now()
	activityLock.Unlock()
}

func monitorInactivity(server *http.Server) {
	for {
		time.Sleep(10 * time.Second)

		activityLock.Lock()
		inactive := time.Since(lastActivity)
		activityLock.Unlock()

		if inactive > time.Duration(timeoutMin)*time.Minute {
			log.Printf("No activity for %d minutes. Shutting down...", timeoutMin)
			server.Shutdown(context.Background())
			return
		}
	}
}

// =====================
// User Management
// =====================

func loadUsers() error {
	usersMutex.Lock()
	defer usersMutex.Unlock()

	users = make(map[string]string)

	data, err := os.ReadFile(userFile)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}

	lines := strings.Split(string(data), "\n")
	for _, line := range lines {
		parts := strings.SplitN(line, ":", 2)
		if len(parts) == 2 {
			users[parts[0]] = parts[1]
		}
	}
	return nil
}

func checkAuth(username, password string) bool {
	usersMutex.RLock()
	hash, ok := users[username]
	usersMutex.RUnlock()

	if !ok {
		return false
	}

	return bcrypt.CompareHashAndPassword([]byte(hash), []byte(password)) == nil
}

func basicAuth(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {

		username, password, ok := r.BasicAuth()
		if !ok || !checkAuth(username, password) {
			w.Header().Set("WWW-Authenticate", `Basic realm="Restricted"`)
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}

		next(w, r)
		updateActivity()
	}
}

// =====================
// File Helpers
// =====================

func isHiddenFile(dir, name string) bool {

	// Always hide internal control file
	if name == ".hidden.txt" {
		return true
	}

	// Hide users file
	if name == filepath.Base(userFile) {
		return true
	}

	// Hide TLS cert and key if defined via flags
	certFlag := flag.Lookup("cert")
	keyFlag := flag.Lookup("key")

	if certFlag != nil && name == filepath.Base(certFlag.Value.String()) {
		return true
	}

	if keyFlag != nil && name == filepath.Base(keyFlag.Value.String()) {
		return true
	}

	// Hide files listed in .hidden.txt
	hiddenFiles := loadHiddenFiles(dir)
	if hiddenFiles[name] {
		return true
	}

	return false
}

func loadHiddenFiles(dir string) map[string]bool {
	hidden := make(map[string]bool)

	path := filepath.Join(dir, ".hidden.txt")
	data, err := os.ReadFile(path)
	if err != nil {
		return hidden // no hidden file = nothing hidden
	}

	lines := strings.Split(string(data), "\n")
	for _, line := range lines {
		name := strings.TrimSpace(line)
		if name != "" {
			hidden[name] = true
		}
	}

	return hidden
}

func listFiles(dir string) ([]FileInfo, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, err
	}

	self := filepath.Base(os.Args[0])
	var files []FileInfo

	for _, entry := range entries {
		name := entry.Name()

		if entry.IsDir() || name == self {
			continue
		}

		if isHiddenFile(dir, name) {
			continue
		}

		info, _ := entry.Info()

		files = append(files, FileInfo{
			Name:     name,
			Size:     info.Size(),
			Modified: info.ModTime().Format(time.RFC3339),
		})
	}

	return files, nil
}

// =====================
// Handlers
// =====================

func uploadHandler(w http.ResponseWriter, r *http.Request) {
	log.Printf("Request: %s %s from %s", r.Method, r.URL.Path, r.RemoteAddr)

	execDir, _ := os.Getwd()

	if r.Method == http.MethodPost {
		file, header, err := r.FormFile("file")
		if err != nil {
			http.Error(w, "Bad upload", http.StatusBadRequest)
			return
		}
		defer file.Close()

		dstPath := filepath.Join(execDir, filepath.Base(header.Filename))
		dst, _ := os.Create(dstPath)
		defer dst.Close()

		io.Copy(dst, file)

		http.Redirect(w, r, "/", http.StatusSeeOther)
		return
	}

	files, _ := listFiles(execDir)
	tmpl := template.Must(template.New("page").Parse(htmlPage))
	tmpl.Execute(w, PageData{Files: files})
}

func downloadHandler(w http.ResponseWriter, r *http.Request) {
	filename := filepath.Base(r.URL.Query().Get("file"))
	if filename == "" {
		http.Error(w, "Missing file", http.StatusBadRequest)
		return
	}

	execDir, _ := os.Getwd()

	if isHiddenFile(execDir, filename) {
		http.Error(w, "Forbidden", http.StatusForbidden)
		return
	}

	fullPath := filepath.Join(execDir, filename)

	info, err := os.Stat(fullPath)
	if err != nil || info.IsDir() {
		http.Error(w, "Not found", http.StatusNotFound)
		return
	}

	w.Header().Set("Content-Disposition",
		fmt.Sprintf(`attachment; filename="%s"`, filename))
	http.ServeFile(w, r, fullPath)
}

// =====================
// Self-Signed Cert
// =====================

func generateSelfSigned(certFile, keyFile string) error {

	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return err
	}

	serial, _ := rand.Int(rand.Reader, big.NewInt(1<<62))

	template := x509.Certificate{
		SerialNumber: serial,
		Subject: pkix.Name{
			Organization: []string{"Upload Server"},
		},
		NotBefore: time.Now(),
		NotAfter:  time.Now().Add(365 * 24 * time.Hour),

		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		DNSNames:              []string{"localhost"},
	}

	template.IPAddresses = []net.IP{net.ParseIP("127.0.0.1")}

	derBytes, err := x509.CreateCertificate(rand.Reader, &template, &template, &priv.PublicKey, priv)
	if err != nil {
		return err
	}

	certOut, _ := os.Create(certFile)
	pem.Encode(certOut, &pem.Block{Type: "CERTIFICATE", Bytes: derBytes})
	certOut.Close()

	keyOut, _ := os.Create(keyFile)
	pem.Encode(keyOut, &pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(priv),
	})
	keyOut.Close()

	log.Println("Generated self-signed certificate")
	return nil
}

// =====================
// Main
// =====================

func main() {

	port := flag.Int("port", 8888, "Port")
	flag.IntVar(&timeoutMin, "timeout", 5, "Inactivity timeout (minutes)")
	https := flag.Bool("https", false, "Enable HTTPS")
	certFile := flag.String("cert", "server.crt", "Certificate file")
	keyFile := flag.String("key", "server.key", "Key file")
	flag.StringVar(&userFile, "users", "users.txt", "User file")
	flag.Parse()

	loadUsers()

	mux := http.NewServeMux()
	mux.HandleFunc("/", basicAuth(uploadHandler))
	mux.HandleFunc("/download", basicAuth(downloadHandler))

	server := &http.Server{
		Addr:    fmt.Sprintf(":%d", *port),
		Handler: mux,
	}

	lastActivity = time.Now()
	go monitorInactivity(server)

	log.Printf("Starting server on port %d (timeout %d min)", *port, timeoutMin)

	if *https {
		if _, err := os.Stat(*certFile); os.IsNotExist(err) {
			generateSelfSigned(*certFile, *keyFile)
		}

		server.TLSConfig = &tls.Config{MinVersion: tls.VersionTLS12}
		log.Fatal(server.ListenAndServeTLS(*certFile, *keyFile))
	} else {
		log.Fatal(server.ListenAndServe())
	}
}
