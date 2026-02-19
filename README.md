# Upload_Server (Go)
A [relatively] minimal, secure file upload server written in Go with:
- File upload & download
- Directory listing
- HTTP Basic Authentication
- bcrypt password hashing
- External user file management tool
- Inactivity-based auto shutdown
- Optional HTTPS (self-signed certificate auto-generation)

Designed to be simple, self-contained, and easy to deploy.

## Features
| Feature | Description |
|-------- | ----------- |
| Authentication | HTTP Basic Auth |
| Password Storage | bcrypt hashed passwords |
| User Management | External CLI tool (usertool.go) |
| TLS Support | Self-signed HTTPS (auto-generated) |
| Auto Shutdown | Stops after X minutes of inactivity |
| No Database | Flat-file user storage |
| No Frameworks | Uses Go standard library |

## Project Structure
```
.
├── upload.go        # Main secure upload server
├── usertool.go      # CLI tool to manage users
├── users.txt        # User database (created automatically)
├── go.mod
├── go.sum
└── README.md
```

## Requirements
- Go 1.20+ (modules required)
Check your version:
```
go version
```

## Setup
1. Initialize Module (first time only)
```
go mod init upload
go get golang.org/x/crypto/bcrypt
```
2. Build
```
go build upload.go
go build usertool.go
```

## User Management
Users are stored in:
```
users.txt
```
Format:
```
username:bcrypt_hash
```
Add User
```
./usertool -add alice
```
Remove User
```
./usertool -remove alice
```
List Users
```
./usertool -list
```
Passwords are securely hashed using bcrypt.

## Running the Server
HTTP Mode
```
./upload
```
Server runs on:
```
http://localhost:8888
```
HTTPS Mode (Self-Signed)
```
./upload -https
```
If _server.crt_ and _server.key_ do not exist, they are automatically generated.

Server runs on:
```
https://localhost:8888
```

__Your browser will show a security warning because the certificate is self-signed.__

## Configuration Flags
| Flag | Default	| Description |
| ----- | ----- | ----- |
| -port | 8888 | Port to listen on |
| -timeout | 5 | Inactivity shutdown timeout (minutes) |
| -https | false | Enable HTTPS |
| -cert | server.crt | TLS certificate file |
| -key | server.key | TLS key file |
| -users | users.txt | User database file |

Example:
```
./upload -https -timeout 10 -port 8443
```
## Inactivity Shutdown
The server automatically shuts down if there are no completed authenticated requests for:
```
5 minutes (default)
```
You can change this:
```
./upload -timeout 15
```
This is useful for:
- Temporary file sharing
- Internal tools
- Ephemeral deployments

## Security Notes
- Uses bcrypt for password hashing
- Uses TLS 1.2 minimum when HTTPS enabled
- Prevents directory traversal
- Self-signed cert for local/private use
- Designed for trusted environments
### This is not a production-grade hardened server. For public internet exposure, consider:
- Reverse proxy (NGINX/Apache)
- Rate limiting
- Upload size limits
- Let’s Encrypt certificates
- Firewall restrictions

## Example Workflow
```
go mod tidy
go build upload.go
go build usertool.go
./usertool -add admin
./upload -https
```
Open:
```
https://localhost:8888
```
Login with your credentials and upload files.
