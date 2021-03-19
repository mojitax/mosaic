package main

import(
	"os"
	"bufio"
	"mosaic/service"
	"github.com/marcellop71/mosaic/abe"
	"path/filepath"
	"crypto/sha256"
	"fmt"
)

func main(){
	filename, _ := filepath.Abs("./examples/config.yaml")
	
	config := service.ReadConfig(filename).Config
	service.InitAbeService(config, nil)

	user := "marcello.paris@gmail.com"
	file, _ := os.Open("files/ciphertext")
    reader := bufio.NewReader(file)
	line, _ :=reader.ReadString('\n')
	secret_enc:=line
	policy := abe.PolicyOfCiphertextJson(secret_enc)
	userattrsJson := service.FetchUserAttrs(user)
	fmt.Printf("%s", secret_enc)
	if abe.CheckPolicyJson(policy, userattrsJson) == "sat" {
		userattrsJson = abe.SelectUserAttrsJson(user, policy, userattrsJson)
		userattrsJson = service.FetchUserkeys(userattrsJson)
		secret_dec := abe.DecryptJson(secret_enc, userattrsJson)
		secret_dec_hash := sha256.Sum256([]byte(secret_dec))
		fmt.Printf("%s", secret_dec_hash)
	}

}	