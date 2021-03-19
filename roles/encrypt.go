package main

import(
	"os"
	//"bufio"
	"mosaic/service"
	"github.com/marcellop71/mosaic/abe"
	"path/filepath"
	//"crypto/sha256"
	"fmt"
)


func main(){
	filename, _ := filepath.Abs("./examples/config.yaml")
	
	config := service.ReadConfig(filename).Config
	service.InitAbeService(config, nil)

	policy:="A@auth0"
	org := "org0"
	if abe.CheckPolicyJson(policy, "") == "sat" {
		// ecnrypting
		secretJson := service.NewRandomSecret(org)
		//secret := abe.NewPointOfJsonStr(secretJson).GetP()
		//secret_hash := sha256.Sum256([]byte(secret))

		policy = abe.RewritePolicy(policy)
		authpubsJson := abe.AuthPubsOfPolicyJson(policy)
		authpubsJson = service.FetchAuthPubs(authpubsJson)
		secret_enc := abe.EncryptJson(secretJson, policy, authpubsJson)
		fmt.Printf("%s\n", secret_enc)
		f, _ := os.Create("files/ciphertext")
		
		f.WriteString(secret_enc)
		
		
	}



}