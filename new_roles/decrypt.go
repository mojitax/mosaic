package main

import(
	"os"
	"github.com/marcellop71/mosaic/abe"
	"bufio"
	"encoding/json"
	"fmt"
)

func main(){
	user:="marcello.paris@gmail.com"
	file, _ := os.Open("new_files/ciphertext.json")
	reader := bufio.NewReader(file)
	ciphertextStr, _:=reader.ReadString('\n')
	
	ciphertext := new(abe.Ciphertext)
	json.Unmarshal([]byte(ciphertextStr), ciphertext)
	ciphertext.OfJsonObj()

	file2, _ := os.Open("new_files/user_keys/"+user+".json")
	reader2 := bufio.NewReader(file2)
	userattrsStr, _:=reader2.ReadString('\n')
	
	userattrs := new(abe.UserAttrs)
	json.Unmarshal([]byte(userattrsStr), userattrs)
	userattrs.OfJsonObj()
	//fmt.Printf("%s", userattrsStr)
	userattrs.SelectUserAttrs(user, ciphertext.Policy)
		
	secret_dec := abe.Decrypt(ciphertext, userattrs)
	secret_dec_hash := abe.SecretHash(secret_dec)
	
	fmt.Printf("%s", secret_dec_hash)
	_=secret_dec_hash

}	