package main

import(
	"os"
	"github.com/marcellop71/mosaic/abe"
	"bufio"
	"crypto/sha256"
	"fmt"
)

func main(){
	
	file, _ := os.Open("files/ciphertext2")
	
    reader := bufio.NewReader(file)
	line, _ :=reader.ReadString('\n')
	secret_enc:=line
	file2, _ := os.Open("files/userattrs")
	
    reader2 := bufio.NewReader(file2)
	line2, _ :=reader2.ReadString('\n')
	userattrsJson:=line2
	
	secret_dec := abe.DecryptJson(secret_enc, userattrsJson)
	secret_dec_hash := sha256.Sum256([]byte(secret_dec))
	
	fmt.Printf("%s", abe.Encode(string(secret_dec_hash[:])))
	

}	