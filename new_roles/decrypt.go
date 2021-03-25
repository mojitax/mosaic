package main

import(
	"os"
	"github.com/marcellop71/mosaic/abe"
	"bufio"
	"encoding/json"
	"fmt"
)

func main(){
	//tu myślę że można dodać parametryzację przy uruchamianiu czyli -user marcello.paris@gmail.com -keyspath .../marcello.paris@gmail.com.json
	//ale to do ustalenia
	user:="marcello.paris@gmail.com"
	file, _ := os.Open("new_files/ciphertext.json")
	reader := bufio.NewReader(file)
	ciphertextStr, _:=reader.ReadString('\n')
	
	ciphertext := new(abe.Ciphertext)
	json.Unmarshal([]byte(ciphertextStr), ciphertext)
	ciphertext.OfJsonObj()
	//otwierzyliśmy ciphertext
	file2, _ := os.Open("new_files/user_keys/"+user+".json")
	reader2 := bufio.NewReader(file2)
	userattrsStr, _:=reader2.ReadString('\n')
	
	userattrs := new(abe.UserAttrs)
	json.Unmarshal([]byte(userattrsStr), userattrs)
	userattrs.OfJsonObj()
	//otworzyliśmy klucze dla atrybutów
	userattrs.SelectUserAttrs(user, ciphertext.Policy)//okrajamy tylko do tych, które się przydadzą
		
	secret_dec := abe.Decrypt(ciphertext, userattrs)//deszyfracja
	secret_dec_hash := abe.SecretHash(secret_dec)//hash
	
	fmt.Printf("%s", secret_dec_hash)//wyświetlić, porównać z tym z decrypta
	

}	