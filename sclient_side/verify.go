package main

import(
	"os"
	"mosaic/abe"
	"bufio"
	"encoding/json"
	"fmt"
//	"crypto/aes"
//    "crypto/sha256"
 //   "crypto/cipher"
//	"flag"
//    "crypto/rand"
//	"encoding/hex"
 //   "errors"
 //   "bytes"
   // "io"
   "math/big"
  // "time"
)

func main(){
	//so we could make it read username and attributes from file as parameter, so far it's hardcoded 
	//tu myślę że można dodać parametryzację przy uruchamianiu czyli -user marcello.paris@gmail.com -keyspath .../marcello.paris@gmail.com.json
	//ale to do ustalenia
	
	file, _ := os.Open("new_files/ciphertext.json")
	reader := bufio.NewReader(file)
	message_pack_str, _:=reader.ReadString('\n')
	message_pack := new(abe.Enc_and_Key)
	json.Unmarshal([]byte(message_pack_str), message_pack)

	file, _ = os.Open("new_files/org.json")
	reader = bufio.NewReader(file)
	orgStr, _:=reader.ReadString('\n')
	org := new(abe.Org)
	json.Unmarshal([]byte(orgStr), org)
	org.OfJsonObj()

	hash:=abe.Decode(message_pack.Plaintext_hash)
	ID:=message_pack.ID
	QID:=org.Crv.HashToGroup(ID, "G1")
	s:=new(big.Int)
	h:= s.SetBytes([]byte(hash))
	h=h.Rsh(h, 2)
	file, _ = os.Open("new_files/sig_master_pub.json")
	reader = bufio.NewReader(file)
	P_pubStr, _:=reader.ReadString('\n')
	P_pub:=new(abe.MiraclPoint)
	json.Unmarshal([]byte(P_pubStr), P_pub)
	P_pub.OfJsonObj(org.Crv)
	
	UStr:=message_pack.Signature_U
	U := new(abe.MiraclPoint)
	json.Unmarshal([]byte(UStr), U)
	U.OfJsonObj(org.Crv)
	VStr:=message_pack.Signature_V
	V := new(abe.MiraclPoint)
	json.Unmarshal([]byte(VStr), V)
	V.OfJsonObj(org.Crv)
	L:=org.Crv.Pair(V, org.G2)
	R:=org.Crv.Pair(org.Crv.Mul(U, org.Crv.Pow(QID, h)),P_pub)
	L.ToJsonObj()
	R.ToJsonObj()
	if(L.GetP()==R.GetP()){
		fmt.Println("Signature is valid")
	}else {
		fmt.Println("Signature is not valid")
	}

  
}	
