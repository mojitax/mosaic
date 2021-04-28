package chat

import (
	"log"
	"mosaic/abe"
	"golang.org/x/net/context"
	"os"
	"bufio"
	"encoding/json"
	"strings"
	"math/big"
	"fmt"
)

type Server struct {
}

func (s *Server) SayHello(ctx context.Context, in *Message) (*Message, error) {
	log.Printf("Receive message body from client: %s", in.Body)
	
	file, _ := os.Open("new_files/authprv.json")
    reader := bufio.NewReader(file)
    authprvStr, _:=reader.ReadString('\n')

	authprv := new(abe.AuthPrv)
    json.Unmarshal([]byte(authprvStr), authprv)
    authprv.OfJsonObj()
	attr_array := strings.Split(in.Body, "\n")
	if(len(attr_array)==1){
		org:=authprv.Org
		file, _ = os.Open("new_files/sig_master_pub.json")
		reader = bufio.NewReader(file)
		P_pubStr, _:=reader.ReadString('\n')
		P_pub:=new(abe.MiraclPoint)
		json.Unmarshal([]byte(P_pubStr), P_pub)
		file, _ = os.Open("new_files/sig_master_secret.json")
		reader = bufio.NewReader(file)
		sStr, _:=reader.ReadString('\n')
		s:=new(big.Int)
		s, ok := s.SetString(sStr, 10)
    	if !ok {
        fmt.Println("SetString: error")
    	}
		ID:=attr_array[0]
		QID:=org.Crv.HashToGroup(ID, "G1")
		DID:=org.Crv.Pow(QID, s)
		DID.ToJsonObj()
		DID_json, _ :=json.Marshal(DID)//zawijania do json stringa
		return &Message{Body: string(DID_json)}, nil

	}
	if (len(attr_array)>1){
	userattrs:=abe.NewRandomUserkey(attr_array[0], attr_array[1], authprv)
	for nr, attribute := range attr_array {
		if (nr<2) {
			continue
		}
		userattrs.Add(abe.NewRandomUserkey(attr_array[0], attribute, authprv))//dodawane kolejne //more atts
	}
	userattrs.ToJsonObj()//trzeba zrobić jsony z wewnętrznych obiektów, żeby zapisać do pliku coś poza nicniewartymi referencjami
	//creating jsons as described earlier
	file2,_:=os.Create("new_files/user_keys/"+attr_array[0]+".json")//plik tworzony jest z nazwą użytkownika
	userattrsJson, _ :=json.Marshal(userattrs)//zawijania do json stringa
	file2.WriteString(string(userattrsJson))//zapis

	return &Message{Body: string(userattrsJson)}, nil}
	return &Message{Body: "error!!!"}, nil
}