package chat

import (
	"log"
	"github.com/marcellop71/mosaic/abe"
	"golang.org/x/net/context"
	"os"
	"bufio"
	"encoding/json"
	"strings"
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

	return &Message{Body: string(userattrsJson)}, nil
}