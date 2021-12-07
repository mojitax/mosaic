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
	"github.com/go-ldap/ldap/v3"
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
		l, err := ldap.DialURL("ldap://44.199.255.188:6061")
		if err != nil {
			log.Fatal(err)
		}
		name:=attr_array[0]
		parts := strings.Split(name, "@")
		err = l.Bind( "pawel@org1", "1234")
		if err != nil {
			log.Fatal(err)
		}
	
		attrlist:=attr_array[1:]
		searchRequest := ldap.NewSearchRequest(
			"aaaa", // The base dn to search
			ldap.ScopeWholeSubtree, 0, 0, 0, false,
			fmt.Sprintf("(name=%s)", parts[0]),
			attrlist,                    // A list attributes to retrieve
			nil,
		)
	
		sr, err := l.Search(searchRequest)
		if err != nil {
			log.Fatal(err)
		}
		given_attrs:=[]string{name}
		for _, entry := range sr.Entries {
			for _, att := range attrlist {
				fmt.Printf("%s: %v\n", entry.DN, entry.GetAttributeValue(att))
				if string(entry.GetAttributeValue(att))!="" {
					given_attrs=append(given_attrs,string(entry.GetAttributeValue(att))+"@"+parts[1])
				}
			}
			
		}

		if (len(given_attrs)>1){
			userattrs:=abe.NewRandomUserkey(given_attrs[0], given_attrs[1], authprv)
			for nr, attribute := range given_attrs {
				if (nr<2) {
					continue
				}
				userattrs.Add(abe.NewRandomUserkey(given_attrs[0], attribute, authprv))//dodawane kolejne //more atts
			}
			userattrs.ToJsonObj()//trzeba zrobić jsony z wewnętrznych obiektów, żeby zapisać do pliku coś poza nicniewartymi referencjami
			//creating jsons as described earlier
			file2,_:=os.Create("new_files/user_keys/"+attr_array[0]+".json")//plik tworzony jest z nazwą użytkownika
			userattrsJson, _ :=json.Marshal(userattrs)//zawijania do json stringa
			file2.WriteString(string(userattrsJson))//zapis

			return &Message{Body: string(userattrsJson)}, nil}}
		else {
			return &Message{Body: "Brak atrybutow w LDAP"}, nil}

	return &Message{Body: "error!!!"}, nil
}
