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

type Auth struct {
	ID      string `json:"ID"`
	TOTP    string `json:"TOTP"`
	Attributes []string `json:"Attributes"`
}
type JEntry struct {
	// DN is the distinguished name of the entry
	DN string `json:"ID"`
	// Attributes are the returned attributes for the entry
	Attributes []JEntryAttribute `json:"attributes"`
}
type JEntryAttribute struct {
	// Name is the name of the attribute
	Name string `json:"name"`
	// Values contain the string values of the attribute
	Value string `json:"value"`
}
func convertToEntry (in *JEntry) (*ldap.Entry){
	entry:=new(ldap.Entry)
	entry.DN=in.DN
	var attributes []*ldap.EntryAttribute
	for _, row := range in.Attributes{
		attributes = append(attributes, &ldap.EntryAttribute{row.Name, []string{row.Value}, nil}) 
	}
	entry.Attributes=attributes
	return entry
}
func (s *Server) SayHello(ctx context.Context, in *Message) (*Message, error) {
	log.Printf("Receive message body from client: %s", in.Body)
	
	file, _ := os.Open("new_files/authprv.json")
    reader := bufio.NewReader(file)
    authprvStr, _:=reader.ReadString('\n')

	authprv := new(abe.AuthPrv)
    json.Unmarshal([]byte(authprvStr), authprv)
    authprv.OfJsonObj()
	in_message:=new(Auth)
	json.Unmarshal([]byte(in.Body), in_message)
	attr_array := in_message.Attributes
	//log.Printf("json: %s", string(in_message.Attributes))
	if(len(attr_array)==0 && in_message.TOTP!="" ){
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
		ID:=in_message.ID
		QID:=org.Crv.HashToGroup(ID, "G1")
		DID:=org.Crv.Pow(QID, s)
		DID.ToJsonObj()
		DID_json, _ :=json.Marshal(DID)//zawijania do json stringa
		return &Message{Body: string(DID_json)}, nil

	} 
	if (len(attr_array)>0){
		
		l, err := ldap.DialURL(os.Getenv("LDAPADDR"))
		
		if err != nil {
			log.Fatal(err)
		}
		
		name:=in_message.ID//im_message.ID
		parts := strings.Split(name, "@")
		attrlist:=[]string{}
		attrlist=append(attrlist, attr_array...)
		
		sr:="{\"ID\":\"kk@org1\",\"attributes\":[{\"name\":\"miasto\",\"value\":\"warszawa\"},{\"name\":\"ulica\",\"value\":\"nowa\"},{\"name\":\"imie\",\"value\":\"krzysztof\"}]}"
		testEntry:=new(JEntry)
	   	json.Unmarshal([]byte(sr), testEntry)
		fmt.Println(name)
		fmt.Println(in_message.TOTP)
		err = l.Bind( name, in_message.TOTP)
		propEntry:=convertToEntry(testEntry)	
		if err != nil {
			fmt.Println("Can't bind to LDAP, running example mode")
		} else {
			/*searchRequest := ldap.NewSearchRequest(
				"aaa", // The base dn to search
				ldap.ScopeWholeSubtree, 0, 0, 0, false,
				fmt.Sprintf("(uid=%s)", ldap.EscapeFilter(name)),
				attrlist,                    // A list attributes to retrieve
				nil,
			)*/
			searchRequest := ldap.NewSearchRequest(
				"ou=Users,dc=WSO2,dc=ORG", // The base dn to search
				ldap.ScopeWholeSubtree, ldap.NeverDerefAliases, 0, 0, false,
				"(name=kk23@org2)", // The filter to apply
				attrlist,                    // A list attributes to retrieve
				nil,
			)
			sres, err := l.Search(searchRequest)
			sres.Print()
			//propEntry=sres.Entries[0]
			if err != nil {
			log.Fatal(err)
			}
		}
		
		
		/*searchRequest := ldap.NewSearchRequest(
			"org1", // The base dn to search
			ldap.ScopeWholeSubtree, 0, 0, 0, false,
			fmt.Sprintf("(name=%s)", name),
			attrlist,                    // A list attributes to retrieve
			nil,
		)
		fmt.Printf("pre-search")
		sr, err := l.Search(searchRequest)
		if err != nil {
			log.Fatal(err)
		}*/
		
		
		given_attrs:=[]string{name}
		for _, att := range attrlist {
			fmt.Printf("%s: %v\n", propEntry.DN, propEntry.GetAttributeValue(att))
			if string(propEntry.GetAttributeValue(att))!="" {
				given_attrs=append(given_attrs,string(propEntry.GetAttributeValue(att))+"@"+parts[1])
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
			return &Message{Body: string(userattrsJson)}, nil
		} 
		return &Message{Body: "Brak atrybutow w LDAP"}, nil
		
	}

	return &Message{Body: "error!!!"}, nil
}
