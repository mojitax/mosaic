package main


import(
	"github.com/marcellop71/mosaic/abe"
	//"github.com/marcellop71/mosaic/abe/log"
	"fmt"
	"os"
	//"bufio"
	"encoding/json"
)

func main(){

	seed:="abcdef"
	curve := abe.NewCurve()
	curve.SetSeed(seed).InitRng()
	org := abe.NewRandomOrg(curve)
	org.ToJsonObj()
	fmt.Printf("%s\n", org)
	orgJson, _ :=json.Marshal(org)
	authkeys := abe.NewRandomAuth(org)

	authpub:=authkeys.AuthPub
	authprv:=authkeys.AuthPrv
	authpub.ToJsonObj()
	authprv.ToJsonObj()
	authpubJson, _ :=json.Marshal(authpub)
	authprvJson, _ :=json.Marshal(authprv)
	file3, _:=os.Create("new_files/org.json") 
	file3.WriteString(string(orgJson))
	file2, _:=os.Create("new_files/authpub.json") 
	file2.WriteString(string(authpubJson))
	file4, _:=os.Create("new_files/authprv.json") 
	file4.WriteString(string(authprvJson))
	users := []string{
		"marcello.paris@gmail.com",
	}
	attributes := []string{
		//"A@auth0",
		"B@auth0",
	}

	for _, user := range users {
		userattrs:=abe.NewRandomUserkey(user, "A@auth0", authkeys.AuthPrv)	
		for _, attribute := range attributes {
			userattrs.Add(abe.NewRandomUserkey(user, attribute, authkeys.AuthPrv))
		}
		//fmt.Printf("%s", userattrs)
		userattrs.ToJsonObj()
		//fmt.Printf("%s", userattrs)
		file,_:=os.Create("new_files/user_keys/"+user+".json")
		userattrsJson, _ :=json.Marshal(userattrs)
		file.WriteString(string(userattrsJson))
	}
}