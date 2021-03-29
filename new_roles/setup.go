package main


import(
	"github.com/marcellop71/mosaic/abe"
	//"github.com/marcellop71/mosaic/abe/log"
	//"fmt"
	"os"
	//"bufio"
	"encoding/json"
)

func main(){
	//generowanie krzywej i organizacji
	//generating curve and organisation
	seed:="abcdef"
	curve := abe.NewCurve()
	curve.SetSeed(seed).InitRng()
	org := abe.NewRandomOrg(curve)
	org.ToJsonObj()

	orgJson, _ :=json.Marshal(org)
	//generowanie kluczy dla nowego kgc
	//gen keys for kgc
	authkeys := abe.NewRandomAuth(org)

	authpub:=authkeys.AuthPub
	authprv:=authkeys.AuthPrv
	/*Zajęło mi dużo czasu zrozumienie jak działają te metody
	ToJsonObj() tworzy kopie obiektów które zawierają się w strukturze i te kopie również przechowywane są w tym nadrzędnym, czyli
	jak mamy sobie authkeys typu AuthKeys to ten typ zawiera obiekt typu AuthPub i AuthPrv poprzez referencje,
	a także po wykonaniu ToJsonObj() odpowiadające tym referencjom Jsony do których odwołać się można poprzez .AuthPub_ - czyli z podkreśleniem na końcu.
	Te Jsony umożliwiają wykonania json.Marshal czyli zawinięcia do postaci stringa jsona, który sobie można zapisać spokojnie do pliku. 
	Po wczytaniu stringa z pliku trzeba na nim wykonać operację odwrotną, żeby odzyskać obiekt, co jest wykorzystywane w pozostałych rolach. 
	W tym celu czytamy linię do zmiennej, tworzymy nowy obiekt pożądanego typu np. ct=new(abe.Ciphertext) i ładujemy wczytaną linię jako argument
	do json.Unmarshal([]byte(linia), ct). Ale to jeszcze nie wszystko, bo wczytaliśmy same jsony do atrybutów obiektu tych z _ czyli np. Ciphertext.C_, ale referencje 
	na prawdziwe obiekty są zupełnie pogubione, dlatego należy je odtworzyć metodą .OfJsonObj() i wtedy mamy sobie już obiekt z referencjami na obiekty wewnętrzne.
	
	So basically every object with type defined in abe/types.go has dual attributes, for example: AuthKeys is a struct containing objects AuthPub and AuthPrv, 
	and also their json strings counterparts named with _, i.e. AuthPub_, AuthPrv_ etc. If we create an object with implemented method, like NewRandomAuth(),
	only the real inside objects are instantiated. Because in case of setup we specifically need AuthPub and AuthPrv (master public and secret keys)
	we don't need to convert AuthKeys to json file, as we are interested only in objects. However what we do need is to somehow store AuthPub for 
	encryption purposes. To store it as a string that can be restored into object we are using ToJsonObj() method creating json counterpart of each
	object inside AuthPub object. Same goes for AuthPrv like below. Now we use native encoding/json library to marshal it and put as string into file.
	In order to restore object from file we need to load it, create new object of chosen type, unmarshal file into object using encoding/json method 
	(used in encrypt for example) and then use OfJsonObj() method, which instantiates objects from those json strings, so that arithmetic operations 
	can be used on them. 
	
	*/
	authpub.ToJsonObj()
	authprv.ToJsonObj()//
	authpubJson, _ :=json.Marshal(authpub)
	authprvJson, _ :=json.Marshal(authprv)
	file3, _:=os.Create("new_files/org.json") 
	file3.WriteString(string(orgJson))
	file2, _:=os.Create("new_files/authpub.json") 
	file2.WriteString(string(authpubJson))
	file4, _:=os.Create("new_files/authprv.json") 
	file4.WriteString(string(authprvJson))

	//Zapisane zostały parametry do plików. Właściwie authprv.json może być niepotrzebny w pliku bo jest wykorzystywany tylko w setupie.
	//So basic parameters are stored into file, I'm not sure if authprv is really necessary, since it's used only by kgc. 
	users := []string{
		"marcello.paris@gmail.com",//tutaj można dodawać kolejnych użytkowników
		//here we can put predefined users
	}
	attributes := []string{
		//"A@auth0",
		"B@auth0",//tutaj działa to tak, że jest lista atrybutów i wszystkie są nadawane każdemu użytkownikowi z listy - trzeba wymyślić jak to robić selektywnie
		//we can put predefined user attributes here, so far all of those are given to all users, some kind of selective way is to-be-done
	    
	}

	for _, user := range users {
		userattrs:=abe.NewRandomUserkey(user, "A@auth0", authkeys.AuthPrv)	//pierwszy atrybut trzeba utworzyć w taki nieładny sposób, bo kolejne będą w pętli do niego dodawane, można powiedzieć, że to taki kontener
		//so because we are adding attributes from table one-by-one we need to create first directly and then add others in loop
		for _, attribute := range attributes {
			userattrs.Add(abe.NewRandomUserkey(user, attribute, authkeys.AuthPrv))//dodawane kolejne //more atts
		}
		
		userattrs.ToJsonObj()//trzeba zrobić jsony z wewnętrznych obiektów, żeby zapisać do pliku coś poza nicniewartymi referencjami
		//creating jsons as described earlier
		file,_:=os.Create("new_files/user_keys/"+user+".json")//plik tworzony jest z nazwą użytkownika
		userattrsJson, _ :=json.Marshal(userattrs)//zawijania do json stringa
		file.WriteString(string(userattrsJson))//zapis
		//stored in file new_files/user_keys with user name 
	}
}