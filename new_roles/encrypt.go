package main

import (
    "bufio"
    "flag"
    "fmt"
    "os"
    "time"
	
    mqtt "github.com/eclipse/paho.mqtt.golang"
    "encoding/json"
	
	"mosaic/abe"
	
	
)

func main() {
	//połączenie z brokerem jak w przykładzie
   //estabilishing broker connection
    var clientName string
    flag.StringVar(&clientName, "client", "", "the client name")
    flag.Parse()
    if len(clientName) == 0 {
            panic("-client is required")
    }
    
    brokerEndpoint := "18.221.34.191:1883"
    mqttClient, err := initMQTT(brokerEndpoint, clientName)
    if err != nil {
            panic(fmt.Sprintf("failed to init mqtt client: %v", err))
    }
    fmt.Printf("> connected to %s\n", brokerEndpoint)
    
    messageTopic := "testB"
    //przykładowe proste policy
	policy:="A@auth0"
	file, _ := os.Open("new_files/org.json")
	reader := bufio.NewReader(file)
	orgStr, _:=reader.ReadString('\n')
	
	org := new(abe.Org)
	json.Unmarshal([]byte(orgStr), org)
	org.OfJsonObj()
        //we got our curve and now are restoring it into object
	//wczytaliśmy org wg opisu z setup.go
	file2, _ := os.Open("new_files/authpub.json")
	reader2 := bufio.NewReader(file2)
	authpubStr, _:=reader2.ReadString('\n')
	
	authpub := new(abe.AuthPub)

	json.Unmarshal([]byte(authpubStr), authpub)
	authpub.OfJsonObj()
        //same with master public key
	//i podobnie klucz publiczny auth
	if abe.CheckPolicyJson(policy, "") == "sat" {
		// ecnrypting
		secret := abe.NewRandomSecret(org)//nowy losowy klucz //new  random secret (treated as random symmetric key)
		policy = abe.RewritePolicy(policy)//przepisanie polityki //rewriting policy
		authpubs := abe.AuthPubsOfPolicy(policy)
		for attr, _ := range authpubs.AuthPub {
			authpubs.AuthPub[attr] = authpub
		}
		//tu coś kobinowane jest z atrybutami, o ile rozumiem to wybierane są po prostu potrzebne atrybuty do szyfrowania na podstawie polityki
                //building table of attributes necessary for encryption
        secret_enc:=abe.Encrypt(secret, policy, authpubs)//szyfrowanie //enc
		secret_enc.ToJsonObj()//tak samo w celu serializacji i ujsonowienia trzeba porobić jsony z atrybutów obiektu Ciphertext
                //we want to have the ciphertext stored as json (contains also org and policy information) so are doing same thing as usual
		secret_encJson, _ :=json.Marshal(secret_enc)//jsonik //j-sonic (^^)
		secret_hash := abe.SecretHash(secret)//obliczamy sobie hash i wyświetlamy go żeby zobaczyć, że jest taki sam co w decrypcie, ten hash może być faktycznym kluczem symetrycznym o ile rozumiem
		fmt.Printf("%s", secret_hash)//we show hash of our secretly chosen symmetric key to compare with decrypted one
        if token := mqttClient.Publish(messageTopic, 1, true, secret_encJson); token.Wait() && token.Error() != nil {//wysyłka do brokera //send-IT
                fmt.Printf("> failed to publish message: %v\n", token.Error())
                
        }
		
	}


	
}

func initMQTT(brokerEndpoint, clientID string) (mqtt.Client, error) {
        opts := mqtt.NewClientOptions()
        opts.AddBroker(brokerEndpoint)
        opts.SetClientID(clientID)
        opts.SetCleanSession(true)

        mqttClient := mqtt.NewClient(opts)
        timeout := time.Second
        if token := mqttClient.Connect(); token.WaitTimeout(timeout) && token.Error() != nil {
                return nil, token.Error()
        }

        return mqttClient, nil
}