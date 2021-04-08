package main

import (
    "bufio"
    "flag"
    "fmt"
    "os"
    "time"
    "crypto/aes"
    "crypto/sha256"
    "crypto/cipher"
    "crypto/rand"
//	"encoding/hex"
    "errors"
    "bytes"
    "io"
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
		//fmt.Printf("%s", secret_hash)//we show hash of our secretly chosen symmetric key to compare with decrypted one
                
                key := []byte(abe.Decode(secret_hash))
                true_plaintext := []byte("stanwodywwisle")
                plaintext, _ :=pkcs7Pad(true_plaintext, 16)
               
               
                // CBC mode works on blocks so plaintexts may need to be padded to the
                // next whole block. For an example of such padding, see
                // https://tools.ietf.org/html/rfc5246#section-6.2.3.2. Here we'll
                // assume that the plaintext is already of the correct length.
                if len(plaintext)%aes.BlockSize != 0 {
                        panic("plaintext is not a multiple of the block size")
                }

                block, err := aes.NewCipher(key)
                if err != nil {
                        panic(err)
                }

                // The IV needs to be unique, but not secure. Therefore it's common to
                // include it at the beginning of the ciphertext.
                ciphertext := make([]byte, aes.BlockSize+len(plaintext))
                iv := ciphertext[:aes.BlockSize]
                if _, err := io.ReadFull(rand.Reader, iv); err != nil {
                        panic(err)
                }
                mode := cipher.NewCBCEncrypter(block, iv)
                mode.CryptBlocks(ciphertext[aes.BlockSize:], plaintext)

                // It's important to remember that ciphertexts must be authenticated
                // (i.e. by using crypto/hmac) as well as being encrypted in order to
                // be secure.
                message_pack := new(abe.Enc_and_Key)
                message_pack.Cipher_suit = "aes-abe-sha256"
                message_pack.Enc_msg = abe.Encode(string(ciphertext))
                message_pack.Enc_key = string(secret_encJson)
                message_pack.IV = abe.Encode(string(iv))
                hash:=sha256.Sum256([]byte(true_plaintext))
                message_pack.Plaintext_hash = abe.Encode(string(hash[:]))
                x, _:= json.Marshal(message_pack)
                x_ := string(x)
                fmt.Printf("\n%v\n", x_)
                if token := mqttClient.Publish(messageTopic, 1, true, x_); token.Wait() && token.Error() != nil {//wysyłka do brokera //send-IT
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

var (
	// ErrInvalidBlockSize indicates hash blocksize <= 0.
	ErrInvalidBlockSize = errors.New("invalid blocksize")

	// ErrInvalidPKCS7Data indicates bad input to PKCS7 pad or unpad.
	ErrInvalidPKCS7Data = errors.New("invalid PKCS7 data (empty or not padded)")

	// ErrInvalidPKCS7Padding indicates PKCS7 unpad fails to bad input.
	ErrInvalidPKCS7Padding = errors.New("invalid padding on input")
)

func pkcs7Pad(b []byte, blocksize int) ([]byte, error) {
	if blocksize <= 0 {
		return nil, ErrInvalidBlockSize
	}
	if b == nil || len(b) == 0 {
		return nil, ErrInvalidPKCS7Data
	}
	n := blocksize - (len(b) % blocksize)
	pb := make([]byte, len(b)+n)
	copy(pb, b)
	copy(pb[len(b):], bytes.Repeat([]byte{byte(n)}, n))
	return pb, nil
}

// pkcs7Unpad validates and unpads data from the given bytes slice.
// The returned value will be 1 to n bytes smaller depending on the
// amount of padding, where n is the block size.
func pkcs7Unpad(b []byte, blocksize int) ([]byte, error) {
	if blocksize <= 0 {
		return nil, ErrInvalidBlockSize
	}
	if b == nil || len(b) == 0 {
		return nil, ErrInvalidPKCS7Data
	}
	if len(b)%blocksize != 0 {
		return nil, ErrInvalidPKCS7Padding
	}
	c := b[len(b)-1]
	n := int(c)
	if n == 0 || n > len(b) {
		return nil, ErrInvalidPKCS7Padding
	}
	for i := 0; i < n; i++ {
		if b[len(b)-n+i] != c {
			return nil, ErrInvalidPKCS7Padding
		}
	}
	return b[:len(b)-n], nil
}
