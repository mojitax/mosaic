package main

import (
    //"bufio"
    "flag"
    "fmt"
    "os"
    "time"
	//"github.com/marcellop71/mosaic/abe"
	//"mosaic/service"
	//"path/filepath"
	//"crypto/sha256"
        mqtt "github.com/eclipse/paho.mqtt.golang"
)

func main() {

        //tu filozofii nie ma - odbiera z brokera stringa i zapisuje do pliku ciphertext.json
        //wszystko jak w przykładzie
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
        token := mqttClient.Subscribe(messageTopic, 1, func(_ mqtt.Client, msg mqtt.Message) {
                fmt.Printf("< received raw message on %s: %s\n", msg.Topic(), msg.Payload())
                f, _ := os.Create("new_files/ciphertext.json")
		f.WriteString(string(msg.Payload()))//zapis do pliku


        })
 
        if !token.Wait() {
                panic(fmt.Sprintf("failed to subscribe to MQTT topic: %v\n", token.Error()))
        }
        fmt.Printf("> subscribed to MQTT topic %s\n", messageTopic)

       for {}
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