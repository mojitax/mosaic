package main

import(
	//"github.com/marcellop71/mosaic/abe"
	"mosaic/service"
	//"fmt"
	//"os"
	//"bufio"
	"path/filepath"
)

func main(){
	filename, _ := filepath.Abs("./examples/config.yaml")
	
	config := service.ReadConfig(filename).Config
	service.InitAbeService(config, nil)

	user := "marcello.paris@gmail.com"
	attrs := []string{"A@auth0", "B@auth0"}
	for _, attr := range attrs {
		service.SetupUserkey(user, attr)
	}


}