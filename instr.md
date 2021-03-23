go mod tidy
(if ubuntu) 
sudo apt install libz3-dev
sudo apt-get install libsnappy-dev
sudo apt-get install libleveldb-dev

go run -tags=z3,miracl roles/setup.go
go run -tags=z3,miracl roles/extract.go
go run -tags=z3,miracl pub_enc.go
