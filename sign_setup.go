package main


import(
	"mosaic/abe"
	//"github.com/marcellop71/mosaic/abe/log"
	"fmt"
	//"os"
	//"bufio"
	//"encoding/json"
	//"math/big"
	"crypto/sha256"
)

func main(){

	seed:="abcdef"
	curve := abe.NewCurve()
	curve.SetSeed(seed).InitRng()
	org := abe.NewRandomOrg(curve)
	org.ToJsonObj()

	//orgJson, _ :=json.Marshal(org)
	/*file, _ := os.Open("new_files/sig_master_secret.json")
	reader := bufio.NewReader(file)
	s_string, _:=reader.ReadString('\n')
	s := new(big.Int)
    s, ok := s.SetString(s_string, 10)
    if !ok {
        fmt.Println("SetString: error")
        return
    }
    fmt.Println(s)
	file2, _ := os.Open("new_files/sig_master_pub.json")
	reader2 := bufio.NewReader(file2)
	p_string, _ := reader2.ReadString('\n')
	p := new(abe.MiraclPoint)
	json.Unmarshal([]byte(p_string), p)
	p.OfJsonObj(org.Crv)
	fmt.Println(p)*/


	//setup
	s,p:=abe.Setup_signature(org)

	//extract
	ID:="sensor_0001"
	QID:=org.Crv.HashToGroup(ID, "G1")
	fmt.Println(QID.ToJsonObj())
	DID:=curve.Pow(QID, s)
	DID.ToJsonObj()
	fmt.Println(DID)


	//sign
	msg:="blabla"
	hs:=sha256.Sum256([]byte(msg))
	h:= s.SetBytes(hs[:])
    
	r:=org.Crv.NewRandomExp()
	U:=curve.Pow(QID, r)
	V:=curve.Pow(DID, r.Add(r, h))
	fmt.Println(U)
	fmt.Println(V)
	//verify
	ID="sensor_chuj"
	QID=org.Crv.HashToGroup(ID, "G1")
	L:=org.Crv.Pair(V, org.G2)
	R:=org.Crv.Pair(org.Crv.Mul(U, org.Crv.Pow(QID, h)),p)
	fmt.Println(L.GetP())
	
	fmt.Println(R.GetP())
}