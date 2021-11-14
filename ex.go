package main


import (
	"github.com/go-ldap/ldap/v3"
	"log"
	"fmt"
)

func main() {
	l, err := ldap.DialURL("ldap://13.51.158.214:6061")
	if err != nil {
		log.Fatal(err)
	}
	defer l.Close()
	err = l.Bind( "pawel", "1234")
	if err != nil {
		log.Fatal(err)
	}

	fmt.Println("stop")

	searchRequest := ldap.NewSearchRequest(
		"ou=Users,dc=WSO2,dc=ORG", // The base dn to search
		ldap.ScopeWholeSubtree, ldap.NeverDerefAliases, 0, 0, false,
		"((name=pawel))", // The filter to apply
		[]string{"name", "requestedAttrubutes", "requestedFilters"},                    // A list attributes to retrieve
		nil,
	)

	sr, err := l.Search(searchRequest)
	if err != nil {
		log.Fatal(err)
	}
	for _, entry := range sr.Entries {
		fmt.Printf("%s: %v\n", entry.DN, entry.GetAttributeValue("requestedAttrubutes"))
	}
	for _, entry := range sr.Entries {
		fmt.Printf("%s: %v\n", entry.DN, entry.GetAttributeValue("requestedFilters"))
	}
	for _, entry := range sr.Entries {
		fmt.Printf("%s\n", entry)
	}
	for _, entry := range sr.Entries {
		fmt.Printf("%s: %v\n", entry.DN, entry.GetAttributeValue("memberof"))
	}
}
