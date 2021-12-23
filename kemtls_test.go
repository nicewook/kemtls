package kemtls

import (
	"bytes"
	"fmt"
)

func ExampleKemtlsExchange() {
	// client, err := sidh.NewKeyPair()
	client, err := NewKeyPair()
	if err != nil {
		fmt.Println(err)
		return
	}

	// server, err := sidh.NewKeyPair()
	server, err := NewKeyPair()
	if err != nil {
		fmt.Println(err)
		return
	}

	ctClient, ssClient, err := client.Encapsulate(server.ExportPublic())
	if err != nil {
		fmt.Println(err)
		return
	}

	ssServer, err := server.Decapsulate(ctClient)
	if err != nil {
		fmt.Println(err)
		return
	}

	fmt.Println(bytes.Equal(ssClient, ssServer))
	// Output: true
}
