package main

import (
	"bufio"
	"fmt"
	"net"
	"os"
)

var conn net.Conn

func main() {
	fmt.Println("Please enter IP and port combined:")
	var ipInput string
	fmt.Scan(&ipInput)

	conn, _ = net.Dial("tcp", ipInput)
	defer conn.Close()
	for {
		reader := bufio.NewReader(os.Stdin)
		fmt.Print("> ")
		text, err := reader.ReadString('\n')
		if text == "quit\n" {
			return
		}
		fmt.Fprintf(conn, text)
		msg, err := bufio.NewReader(conn).ReadString('\n')

		if err != nil {
			return
		}
		fmt.Print("From server: " + msg)
	}
}
