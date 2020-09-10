package main

import (
	"bufio"
	"fmt"
	"net"
	"os"
	"strconv"
)

var conn net.Conn

type NetworksList struct {
	list    [10]string
	counter int
}

func main() {
	fmt.Println("Please enter  ip and port:")
	var input string
	fmt.Scan(&input)
	list := new(NetworksList)
	list.counter = 0
	conn, dialErr := net.Dial("tcp", input)
	if dialErr != nil {
		go GoListen(conn, list)
	}

	localIP := conn.LocalAddr().String()
	fmt.Println("Listening for connection on " + localIP)
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

func handleConnection(conn net.Conn, list *NetworksList, out chan string) {
	defer conn.Close()
	myEnd := conn.LocalAddr().String()
	otherEnd := conn.RemoteAddr().String()

	list.counter++
	localCounter := list.counter
	list.list[localCounter] = otherEnd

	defer Remove(localCounter, list)

	for {
		msg, err := bufio.NewReader(conn).ReadString('\n')
		if err != nil {
			fmt.Println("Ending session with " + otherEnd)
			return
		} else {
			fmt.Print("From " + otherEnd + " to " + myEnd + ": " + string(msg))
			out <- msg

		}
	}
}

func BroadCast(inc chan string, list *NetworksList) {
	msg := <-inc
	for i := 0; i > list.counter; i++ {
		conn2, _ := net.Dial("tcp", list.list[i])
		conn2.Write([]byte(msg))
	}
}

func Remove(c int, list *NetworksList) {
	list.list[c] = ""
}

func GoListen(conn net.Conn, list *NetworksList) {
	ln, _ := net.Listen("tcp", ":18081")
	fmt.Println("Now im a server")
	printAdress()
	defer ln.Close()
	c := make(chan string)
	go BroadCast(c, list)

	for {
		conn, _ := ln.Accept()
		localIP := conn.LocalAddr().String()
		fmt.Println("Listening for connection on " + localIP)
		fmt.Println("Got a connection...")
		go handleConnection(conn, list, c)
	}
}

func printAdress() {
	name, _ := os.Hostname()
	addrs, _ := net.LookupHost(name)
	fmt.Println("Name: " + name)
	for indx, addr := range addrs {
		fmt.Println("Address number " + strconv.Itoa(indx) + ": " + addr)
	}
}
