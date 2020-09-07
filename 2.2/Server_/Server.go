package main

import (
	"bufio"
	"fmt"
	"net"
	"os"
	"strconv"
)

type ConnectionWatcher struct {
	ConnAmount int
	IPadresses [10]string
}

func HandleIncoming(conn net.Conn, outB chan string, c *ConnectionWatcher) {
	defer conn.Close()

	myEnd := conn.LocalAddr().String()
	otherEnd := conn.RemoteAddr().String()
	c.ConnAmount++
	tempCA := c.ConnAmount

	for {
		msg, err := bufio.NewReader(conn).ReadString('\n')
		if err != nil {
			fmt.Println("Ending session with " + otherEnd)
			c.ConnAmount--
			return
		} else {

			fmt.Print("From " + otherEnd + " to " + myEnd + ": " + string(msg))
			outGmsg := otherEnd + " : " + string(msg)
			c.IPadresses[tempCA] = otherEnd
			fmt.Println("Kommer den hertil?")
			outB <- outGmsg
			fmt.Println(myEnd + "#" + strconv.Itoa(c.ConnAmount) + " " + outGmsg)
		}
	}
}

func Broadcast(IncB chan string, c *ConnectionWatcher) {
	fmt.Println("Her??")
	msg := <-IncB
	for i := 1; i > c.ConnAmount; i++ {
		fmt.Println("Og hertil?")
		fmt.Println("Got message: " + msg)
		conn, err := net.Dial("tcp", c.IPadresses[i])
		if err != nil {
			return
		}
		conn.Write([]byte(msg))
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

func main() {
	printAdress()

	ln, _ := net.Listen("tcp", ":")
	defer ln.Close()

	c := make(chan string)
	var myCW = new(ConnectionWatcher)
	myCW.ConnAmount = 0

	for {
		go Broadcast(c, myCW)
		_, port, _ := net.SplitHostPort(ln.Addr().String())
		fmt.Println("Listening on port " + port)
		conn, _ := ln.Accept()
		fmt.Println("Got a connection...")

		go HandleIncoming(conn, c, myCW)
	}
}
