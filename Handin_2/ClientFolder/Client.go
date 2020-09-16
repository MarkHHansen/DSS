package main

import (
	"bufio"
	"fmt"
	"net"
	"os"
	"strings"
	"sync"
	"time"
)

var conn net.Conn

type NetworksList struct {
	networkMap map[string]net.Conn
	sortedList []string
	mux        sync.Mutex
}

type MapOfStrings struct {
	mapOS map[string]bool
	mux   sync.Mutex
}

type Ledger struct {
	Accounts map[string]int
	lock     sync.Mutex
}

func MakeLedger() *Ledger {
	ledger := new(Ledger)
	ledger.Accounts = make(map[string]int)
	return ledger
}

type Transaction struct {
	ID     string
	From   string
	To     string
	Amount int
}

func (l *Ledger) Transaction(t *Transaction) {
	l.lock.Lock()
	defer l.lock.Unlock()
	l.Accounts[t.From] -= t.Amount
	l.Accounts[t.To] += t.Amount
}

func BroadCast(inc chan string, list *NetworksList) {
	for {
		msg := <-inc
		list.mux.Lock()
		for _, k := range list.networkMap {
			k.Write([]byte(msg))
		}
		list.mux.Unlock()
	}
}

func Recieve(channels chan string, list *NetworksList, mapOfStrings *MapOfStrings, conn net.Conn) {
	for {
		msg, err := bufio.NewReader(conn).ReadString('\n')

		if err != nil {
			list.mux.Lock()
			fmt.Println("Ending session with " + conn.RemoteAddr().String())
			delete(list.networkMap, conn.RemoteAddr().String())
			list.mux.Unlock()
			break
		}
		mapOfStrings.mux.Lock()
		if mapOfStrings.mapOS[msg] != true {
			fmt.Print("Recieved String: " + string(msg))
			channels <- msg
			fmt.Println("String added to saved messages: " + msg)
			fmt.Print("> ")
			mapOfStrings.mapOS[msg] = true
		}
		mapOfStrings.mux.Unlock()
	}

}

func HandleConnections(InputConn net.Conn, list *NetworksList, channels chan string, mapOfStrings *MapOfStrings) {
	defer InputConn.Close()

	for i, _ := range list.networkMap {
		fmt.Println(i)
		InputConn.Write([]byte(i))
		time.Sleep(1)
	}

	Recieve(channels, list, mapOfStrings, InputConn)
}

func LookForConnection(ln net.Listener, list *NetworksList, channels chan string, mapOfStrings *MapOfStrings) {
	defer ln.Close()

	go BroadCast(channels, list)

	for {
		fmt.Println("Listening for connection...")
		fmt.Print("> ")
		InputConn, _ := ln.Accept()
		fmt.Println("Got a connection...")
		fmt.Print("> ")
		list.mux.Lock()
		list.networkMap[InputConn.RemoteAddr().String()] = InputConn
		list.mux.Unlock()
		go HandleConnections(InputConn, list, channels, mapOfStrings)
	}
}

func SendManuallyToConnections(channels chan string, mapOfStrings *MapOfStrings) {
	for {
		reader := bufio.NewReader(os.Stdin)
		fmt.Print("> ")
		text, err := reader.ReadString('\n')
		mapOfStrings.mux.Lock()
		mapOfStrings.mapOS[text] = true
		mapOfStrings.mux.Unlock()

		if err != nil {
			return
		}
		channels <- text
	}

}

func main() {
	list := new(NetworksList)
	list.networkMap = make(map[string]net.Conn)
	channels := make(chan string)
	mapOfStrings := new(MapOfStrings)
	mapOfStrings.mapOS = make(map[string]bool)
	//myLedger := MakeLedger()

	fmt.Println("Write ip-address: ")
	var ipInput string
	fmt.Print("> ")
	fmt.Scan(&ipInput)

	fmt.Println("Write port: ")
	var portInput string
	fmt.Print("> ")
	fmt.Scan(&portInput)

	var ipPort string
	ipPort = ipInput + ":" + portInput
	conn, err := net.Dial("tcp", ipPort)

	if err != nil {
		ln, _ := net.Listen("tcp", ":18081")
		defer ln.Close()
		for {
			fmt.Println("Local Ip-Address and port number: " + "127.0.0.1:18081")
			go LookForConnection(ln, list, channels, mapOfStrings)

			SendManuallyToConnections(channels, mapOfStrings)
		}
	}

	defer conn.Close()
	LocalIPPort := conn.LocalAddr().String()
	fmt.Println("Local Ip-Address and port number: " + LocalIPPort)

	s := strings.Split(LocalIPPort, ":")
	port := s[1]

	list.mux.Lock()
	list.networkMap[conn.RemoteAddr().String()] = conn
	list.mux.Unlock()

	ln, _ := net.Listen("tcp", ":"+port)

	go LookForConnection(ln, list, channels, mapOfStrings)

	go Recieve(channels, list, mapOfStrings, conn)

	SendManuallyToConnections(channels, mapOfStrings)
}
