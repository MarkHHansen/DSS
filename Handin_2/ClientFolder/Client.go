package main

import (
	"bufio"
	"fmt"
	"net"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"
)

var conn net.Conn

type NetworksList struct {
	networkMap map[string]net.Conn
	sortedList [11]IPList
	mux        sync.Mutex
}

type MapOfStrings struct {
	mapOS map[string]bool
	mux   sync.Mutex
}
type IPList struct {
	id int
	ip string
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

func TransActionHandler(myledger *Ledger, transchan chan string, broadcast chan string) {
	for {
		transactions := <-transchan

		transArray := strings.Split(transactions, ",")
		newTrans := new(Transaction)
		newTrans.ID = transArray[0]
		newTrans.From = transArray[1]
		newTrans.To = transArray[2]
		newTrans.Amount, _ = strconv.Atoi(transArray[3])

		myledger.Transaction(newTrans)

		broadcast <- transactions
	}
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

func Recieve(channels chan string, list *NetworksList, tc chan string, conn net.Conn) {
	counter := 0
	for {
		msg, err := bufio.NewReader(conn).ReadString('\n')

		if err != nil {
			list.mux.Lock()
			fmt.Println("Ending session with " + conn.RemoteAddr().String())
			delete(list.networkMap, conn.RemoteAddr().String())
			list.mux.Unlock()
			break
		}

		if msg == "IPs incoming" {
			counter++
		}
		if counter > 0 {
			ips := strings.Split(msg, ",")
			for i := range ips {
				list.sortedList[counter].id = i + 1
				list.sortedList[counter].ip = ips[i+1]
			}
		}
		if msg == "New peer" {
			conn.Write([]byte("IPs incoming"))
			IPs := ""
			for _, k := range list.sortedList {
				IPs += "," + k.ip
			}
		} else {
			tc <- msg
		}

	}
}

func HandleConnections(InputConn net.Conn, list *NetworksList, channels chan string, tc chan string) {
	defer InputConn.Close()

	for i, _ := range list.networkMap {
		fmt.Println(i)
		InputConn.Write([]byte(i))
		time.Sleep(1)
	}

	Recieve(channels, list, tc, InputConn)
}

func LookForConnection(ln net.Listener, list *NetworksList, broad chan string, tc chan string) {
	//defer ln.Close()

	go BroadCast(broad, list)

	for {
		fmt.Println("Listening for connection...")
		fmt.Print("> ")
		fmt.Println(ln.Addr().String())
		InputConn, _ := ln.Accept()

		fmt.Println("Got a connection...")
		fmt.Print("> ")

		list.mux.Lock()
		list.sortedList[1].id = 1
		list.sortedList[1].ip = InputConn.RemoteAddr().String()
		list.mux.Unlock()

		go HandleConnections(InputConn, list, broad, tc)
	}
}

func SendManuallyToConnections(tc chan string) {
	for {
		fmt.Println("Choose ID: ")
		var idInput string
		fmt.Print("> ")
		fmt.Scan(&idInput)

		fmt.Println("Choose sender: ")
		var senderInput string
		fmt.Print("> ")
		fmt.Scan(&senderInput)

		fmt.Println("Choose receiver: ")
		var receiver string
		fmt.Print("> ")
		fmt.Scan(&receiver)

		reader := bufio.NewReader(os.Stdin)
		fmt.Print("Choose amount \n > ")
		amount, err := reader.ReadString('\n')

		if err != nil {
			return
		}

		trans := idInput + "," + senderInput + "," + receiver + "," + amount

		tc <- trans
	}

}

func main() {
	list := new(NetworksList)
	list.networkMap = make(map[string]net.Conn)

	broadcastchan := make(chan string)
	transactionchan := make(chan string)
	mapOfStrings := new(MapOfStrings)
	mapOfStrings.mapOS = make(map[string]bool)
	myLedger := MakeLedger()

	fmt.Println("Write ip-address: ")
	var ipInput string
	fmt.Print("> ")
	fmt.Scan(&ipInput)

	fmt.Println("Write port: ")
	var portInput string
	fmt.Print("> ")
	fmt.Scan(&portInput)

	go TransActionHandler(myLedger, transactionchan, broadcastchan)

	var ipPort string
	ipPort = ipInput + ":" + portInput
	conn, err := net.Dial("tcp", ipPort)

	if err != nil {
		ln, _ := net.Listen("tcp", ":18081")
		defer ln.Close()
		for {
			fmt.Println("Local Ip-Address and port number: " + "127.0.0.1:18081")
			go LookForConnection(ln, list, broadcastchan, transactionchan)

			SendManuallyToConnections(transactionchan)
		}
	}

	defer conn.Close()
	LocalIPPort := conn.LocalAddr().String()
	fmt.Println("Local Ip-Address and port number: " + LocalIPPort)

	s := strings.Split(LocalIPPort, ":")
	port := s[1]
	fmt.Println(port)
	list.mux.Lock()
	list.networkMap[conn.RemoteAddr().String()] = conn
	list.mux.Unlock()

	conn.Write([]byte("New peer"))

	ln, err := net.Listen("tcp", ":"+port)
	if err != nil {

		fmt.Println("What the fuck, cant listen")
	}

	go LookForConnection(ln, list, broadcastchan, transactionchan)

	go Recieve(broadcastchan, list, transactionchan, conn)

	SendManuallyToConnections(transactionchan)
}
