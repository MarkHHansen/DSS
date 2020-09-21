package main

import (
	"bufio"
	"fmt"
	"net"
	"strconv"
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

type MapOfTrans struct {
	mapOT map[string]bool
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
	fmt.Println("Hej fra Transaction funktion")
}

func TransActionHandler(myledger *Ledger, transchan chan string, broadcast chan string, tmap *MapOfTrans) {
	for {
		transactions := <-transchan
		if tmap.mapOT[transactions] == false {
			fmt.Println("modtaget i Transactionshandler: " + transactions)
			transArray := strings.Split(transactions, ",")
			if len(transArray) > 2 {
				newTrans := new(Transaction)
				newTrans.ID = transArray[0]
				newTrans.From = transArray[1]
				newTrans.To = transArray[2]
				newTrans.Amount, _ = strconv.Atoi(transArray[3])

				myledger.Transaction(newTrans)

				tmap.mapOT[transactions] = true

				broadcast <- transactions
			}
		}
	}
}

func BroadCast(inc chan string, list *NetworksList) {
	for {
		msg := <-inc
		fmt.Println(msg)
		list.mux.Lock()
		for i, k := range list.networkMap {
			fmt.Println(i)
			k.Write([]byte(msg + "\n"))
		}
		list.mux.Unlock()
	}
}

func Recieve(channels chan string, list *NetworksList, tc chan string, conn net.Conn) {
	counter := 0
	for {
		fmt.Println("Hej fra receveiver")

		msg, err := bufio.NewReader(conn).ReadString('\n')

		for i := 0; i > len(list.sortedList); i++ {
			fmt.Println(list.sortedList[i])
		}

		if err != nil {
			list.mux.Lock()
			fmt.Println("Ending session with " + conn.RemoteAddr().String())
			delete(list.networkMap, conn.RemoteAddr().String())
			list.mux.Unlock()
			break
		}

		fmt.Println("Modtaget besked: " + msg)

		if msg == "IPs incoming\n" {
			counter++
		} else if counter > 0 {
			ips := strings.Split(msg, ",")
			fmt.Println("Modtaget i counter if loop: " + msg)
			if len(ips) > 1 {
				fmt.Println("et skridt længere inde")
				for i := 0; i > len(ips); i++ {
					if ips[i] == conn.LocalAddr().String() {
						continue
					}
					list.sortedList = append(list.sortedList, ips[i])
					// list.sortedList[counter].id = i
					// list.sortedList[counter].ip = ips[i]
					counter++
				}

				counter = 0
			}
		} else if msg == "New peer\n" {
			conn.Write([]byte("IPs incoming\n"))
			IPs := ""
			for _, k := range list.sortedList {
				if k == "" {
					continue
				}
				IPs += k + ","
			}
			time.Sleep(2 * time.Second)
			conn.Write([]byte(IPs + "\n"))
		} else {
			tc <- msg
		}

	}
}

func HandleConnections(InputConn net.Conn, list *NetworksList, channels chan string, tc chan string) {
	defer InputConn.Close()

	// for i, _ := range list.networkMap {
	// 	fmt.Println(i)
	// 	InputConn.Write([]byte(i))
	// 	time.Sleep(1)
	// }

	Recieve(channels, list, tc, InputConn)
}

func LookForConnection(ln net.Listener, list *NetworksList, channels chan string, tc chan string) {
	defer ln.Close()

	go BroadCast(channels, list)
	counter := 0
	for {
		fmt.Println("Listening for connection...")
		fmt.Print("> ")
		InputConn, _ := ln.Accept()

		if counter == 0 {
			list.sortedList = append(list.sortedList, InputConn.LocalAddr().String())
			//list.sortedList[counter].id = counter
		}

		fmt.Println("Got a connection...")
		fmt.Print("> ")
		counter++
		list.mux.Lock()
		list.sortedList = append(list.sortedList, InputConn.RemoteAddr().String())
		// list.sortedList[counter].ip =
		list.networkMap[InputConn.RemoteAddr().String()] = InputConn
		list.mux.Unlock()

		go HandleConnections(InputConn, list, channels, tc)
	}
}

func SendManuallyToConnections(tc chan string, tmap *MapOfTrans) {
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

		fmt.Println("Choose amount: ")
		var amount string
		fmt.Print("> ")
		fmt.Scan(&amount)

		// reader := bufio.NewReader(os.Stdin)
		// fmt.Print("Choose amount \n > ")
		// amount, err := reader.ReadString('\n')

		trans := idInput + "," + senderInput + "," + receiver + "," + amount

		tc <- trans
	}

}

func main() {
	list := new(NetworksList)
	list.networkMap = make(map[string]net.Conn)
	list.sortedList = make([]string, 1)
	transMap := new(MapOfTrans)
	transMap.mapOT = make(map[string]bool)
	broadcastchan := make(chan string)
	transactionchan := make(chan string)
	myLedger := MakeLedger()

	fmt.Println("Write ip-address: ")
	var ipInput string
	fmt.Print("> ")
	fmt.Scan(&ipInput)

	fmt.Println("Write port: ")
	var portInput string
	fmt.Print("> ")
	fmt.Scan(&portInput)

	go TransActionHandler(myLedger, transactionchan, broadcastchan, transMap)

	var ipPort string
	ipPort = ipInput + ":" + portInput
	conn, err := net.Dial("tcp", ipPort)

	if err != nil {
		ln, _ := net.Listen("tcp", ":18081")
		defer ln.Close()
		for {
			fmt.Println("Local Ip-Address and port number: " + "127.0.0.1:18081")
			go LookForConnection(ln, list, broadcastchan, transactionchan)

			SendManuallyToConnections(transactionchan, transMap)
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

	conn.Write([]byte("New peer\n"))

	ln, _ := net.Listen("tcp", ":"+port)

	go LookForConnection(ln, list, broadcastchan, transactionchan)

	go Recieve(broadcastchan, list, transactionchan, conn)

	SendManuallyToConnections(transactionchan, transMap)
}
