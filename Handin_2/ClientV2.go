package main

import (
	"bufio"
	"fmt"
	"net"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"
)

var conn net.Conn

//Map over connections and a sorted list of connections
type NetworksList struct {
	networkMap map[string]net.Conn
	sortedList []string
	mux        sync.Mutex
}

//Map to make sure trancactions arent duplicated
type MapOfTrans struct {
	mapOT map[string]bool
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

///Håndterer indkommende strings, og opdaterer ledger med information. Søger for det kun bliver opdateret en gang
func TransActionHandler(myledger *Ledger, transchan chan string, broadcast chan string, maptrans *MapOfTrans) {
	for {

		transactions := <-transchan
		//Removes any unwanted spaces from the incoming message. Without this, the last part of the message, the amount, cannot be parsed to an integer.
		re := regexp.MustCompile(`\r?\n`)
		transactions = re.ReplaceAllString(transactions, "")

		maptrans.mux.Lock()
		//Checks if transaction has already been made, otherwise makes it
		if maptrans.mapOT[transactions] == false {
			transArray := strings.Split(transactions, ",")
			if len(transArray) > 2 {
				newTrans := new(Transaction)
				newTrans.ID = transArray[0]
				newTrans.From = transArray[1]
				newTrans.To = transArray[2]
				tempInt := transArray[3]

				amount, _ := strconv.Atoi(tempInt)

				newTrans.Amount = amount

				myledger.Transaction(newTrans)

				maptrans.mapOT[transactions] = true

				broadcast <- transactions
			}
			fmt.Println("Updated ledgder: ")
			for i, k := range myledger.Accounts {
				fmt.Println("Account: " + i + " has balance: " + strconv.Itoa(k))
			}
		}
		maptrans.mux.Unlock()
	}
}

//Broadcasts to all connections
func BroadCast(inc chan string, list *NetworksList) {
	for {
		msg := <-inc
		fmt.Println(msg)
		list.mux.Lock()
		for _, k := range list.networkMap {
			k.Write([]byte(msg + "\n"))
		}
		list.mux.Unlock()
	}
}

//Waits for input on port, and handles the message
func Recieve(channels chan string, list *NetworksList, tc chan string, conn net.Conn, localIP string) {
	for {
		msg, err := bufio.NewReader(conn).ReadString('\n')

		fmt.Println("Modtaget besked: " + msg)

		//Deletes connection if sessionis ended
		if err != nil {
			list.mux.Lock()
			fmt.Println("Ending session with " + conn.RemoteAddr().String())
			delete(list.networkMap, conn.RemoteAddr().String())
			list.mux.Unlock()
			break
		}

		ips := strings.Split(msg, ",")
		//If a new peer is connected, this returns the ip's connected to the new peer
		if msg == "New peer\n" {
			IPs := "MyPeers,"
			if len(list.sortedList) > 10 {
				counter := 0
				for i := len(list.sortedList) - 1; i == len(list.sortedList)-10; i-- {
					if list.sortedList[i] == "" {
						continue
					}
					IPs += list.sortedList[i] + ","
					counter++
				}
			} else {
				for _, i := range list.sortedList {
					if i == "" {
						continue
					}
					IPs += i + ","
				}
			}
			conn.Write([]byte(IPs + "\n"))
		} else if ips[0] == "MyPeers" { //If MyPeers is the first part of the message, it means all the IP's is received, and these are saved in the slice.
			for _, k := range ips {

				if list.sortedList[0] == k || k == "MyPeers" || k == "\n" {
					continue
				} else {
					list.sortedList = append(list.sortedList, k)
				}

			}

			//Broadcast precense to all connections
			for _, k := range list.sortedList {
				if k == "MyPeers" || k == localIP || k == conn.RemoteAddr().String() || k == "\n" || k == "" {
					continue
				}
				go BroadcastPrecense(k, channels, list, tc, localIP)
			}
			//If the message is NewConnection, this is added to the saved IP's
		} else if ips[0] == "NewConnection" {
			list.mux.Lock()
			list.networkMap[ips[1]] = conn
			list.sortedList = append(list.sortedList, ips[1])

			for i, k := range list.sortedList {
				_, ok := list.networkMap[k]
				if ok == false {
					if k == localIP {
						continue
					} else {
						fmt.Println("Was not here: " + ":" + k + ":")
						list.sortedList = remove(list.sortedList, i)
					}
				}
			}
			list.mux.Unlock()

			for _, k := range list.sortedList {
				fmt.Println("SortedList: " + k)
			}

			for i := range list.networkMap {
				fmt.Println("networkMap: " + i)
			}

		} else {
			tc <- msg
		}
	}
}

//Removes a string from a slice
func remove(s []string, i int) []string {
	return append(s[:i], s[i+1:]...)
}

//Broadcasts theip of this program to all saved IP's
func BroadcastPrecense(connection string, channels chan string, list *NetworksList, tc chan string, localIP string) {
	conn, err := net.Dial("tcp", connection)

	if err != nil {
		fmt.Println("Could not dial: " + connection)
	}

	text := "NewConnection," + localIP + "\n"

	list.mux.Lock()
	list.networkMap[conn.RemoteAddr().String()] = conn
	list.mux.Unlock()

	go Recieve(channels, list, tc, conn, localIP)

	conn.Write([]byte(text))
}

//Waits for a incoming connection
func LookForConnection(ln net.Listener, list *NetworksList, channels chan string, tc chan string, localIP string) {
	defer ln.Close()

	go BroadCast(channels, list)

	for {
		fmt.Println("Listening for connection...")
		fmt.Print("> ")
		InputConn, _ := ln.Accept()

		fmt.Println("Got a connection...")
		fmt.Print("> ")

		list.mux.Lock()
		list.sortedList = append(list.sortedList, InputConn.RemoteAddr().String())
		list.networkMap[InputConn.RemoteAddr().String()] = InputConn
		list.mux.Unlock()

		go Recieve(channels, list, tc, InputConn, localIP)
	}
}

//Waits for a short while, and then waits for inputs from the user to make a new transaction
func SendManuallyToConnections(tc chan string) {
	time.Sleep(10 * time.Second)
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

		trans := idInput + "," + senderInput + "," + receiver + "," + amount

		fmt.Println("Hej fra Receiver: " + trans)

		tc <- trans
	}

}

func main() {
	list := new(NetworksList)
	list.networkMap = make(map[string]net.Conn)
	list.sortedList = make([]string, 1)

	broadcastchan := make(chan string)
	transactionchan := make(chan string)
	mapOfTrans := new(MapOfTrans)
	mapOfTrans.mapOT = make(map[string]bool)
	myLedger := MakeLedger()

	fmt.Println("Write ip-address: ")
	var ipInput string
	fmt.Print("> ")
	fmt.Scan(&ipInput)

	fmt.Println("Write port: ")
	var portInput string
	fmt.Print("> ")
	fmt.Scan(&portInput)

	go TransActionHandler(myLedger, transactionchan, broadcastchan, mapOfTrans)

	ipPort := ipInput + ":" + portInput
	conn, err := net.Dial("tcp", ipPort)

	if err != nil {
		ln, _ := net.Listen("tcp", ":")
		tempString := ln.Addr().String()
		localArr := strings.Split(tempString, ":")
		localIP := "127.0.0.1:" + localArr[3]
		defer ln.Close()
		for {
			fmt.Println("Local Ip-Address and port number: " + localIP)
			list.sortedList = append(list.sortedList, localIP)
			go LookForConnection(ln, list, broadcastchan, transactionchan, localIP)

			SendManuallyToConnections(transactionchan)
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

	go Recieve(broadcastchan, list, transactionchan, conn, LocalIPPort)

	ln, _ := net.Listen("tcp", ":"+port)

	list.sortedList = append(list.sortedList, LocalIPPort)

	go LookForConnection(ln, list, broadcastchan, transactionchan, LocalIPPort)

	conn.Write([]byte("New peer\n"))

	SendManuallyToConnections(transactionchan)
}
