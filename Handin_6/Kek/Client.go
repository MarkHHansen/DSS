package main

import (
	"bufio"
	"fmt"
	"math/big"
	"net"
	"regexp"
	"rsacustom"
	"strconv"
	"strings"
	"sync"
	"time"
)

var conn net.Conn

//KeyPair is a pair of private and public keys
type KeyPair struct {
	PublicKey  *rsacustom.PublicKey
	PrivateKey *rsacustom.PrivateKey
}

//NetworksList is a map over connections and a sorted list of connections
type NetworksList struct {
	networkMap map[string]net.Conn
	sortedList []string
	publicKeys map[string]*rsacustom.PublicKey
	mux        sync.Mutex
}

//MapOfTrans is to make sure trancactions arent duplicated
type MapOfTrans struct {
	mapOT map[string]bool
	mux   sync.Mutex
}

//Ledger which holds all transactions for accounts
type Ledger struct {
	Accounts map[string]int
	lock     sync.Mutex
}

//MakeLedger makes a new ledger
func MakeLedger() *Ledger {
	ledger := new(Ledger)
	ledger.Accounts = make(map[string]int)
	return ledger
}

//SignedTransaction as given from the exercise
type SignedTransaction struct {
	ID        string
	From      string
	To        string
	Amount    int
	Signature string
}

//Transaction verificerer en transaction
func (l *Ledger) Transaction(t *SignedTransaction) {
	l.lock.Lock()
	defer l.lock.Unlock()

	sigArray := strings.Split(t.From, ",")
	tempKey := new(rsacustom.PublicKey)
	tempKey.E, _ = new(big.Int).SetString(sigArray[1], 10)
	tempKey.N, _ = new(big.Int).SetString(sigArray[0], 10)

	signature, _ := new(big.Int).SetString(t.Signature, 10)
	amountStr := strconv.Itoa(t.Amount)
	hashingText, _ := new(big.Int).SetString(t.ID+","+t.From+","+t.To+","+amountStr, 10)
	validSignature := rsacustom.Verify(tempKey, signature, rsacustom.Hash(hashingText))

	if validSignature == true || t.Amount > 1 {
		l.Accounts[t.From] -= t.Amount
		l.Accounts[t.To] += t.Amount
	} else {
		fmt.Println("Invalid account for this ledgder")
	}
}

//TransActionHandler håndterer indkommende strings, og opdaterer ledger med information. Søger for det kun bliver opdateret en gang
func TransActionHandler(myledger *Ledger, transchan chan string, broadcast chan string, maptrans *MapOfTrans, keypair *KeyPair) {
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
				newTrans := new(SignedTransaction)
				newTrans.ID = transArray[0]
				newTrans.From = transArray[1] + "," + transArray[2]
				newTrans.To = transArray[3] + "," + transArray[4]
				tempInt := transArray[5]

				amount, _ := strconv.Atoi(tempInt)

				newTrans.Amount = amount

				fmt.Println(transactions)
				signString, _ := new(big.Int).SetString(transactions, 10)
				fmt.Println("Sign string big integer")
				fmt.Println(signString)
				sig, _ := rsacustom.Sign(keypair.PrivateKey, signString)
				newTrans.Signature = sig.String()

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

//BroadCast to all connections
func BroadCast(inc chan string, list *NetworksList) {
	for {
		msg := <-inc
		list.mux.Lock()
		for _, k := range list.networkMap {
			k.Write([]byte(msg + "\n"))
		}
		list.mux.Unlock()
	}
}

//HandleConnection waits for input on port, and handles the message
func HandleConnection(channels chan string, list *NetworksList, tc chan string, conn net.Conn, localIP string, keypair *KeyPair) {
	for {
		defer conn.Close()
		msg, err := bufio.NewReader(conn).ReadString('\n')

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
		if ips[0] == "New peer" {
			IPs := "MyPeers,"
			//If there is more than 10 peers in the list
			if len(list.sortedList) > 10 {
				counter := 0
				for i := len(list.sortedList) - 1; i == len(list.sortedList)-10; i-- {
					if list.sortedList[i] == "" || list.sortedList[i] == "\n" {
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
			fmt.Println("Lige før key sættes")
			print(ips[1])
			print("\n")
			print(ips[2])

			tempKey := new(rsacustom.PublicKey)
			tempKey.E, _ = new(big.Int).SetString(ips[1], 10)
			tempKey.N, _ = new(big.Int).SetString(ips[2], 10)
			list.publicKeys[conn.RemoteAddr().String()] = tempKey

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
				go BroadcastPrecense(k, channels, list, tc, localIP, keypair)
			}
			//If the message is NewConnection, this is added to the saved IP's
		} else if ips[0] == "NewConnection" {
			list.mux.Lock()
			list.networkMap[ips[1]] = conn
			list.sortedList = append(list.sortedList, ips[1])
			tempKey := new(rsacustom.PublicKey)
			tempKey.E, _ = new(big.Int).SetString(ips[2], 10)
			tempKey.N, _ = new(big.Int).SetString(ips[3], 10)
			list.publicKeys[conn.RemoteAddr().String()] = tempKey
			list.mux.Unlock()

		} else {
			tc <- msg
		}
	}
}

//Removes a string from a slice
func remove(s []string, i int) []string {
	return append(s[:i], s[i+1:]...)
}

//BroadcastPrecense broadcasts theip of this program to all saved IP's
func BroadcastPrecense(connection string, channels chan string, list *NetworksList, tc chan string, localIP string, keypair *KeyPair) {
	conn, err := net.Dial("tcp", connection)

	if err != nil {
		fmt.Println("Could not dial: " + connection)
	}

	text := "NewConnection," + localIP + "," + keypair.PublicKey.E.String() + "," + keypair.PublicKey.N.String() + "\n"

	fmt.Println(text)

	list.mux.Lock()
	list.networkMap[conn.RemoteAddr().String()] = conn
	list.mux.Unlock()

	go HandleConnection(channels, list, tc, conn, localIP, keypair)

	conn.Write([]byte(text))
}

//LookForConnection waits for a incoming connection
func LookForConnection(ln net.Listener, list *NetworksList, channels chan string, tc chan string, localIP string, keypair *KeyPair) {
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

		go HandleConnection(channels, list, tc, InputConn, localIP, keypair)
	}
}

//SendManuallyToConnections waits for a short while, and then waits for inputs from the user to make a new transaction
func SendManuallyToConnections(tc chan string, pair *KeyPair, ip string, list *NetworksList) {
	list.publicKeys[ip] = pair.PublicKey
	time.Sleep(10 * time.Second)
	for {
		fmt.Println("Choose ID: ")
		var idInput string
		fmt.Print("> ")
		fmt.Scan(&idInput)

		fmt.Println("Choose sender: \n Following senders are possible: ")
		for i := range list.networkMap {
			print(i)
			print("\n")
		}
		fmt.Println(ip)
		var tempSender string
		fmt.Print("> ")
		fmt.Scan(&tempSender)
		send := list.publicKeys[tempSender]
		sender := send.E.String() + "," + send.N.String()
		fmt.Println(sender)
		fmt.Println("Choose receiver: \n Following receivers are possible: ")
		for i := range list.networkMap {
			if i == tempSender {
				continue
			}
			print(i)
			print("\n")
		}
		fmt.Println(ip)

		var tempReceiver string
		fmt.Print("> ")
		fmt.Scan(&tempReceiver)
		recev := list.publicKeys[tempReceiver]
		receiver := recev.E.String() + "," + recev.N.String()

		fmt.Println("Choose amount: ")
		var amount string
		fmt.Print("> ")
		fmt.Scan(&amount)

		trans := idInput + "," + sender + "," + receiver + "," + amount

		tc <- trans
	}

}

func main() {
	list := new(NetworksList)
	list.networkMap = make(map[string]net.Conn)
	list.sortedList = make([]string, 1)
	list.publicKeys = make(map[string]*rsacustom.PublicKey)

	broadcastchan := make(chan string)
	transactionchan := make(chan string)
	mapOfTrans := new(MapOfTrans)
	mapOfTrans.mapOT = make(map[string]bool)
	myLedger := MakeLedger()
	myKeypair := new(KeyPair)
	pubKey, privKey, _ := rsacustom.KeyGen(128)
	myKeypair.PublicKey = pubKey
	myKeypair.PrivateKey = privKey

	fmt.Println("Private key N:")
	fmt.Println(myKeypair.PrivateKey.N)

	fmt.Println("Write ip-address: ")
	var ipInput string
	fmt.Print("> ")
	fmt.Scan(&ipInput)

	fmt.Println("Write port: ")
	var portInput string
	fmt.Print("> ")
	fmt.Scan(&portInput)

	go TransActionHandler(myLedger, transactionchan, broadcastchan, mapOfTrans, myKeypair)

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
			go LookForConnection(ln, list, broadcastchan, transactionchan, localIP, myKeypair)

			SendManuallyToConnections(transactionchan, myKeypair, localIP, list)
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

	go HandleConnection(broadcastchan, list, transactionchan, conn, LocalIPPort, myKeypair)

	ln, _ := net.Listen("tcp", ":"+port)

	list.sortedList = append(list.sortedList, LocalIPPort)

	go LookForConnection(ln, list, broadcastchan, transactionchan, LocalIPPort, myKeypair)

	conn.Write([]byte("New peer" + "," + myKeypair.PublicKey.E.String() + "," + myKeypair.PublicKey.N.String() + "\n"))

	SendManuallyToConnections(transactionchan, myKeypair, LocalIPPort, list)
}
