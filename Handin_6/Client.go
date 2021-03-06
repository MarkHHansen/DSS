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
	tempKey.E, _ = new(big.Int).SetString(sigArray[0], 10)
	tempKey.N, _ = new(big.Int).SetString(sigArray[1], 10)

	signature, _ := new(big.Int).SetString(t.Signature, 10)

	amountStr := strconv.Itoa(t.Amount)
	tempString := t.ID + t.From + t.To + amountStr

	//Removes unnessecary characters or spaces
	re, _ := regexp.Compile(`[^\w]`)
	tempString = re.ReplaceAllString(tempString, "")

	hashingInt, _ := new(big.Int).SetString(tempString, 10)
	hashingTxt := rsacustom.Hash(hashingInt)

	//Uses the verify function from ealiere exercise, to verify the signature
	validSignature := rsacustom.Verify(tempKey, signature, hashingTxt)

	if validSignature == true && t.Amount > 1 {
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

				keyString := keypair.PublicKey.E.String() + "," + keypair.PublicKey.N.String()

				//If the key in the transaction is the same as the local key, it will be signed
				if newTrans.From == keyString {
					re, _ := regexp.Compile(`[^\w]`)
					str1 := re.ReplaceAllString(transactions, "")
					signString, _ := new(big.Int).SetString(str1, 10)

					sig, _ := rsacustom.Sign(keypair.PrivateKey, signString)
					newTrans.Signature = sig.String()

					transactions = transactions + "," + sig.String()

				} else {
					newTrans.Signature = transArray[6]
				}
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

			tempKey := new(rsacustom.PublicKey)
			tempKey.E, _ = new(big.Int).SetString(ips[1], 10)
			n := new(big.Int)
			n, ok := n.SetString(ips[2], 10)
			if !ok {
				fmt.Println("SetString: error")
				return
			}

			tempKey.N = n
			list.publicKeys[conn.RemoteAddr().String()] = tempKey

			//tempVal := list.publicKeys[conn.RemoteAddr().String()]

			conn.Write([]byte(keypair.PublicKey.E.String() + "," + keypair.PublicKey.N.String() + "," + IPs + "\n"))

		} else if ips[2] == "MyPeers" { //If MyPeers is the first part of the message, it means all the IP's is received, and these are saved in the slice.

			tempKey := new(rsacustom.PublicKey)
			tempKey.E, _ = new(big.Int).SetString(ips[0], 10)
			tempKey.N, _ = new(big.Int).SetString(ips[1], 10)
			list.publicKeys[conn.RemoteAddr().String()] = tempKey

			for _, k := range ips[3:] {
				list.sortedList = append(list.sortedList, k)
			}

			//Broadcast precense to all connections
			for _, k := range list.sortedList {
				if k == "MyPeers" || k == localIP || k == conn.RemoteAddr().String() || k == "\n" || k == "" {
					continue
				}
				go BroadcastPrecense(k, channels, list, tc, localIP, keypair)
			}

			//If the message is NewConnection, this is added to the saved IP's. Furthermore, the new received key is saved.
		} else if ips[0] == "NewConnection" {
			list.mux.Lock()
			list.networkMap[ips[1]] = conn
			list.sortedList = append(list.sortedList, ips[1])

			tempKey := new(rsacustom.PublicKey)
			tempKey.E, _ = new(big.Int).SetString(ips[2], 10)
			tempKey.N, _ = new(big.Int).SetString(ips[3], 10)
			list.publicKeys[ips[1]] = tempKey
			list.mux.Unlock()
			conn.Write([]byte("NewKey" + "," + keypair.PublicKey.E.String() + "," + keypair.PublicKey.N.String() + "," + "\n"))

		} else if ips[0] == "NewKey" {
			tempKey := new(rsacustom.PublicKey)
			tempKey.E, _ = new(big.Int).SetString(ips[1], 10)
			tempKey.N, _ = new(big.Int).SetString(ips[2], 10)
			list.publicKeys[conn.RemoteAddr().String()] = tempKey
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

	text := "NewConnection," + localIP + "," + keypair.PublicKey.E.String() + "," + keypair.PublicKey.N.String() + "," + "\n"

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

	time.Sleep(5 * time.Second)
	for {
		fmt.Println("Choose ID: ")
		var idInput string
		fmt.Print("> ")
		fmt.Scan(&idInput)

		fmt.Print("Sender is this account: ")
		fmt.Println(ip)
		sender := pair.PublicKey.E.String() + "," + pair.PublicKey.N.String()

		fmt.Println("Choose receiver: \nFollowing receivers are possible: ")
		for i := range list.publicKeys {
			if i != ip {
				print(i)
				print("\n")
			}
		}

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
	pubKey, privKey, _ := rsacustom.KeyGen(256)
	myKeypair.PublicKey = pubKey
	myKeypair.PrivateKey = privKey

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

	conn.Write([]byte("New peer" + "," + myKeypair.PublicKey.E.String() + "," + myKeypair.PublicKey.N.String() + "," + "\n"))

	SendManuallyToConnections(transactionchan, myKeypair, LocalIPPort, list)
}
