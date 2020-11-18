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

//TransActionQueue is
type TransActionQueue struct {
	counterBloks int
	transActions []string
}

//Tree is the tree of the blocks
type Tree struct {
	blocks       []string
	blockCounter int
	readyLottery chan string
	seed         string
	hardness     *big.Int
}

//Block is a block
type Block struct {
	name         string
	pubKey       *rsacustom.PublicKey
	slot         string
	Draw         *big.Int
	transactions string
	amountTrans  string
	prevBlock    *big.Int
	signing      *big.Int
}

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
		transArray := strings.Split(transactions, ",")

		if transArray[0] == "Genesis" {
			keyString := transArray[1] + "," + transArray[2]
			myledger.Accounts[keyString] = 1000000
		}

		maptrans.mux.Lock()
		//Checks if transaction has already been made, otherwise makes it
		if maptrans.mapOT[transactions] == false {

			if len(transArray) > 2 {
				newTrans := new(SignedTransaction)
				newTrans.ID = transArray[0]
				newTrans.From = transArray[1] + "," + transArray[2]
				newTrans.To = transArray[3] + "," + transArray[4]
				tempInt := transArray[5]

				amount, _ := strconv.Atoi(tempInt)

				newTrans.Amount = amount - 1

				keyString := keypair.PublicKey.E.String() + "," + keypair.PublicKey.N.String()

				//If the key in the transaction is the same as the local key, it will be signed
				if newTrans.From == keyString {
					re, _ := regexp.Compile(`[^\w]`)
					str1 := re.ReplaceAllString(transactions, "")
					signString, _ := new(big.Int).SetString(str1, 10)

					sig, _ := rsacustom.SignOld(keypair.PrivateKey, signString)
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
func HandleConnection(channels chan string, list *NetworksList, tc chan string, conn net.Conn, localIP string, keypair *KeyPair, blockTree *Tree, transActionsQueue *TransActionQueue) {
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
			if len(list.publicKeys) < 3 {
				tc <- "Genesis" + ips[1] + "," + ips[2]
				blockTree.blocks[0] += "," + ips[1] + ":" + ips[2] + ":1000000" + ","
			} else {
				blockTree.readyLottery <- "True"
			}
			list.publicKeys[conn.RemoteAddr().String()] = tempKey

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
				go BroadcastPrecense(k, channels, list, tc, localIP, keypair, blockTree, transActionsQueue)
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

		} else if ips[0] == "BLOCK" {
			winnerCorrect := false
			newWinnerBlock := new(Block)
			newWinnerBlock.name = ips[0]

			pubKeyE, _ := new(big.Int).SetString(ips[1], 10)
			pubKeyN, _ := new(big.Int).SetString(ips[2], 10)
			newWinnerBlock.pubKey.E = pubKeyE
			newWinnerBlock.pubKey.N = pubKeyN

			newWinnerBlock.slot = ips[3]
			newWinnerBlock.Draw, _ = new(big.Int).SetString(ips[4], 10)
			newWinnerBlock.amountTrans = ips[5]

			aomuntInt, _ := strconv.Atoi(ips[5])
			amountIndex := aomuntInt * 7

			newWinnerBlock.prevBlock, _ = new(big.Int).SetString(ips[amountIndex+5], 10)
			newWinnerBlock.signing, _ = new(big.Int).SetString(ips[amountIndex+6], 10)

			for i := 6; i < amountIndex; {
				newWinnerBlock.transactions += ips[i] + ips[i+1] + ips[i+2] + ips[i+3] + ips[i+4] + ips[i+5] + ips[i+6]
				i += 7
			}

			hashMsg, _ := new(big.Int).SetString("LOTTERY"+blockTree.seed+newWinnerBlock.slot, 10)
			winnerCorrect = rsacustom.Verify(newWinnerBlock.pubKey, newWinnerBlock.signing, hashMsg)
			if winnerCorrect != true {
				fmt.Println("Winner not verified")
				continue
			}

			seedSlot, _ := new(big.Int).SetString("BLOCK"+newWinnerBlock.slot, 10)
			pubKeySum := new(big.Int).Add(newWinnerBlock.pubKey.E, newWinnerBlock.pubKey.N)
			seedSlotPubKey := new(big.Int).Add(seedSlot, pubKeySum)
			totalSummed := new(big.Int).Add(seedSlotPubKey, newWinnerBlock.Draw)
			hashedTicket := rsacustom.Hash(totalSummed)

			//keyString := newWinnerBlock.pubKey.E.String() + "," + newWinnerBlock.pubKey.N.String()
			//coinAmount := strconv.Itoa(myLedger.Accounts[keyString])
			//coinAmountBigInt, _ := new(big.Int).SetString(coinAmount, 10)
			//multipliedInts := new(big.Int).Mul(hashedTicket, coinAmountBigInt)

			if hashedTicket.Cmp(blockTree.hardness) <= 0 {
				fmt.Println("Winner not approved")
				winnerCorrect = false
				continue
			}

			nameSlotInt, _ := new(big.Int).SetString(newWinnerBlock.name+newWinnerBlock.slot, 10)
			transactionsInt, _ := new(big.Int).SetString(newWinnerBlock.transactions, 10)
			nameSlotTransInt := new(big.Int).Add(nameSlotInt, transactionsInt)
			fullInt := new(big.Int).Add(nameSlotTransInt, newWinnerBlock.prevBlock)

			sigmaToVerify := rsacustom.Hash(fullInt)
			winnerCorrect = rsacustom.Verify(newWinnerBlock.pubKey, newWinnerBlock.signing, sigmaToVerify)
			if winnerCorrect != true {
				fmt.Println("The signed block is not verified")
				continue
			}

			for i := 6; i < amountIndex; {
				myTrans := ips[i] + ips[i+1] + ips[i+2] + ips[i+3] + ips[i+4] + ips[i+5] + ips[i+6]
				tc <- myTrans
			}

		} else {
			transActionsQueue.transActions[transActionsQueue.counterBloks] = msg
			transActionsQueue.counterBloks++
		}
	}
}

//Removes a string from a slice
func remove(s []string, i int) []string {
	return append(s[:i], s[i+1:]...)
}

//BroadcastPrecense broadcasts theip of this program to all saved IP's
func BroadcastPrecense(connection string, channels chan string, list *NetworksList, tc chan string, localIP string, keypair *KeyPair, myTree *Tree, transActionsQueue *TransActionQueue) {
	conn, err := net.Dial("tcp", connection)

	if err != nil {
		fmt.Println("Could not dial: " + connection)
	}

	text := "NewConnection," + localIP + "," + keypair.PublicKey.E.String() + "," + keypair.PublicKey.N.String() + "," + "\n"

	list.mux.Lock()
	list.networkMap[conn.RemoteAddr().String()] = conn
	list.mux.Unlock()

	go HandleConnection(channels, list, tc, conn, localIP, keypair, myTree, transActionsQueue)

	conn.Write([]byte(text))
}

//LookForConnection waits for a incoming connection
func LookForConnection(ln net.Listener, list *NetworksList, channels chan string, tc chan string, localIP string, keypair *KeyPair, myTree *Tree, transActionsQueue *TransActionQueue) {
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

		go HandleConnection(channels, list, tc, InputConn, localIP, keypair, myTree, transActionsQueue)
	}
}

//ExpiredTimer checks if the timer is done and returns true/false
func ExpiredTimer(T *time.Timer) bool {
	select {
	case <-T.C:
		return true
	default:
		time.Now()
		return false
	}
}

//DrawLottery is a function
func DrawLottery(seed string, myLedger *Ledger, keypair *KeyPair, hardness *big.Int, blocksTree *Tree, broadcastChan chan string, blockTree *Tree, transactionQueue *TransActionQueue) {
	timer := time.NewTimer(time.Second * 1)
	slot := 0
	for {
		select {
		case _, ok := <-blocksTree.readyLottery:
			if ok == true {
				if ExpiredTimer(timer) {
					slot++
					slotString := strconv.Itoa(slot)
					hashMsg, _ := new(big.Int).SetString("LOTTERY"+seed+slotString, 10)
					drawSlot, _ := rsacustom.SignOld(keypair.PrivateKey, hashMsg)

					seedSlot, _ := new(big.Int).SetString("BLOCK"+slotString, 10)
					pubKeySum := new(big.Int).Add(keypair.PublicKey.E, keypair.PublicKey.N)
					seedSlotPubKey := new(big.Int).Add(seedSlot, pubKeySum)
					totalSummed := new(big.Int).Add(seedSlotPubKey, drawSlot)
					hashedTicket := rsacustom.Hash(totalSummed)

					keyString := keypair.PublicKey.E.String() + "," + keypair.PublicKey.N.String()
					coinAmount := strconv.Itoa(myLedger.Accounts[keyString])
					coinAmountBigInt, _ := new(big.Int).SetString(coinAmount, 10)

					multipliedInts := new(big.Int).Mul(hashedTicket, coinAmountBigInt)
					if multipliedInts.Cmp(hardness) > 0 {
						winnerBlock := new(Block)
						winnerBlock.name = "BLOCK"
						winnerBlock.pubKey = keypair.PublicKey
						winnerBlock.slot = slotString
						winnerBlock.Draw = drawSlot
						for i := 0; i < transactionQueue.counterBloks; i++ {
							winnerBlock.transactions += transactionQueue.transActions[i]
						}
						winnerBlock.amountTrans = strconv.Itoa(transactionQueue.counterBloks)

						prevBlockInt, _ := new(big.Int).SetString(blockTree.blocks[blockTree.blockCounter], 10)
						preblockHash := rsacustom.Hash(prevBlockInt)
						winnerBlock.prevBlock = preblockHash

						go WinnerBroadcast(winnerBlock, broadcastChan, keypair)
					}

					timer.Reset(time.Second * 1)
				}
			}
		default:

		}
	}

}

//WinnerBroadcast formats the information from the winner block, and broadcasts this.
func WinnerBroadcast(winnerblock *Block, broadcastChan chan string, keypair *KeyPair) {
	nameSlotInt, _ := new(big.Int).SetString(winnerblock.name+winnerblock.slot, 10)
	transactionsInt, _ := new(big.Int).SetString(winnerblock.transactions, 10)
	nameSlotTransInt := new(big.Int).Add(nameSlotInt, transactionsInt)
	fullInt := new(big.Int).Add(nameSlotTransInt, winnerblock.prevBlock)

	sigmaToHash := rsacustom.Hash(fullInt)
	sigma, _ := rsacustom.SignOld(keypair.PrivateKey, sigmaToHash)

	MessageToBroadcast := winnerblock.name + "," + winnerblock.pubKey.E.String() + "," + winnerblock.pubKey.N.String() + "," + winnerblock.slot + "," + winnerblock.Draw.String() + "," + winnerblock.amountTrans + "," + winnerblock.transactions + "," + winnerblock.prevBlock.String() + "," + sigma.String()
	broadcastChan <- MessageToBroadcast
}

//SendManuallyToConnections waits for a short while, and then waits for inputs from the user to make a new transaction
func SendManuallyToConnections(broadcast chan string, pair *KeyPair, ip string, list *NetworksList, transActionsQueue *TransActionQueue) {
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
		intAmount, _ := strconv.Atoi(amount)
		if intAmount < 1 {
			fmt.Println("Amount has to be atleast 1")
			continue
		}
		trans := idInput + "," + sender + "," + receiver + "," + amount

		re, _ := regexp.Compile(`[^\w]`)
		str1 := re.ReplaceAllString(trans, "")
		signString, _ := new(big.Int).SetString(str1, 10)

		sig, _ := rsacustom.SignOld(pair.PrivateKey, signString)
		signature := sig.String()
		trans = trans + "," + signature

		transActionsQueue.transActions[transActionsQueue.counterBloks] = trans
		transActionsQueue.counterBloks++

		broadcast <- trans
	}

}

func main() {
	list := new(NetworksList)
	list.networkMap = make(map[string]net.Conn)
	list.sortedList = make([]string, 1)
	list.publicKeys = make(map[string]*rsacustom.PublicKey)

	broadcastchan := make(chan string)
	transactionchan := make(chan string)
	//lotteryChan := make(chan string)

	mapOfTrans := new(MapOfTrans)
	mapOfTrans.mapOT = make(map[string]bool)
	myLedger := MakeLedger()
	myKeypair := new(KeyPair)
	pubKey, privKey, _ := rsacustom.KeyGen(2048)
	myKeypair.PublicKey = pubKey
	myKeypair.PrivateKey = privKey

	myTree := new(Tree)
	myTree.blocks = make([]string, 50)
	myTree.blockCounter = 0
	seed := "12345678"
	myTree.blocks[0] = "Seed:" + seed
	myTree.readyLottery = make(chan string)
	myTree.seed = seed

	fmt.Println("Write ip-address: ")
	var ipInput string
	fmt.Print("> ")
	fmt.Scan(&ipInput)

	fmt.Println("Write port: ")
	var portInput string
	fmt.Print("> ")
	fmt.Scan(&portInput)

	transActionQueue := new(TransActionQueue)
	transActionQueue.transActions = make([]string, 500)
	transActionQueue.counterBloks = 0

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
			go LookForConnection(ln, list, broadcastchan, transactionchan, localIP, myKeypair, myTree, transActionQueue)

			SendManuallyToConnections(broadcastchan, myKeypair, localIP, list, transActionQueue)
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

	go HandleConnection(broadcastchan, list, transactionchan, conn, LocalIPPort, myKeypair, myTree, transActionQueue)

	ln, _ := net.Listen("tcp", ":"+port)

	list.sortedList = append(list.sortedList, LocalIPPort)

	go LookForConnection(ln, list, broadcastchan, transactionchan, LocalIPPort, myKeypair, myTree, transActionQueue)

	conn.Write([]byte("New peer" + "," + myKeypair.PublicKey.E.String() + "," + myKeypair.PublicKey.N.String() + "," + "\n"))

	SendManuallyToConnections(broadcastchan, myKeypair, LocalIPPort, list, transActionQueue)
}
