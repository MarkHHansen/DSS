package main

import (
	"net"
	"sync"
)

type NetworksList struct {
	networkMap map[string]net.Conn
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

func main() {
	list := new(NetworksList)
	list.networkMap = make(map[string]net.Conn)
	myLedger := MakeLedger()

}
