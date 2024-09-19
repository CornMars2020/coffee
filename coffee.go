package main

import (
	"coffee/wallet"
	"flag"
	"fmt"
	"log"
	"os"
	"strings"
	"time"

	"github.com/CornMars2020/color"
	"github.com/CornMars2020/hdkey"
)

var defaultNetwork = "mainnet"

func GenMnemonic() (km *hdkey.KeyManager) {
	fmt.Println("")

	km, err := hdkey.NewKeyManager("", "", defaultNetwork)
	if err != nil {
		fmt.Printf(color.GetRed("NewKeyManager %s\n"), err)
		return
	}
	masterKey, err := km.GetMasterKey()
	if err != nil {
		fmt.Printf(color.GetRed("GetMasterKey %s\n"), err)
		return
	}

	passphrase := km.Passphrase
	if passphrase == "" {
		passphrase = "<none>"
	}
	fmt.Printf("\n%-18s %s\n", "BIP39 Mnemonic:", km.Mnemonic)
	fmt.Printf("%-18s %s\n", "BIP39 Passphrase:", passphrase)
	fmt.Printf("%-18s %x\n", "BIP39 Seed:", km.GetSeed())
	fmt.Printf("%-18s %s\n", "BIP32 Root Key:", masterKey.B58Serialize())

	return km
}

func GetAddress(km *hdkey.KeyManager, searcher []string) {
	types := []string{"legacy", "nested-segwit", "native-segwit", "taproot"}

	for _, t := range types {
		mnemonic, walletAddress, walletWif, walletPubKeyHex := wallet.GenWallet(km.Mnemonic, km.Passphrase, defaultNetwork, t, 0, true)

		lowerWalletAddress := strings.ToLower(walletAddress)
		for _, s := range searcher {
			if strings.Contains(lowerWalletAddress, s) {
				log.Println("")
				log.Println(strings.Repeat("=", 80))
				log.Println("wallet address", walletAddress)
				log.Println("Mnemonic", mnemonic)
				log.Println("Passphrase", "<none>")
				log.Println("WIF", walletWif)
				log.Println("PubKey", walletPubKeyHex)
				log.Println(strings.Repeat("=", 80))
				log.Println("")
			}
		}
	}
}

var keys string
var searchKeys []string

func init() {
	flag.StringVar(&keys, "keys", "", "search keys, using comma to separate multiple keys")
	flag.Parse()

	searchKeys = strings.Split(strings.ReplaceAll(keys, " ", ""), ",")
	if keys == "" || len(searchKeys) == 0 {
		searchKeys = []string{"coffee", "beer"}
		fmt.Printf("no key set, use default search keys: %#v", searchKeys)
	}
}

func main() {
	f, err := os.OpenFile("coffee.log", os.O_RDWR|os.O_CREATE|os.O_APPEND, 0666)
	if err != nil {
		log.Fatalf("error opening file: %v", err)
	}
	defer f.Close()

	log.SetOutput(f)
	log.Printf("start mining, search keys: %#v", searchKeys)

	tk := time.NewTicker(time.Millisecond * 10)

	for {
		km, err := hdkey.NewKeyManager("", "", defaultNetwork)
		if err != nil {
			fmt.Printf(color.GetRed("NewKeyManager %s\n"), err)
			return
		}

		GetAddress(km, searchKeys)
		<-tk.C
	}
}
