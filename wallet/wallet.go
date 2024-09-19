package wallet

import (
	"fmt"
	"strings"

	"github.com/CornMars2020/color"
	"github.com/CornMars2020/hdkey"
)

func GenWallet(_mnemonic string, _passphrase string, _network string, _addressType string, index uint32, compress bool) (mnemonic string, walletAddress string, walletWif string, walletPubKeyHex string) {
	km, err := hdkey.NewKeyManager(_mnemonic, _passphrase, _network)
	if err != nil {
		fmt.Printf(color.GetRed("NewKeyManager %s\n"), err)
	}
	masterKey, err := km.GetMasterKey()
	if err != nil {
		fmt.Printf(color.GetRed("GetMasterKey %s\n"), err)
	}
	passphrase := km.Passphrase
	if passphrase == "" {
		passphrase = "<none>"
	}
	fmt.Printf("\n%-18s %s\n", "BIP39 Mnemonic:", km.Mnemonic)
	fmt.Printf("%-18s %s\n", "BIP39 Passphrase:", passphrase)
	fmt.Printf("%-18s %x\n", "BIP39 Seed:", km.GetSeed())
	fmt.Printf("%-18s %s\n", "BIP32 Root Key:", masterKey.B58Serialize())

	fmt.Printf("\n%-18s %-30s %-62s %-52s %-66s\n", "Path", "AddressType", "Address", "WIF(Wallet Import Format)", "Public Key")
	fmt.Println(strings.Repeat("-", 233))

	key, err := km.GetBTCLegacyKey(index)
	if err != nil {
		fmt.Printf(color.GetRed("GetKey Path(BIP44) %s\n"), err)
	}
	legacyWif, legacySerializedPubKeyHex, legacyAddress, _, _, _, err := key.Calculate(compress)
	if err != nil {
		fmt.Printf(color.GetRed("Calculate Path(BIP44) %s\n"), err)
	}

	fmt.Printf("%-18s %-30s %-62s %-52s %-66s\n", key.Path, "Legacy(P2PKH, compresed)", legacyAddress, legacyWif, legacySerializedPubKeyHex)

	key, err = km.GetBTCNestedSegWitKey(index)
	if err != nil {
		fmt.Printf(color.GetRed("GetKey Path(BIP49) %s\n"), err)
	}
	segwitNestedWif, segwitNestedSerializedPubKeyHex, _, _, segwitNestedAddress, _, err := key.Calculate(compress)
	if err != nil {
		fmt.Printf(color.GetRed("Calculate Path(BIP49) %s\n"), err)
	}

	fmt.Printf("%-18s %-30s %-62s %-52s %-66s\n", key.Path, "Nested SegWit(P2SH-P2WPKH)", segwitNestedAddress, segwitNestedWif, segwitNestedSerializedPubKeyHex)

	key, err = km.GetBTCNativeSegWitKey(index)
	if err != nil {
		fmt.Printf(color.GetRed("GetKey Path(BIP84) %s\n"), err)
	}
	segwitBech32Wif, segwitBech32SerializedPubKeyHex, _, segwitBech32Address, _, _, err := key.Calculate(compress)
	if err != nil {
		fmt.Printf(color.GetRed("Calculate Path(BIP84) %s\n"), err)
	}

	fmt.Printf("%-18s %-30s %-62s %-52s %-66s\n", key.Path, "Native SegWit(P2WPKH, bech32)", segwitBech32Address, segwitBech32Wif, segwitBech32SerializedPubKeyHex)

	key, err = km.GetBTCTaprootKey(0)
	if err != nil {
		fmt.Printf(color.GetRed("GetKey Path(BIP86) %s\n"), err)
	}
	taprootWif, taprootSerializedPubKeyHex, _, _, _, taprootAddress, err := key.Calculate(compress)
	if err != nil {
		fmt.Printf(color.GetRed("Calculate Path(BIP86) %s\n"), err)
	}

	fmt.Printf("%-18s %-30s %-62s %-52s %-66s\n", key.Path, "Taproot(P2TR, bech32m)", taprootAddress, taprootWif, taprootSerializedPubKeyHex)

	switch _addressType {
	case "legacy":
		walletAddress = legacyAddress
		walletWif = legacyWif
		walletPubKeyHex = legacySerializedPubKeyHex
	case "nested-segwit":
		walletAddress = segwitNestedAddress
		walletWif = segwitNestedWif
		walletPubKeyHex = segwitNestedSerializedPubKeyHex
	case "native-segwit":
		walletAddress = segwitBech32Address
		walletWif = segwitBech32Wif
		walletPubKeyHex = segwitBech32SerializedPubKeyHex
	case "taproot":
		walletAddress = taprootAddress
		walletWif = taprootWif
		walletPubKeyHex = taprootSerializedPubKeyHex
	default:
		walletAddress = ""
	}

	return km.Mnemonic, walletAddress, walletWif, walletPubKeyHex
}

func GenWalletFromWIF(_wif string, _network string, _addressType string, compress bool) (walletAddress string, walletWif string, walletPubKeyHex string) {
	networkParams := GetNetworkParams(_network)

	_, serializedPubKeyHex, legacyAddress, segwitNativeAddress, segwitNestedAddress, taprootAddress, err := hdkey.CalculateFromWif(_wif, compress, networkParams)
	if err != nil {
		fmt.Printf(color.GetRed("CalculateFromWif %s\n"), err)
		return
	}

	fmt.Printf("\n%-18s %-30s %-62s %-52s %-66s\n", "Path", "AddressType", "Address", "WIF(Wallet Import Format)", "Public Key")
	fmt.Println(strings.Repeat("-", 233))

	walletWif = _wif
	walletPubKeyHex = serializedPubKeyHex

	switch _addressType {
	case "legacy":
		fmt.Printf("%-18s %-30s %-62s %-52s %-66s\n", "", "Legacy(P2PKH, compresed)", legacyAddress, _wif, serializedPubKeyHex)
		walletAddress = legacyAddress
	case "nested-segwit":
		fmt.Printf("%-18s %-30s %-62s %-52s %-66s\n", "", "Nested SegWit(P2SH-P2WPKH)", segwitNestedAddress, _wif, serializedPubKeyHex)
		walletAddress = segwitNestedAddress
	case "native-segwit":
		fmt.Printf("%-18s %-30s %-62s %-52s %-66s\n", "", "Native SegWit(P2WPKH, bech32)", segwitNativeAddress, _wif, serializedPubKeyHex)
		walletAddress = segwitNativeAddress
	case "taproot":
		fmt.Printf("%-18s %-30s %-62s %-52s %-66s\n", "", "Taproot(P2TR, bech32m)", taprootAddress, _wif, serializedPubKeyHex)
		walletAddress = taprootAddress
	default:
		fmt.Printf(color.GetRed("unknown address type %s\n"), _addressType)
	}

	return walletAddress, walletWif, walletPubKeyHex
}
