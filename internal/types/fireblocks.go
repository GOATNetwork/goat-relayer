package types

type FbSignature struct {
	FullSig string `json:"fullSig"`
	R       string `json:"r"`
	S       string `json:"s"`
	V       int    `json:"v"`
}

type FbSignedMessage struct {
	Content        string      `json:"content"`
	Algorithm      string      `json:"algorithm"`
	DerivationPath []int       `json:"derivationPath"`
	Signature      FbSignature `json:"signature"`
	PublicKey      string      `json:"publicKey"`
}
