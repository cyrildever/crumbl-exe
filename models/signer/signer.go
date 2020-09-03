package signer

//--- TYPES

// Signer ...
type Signer struct {
	EncryptionAlgorithm string `json:"algorithm"`
	PrivateKey          []byte `json:"privateKey,omitempty"`
	PublicKey           []byte `json:"publicKey,omitempty"`
}
