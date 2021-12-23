package kemtls

import (
	"crypto/rand"

	"github.com/cloudflare/circl/dh/sidh"
	"github.com/twisted-lyfes/utility/dh"
)

type KeyPair struct {
	priv *sidh.PrivateKey
	pub  *sidh.PublicKey
	kem  *sidh.KEM
}

func (k *KeyPair) Encapsulate(publicKey []byte) (ct []byte, ss []byte, err error) {
	ct = make([]byte, k.kem.CiphertextSize())
	ss = make([]byte, k.kem.SharedSecretSize())
	external := sidh.NewPublicKey(sidh.Fp751, sidh.KeyVariantSike)
	if err := external.Import(publicKey); err != nil {
		return nil, nil, err
	}

	if err := k.kem.Encapsulate(ct, ss, external); err != nil {
		return nil, nil, err
	}
	return ct, ss, nil
}

func (k *KeyPair) Decapsulate(cipherText []byte) (ss []byte, err error) {
	ss = make([]byte, k.kem.SharedSecretSize())
	if err := k.kem.Decapsulate(ss, k.priv, k.pub, cipherText); err != nil {
		return nil, err
	}
	return ss, nil
}

func (k *KeyPair) ExportPrivate() []byte {
	out := make([]byte, k.kem.PrivateKeySize())
	k.priv.Export(out)
	return out
}

func (k *KeyPair) ExportPublic() []byte {
	out := make([]byte, k.kem.PublicKeySize())
	k.pub.Export(out)
	return out
}
func (k *KeyPair) ImportPrivate(privateKey []byte) error {
	return k.priv.Import(privateKey)
}

func (k *KeyPair) ImportPublic(publicKey []byte) error {
	return k.pub.Import(publicKey)
}

func NewKeyPair() (dh.DH, error) {
	priv := sidh.NewPrivateKey(sidh.Fp751, sidh.KeyVariantSike)
	if err := priv.Generate(rand.Reader); err != nil {
		return nil, err
	}
	pub := sidh.NewPublicKey(sidh.Fp751, sidh.KeyVariantSike)
	priv.GeneratePublicKey(pub)

	return &KeyPair{
		priv: priv,
		pub:  pub,
		kem:  sidh.NewSike751(rand.Reader),
	}, nil
}
