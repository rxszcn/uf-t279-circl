package hpke_test

import (
	"bytes"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"testing"

	"github.com/cloudflare/circl/hpke"
	"github.com/cloudflare/circl/internal/test"
	"github.com/cloudflare/circl/kem"
)

func Example() {
	// import "github.com/cloudflare/circl/hpke"
	// import "crypto/rand"

	// HPKE suite is a domain parameter.
	kemID := hpke.KEM_P384_HKDF_SHA384
	kdfID := hpke.KDF_HKDF_SHA384
	aeadID := hpke.AEAD_AES256GCM
	suite := hpke.NewSuite(kemID, kdfID, aeadID)
	info := []byte("public info string, known to both Alice and Bob")

	// Bob prepares to receive messages and announces his public key.
	publicBob, privateBob, err := kemID.Scheme().GenerateKeyPair()
	if err != nil {
		panic(err)
	}
	Bob, err := suite.NewReceiver(privateBob, info)
	if err != nil {
		panic(err)
	}

	// Alice gets Bob's public key.
	Alice, err := suite.NewSender(publicBob, info)
	if err != nil {
		panic(err)
	}
	enc, sealer, err := Alice.Setup(rand.Reader)
	if err != nil {
		panic(err)
	}

	// Alice encrypts some plaintext and sends the ciphertext to Bob.
	ptAlice := []byte("text encrypted to Bob's public key")
	aad := []byte("additional public data")
	ct, err := sealer.Seal(ptAlice, aad)
	if err != nil {
		panic(err)
	}

	// Bob decrypts the ciphertext.
	opener, err := Bob.Setup(enc)
	if err != nil {
		panic(err)
	}
	ptBob, err := opener.Open(ct, aad)
	if err != nil {
		panic(err)
	}

	// Plaintext was sent successfully.
	fmt.Println(bytes.Equal(ptAlice, ptBob))
	// Output: true
}

func TestHybridKEMMalformedInputs(t *testing.T) {
	scheme := hpke.KEM_X25519_KYBER768_DRAFT00.Scheme()
	pk, sk, err := scheme.GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}

	_, err = scheme.Decapsulate(sk, []byte{})
	if err == nil {
		t.Error("Decapsulate with short ciphertext should fail")
	}

	_, err = scheme.UnmarshalBinaryPrivateKey([]byte{})
	if err == nil {
		t.Error("UnmarshalBinaryPrivateKey with short data should fail")
	}

	_, err = scheme.UnmarshalBinaryPublicKey([]byte{})
	if err == nil {
		t.Error("UnmarshalBinaryPublicKey with short data should fail")
	}

	seed := make([]byte, scheme.EncapsulationSeedSize())
	_, _, err = scheme.EncapsulateDeterministically(pk, []byte{})
	if err == nil {
		t.Error("EncapsulateDeterministically with short seed should fail")
	}

	_, _, err = scheme.EncapsulateDeterministically(pk, seed)
	if err != nil {
		t.Errorf("EncapsulateDeterministically with correct seed failed: %v", err)
	}
}

func runHpkeBenchmark(b *testing.B, kem hpke.KEM, kdf hpke.KDF, aead hpke.AEAD) {
	suite := hpke.NewSuite(kem, kdf, aead)

	pkR, skR, err := kem.Scheme().GenerateKeyPair()
	if err != nil {
		b.Fatal(err)
	}

	info := []byte("public info string")
	sender, err := suite.NewSender(pkR, info)
	if err != nil {
		b.Fatal(err)
	}

	b.Run(fmt.Sprintf("SetupSender-%04x-%04x-%04x", kem, kdf, aead), func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			_, _, err = sender.Setup(rand.Reader)
			if err != nil {
				b.Fatal(err)
			}
		}
	})

	enc, _, err := sender.Setup(rand.Reader)
	if err != nil {
		b.Fatal(err)
	}

	receiver, err := suite.NewReceiver(skR, info)
	if err != nil {
		b.Fatal(err)
	}

	b.Run(fmt.Sprintf("SetupReceiver-%04x-%04x-%04x", kem, kdf, aead), func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			_, err := receiver.Setup(enc)
			if err != nil {
				b.Fatal(err)
			}
		}
	})

	b.Run(fmt.Sprintf("Encrypt-%04x-%04x-%04x", kem, kdf, aead), func(b *testing.B) {
		pt := []byte("plaintext")
		aad := []byte("additional authenticated data")
		cts := make([][]byte, b.N)
		_, sealer, err := sender.Setup(rand.Reader)
		if err != nil {
			b.Fatal(err)
		}

		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			cts[i], err = sealer.Seal(pt, aad)
			if err != nil {
				b.Fatal(err)
			}
		}
	})

	b.Run(fmt.Sprintf("Decrypt-%04x-%04x-%04x", kem, kdf, aead), func(b *testing.B) {
		pt := []byte("plaintext")
		aad := []byte("additional authenticated data")
		cts := make([][]byte, b.N)
		enc, sealer, err := sender.Setup(rand.Reader)
		if err != nil {
			b.Fatal(err)
		}
		opener, err := receiver.Setup(enc)
		if err != nil {
			b.Fatal(err)
		}
		for i := 0; i < b.N; i++ {
			cts[i], err = sealer.Seal(pt, aad)
			if err != nil {
				b.Fatal(err)
			}
		}
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			_, err = opener.Open(cts[i], aad)
			if err != nil {
				b.Log(i)
				b.Fatal(err)
			}
		}
	})
}

func BenchmarkHpkeRoundTrip(b *testing.B) {
	tests := []struct {
		kem  hpke.KEM
		kdf  hpke.KDF
		aead hpke.AEAD
	}{
		{hpke.KEM_P256_HKDF_SHA256, hpke.KDF_HKDF_SHA256, hpke.AEAD_AES128GCM},
		{hpke.KEM_P384_HKDF_SHA384, hpke.KDF_HKDF_SHA384, hpke.AEAD_AES256GCM},
		{hpke.KEM_P521_HKDF_SHA512, hpke.KDF_HKDF_SHA512, hpke.AEAD_AES256GCM},
		{hpke.KEM_X25519_HKDF_SHA256, hpke.KDF_HKDF_SHA256, hpke.AEAD_AES128GCM},
		{hpke.KEM_X25519_KYBER768_DRAFT00, hpke.KDF_HKDF_SHA256, hpke.AEAD_AES128GCM},
		{hpke.KEM_XWING, hpke.KDF_HKDF_SHA256, hpke.AEAD_AES128GCM},
	}
	for _, test := range tests {
		runHpkeBenchmark(b, test.kem, test.kdf, test.aead)
	}
}

// exportOnlyAlgorithms are the KEM/KDF pairs used by the export-only entries
// of the official RFC 9180 test vectors.
var exportOnlyAlgorithms = []struct {
	kem hpke.KEM
	kdf hpke.KDF
}{
	{hpke.KEM_P256_HKDF_SHA256, hpke.KDF_HKDF_SHA256},
	{hpke.KEM_P384_HKDF_SHA384, hpke.KDF_HKDF_SHA384},
	{hpke.KEM_X25519_HKDF_SHA256, hpke.KDF_HKDF_SHA256},
	{hpke.KEM_P521_HKDF_SHA512, hpke.KDF_HKDF_SHA512},
}

// TestExportOnlyAEADProperties checks the export-only AEAD codepoint is a valid
// suite component whose AEAD operations report ErrAEADExportOnly rather than
// crashing.
func TestExportOnlyAEADProperties(t *testing.T) {
	aead := hpke.AEAD_ExportOnly
	if !aead.IsValid() {
		t.Fatal("AEAD_ExportOnly must be a valid AEAD identifier")
	}
	if got := aead.KeySize(); got != 0 {
		t.Errorf("KeySize: got %d; want 0", got)
	}
	if got := aead.NonceSize(); got != 0 {
		t.Errorf("NonceSize: got %d; want 0", got)
	}
	if got := aead.CipherLen(16); got != 0 {
		t.Errorf("CipherLen: got %d; want 0", got)
	}
	if _, err := aead.New(nil); err != hpke.ErrAEADExportOnly {
		t.Errorf("New: got %v; want %v", err, hpke.ErrAEADExportOnly)
	}
}

// TestExportOnlySuiteConstruction checks that building a suite with the
// export-only AEAD codepoint no longer panics (the regression that made the
// mode unusable).
func TestExportOnlySuiteConstruction(t *testing.T) {
	for _, alg := range exportOnlyAlgorithms {
		alg := alg
		t.Run(fmt.Sprintf("%04x-%04x", alg.kem, alg.kdf), func(t *testing.T) {
			var suite hpke.Suite
			err := checkNoPanic(func() {
				suite = hpke.NewSuite(alg.kem, alg.kdf, hpke.AEAD_ExportOnly)
			})
			if err != nil {
				t.Fatalf("NewSuite panicked: %v", err)
			}

			kemID, kdfID, aeadID := suite.Params()
			if kemID != alg.kem || kdfID != alg.kdf || aeadID != hpke.AEAD_ExportOnly {
				t.Fatalf("Params: got (%x, %x, %x)", kemID, kdfID, aeadID)
			}

			// A full setup must also succeed without panicking.
			pkR, skR, err := alg.kem.Scheme().GenerateKeyPair()
			if err != nil {
				t.Fatal(err)
			}
			sender, err := suite.NewSender(pkR, []byte("info"))
			if err != nil {
				t.Fatal(err)
			}
			receiver, err := suite.NewReceiver(skR, []byte("info"))
			if err != nil {
				t.Fatal(err)
			}
			var enc []byte
			var sealer hpke.Sealer
			err = checkNoPanic(func() {
				enc, sealer, err = sender.Setup(rand.Reader)
			})
			if err != nil {
				t.Fatalf("sender setup panicked or failed: %v", err)
			}
			if sealer == nil {
				t.Fatal("nil sealer")
			}
			var opener hpke.Opener
			err = checkNoPanic(func() {
				opener, err = receiver.Setup(enc)
			})
			if err != nil {
				t.Fatalf("receiver setup panicked or failed: %v", err)
			}
			if opener == nil {
				t.Fatal("nil opener")
			}
		})
	}
}

// TestExportOnlyExportConsistency checks that the sender and receiver derive
// byte-identical export values, including for the empty exporter context.
func TestExportOnlyExportConsistency(t *testing.T) {
	const kemID, kdfID = hpke.KEM_X25519_HKDF_SHA256, hpke.KDF_HKDF_SHA256
	suite := hpke.NewSuite(kemID, kdfID, hpke.AEAD_ExportOnly)

	pkR, skR, err := kemID.Scheme().GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	info := []byte("archive gateway key schedule")
	sender, err := suite.NewSender(pkR, info)
	if err != nil {
		t.Fatal(err)
	}
	receiver, err := suite.NewReceiver(skR, info)
	if err != nil {
		t.Fatal(err)
	}
	enc, sealer, err := sender.Setup(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	opener, err := receiver.Setup(enc)
	if err != nil {
		t.Fatal(err)
	}

	// nil and []byte{} both denote the empty exporter context; the empty label
	// and the registered length tier are exercised explicitly below.
	contexts := [][]byte{nil, []byte("archive/stream/42"), {0x00}}
	seen := make(map[string]bool)
	for i, ctx := range contexts {
		gotS := sealer.Export(ctx, 32)
		gotR := opener.Export(ctx, 32)
		if !bytes.Equal(gotS, gotR) {
			t.Fatalf("context %d: sender %x != receiver %x", i, gotS, gotR)
		}
		if len(gotS) != 32 {
			t.Fatalf("context %d: export length %d; want 32", i, len(gotS))
		}
		if bytes.Equal(gotS, make([]byte, 32)) {
			t.Fatalf("context %d: export is all-zero", i)
		}
		if seen[string(gotS)] {
			t.Fatalf("context %d: export repeats an earlier value", i)
		}
		seen[string(gotS)] = true
	}
}

// TestExportOnlyEncryptionRejected checks that calling the encryption
// primitives on an export-only context reports ErrAEADExportOnly explicitly,
// rather than crashing on a nil AEAD or silently succeeding.
func TestExportOnlyEncryptionRejected(t *testing.T) {
	suite := hpke.NewSuite(hpke.KEM_X25519_HKDF_SHA256, hpke.KDF_HKDF_SHA256,
		hpke.AEAD_ExportOnly)
	pkR, skR, err := hpke.KEM_X25519_HKDF_SHA256.Scheme().GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	sender, err := suite.NewSender(pkR, nil)
	if err != nil {
		t.Fatal(err)
	}
	receiver, err := suite.NewReceiver(skR, nil)
	if err != nil {
		t.Fatal(err)
	}
	enc, sealer, err := sender.Setup(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	opener, err := receiver.Setup(enc)
	if err != nil {
		t.Fatal(err)
	}

	var ct []byte
	var sealErr error
	runErr := checkNoPanic(func() {
		ct, sealErr = sealer.Seal([]byte("plaintext"), []byte("aad"))
	})
	if runErr != nil {
		t.Fatalf("Seal panicked: %v", runErr)
	}
	if sealErr != hpke.ErrAEADExportOnly {
		t.Errorf("Seal: got (%x, %v); want (nil, %v)", ct, sealErr, hpke.ErrAEADExportOnly)
	}
	if ct != nil {
		t.Errorf("Seal returned a ciphertext in export-only mode: %x", ct)
	}

	var pt []byte
	var openErr error
	runErr = checkNoPanic(func() {
		pt, openErr = opener.Open([]byte("ciphertext"), []byte("aad"))
	})
	if runErr != nil {
		t.Fatalf("Open panicked: %v", runErr)
	}
	if openErr != hpke.ErrAEADExportOnly {
		t.Errorf("Open: got (%x, %v); want (nil, %v)", pt, openErr, hpke.ErrAEADExportOnly)
	}
	if pt != nil {
		t.Errorf("Open returned a plaintext in export-only mode: %x", pt)
	}
}

// TestExportOnlySerialization checks that an export-only context round-trips
// through the serialized form with readable empty key, base nonce, and
// sequence number fields, and that Export is preserved across the round trip.
func TestExportOnlySerialization(t *testing.T) {
	suite := hpke.NewSuite(hpke.KEM_X25519_HKDF_SHA256, hpke.KDF_HKDF_SHA256,
		hpke.AEAD_ExportOnly)
	kemID, kdfID, _ := suite.Params()

	pkR, skR, err := kemID.Scheme().GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	sender, err := suite.NewSender(pkR, []byte("info"))
	if err != nil {
		t.Fatal(err)
	}
	receiver, err := suite.NewReceiver(skR, []byte("info"))
	if err != nil {
		t.Fatal(err)
	}
	enc, sealer, err := sender.Setup(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	opener, err := receiver.Setup(enc)
	if err != nil {
		t.Fatal(err)
	}

	ctx := []byte("archive/stream/7")
	want := sealer.Export(ctx, 48)

	rawSealer, err := sealer.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	checkExportOnlyEncoding(t, rawSealer, kdfID.ExtractSize())

	parsedSealer, err := hpke.UnmarshalSealer(rawSealer)
	if err != nil {
		t.Fatalf("UnmarshalSealer: %v", err)
	}
	if got := parsedSealer.Export(ctx, 48); !bytes.Equal(got, want) {
		t.Errorf("sealer export after round trip: got %x; want %x", got, want)
	}

	rawOpener, err := opener.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	checkExportOnlyEncoding(t, rawOpener, kdfID.ExtractSize())
	parsedOpener, err := hpke.UnmarshalOpener(rawOpener)
	if err != nil {
		t.Fatalf("UnmarshalOpener: %v", err)
	}
	if got := parsedOpener.Export(ctx, 48); !bytes.Equal(got, want) {
		t.Errorf("opener export after round trip: got %x; want %x", got, want)
	}

	// Role is still enforced for export-only contexts.
	if _, err := hpke.UnmarshalOpener(rawSealer); err == nil {
		t.Error("parsing an export-only sealer as an opener succeeded")
	}
}

// checkExportOnlyEncoding verifies the serialized layout keeps the empty key,
// base nonce, and sequence number fields readable: role(1) || kem(2) || kdf(2)
// || aead(2) || exporter_secret(1+Nh) || key(1+0) || base_nonce(1+0) || seq(1+0).
func checkExportOnlyEncoding(t *testing.T, raw []byte, nh int) {
	t.Helper()
	const header = 1 + 2 + 2 + 2
	wantLen := header + 1 + nh + 1 + 1 + 1
	if len(raw) != wantLen {
		t.Fatalf("serialized length: got %d; want %d", len(raw), wantLen)
	}
	keyLen := raw[header+1+nh]
	nonceLen := raw[header+1+nh+1]
	seqLen := raw[header+1+nh+2]
	if keyLen != 0 || nonceLen != 0 || seqLen != 0 {
		t.Errorf("empty fields not readable: key=%d base_nonce=%d seq=%d",
			keyLen, nonceLen, seqLen)
	}
}

// officialExportVector is the subset of an RFC 9180 test vector needed to
// replay an export-only derivation: the fixed mode/algorithms and the vector's
// own key material and expected export readout.
type officialExportVector struct {
	ModeID  uint8         `json:"mode"`
	KemID   uint16        `json:"kem_id"`
	KdfID   uint16        `json:"kdf_id"`
	AeadID  uint16        `json:"aead_id"`
	Info    test.HexBytes `json:"info"`
	IkmE    test.HexBytes `json:"ikmE"`
	SkRm    test.HexBytes `json:"skRm"`
	SkSm    test.HexBytes `json:"skSm"`
	Psk     test.HexBytes `json:"psk"`
	PskID   test.HexBytes `json:"psk_id"`
	PkSm    test.HexBytes `json:"pkSm"`
	PkRm    test.HexBytes `json:"pkRm"`
	Exports []exportKAT   `json:"exports"`
}

type exportKAT struct {
	ExportContext test.HexBytes `json:"exporter_context"`
	ExportLength  int           `json:"L"`
	ExportValue   test.HexBytes `json:"exported_value"`
}

const officialVectorPath = "testdata/vectors_rfc9180_5f503c5.json.gz"

// TestExportOnlyOfficialVectors replays every export-only entry bundled with
// the repository, derives the exporter secret and export values from the
// vector's own key material, and logs the per-entry byte readout. It fails if
// any export-only entry is skipped or any derived value differs.
func TestExportOnlyOfficialVectors(t *testing.T) {
	vectors := readOfficialExportVectors(t)
	checked := 0
	for i, v := range vectors {
		if hpke.AEAD(v.AeadID) != hpke.AEAD_ExportOnly {
			continue
		}
		checked++
		t.Run(fmt.Sprintf("v%d", i), func(t *testing.T) {
			verifyExportOnlyVector(t, v)
		})
	}
	if want := 32; checked != want {
		t.Fatalf("export-only entries: got %d; want %d", checked, want)
	}
}

func readOfficialExportVectors(t *testing.T) []officialExportVector {
	t.Helper()
	input, err := test.ReadGzip(officialVectorPath)
	if err != nil {
		t.Fatalf("read %s: %v", officialVectorPath, err)
	}
	var vectors []officialExportVector
	if err := json.Unmarshal(input, &vectors); err != nil {
		t.Fatalf("parse %s: %v", officialVectorPath, err)
	}
	return vectors
}

func verifyExportOnlyVector(t *testing.T, v officialExportVector) {
	t.Helper()
	kemID, kdfID := hpke.KEM(v.KemID), hpke.KDF(v.KdfID)
	if !kemID.IsValid() || !kdfID.IsValid() {
		t.Fatalf("unsupported export-only algorithms: kem=%x kdf=%x", kemID, kdfID)
	}
	suite := hpke.NewSuite(kemID, kdfID, hpke.AEAD_ExportOnly)
	scheme := kemID.Scheme()

	pkR, err := scheme.UnmarshalBinaryPublicKey(v.PkRm)
	if err != nil {
		t.Fatalf("bad public key: %v", err)
	}
	skR, err := scheme.UnmarshalBinaryPrivateKey(v.SkRm)
	if err != nil {
		t.Fatalf("bad private key: %v", err)
	}
	sender, err := suite.NewSender(pkR, v.Info)
	if err != nil {
		t.Fatalf("sender: %v", err)
	}
	receiver, err := suite.NewReceiver(skR, v.Info)
	if err != nil {
		t.Fatalf("receiver: %v", err)
	}

	var enc []byte
	var sealer hpke.Sealer
	var opener hpke.Opener

	// Every mode needs the sender's private key only for Auth/AuthPSK.
	var skS kem.PrivateKey
	var pkS kem.PublicKey
	if v.ModeID == 0x02 || v.ModeID == 0x03 {
		skS, err = scheme.UnmarshalBinaryPrivateKey(v.SkSm)
		if err != nil {
			t.Fatalf("bad sender private key: %v", err)
		}
		pkS, err = scheme.UnmarshalBinaryPublicKey(v.PkSm)
		if err != nil {
			t.Fatalf("bad sender public key: %v", err)
		}
	}

	// The vector's ikmE seeds the encapsulation deterministically, so each
	// setup consumes the same bytes on the sender side.
	newRnd := func() *bytes.Reader { return bytes.NewReader(v.IkmE) }
	switch v.ModeID {
	case 0x00:
		enc, sealer, err = sender.Setup(newRnd())
		if err == nil {
			opener, err = receiver.Setup(enc)
		}
	case 0x01:
		enc, sealer, err = sender.SetupPSK(newRnd(), v.Psk, v.PskID)
		if err == nil {
			opener, err = receiver.SetupPSK(enc, v.Psk, v.PskID)
		}
	case 0x02:
		enc, sealer, err = sender.SetupAuth(newRnd(), skS)
		if err == nil {
			opener, err = receiver.SetupAuth(enc, pkS)
		}
	case 0x03:
		enc, sealer, err = sender.SetupAuthPSK(newRnd(), skS, v.Psk, v.PskID)
		if err == nil {
			opener, err = receiver.SetupAuthPSK(enc, v.Psk, v.PskID, pkS)
		}
	default:
		t.Fatalf("unsupported mode: %d", v.ModeID)
	}
	if err != nil {
		t.Fatalf("setup: %v", err)
	}

	for j, kat := range v.Exports {
		got := sealer.Export(kat.ExportContext, uint(kat.ExportLength))
		if !bytes.Equal(got, kat.ExportValue) {
			t.Fatalf("export %d: got %x; want %x", j, got, kat.ExportValue)
		}
		gotReceiver := opener.Export(kat.ExportContext, uint(kat.ExportLength))
		if !bytes.Equal(gotReceiver, got) {
			t.Fatalf("export %d: receiver %x != sender %x", j, gotReceiver, got)
		}
		t.Logf("mode=%d kem=%04x kdf=%04x aead=%04x ctx=%x L=%d export=%x",
			v.ModeID, v.KemID, v.KdfID, v.AeadID,
			kat.ExportContext, kat.ExportLength, got)
	}
}

// checkNoPanic runs f and returns a non-nil error if it panics.
func checkNoPanic(f func()) (err error) {
	defer func() {
		if r := recover(); r != nil {
			err = fmt.Errorf("panic: %v", r)
		}
	}()
	f()
	return nil
}
