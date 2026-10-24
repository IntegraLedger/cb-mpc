package cbmpc

// Signatures and derived keys are checked with decred's secp256k1, an implementation independent of cb-mpc.

import (
	"bytes"
	"crypto/sha256"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/decred/dcrd/dcrec/secp256k1/v4"
	"github.com/decred/dcrd/dcrec/secp256k1/v4/ecdsa"
)

// pipe is an in-process transport between the two parties. Closing it unblocks both sides.
type pipe struct {
	toP1, toP2 chan []byte
	done       chan struct{}
	once       sync.Once
}

func newPipe() *pipe {
	return &pipe{toP1: make(chan []byte, 8), toP2: make(chan []byte, 8), done: make(chan struct{})}
}

func (p *pipe) close() { p.once.Do(func() { close(p.done) }) }

type end struct {
	p    *pipe
	self Party
}

func (e end) Send(receiver Party, msg []byte) error {
	ch := e.p.toP2
	if receiver == P1 {
		ch = e.p.toP1
	}
	select {
	case ch <- msg:
		return nil
	case <-e.p.done:
		return errors.New("pipe closed")
	}
}

func (e end) Receive(sender Party) ([]byte, error) {
	ch := e.p.toP1
	if e.self == P2 {
		ch = e.p.toP2
	}
	select {
	case m := <-ch:
		return m, nil
	case <-e.p.done:
		return nil, errors.New("pipe closed")
	case <-time.After(60 * time.Second):
		return nil, errors.New("receive timeout")
	}
}

// run executes f1 as P1 and f2 as P2 concurrently; when either fails the pipe closes so the other cannot hang.
func run(t *testing.T, f1, f2 func(Transport) error) (error, error) {
	t.Helper()
	p := newPipe()
	var e1, e2 error
	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		if e1 = f1(end{p, P1}); e1 != nil {
			p.close()
		}
	}()
	go func() {
		defer wg.Done()
		if e2 = f2(end{p, P2}); e2 != nil {
			p.close()
		}
	}()
	wg.Wait()
	return e1, e2
}

func dkg(t *testing.T) (KeyBlob, KeyBlob) {
	t.Helper()
	var k1, k2 KeyBlob
	e1, e2 := run(t,
		func(tr Transport) (err error) { k1, err = DKG(P1, tr); return },
		func(tr Transport) (err error) { k2, err = DKG(P2, tr); return })
	if e1 != nil || e2 != nil {
		t.Fatalf("dkg: p1=%v p2=%v", e1, e2)
	}
	return k1, k2
}

func sign(t *testing.T, k1, k2 KeyBlob, hash [32]byte) []byte {
	t.Helper()
	var sig1, sig2 []byte
	e1, e2 := run(t,
		func(tr Transport) (err error) { sig1, err = Sign(P1, tr, k1, hash); return },
		func(tr Transport) (err error) { sig2, err = Sign(P2, tr, k2, hash); return })
	if e1 != nil || e2 != nil {
		t.Fatalf("sign: p1=%v p2=%v", e1, e2)
	}
	if len(sig1) == 0 {
		t.Fatal("P1 received no signature")
	}
	if sig2 != nil {
		t.Fatalf("P2 received a signature (%d bytes); only P1 should", len(sig2))
	}
	return sig1
}

func verify(t *testing.T, pub []byte, hash [32]byte, der []byte) bool {
	t.Helper()
	pk, err := secp256k1.ParsePubKey(pub)
	if err != nil {
		t.Fatalf("parse public key: %v", err)
	}
	sig, err := ecdsa.ParseDERSignature(der)
	if err != nil {
		t.Fatalf("parse DER signature: %v", err)
	}
	return sig.Verify(hash[:], pk)
}

func TestDKGSignVerify(t *testing.T) {
	k1, k2 := dkg(t)
	pub1, err := PublicKey(k1)
	if err != nil {
		t.Fatal(err)
	}
	pub2, err := PublicKey(k2)
	if err != nil {
		t.Fatal(err)
	}
	if len(pub1) != 33 || !bytes.Equal(pub1, pub2) {
		t.Fatalf("parties disagree on the public key: %x vs %x", pub1, pub2)
	}

	hash := sha256.Sum256([]byte("integra"))
	der := sign(t, k1, k2, hash)
	if !verify(t, pub1, hash, der) {
		t.Fatal("signature does not verify")
	}
	other := sha256.Sum256([]byte("other"))
	if verify(t, pub1, other, der) {
		t.Fatal("control failed: signature verifies over a different hash")
	}
}

func TestDeriveChildSignsUnderQPlusTweakG(t *testing.T) {
	k1, k2 := dkg(t)
	master, err := PublicKey(k1)
	if err != nil {
		t.Fatal(err)
	}
	tweak := sha256.Sum256([]byte("document content"))

	c1, err := DeriveChild(k1, tweak)
	if err != nil {
		t.Fatal(err)
	}
	c2, err := DeriveChild(k2, tweak)
	if err != nil {
		t.Fatal(err)
	}
	pub, err := PublicKey(c1)
	if err != nil {
		t.Fatal(err)
	}

	// Q + t*G, independently.
	var Q, tG, sum secp256k1.JacobianPoint
	mpk, err := secp256k1.ParsePubKey(master)
	if err != nil {
		t.Fatal(err)
	}
	mpk.AsJacobian(&Q)
	var ts secp256k1.ModNScalar
	if overflow := ts.SetBytes(&tweak); overflow != 0 {
		t.Fatal("tweak overflows the group order")
	}
	secp256k1.ScalarBaseMultNonConst(&ts, &tG)
	secp256k1.AddNonConst(&Q, &tG, &sum)
	sum.ToAffine()
	want := secp256k1.NewPublicKey(&sum.X, &sum.Y).SerializeCompressed()
	if !bytes.Equal(pub, want) {
		t.Fatalf("derived public key %x, want Q+tG %x", pub, want)
	}

	hash := sha256.Sum256([]byte("sign under the derived key"))
	der := sign(t, c1, c2, hash)
	if !verify(t, pub, hash, der) {
		t.Fatal("child signature does not verify under Q+tG")
	}
	if verify(t, master, hash, der) {
		t.Fatal("control failed: child signature verifies under the master key")
	}
}

func TestDeriveChildRejectsZeroTweak(t *testing.T) {
	_, k2 := dkg(t)
	var zero [32]byte
	_, err := DeriveChild(k2, zero)
	var cerr *Error
	if !errors.As(err, &cerr) {
		t.Fatalf("zero tweak: got %v, want a cb-mpc error", err)
	}
}

type failingReceive struct{ Transport }

var errInjected = errors.New("injected receive failure")

func (failingReceive) Receive(Party) ([]byte, error) { return nil, errInjected }

func TestTransportErrorIsReported(t *testing.T) {
	e1, e2 := run(t,
		func(tr Transport) error { _, err := DKG(P1, tr); return err },
		func(tr Transport) error { _, err := DKG(P2, failingReceive{tr}); return err })
	if !errors.Is(e2, ErrTransport) || !errors.Is(e2, errInjected) {
		t.Fatalf("P2: got %v, want ErrTransport wrapping the injected error", e2)
	}
	if e1 == nil {
		t.Fatal("P1 completed DKG although P2 aborted")
	}
}
