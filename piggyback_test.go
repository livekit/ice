// SPDX-FileCopyrightText: 2026 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

//go:build !js

package ice

import (
	"context"
	"net"
	"testing"

	"github.com/pion/logging"
	"github.com/pion/transport/v4/test"
	"github.com/stretchr/testify/require"
)

func TestSped(t *testing.T) {
	defer test.CheckRoutines(t)()

	t.Run("Basic embedding", func(t *testing.T) {
		aNotifier, aConnected := onConnected()
		aAgent, err := NewAgent(&AgentConfig{
			NetworkTypes: supportedNetworkTypes(),
		})
		require.NoError(t, err)
		require.NoError(t, aAgent.OnConnectionStateChange(aNotifier))

		var toA string
		fromA := "Hello from A"
		aAgent.SetDtlsCallback(func(packet []byte, rAddr net.Addr) {
			toA = string(packet)
		})
		require.True(t, aAgent.Piggyback([]byte(fromA), true))

		bNotifier, bConnected := onConnected()
		bAgent, err := NewAgent(&AgentConfig{
			NetworkTypes: supportedNetworkTypes(),
		})
		require.NoError(t, err)
		require.NoError(t, bAgent.OnConnectionStateChange(bNotifier))

		var toB string
		fromB := "Hello from B"
		bAgent.SetDtlsCallback(func(packet []byte, rAddr net.Addr) {
			toB = string(packet)
		})
		require.True(t, bAgent.Piggyback([]byte(fromB), true))

		gatherAndExchangeCandidates(t, aAgent, bAgent)
		go func() {
			bUfrag, bPwd, err := bAgent.GetLocalUserCredentials()
			require.NoError(t, err)
			_, err = aAgent.Accept(context.TODO(), bUfrag, bPwd)
			require.NoError(t, err)
		}()

		go func() {
			aUfrag, aPwd, err := aAgent.GetLocalUserCredentials()
			require.NoError(t, err)
			_, err = bAgent.Dial(context.TODO(), aUfrag, aPwd)
			require.NoError(t, err)
		}()

		<-aConnected
		<-bConnected
		require.NoError(t, aAgent.Close())
		require.NoError(t, bAgent.Close())

		require.Equal(t, toA, fromB)
		require.Equal(t, toB, fromA)
	})
}

// TestSpedFlushStrandedFlight covers the DTLS-in-STUN (SPED) completion fix.
//
// The piggyback controller can flip to Complete on the remote's "done" STUN
// while a local DTLS flight is still unacked. Once Complete, that flight is no
// longer carried on STUN, so it must be flushed as plain DTLS instead of being
// silently stranded (which stalls the peer's handshake).
func TestSpedFlushStrandedFlight(t *testing.T) {
	newPending := func() []packetWithCrc { return []packetWithCrc{{data: []byte("flight")}} }

	t.Run("flushOnConnected flushes leftover flight when Complete", func(t *testing.T) {
		// Off (piggybacking unsupported) already flushed; Complete must flush
		// too, else a flight left over at completion is never sent.
		for _, st := range []piggybackingState{PiggybackingStateOff, PiggybackingStateComplete} {
			p := &piggybackingController{state: st, packets: newPending()}
			got := p.flushOnConnected()
			require.Len(t, got, 1, "state %d must flush the pending flight", st)
			require.Equal(t, []byte("flight"), got[0].data)
			require.Empty(t, p.packets, "packets drained after flush")
		}
	})

	t.Run("flushOnConnected keeps flight while handshake still active", func(t *testing.T) {
		// While the fold is in progress the flight must stay queued so it keeps
		// riding STUN; flushing early would be premature.
		for _, st := range []piggybackingState{
			PiggybackingStateTentative, PiggybackingStateConfirmed, PiggybackingStatePending,
		} {
			p := &piggybackingController{state: st, packets: newPending()}
			require.Nil(t, p.flushOnConnected(), "state %d must not flush", st)
			require.Len(t, p.packets, 1, "packets retained while active")
		}
	})
}

// TestSpedPiggybackCompleteSendsPlain verifies that once the fold is Complete,
// Piggyback behaves like Off: a late/retransmitted handshake packet is reported
// as not-consumed when connected (so the DTLS layer sends it as plain DTLS)
// rather than being appended to a queue that a Complete controller never drains
// (which would silently swallow it).
func TestSpedPiggybackCompleteSendsPlain(t *testing.T) {
	a := &Agent{log: logging.NewDefaultLoggerFactory().NewLogger("ice")}
	a.piggyback.state = PiggybackingStateComplete

	// Connected: not consumed -> DTLS layer sends it as plain DTLS.
	a.connectionState = ConnectionStateConnected
	require.False(t, a.Piggyback([]byte("late"), true))

	// Not connected: no writable path yet, report consumed (don't send).
	a.connectionState = ConnectionStateChecking
	require.True(t, a.Piggyback([]byte("late"), true))

	// A Complete controller must never accumulate swallowed packets.
	require.Empty(t, a.piggyback.packets)
}

// TestSpedDoneKeepsStrandedFlight covers the Done-before-connected ordering:
// when the remote signals completion (a STUN with no DTLS payload and no acks)
// while a local flight is still pending and no candidate pair is selected yet,
// the flight must be retained (not dropped) so flushOnConnected can send it as
// plain DTLS once the connection is established.
func TestSpedDoneKeepsStrandedFlight(t *testing.T) {
	a := &Agent{log: logging.NewDefaultLoggerFactory().NewLogger("ice")}
	a.piggyback.state = PiggybackingStatePending
	a.piggyback.acks = []uint32{1} // we have received DTLS, so "done" is valid
	a.piggyback.packets = []packetWithCrc{{data: []byte("flight")}}

	// Remote "done" STUN; no pair selected yet (getSelectedPair() == nil).
	a.ReportPiggybacking(nil, nil, &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})

	require.Equal(t, PiggybackingStateComplete, a.piggyback.state)
	require.Len(t, a.piggyback.packets, 1, "flight retained for flushOnConnected")

	// flushOnConnected then delivers it as plain DTLS on connect.
	got := a.piggyback.flushOnConnected()
	require.Len(t, got, 1)
	require.Equal(t, []byte("flight"), got[0].data)
}
