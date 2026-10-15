package main

// Streaming replay: evaluate EVERY block of a contiguous round range, carrying
// the chain's state forward locally instead of re-reading it per block.
//
// State is an overlay of the chain's own state deltas on top of cold reads at
// ONE round, base = start-1. A key the overlay does not hold has not been
// written by any block replayed since base (every block is replayed), so its
// value at base is its value now. Each block's delta comes from go-algorand's
// eval.Eval over the overlay (endOfBlock included), and every top-level
// ApplyData it computes is checked against the block's: on any disagreement
// the overlay is thrown away and the stream re-bases cold on that block.
//
// Blocks with groups that call a target app are additionally judged, before
// the delta is applied, exactly as `replay` judges one block: an `orig`
// variant and a `lifted` one with every program whose sha256 is in
// Lifted swapped for its replacement (and `lifted_xb` with extra budget where
// the plain lifted run ran out of budget).

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/algorand/go-algorand/config"
	"github.com/algorand/go-algorand/crypto"
	"github.com/algorand/go-algorand/data/basics"
	"github.com/algorand/go-algorand/data/bookkeeping"
	"github.com/algorand/go-algorand/data/transactions"
	"github.com/algorand/go-algorand/data/transactions/logic"
	"github.com/algorand/go-algorand/ledger/eval"
	"github.com/algorand/go-algorand/ledger/eval/prefetcher"
	"github.com/algorand/go-algorand/ledger/ledgercore"
	"github.com/algorand/go-algorand/protocol"
)

type StreamRequest struct {
	Node        string            `json:"node"`
	Start       uint64            `json:"start"`
	End         uint64            `json:"end"`
	Apps        []uint64          `json:"apps"`         // judge groups calling any of these (inner calls included)
	Lifted      map[string]string `json:"lifted"`       // sha256 hex of a deployed approval program -> b64 replacement
	ExtraBudget int               `json:"extra_budget"` // for lifted_xb
	Coverage    bool              `json:"coverage"`
	Prefetch    int               `json:"prefetch"` // blocks fetched + warmed ahead, and cold reads in flight per block (default 8)
	CacheDir    string            `json:"cache_dir"`
}

type StreamBlock struct {
	Round    uint64              `json:"round"`
	Groups   int                 `json:"groups"`
	Targets  map[string][]uint64 `json:"targets,omitempty"`  // judged group -> target apps it calls
	Unlifted map[string]string   `json:"unlifted,omitempty"` // target app -> b64 approval with no replacement
	Variants []VariantResult     `json:"variants,omitempty"`
	Upgraded bool                `json:"protocol_upgraded,omitempty"`
	ChainOK  bool                `json:"chain_ok"`
	Error    string              `json:"error,omitempty"`
	Rebased  bool                `json:"rebased,omitempty"` // state re-based cold on this block (after a chain miss)
	HTTP     int                 `json:"http_calls"`
	Millis   int64               `json:"ms"`
	Done     bool                `json:"done,omitempty"`
}

// ---------------------------------------------------------------- state

type creatableKey struct {
	idx   basics.CreatableIndex
	ctype basics.CreatableType
}

type found[T any] struct {
	v  T
	ok bool
}

type streamLedger struct {
	mu          sync.Mutex
	base        *remoteLedger // cold reads at base.prev
	prev        basics.Round  // the last applied block
	accts       map[basics.Address]ledgercore.AccountData
	appParams   map[ledgercore.AccountApp]found[basics.AppParams]
	appLocal    map[ledgercore.AccountApp]found[basics.AppLocalState]
	assetParams map[ledgercore.AccountAsset]found[basics.AssetParams]
	assetHold   map[ledgercore.AccountAsset]found[basics.AssetHolding]
	kv          map[string]found[[]byte]
	creators    map[creatableKey]found[basics.Address]
	hdrs        map[basics.Round]bookkeeping.BlockHeader
	totals      *ledgercore.AccountTotals
}

func newStreamLedger(rem *remote, base basics.Round) *streamLedger {
	return &streamLedger{
		base: &remoteLedger{r: rem, prev: base, hdrs: map[basics.Round]bookkeeping.BlockHeader{},
			unsupported: map[string]bool{}},
		prev:        base,
		accts:       map[basics.Address]ledgercore.AccountData{},
		appParams:   map[ledgercore.AccountApp]found[basics.AppParams]{},
		appLocal:    map[ledgercore.AccountApp]found[basics.AppLocalState]{},
		assetParams: map[ledgercore.AccountAsset]found[basics.AssetParams]{},
		assetHold:   map[ledgercore.AccountAsset]found[basics.AssetHolding]{},
		kv:          map[string]found[[]byte]{},
		creators:    map[creatableKey]found[basics.Address]{},
		hdrs:        map[basics.Round]bookkeeping.BlockHeader{},
	}
}

func (s *streamLedger) baseRound() basics.Round { return s.base.prev }

// apply commits one block's delta: from now on the overlay answers for every
// key it touched.
func (s *streamLedger) apply(d ledgercore.StateDelta) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, br := range d.Accts.Accts {
		s.accts[br.Addr] = br.AccountData
	}
	for _, r := range d.Accts.AppResources {
		k := ledgercore.AccountApp{Address: r.Addr, App: r.Aidx}
		if r.Params.Deleted {
			s.appParams[k] = found[basics.AppParams]{}
		} else if r.Params.Params != nil {
			s.appParams[k] = found[basics.AppParams]{r.Params.Params.Clone(), true}
		}
		if r.State.Deleted {
			s.appLocal[k] = found[basics.AppLocalState]{}
		} else if r.State.LocalState != nil {
			s.appLocal[k] = found[basics.AppLocalState]{cloneLocal(*r.State.LocalState), true}
		}
	}
	for _, r := range d.Accts.AssetResources {
		k := ledgercore.AccountAsset{Address: r.Addr, Asset: r.Aidx}
		if r.Params.Deleted {
			s.assetParams[k] = found[basics.AssetParams]{}
		} else if r.Params.Params != nil {
			s.assetParams[k] = found[basics.AssetParams]{*r.Params.Params, true}
		}
		if r.Holding.Deleted {
			s.assetHold[k] = found[basics.AssetHolding]{}
		} else if r.Holding.Holding != nil {
			s.assetHold[k] = found[basics.AssetHolding]{*r.Holding.Holding, true}
		}
	}
	for k, v := range d.KvMods {
		if v.Data == nil {
			s.kv[k] = found[[]byte]{}
		} else {
			s.kv[k] = found[[]byte]{append([]byte(nil), v.Data...), true}
		}
	}
	for idx, c := range d.Creatables {
		s.creators[creatableKey{idx, c.Ctype}] = found[basics.Address]{c.Creator, c.Created}
	}
	if d.Hdr != nil {
		s.hdrs[d.Hdr.Round] = *d.Hdr
		s.prev = d.Hdr.Round
	}
	t := d.Totals
	s.totals = &t
}

func cloneLocal(ls basics.AppLocalState) basics.AppLocalState {
	ls.KeyValue = ls.KeyValue.Clone()
	return ls
}

func (s *streamLedger) BlockHdr(rnd basics.Round) (bookkeeping.BlockHeader, error) {
	s.mu.Lock()
	h, ok := s.hdrs[rnd]
	s.mu.Unlock()
	if ok {
		return h, nil
	}
	return s.base.BlockHdr(rnd)
}

func (s *streamLedger) GenesisHash() crypto.Digest {
	h, err := s.BlockHdr(s.baseRound())
	if err != nil {
		panic(err)
	}
	return h.GenesisHash
}

func (s *streamLedger) GenesisProto() config.ConsensusParams {
	h, err := s.BlockHdr(0)
	if err != nil {
		panic(err)
	}
	return config.Consensus[h.CurrentProtocol]
}

func (s *streamLedger) CheckDup(config.ConsensusParams, basics.Round, basics.Round, basics.Round, transactions.Txid, ledgercore.Txlease) error {
	return nil
}

func (s *streamLedger) LookupWithoutRewards(_ basics.Round, addr basics.Address) (ledgercore.AccountData, basics.Round, error) {
	s.mu.Lock()
	ad, ok := s.accts[addr]
	prev := s.prev
	s.mu.Unlock()
	if ok {
		return ad, prev, nil
	}
	ad, _, err := s.base.LookupWithoutRewards(s.baseRound(), addr)
	if err != nil {
		return ad, prev, err
	}
	s.mu.Lock()
	if _, raced := s.accts[addr]; !raced {
		s.accts[addr] = ad
	}
	s.mu.Unlock()
	return ad, prev, nil
}

// Online data, circulation and knock-offline candidates come from the node at
// the asked round (the time-travel node serves any round); the evaluator only
// reads them for voter_params_get / online_stake and block-end bookkeeping.
func (s *streamLedger) LookupAgreement(rnd basics.Round, addr basics.Address) (basics.OnlineAccountData, error) {
	return s.base.LookupAgreement(rnd, addr)
}

func (s *streamLedger) GetKnockOfflineCandidates(basics.Round, config.ConsensusParams) (map[basics.Address]basics.OnlineAccountData, error) {
	return nil, nil
}

func (s *streamLedger) OnlineCirculation(rnd basics.Round, voteRnd basics.Round) (basics.MicroAlgos, error) {
	return s.base.OnlineCirculation(rnd, voteRnd)
}

func (s *streamLedger) LookupAsset(_ basics.Round, addr basics.Address, aidx basics.AssetIndex) (ledgercore.AssetResource, error) {
	k := ledgercore.AccountAsset{Address: addr, Asset: aidx}
	s.mu.Lock()
	p, pok := s.assetParams[k]
	h, hok := s.assetHold[k]
	s.mu.Unlock()
	if !pok || !hok {
		cold, err := s.base.LookupAsset(s.baseRound(), addr, aidx)
		if err != nil {
			return ledgercore.AssetResource{}, err
		}
		s.mu.Lock()
		if p2, ok := s.assetParams[k]; ok {
			p = p2
		} else {
			p = found[basics.AssetParams]{}
			if cold.AssetParams != nil {
				p = found[basics.AssetParams]{*cold.AssetParams, true}
			}
			s.assetParams[k] = p
		}
		if h2, ok := s.assetHold[k]; ok {
			h = h2
		} else {
			h = found[basics.AssetHolding]{}
			if cold.AssetHolding != nil {
				h = found[basics.AssetHolding]{*cold.AssetHolding, true}
			}
			s.assetHold[k] = h
		}
		s.mu.Unlock()
	}
	var res ledgercore.AssetResource
	if p.ok {
		v := p.v
		res.AssetParams = &v
	}
	if h.ok {
		v := h.v
		res.AssetHolding = &v
	}
	return res, nil
}

func (s *streamLedger) lookupApp(addr basics.Address, aidx basics.AppIndex) (ledgercore.AppResource, error) {
	k := ledgercore.AccountApp{Address: addr, App: aidx}
	s.mu.Lock()
	p, pok := s.appParams[k]
	l, lok := s.appLocal[k]
	s.mu.Unlock()
	if !pok || !lok {
		cold, err := s.base.LookupApplication(s.baseRound(), addr, aidx)
		if err != nil {
			return ledgercore.AppResource{}, err
		}
		s.mu.Lock()
		if p2, ok := s.appParams[k]; ok {
			p = p2
		} else {
			p = found[basics.AppParams]{}
			if cold.AppParams != nil {
				p = found[basics.AppParams]{*cold.AppParams, true}
			}
			s.appParams[k] = p
		}
		if l2, ok := s.appLocal[k]; ok {
			l = l2
		} else {
			l = found[basics.AppLocalState]{}
			if cold.AppLocalState != nil {
				l = found[basics.AppLocalState]{*cold.AppLocalState, true}
			}
			s.appLocal[k] = l
		}
		s.mu.Unlock()
	}
	var res ledgercore.AppResource
	if p.ok {
		v := p.v.Clone()
		res.AppParams = &v
	}
	if l.ok {
		v := cloneLocal(l.v)
		res.AppLocalState = &v
	}
	return res, nil
}

func (s *streamLedger) LookupApplication(_ basics.Round, addr basics.Address, aidx basics.AppIndex) (ledgercore.AppResource, error) {
	return s.lookupApp(addr, aidx)
}

func (s *streamLedger) LookupKv(_ basics.Round, key string) ([]byte, error) {
	s.mu.Lock()
	v, ok := s.kv[key]
	s.mu.Unlock()
	if !ok {
		cold, err := s.base.LookupKv(s.baseRound(), key)
		if err != nil {
			return nil, err
		}
		v = found[[]byte]{cold, cold != nil}
		s.mu.Lock()
		if v2, raced := s.kv[key]; raced {
			v = v2
		} else {
			s.kv[key] = v
		}
		s.mu.Unlock()
	}
	if !v.ok {
		return nil, nil
	}
	return append([]byte(nil), v.v...), nil
}

func (s *streamLedger) GetCreatorForRound(_ basics.Round, cidx basics.CreatableIndex, ctype basics.CreatableType) (basics.Address, bool, error) {
	k := creatableKey{cidx, ctype}
	s.mu.Lock()
	c, ok := s.creators[k]
	s.mu.Unlock()
	if ok {
		return c.v, c.ok, nil
	}
	addr, exists, err := s.base.GetCreatorForRound(s.baseRound(), cidx, ctype)
	if err != nil {
		return addr, exists, err
	}
	s.mu.Lock()
	if c2, raced := s.creators[k]; raced {
		addr, exists = c2.v, c2.ok
	} else {
		s.creators[k] = found[basics.Address]{addr, exists}
	}
	s.mu.Unlock()
	return addr, exists, nil
}

func (s *streamLedger) GetStateProofVerificationContext(basics.Round) (*ledgercore.StateProofVerificationContext, error) {
	return s.base.GetStateProofVerificationContext(0)
}

func (s *streamLedger) LatestTotals() (basics.Round, ledgercore.AccountTotals, error) {
	s.mu.Lock()
	t, prev := s.totals, s.prev
	s.mu.Unlock()
	if t != nil {
		return prev, *t, nil
	}
	// The REST view has no per-status totals, and CalculateTotals subtracts
	// every changed account from its category: start each category with a
	// buffer no block can exhaust. Totals feed no ApplyData (online_stake reads
	// OnlineCirculation), so the carried totals are bookkeeping only.
	// Reward units (whole Algos) stay well below 2^40; the rewards level
	// starts at the base header's, so rewards accrue only per replayed block.
	hdr, err := s.BlockHdr(prev)
	if err != nil {
		return prev, ledgercore.AccountTotals{}, err
	}
	tot := ledgercore.AccountTotals{RewardsLevel: hdr.RewardsLevel}
	for _, c := range []*ledgercore.AlgoCount{&tot.Online, &tot.Offline, &tot.NotParticipating} {
		c.Money.Raw, c.RewardUnits = 1<<62, 1<<40
	}
	return prev, tot, nil
}

func (s *streamLedger) VotersForStateProof(basics.Round) (*ledgercore.VotersForRound, error) {
	return nil, nil
}

func (s *streamLedger) FlushCaches() {}

func (s *streamLedger) unsupportedKeys() []string {
	return s.base.unsupportedKeys()
}

// streamView is the overlay seen through a variant's program swaps: any app
// whose approval program hashes to a key of swap runs the replacement.
type streamView struct {
	*streamLedger
	swap map[string][]byte
}

func progSha(p []byte) string {
	sum := sha256.Sum256(p)
	return hex.EncodeToString(sum[:])
}

func (v streamView) LookupApplication(rnd basics.Round, addr basics.Address, aidx basics.AppIndex) (ledgercore.AppResource, error) {
	res, err := v.streamLedger.lookupApp(addr, aidx)
	if err == nil && res.AppParams != nil {
		if r, ok := v.swap[progSha(res.AppParams.ApprovalProgram)]; ok {
			res.AppParams.ApprovalProgram = r
		}
	}
	return res, err
}

// ---------------------------------------------------------------- driver

// chainTracer collects every top-level ApplyData of a block in order, to check
// the state-carrying evaluation against the chain.
type chainTracer struct {
	logic.NullEvalTracer
	depth int
	ads   []transactions.ApplyData
	errs  []string
}

func (t *chainTracer) BeforeTxnGroup(*logic.EvalParams) { t.depth++ }
func (t *chainTracer) AfterTxnGroup(*logic.EvalParams, *ledgercore.StateDelta, error) {
	t.depth--
}
func (t *chainTracer) AfterTxn(_ *logic.EvalParams, _ int, ad transactions.ApplyData, err error) {
	if t.depth == 1 {
		t.ads = append(t.ads, ad)
		if err != nil {
			t.errs = append(t.errs, err.Error())
		}
	}
}

// appsCalled lists the target apps a transaction calls, inner calls included.
func appsCalled(txn transactions.Transaction, ad transactions.ApplyData, apps map[basics.AppIndex]bool, into map[uint64]bool) {
	if txn.Type == protocol.ApplicationCallTx {
		for _, a := range []basics.AppIndex{txn.ApplicationID, ad.ApplicationID} {
			if apps[a] {
				into[uint64(a)] = true
			}
		}
	}
	for _, inner := range ad.EvalDelta.InnerTxns {
		appsCalled(inner.Txn, inner.ApplyData, apps, into)
	}
}

type fetched struct {
	round uint64
	blk   bookkeeping.Block
	err   error
}

func fetchBlock(rem *remote, rnd uint64) (bookkeeping.Block, error) {
	status, body, err := rem.get(fmt.Sprintf("/v2/blocks/%d?format=msgpack", rnd))
	if err != nil || status != 200 {
		return bookkeeping.Block{}, fmt.Errorf("fetch block %d: status %d err %v", rnd, status, err)
	}
	var wrapped struct {
		_struct struct{}          `codec:""`
		Block   bookkeeping.Block `codec:"block"`
		Cert    interface{}       `codec:"cert"`
	}
	if err := protocol.DecodeReflect(body, &wrapped); err != nil {
		return bookkeeping.Block{}, fmt.Errorf("decode block %d: %w", rnd, err)
	}
	return wrapped.Block, nil
}

// prefetchBlocks fetches [start, end] in order with up to n blocks in flight,
// running warm on each before handing it over: the next n blocks' state loads
// while the current one is evaluated.
func prefetchBlocks(rem *remote, start, end uint64, n int, warm func(bookkeeping.Block)) <-chan fetched {
	out := make(chan fetched, n)
	go func() {
		defer close(out)
		slots := make(chan chan fetched, n)
		go func() {
			defer close(slots)
			for r := start; r <= end; r++ {
				ch := make(chan fetched, 1)
				slots <- ch
				go func(r uint64) {
					blk, err := fetchBlock(rem, r)
					if err == nil && warm != nil {
						warm(blk)
					}
					ch <- fetched{r, blk, err}
				}(r)
			}
		}()
		for ch := range slots {
			out <- <-ch
		}
	}()
	return out
}

// holder is the current overlay, swapped on a re-base; warmers read it.
type holder struct {
	mu sync.Mutex
	sl *streamLedger
}

func (h *holder) get() *streamLedger {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.sl
}

func (h *holder) set(sl *streamLedger) {
	h.mu.Lock()
	h.sl = sl
	h.mu.Unlock()
}

// warmBlock loads, into the overlay, the state a block will read: what
// go-algorand's prefetcher derives from the transactions, plus what the
// chain's recorded inner transactions touch. A cold value never overwrites an
// applied one, so warming ahead of evaluation is safe.
func warmBlock(sl *streamLedger, blk bookkeeping.Block, par int) {
	defer func() { recover() }()
	groups, err := blk.DecodePaysetGroups()
	if err != nil {
		return
	}
	proto, ok := config.Consensus[blk.CurrentProtocol]
	if !ok {
		return
	}
	v := streamView{sl, nil}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	for range prefetcher.BlockReferences(ctx, v, blk.Round()-1, groups, blk.FeeSink, proto) {
	}
	sem := make(chan struct{}, par)
	var wg sync.WaitGroup
	do := func(f func()) {
		wg.Add(1)
		sem <- struct{}{}
		go func() {
			defer func() { <-sem; wg.Done(); recover() }()
			f()
		}()
	}
	seen := map[string]bool{}
	once := func(key string) bool {
		if seen[key] {
			return false
		}
		seen[key] = true
		return true
	}
	var walk func(t transactions.Transaction, ad transactions.ApplyData, inner bool)
	walk = func(t transactions.Transaction, ad transactions.ApplyData, inner bool) {
		if inner {
			for _, a := range []basics.Address{t.Sender, t.Receiver, t.CloseRemainderTo, t.AssetReceiver, t.AssetCloseTo, t.AssetSender} {
				if !a.IsZero() && once("a"+a.String()) {
					a := a
					do(func() { sl.LookupWithoutRewards(0, a) })
				}
			}
			if t.Type == protocol.AssetTransferTx {
				for _, a := range []basics.Address{t.Sender, t.AssetReceiver, t.AssetCloseTo, t.AssetSender} {
					if !a.IsZero() && once(fmt.Sprint("h", a, t.XferAsset)) {
						a, x := a, t.XferAsset
						do(func() { sl.LookupAsset(0, a, x) })
					}
				}
			}
			if t.Type == protocol.ApplicationCallTx && t.ApplicationID != 0 && once(fmt.Sprint("p", t.ApplicationID, t.Sender)) {
				app, sender := t.ApplicationID, t.Sender
				do(func() {
					if c, ok, err := sl.GetCreatorForRound(0, basics.CreatableIndex(app), basics.AppCreatable); err == nil && ok {
						sl.lookupApp(c, app)
					}
					sl.lookupApp(sender, app)
				})
			}
		}
		for _, in := range ad.EvalDelta.InnerTxns {
			walk(in.Txn, in.ApplyData, true)
		}
	}
	for _, g := range groups {
		for _, t := range g {
			walk(t.Txn, t.ApplyData, false)
		}
	}
	wg.Wait()
}

func adEqual(a, b transactions.ApplyData) bool { return a.Equal(b) }

func stream(req StreamRequest, enc *json.Encoder) {
	if req.Prefetch <= 0 {
		req.Prefetch = 8
	}
	// Blocks are not cached (a window is tens of GB); cold state reads are
	// remembered decoded in the overlay, so only headers stay in memory here.
	rem := &remote{base: strings.TrimRight(req.Node, "/"), client: &http.Client{Timeout: 60 * time.Second},
		cache: map[string]cached{}, cacheDir: req.CacheDir, noMem: true}
	swap := map[string][]byte{}
	for h, b := range req.Lifted {
		r, err := base64.StdEncoding.DecodeString(b)
		if err != nil {
			enc.Encode(StreamBlock{Error: fmt.Sprintf("lifted %s: %v", h, err), Done: true})
			return
		}
		swap[h] = r
	}
	apps := map[basics.AppIndex]bool{}
	for _, a := range req.Apps {
		apps[basics.AppIndex(a)] = true
	}
	cur := &holder{sl: newStreamLedger(rem, basics.Round(req.Start-1))}
	sl := cur.get()
	rebase := false
	warm := func(blk bookkeeping.Block) { warmBlock(cur.get(), blk, req.Prefetch) }
	for f := range prefetchBlocks(rem, req.Start, req.End, req.Prefetch, warm) {
		t0 := time.Now()
		calls0 := rem.callCount()
		out := StreamBlock{Round: f.round}
		if f.err != nil {
			out.Error = f.err.Error()
			enc.Encode(out)
			rebase = true
			continue
		}
		if rebase {
			sl = newStreamLedger(rem, basics.Round(f.round-1))
			cur.set(sl)
			rebase = false
		}
		out.Rebased = sl.prev == sl.baseRound() // a fresh overlay: every read is cold
		blk := f.blk
		groups, err := blk.DecodePaysetGroups()
		if err != nil {
			out.Error = "decode payset: " + err.Error()
			enc.Encode(out)
			rebase = true
			continue
		}
		out.Groups = len(groups)
		if debugFetch {
			fmt.Fprintln(os.Stderr, "eval-start", time.Now().UnixMilli(), f.round)
		}
		judgeBlock(sl, blk, groups, apps, swap, req, &out)

		// Advance: the chain's own evaluation of the block, checked against it.
		tr := &chainTracer{}
		delta, err := eval.Eval(context.Background(), streamView{sl, nil}, blk, false, nil, nil, tr)
		var chain []transactions.ApplyData
		for _, g := range groups {
			for _, t := range g {
				chain = append(chain, t.ApplyData)
			}
		}
		switch {
		case err != nil:
			out.Error = "advance: " + err.Error()
		case len(tr.ads) != len(chain):
			out.Error = fmt.Sprintf("advance: %d top-level txns evaluated, block has %d", len(tr.ads), len(chain))
		default:
			out.ChainOK = true
			for i := range chain {
				if !adEqual(tr.ads[i], chain[i]) {
					out.ChainOK = false
					out.Error = fmt.Sprintf("advance: txn %d ApplyData differs from the chain", i)
					break
				}
			}
		}
		if out.ChainOK {
			sl.apply(delta)
		} else {
			rebase = true // re-base cold on the next block
		}
		if debugFetch {
			fmt.Fprintln(os.Stderr, "eval-end", time.Now().UnixMilli(), f.round)
		}
		out.HTTP = rem.callCount() - calls0
		out.Millis = time.Since(t0).Milliseconds()
		enc.Encode(out)
	}
	enc.Encode(StreamBlock{Done: true, HTTP: rem.callCount()})
}

// judgeBlock runs the orig / lifted (/ lifted_xb) variants over the overlay at
// the block's predecessor, for the groups that call a target app.
func judgeBlock(sl *streamLedger, blk bookkeeping.Block, groups [][]transactions.SignedTxnWithAD,
	apps map[basics.AppIndex]bool, swap map[string][]byte, req StreamRequest, out *StreamBlock) {
	want := map[int]bool{}
	involved := map[uint64]bool{}
	for gi, g := range groups {
		called := map[uint64]bool{}
		for _, t := range g {
			appsCalled(t.Txn, t.ApplyData, apps, called)
		}
		if len(called) == 0 {
			continue
		}
		want[gi] = true
		if out.Targets == nil {
			out.Targets = map[string][]uint64{}
		}
		ids := make([]uint64, 0, len(called))
		for a := range called {
			ids = append(ids, a)
			involved[a] = true
		}
		sort.Slice(ids, func(i, j int) bool { return ids[i] < ids[j] })
		out.Targets[fmt.Sprint(gi)] = ids
	}
	if len(want) == 0 {
		return
	}
	// Programs as of the block's start; an app created in this block has none yet.
	for a := range involved {
		creator, ok, err := sl.GetCreatorForRound(sl.prev, basics.CreatableIndex(a), basics.AppCreatable)
		if err != nil || !ok {
			continue
		}
		res, err := sl.lookupApp(creator, basics.AppIndex(a))
		if err != nil || res.AppParams == nil {
			continue
		}
		if _, ok := swap[progSha(res.AppParams.ApprovalProgram)]; !ok {
			if out.Unlifted == nil {
				out.Unlifted = map[string]string{}
			}
			out.Unlifted[fmt.Sprint(a)] = base64.StdEncoding.EncodeToString(res.AppParams.ApprovalProgram)
		}
	}
	run := func(b bookkeeping.Block) []VariantResult {
		vs := []VariantResult{
			evaluate(streamView{sl, nil}, b, groups, want, true, req.Coverage, Variant{Name: "orig"}),
			evaluate(streamView{sl, swap}, b, groups, want, true, req.Coverage, Variant{Name: "lifted"}),
		}
		if anyGroupError(vs[1], "budget exceeded") {
			vs = append(vs, evaluate(streamView{sl, swap}, b, groups, want, true, req.Coverage,
				Variant{Name: "lifted_xb", ExtraBudget: req.ExtraBudget}))
		}
		return vs
	}
	out.Variants = run(blk)
	if anyGroupError(out.Variants[1], "greater than protocol supported version") {
		up := blk
		up.BlockHeader.CurrentProtocol = protocol.ConsensusCurrentVersion
		out.Variants = run(up)
		out.Upgraded = true
	}
}

func anyGroupError(v VariantResult, marker string) bool {
	for _, g := range v.Groups {
		if strings.Contains(g.Error, marker) {
			return true
		}
		for _, t := range g.Txns {
			if strings.Contains(t.Error, marker) {
				return true
			}
		}
	}
	return false
}
