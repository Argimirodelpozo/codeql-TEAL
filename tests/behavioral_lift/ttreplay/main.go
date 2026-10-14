// ttreplay re-evaluates historical mainnet blocks with go-algorand's own block
// evaluator, reading ledger state lazily from a time-travel algod
// (d13co/go-algorand@timetravel) at the round before the block, and lets the
// caller swap any app's programs. It is the oracle for the lift's behavioural
// gate: replay with the deployed program must reproduce the chain's ApplyData
// (proves the remote ledger is faithful), then replay with the lift-recompiled
// program and compare.
//
// Built inside a go-algorand checkout (see build.sh); not part of the Python
// package. Commands:
//
//	ttreplay asm      < prog.teal     -> {"program": b64} | {"error": ...}
//	ttreplay disasm   < b64           -> TEAL text
//	ttreplay replay   < request.json  -> response JSON (see Request/Response)
package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/algorand/avm-abi/apps"
	"github.com/algorand/go-algorand/config"
	"github.com/algorand/go-algorand/crypto"
	v2 "github.com/algorand/go-algorand/daemon/algod/api/server/v2"
	"github.com/algorand/go-algorand/daemon/algod/api/server/v2/generated/model"
	"github.com/algorand/go-algorand/data/basics"
	"github.com/algorand/go-algorand/data/bookkeeping"
	"github.com/algorand/go-algorand/data/transactions"
	"github.com/algorand/go-algorand/data/transactions/logic"
	"github.com/algorand/go-algorand/ledger/eval"
	"github.com/algorand/go-algorand/ledger/eval/prefetcher"
	"github.com/algorand/go-algorand/ledger/ledgercore"
	"github.com/algorand/go-algorand/protocol"
)

// ---------------------------------------------------------------- HTTP

type remote struct {
	base     string
	client   *http.Client
	mu       sync.Mutex
	cache    map[string]cached
	calls    int
	cacheDir string // optional on-disk cache; every query names a round, so answers never change
}

func (r *remote) diskPath(path string) string {
	if r.cacheDir == "" || !strings.Contains(path, "round=") && !strings.HasPrefix(path, "/v2/blocks/") {
		return ""
	}
	sum := sha256.Sum256([]byte(r.base + path))
	name := hex.EncodeToString(sum[:])
	return filepath.Join(r.cacheDir, name[:2], name)
}

type cached struct {
	status int
	body   []byte
}

// get returns (status, body). 404 is a normal answer (absent object); other
// non-2xx statuses are retried with backoff, then reported as errors.
func (r *remote) get(path string) (int, []byte, error) {
	r.mu.Lock()
	if c, ok := r.cache[path]; ok {
		r.mu.Unlock()
		return c.status, c.body, nil
	}
	r.mu.Unlock()
	disk := r.diskPath(path)
	if disk != "" {
		if raw, err := os.ReadFile(disk); err == nil && len(raw) >= 2 {
			c := cached{status: int(raw[0])<<8 | int(raw[1]), body: raw[2:]}
			r.mu.Lock()
			r.cache[path] = c
			r.mu.Unlock()
			return c.status, c.body, nil
		}
	}
	var lastErr error
	for attempt := 0; attempt < 6; attempt++ {
		if attempt > 0 {
			time.Sleep(time.Duration(1<<attempt) * 250 * time.Millisecond)
		}
		req, _ := http.NewRequest("GET", r.base+path, nil)
		req.Header.Set("User-Agent", "tealql-ttreplay")
		resp, err := r.client.Do(req)
		if err != nil {
			lastErr = err
			continue
		}
		body, err := io.ReadAll(resp.Body)
		resp.Body.Close()
		if err != nil {
			lastErr = err
			continue
		}
		r.mu.Lock()
		r.calls++
		r.mu.Unlock()
		if resp.StatusCode == 200 || resp.StatusCode == 404 {
			r.mu.Lock()
			r.cache[path] = cached{resp.StatusCode, body}
			r.mu.Unlock()
			if disk != "" {
				os.MkdirAll(filepath.Dir(disk), 0o755)
				tmp := disk + ".tmp" + fmt.Sprint(time.Now().UnixNano())
				if os.WriteFile(tmp, append([]byte{byte(resp.StatusCode >> 8), byte(resp.StatusCode)}, body...), 0o644) == nil {
					os.Rename(tmp, disk)
				}
			}
			return resp.StatusCode, body, nil
		}
		lastErr = fmt.Errorf("GET %s: HTTP %d: %s", path, resp.StatusCode, truncate(string(body), 300))
		if resp.StatusCode < 500 && resp.StatusCode != 429 {
			break
		}
	}
	return 0, nil, lastErr
}

func (r *remote) getJSON(path string, out interface{}) (bool, error) {
	status, body, err := r.get(path)
	if err != nil {
		return false, err
	}
	if status == 404 {
		return false, nil
	}
	return true, json.Unmarshal(body, out)
}

func truncate(s string, n int) string {
	if len(s) > n {
		return s[:n] + "..."
	}
	return s
}

// ---------------------------------------------------------------- ledger

type programs struct {
	Approval []byte
	Clear    []byte
}

// remoteLedger answers eval.LedgerForEvaluator from a time-travel node's REST
// API. Every lookup round is the block's predecessor (the evaluator asks for
// prevHeader.Round), which the node serves from its history.
type remoteLedger struct {
	r         *remote
	prev      basics.Round
	overrides map[basics.AppIndex]programs
	hdrs      map[basics.Round]bookkeeping.BlockHeader
	genesis   *bookkeeping.BlockHeader
	// unsupported records lookups this ledger can only approximate; a run that
	// touched one is reported so its verdict is not trusted blindly.
	unsupported map[string]bool
}

func (l *remoteLedger) note(what string) { l.unsupported[what] = true }

func (l *remoteLedger) BlockHdr(rnd basics.Round) (bookkeeping.BlockHeader, error) {
	if h, ok := l.hdrs[rnd]; ok {
		return h, nil
	}
	status, body, err := l.r.get(fmt.Sprintf("/v2/blocks/%d?header-only=true&format=msgpack", rnd))
	if err != nil {
		return bookkeeping.BlockHeader{}, err
	}
	if status == 404 {
		return bookkeeping.BlockHeader{}, fmt.Errorf("block header %d not found", rnd)
	}
	var wrapped struct {
		_struct struct{}              `codec:""`
		Block   bookkeeping.BlockHeader `codec:"block"`
		Cert    interface{}             `codec:"cert"`
	}
	if err := protocol.DecodeReflect(body, &wrapped); err != nil {
		return bookkeeping.BlockHeader{}, fmt.Errorf("decode header %d: %w", rnd, err)
	}
	l.hdrs[rnd] = wrapped.Block
	return wrapped.Block, nil
}

func (l *remoteLedger) genesisHdr() bookkeeping.BlockHeader {
	if l.genesis == nil {
		h, err := l.BlockHdr(0)
		if err != nil {
			panic(err)
		}
		l.genesis = &h
	}
	return *l.genesis
}

func (l *remoteLedger) GenesisHash() crypto.Digest {
	h, err := l.BlockHdr(l.prev)
	if err != nil {
		panic(err)
	}
	return h.GenesisHash
}

func (l *remoteLedger) GenesisProto() config.ConsensusParams {
	return config.Consensus[l.genesisHdr().CurrentProtocol]
}

func (l *remoteLedger) CheckDup(config.ConsensusParams, basics.Round, basics.Round, basics.Round, transactions.Txid, ledgercore.Txlease) error {
	return nil // the block was certified: no duplicates by construction
}

func (l *remoteLedger) account(rnd basics.Round, addr basics.Address) (model.Account, error) {
	var a model.Account
	ok, err := l.r.getJSON(fmt.Sprintf("/v2/accounts/%s?round=%d&exclude=all", addr, rnd), &a)
	if err != nil {
		return a, err
	}
	if !ok {
		return model.Account{}, nil
	}
	return a, nil
}

func addrOf(s *string) basics.Address {
	if s == nil || *s == "" {
		return basics.Address{}
	}
	a, err := basics.UnmarshalChecksumAddress(*s)
	if err != nil {
		panic(fmt.Sprintf("bad address %q: %v", *s, err))
	}
	return a
}

func (l *remoteLedger) LookupWithoutRewards(rnd basics.Round, addr basics.Address) (ledgercore.AccountData, basics.Round, error) {
	a, err := l.account(rnd, addr)
	if err != nil {
		return ledgercore.AccountData{}, rnd, err
	}
	var ad ledgercore.AccountData
	switch a.Status {
	case "Online":
		ad.Status = basics.Online
	case "NotParticipating":
		ad.Status = basics.NotParticipating
	default:
		ad.Status = basics.Offline
	}
	// The REST view applies pending rewards: amount and reward-base are
	// advanced to round rnd's rewards level, amount-without-pending-rewards is
	// the stored balance. The evaluator needs the STORED record (it credits the
	// pending rewards itself, into ApplyData's ss/rs/rc), so undo the
	// advance: pending = (level - base) * units, units = stored / RewardUnit.
	ad.MicroAlgos = basics.MicroAlgos{Raw: a.AmountWithoutPendingRewards}
	if a.RewardBase != nil {
		ad.RewardsBase = *a.RewardBase
	}
	ad.RewardedMicroAlgos = basics.MicroAlgos{Raw: a.Rewards - a.PendingRewards}
	if a.PendingRewards > 0 {
		hdr, err := l.BlockHdr(rnd)
		if err != nil {
			return ledgercore.AccountData{}, rnd, err
		}
		units := a.AmountWithoutPendingRewards / config.Consensus[hdr.CurrentProtocol].RewardUnit
		if units == 0 || a.PendingRewards%units != 0 {
			return ledgercore.AccountData{}, rnd, fmt.Errorf(
				"account %s: pending rewards %d not a multiple of %d reward units", addr, a.PendingRewards, units)
		}
		ad.RewardsBase = hdr.RewardsLevel - a.PendingRewards/units
	}
	ad.AuthAddr = addrOf(a.AuthAddr)
	if a.IncentiveEligible != nil {
		ad.IncentiveEligible = *a.IncentiveEligible
	}
	if a.AppsTotalSchema != nil {
		ad.TotalAppSchema = basics.StateSchema{NumUint: a.AppsTotalSchema.NumUint, NumByteSlice: a.AppsTotalSchema.NumByteSlice}
	}
	if a.AppsTotalExtraPages != nil {
		ad.TotalExtraAppPages = uint32(*a.AppsTotalExtraPages)
	}
	ad.TotalAppParams = a.TotalCreatedApps
	ad.TotalAppLocalStates = a.TotalAppsOptedIn
	ad.TotalAssetParams = a.TotalCreatedAssets
	ad.TotalAssets = a.TotalAssetsOptedIn
	if a.TotalBoxes != nil {
		ad.TotalBoxes = *a.TotalBoxes
	}
	if a.TotalBoxBytes != nil {
		ad.TotalBoxBytes = *a.TotalBoxBytes
	}
	if a.LastProposed != nil {
		ad.LastProposed = *a.LastProposed
	}
	if a.LastHeartbeat != nil {
		ad.LastHeartbeat = *a.LastHeartbeat
	}
	if p := a.Participation; p != nil {
		copy(ad.VoteID[:], p.VoteParticipationKey)
		copy(ad.SelectionID[:], p.SelectionParticipationKey)
		if p.StateProofKey != nil {
			copy(ad.StateProofID[:], *p.StateProofKey)
		}
		ad.VoteFirstValid = basics.Round(p.VoteFirstValid)
		ad.VoteLastValid = basics.Round(p.VoteLastValid)
		ad.VoteKeyDilution = p.VoteKeyDilution
	}
	return ad, rnd, nil
}

func (l *remoteLedger) LookupAgreement(rnd basics.Round, addr basics.Address) (basics.OnlineAccountData, error) {
	l.note("online account data (online_stake / voter_params_get)")
	ad, _, err := l.LookupWithoutRewards(rnd, addr)
	if err != nil || ad.Status != basics.Online {
		return basics.OnlineAccountData{}, err
	}
	return basics.OnlineAccountData{MicroAlgosWithRewards: ad.MicroAlgos, VotingData: ad.VotingData}, nil
}

func (l *remoteLedger) GetKnockOfflineCandidates(basics.Round, config.ConsensusParams) (map[basics.Address]basics.OnlineAccountData, error) {
	return nil, nil
}

func assetParams(p *model.AssetParams) *basics.AssetParams {
	ap := &basics.AssetParams{
		Total:    p.Total,
		Decimals: uint32(p.Decimals),
		Manager:  addrOf(p.Manager),
		Reserve:  addrOf(p.Reserve),
		Freeze:   addrOf(p.Freeze),
		Clawback: addrOf(p.Clawback),
	}
	if p.DefaultFrozen != nil {
		ap.DefaultFrozen = *p.DefaultFrozen
	}
	if p.UnitNameB64 != nil {
		ap.UnitName = string(*p.UnitNameB64)
	} else if p.UnitName != nil {
		ap.UnitName = *p.UnitName
	}
	if p.NameB64 != nil {
		ap.AssetName = string(*p.NameB64)
	} else if p.Name != nil {
		ap.AssetName = *p.Name
	}
	if p.UrlB64 != nil {
		ap.URL = string(*p.UrlB64)
	} else if p.Url != nil {
		ap.URL = *p.Url
	}
	if p.MetadataHash != nil {
		copy(ap.MetadataHash[:], *p.MetadataHash)
	}
	return ap
}

func (l *remoteLedger) LookupAsset(rnd basics.Round, addr basics.Address, aidx basics.AssetIndex) (ledgercore.AssetResource, error) {
	var resp model.AccountAssetResponse
	ok, err := l.r.getJSON(fmt.Sprintf("/v2/accounts/%s/assets/%d?round=%d", addr, aidx, rnd), &resp)
	if err != nil || !ok {
		return ledgercore.AssetResource{}, err
	}
	var res ledgercore.AssetResource
	if h := resp.AssetHolding; h != nil {
		res.AssetHolding = &basics.AssetHolding{Amount: h.Amount, Frozen: h.IsFrozen}
	}
	if p := resp.CreatedAsset; p != nil {
		res.AssetParams = assetParams(p)
	}
	return res, nil
}

func tkv(store *model.TealKeyValueStore) (basics.TealKeyValue, error) {
	if store == nil || len(*store) == 0 {
		return nil, nil
	}
	out := make(basics.TealKeyValue, len(*store))
	for _, kv := range *store {
		k, err := base64.StdEncoding.DecodeString(kv.Key)
		if err != nil {
			return nil, err
		}
		b, err := base64.StdEncoding.DecodeString(kv.Value.Bytes)
		if err != nil {
			return nil, err
		}
		out[string(k)] = basics.TealValue{Type: basics.TealType(kv.Value.Type), Uint: kv.Value.Uint, Bytes: string(b)}
	}
	return out, nil
}

func (l *remoteLedger) appParams(aidx basics.AppIndex, p *model.ApplicationParams) (*basics.AppParams, error) {
	ap, err := v2.ApplicationParamsToAppParams(p)
	if err != nil {
		return nil, err
	}
	if o, ok := l.overrides[aidx]; ok {
		if o.Approval != nil {
			ap.ApprovalProgram = o.Approval
		}
		if o.Clear != nil {
			ap.ClearStateProgram = o.Clear
		}
	}
	return &ap, nil
}

func (l *remoteLedger) LookupApplication(rnd basics.Round, addr basics.Address, aidx basics.AppIndex) (ledgercore.AppResource, error) {
	var resp model.AccountApplicationResponse
	ok, err := l.r.getJSON(fmt.Sprintf("/v2/accounts/%s/applications/%d?round=%d", addr, aidx, rnd), &resp)
	if err != nil || !ok {
		return ledgercore.AppResource{}, err
	}
	var res ledgercore.AppResource
	if s := resp.AppLocalState; s != nil {
		kv, err := tkv(s.KeyValue)
		if err != nil {
			return res, err
		}
		res.AppLocalState = &basics.AppLocalState{
			Schema:   basics.StateSchema{NumUint: s.Schema.NumUint, NumByteSlice: s.Schema.NumByteSlice},
			KeyValue: kv,
		}
	}
	if p := resp.CreatedApp; p != nil {
		if res.AppParams, err = l.appParams(aidx, p); err != nil {
			return res, err
		}
	}
	return res, nil
}

func (l *remoteLedger) LookupKv(rnd basics.Round, key string) ([]byte, error) {
	app, name, err := apps.SplitBoxKey(key)
	if err != nil {
		return nil, err
	}
	var box model.Box
	q := url.QueryEscape("b64:" + base64.StdEncoding.EncodeToString([]byte(name)))
	ok, err := l.r.getJSON(fmt.Sprintf("/v2/applications/%d/box?name=%s&round=%d", app, q, rnd), &box)
	if err != nil || !ok {
		return nil, err
	}
	return box.Value, nil
}

func (l *remoteLedger) GetCreatorForRound(rnd basics.Round, cidx basics.CreatableIndex, ctype basics.CreatableType) (basics.Address, bool, error) {
	switch ctype {
	case basics.AppCreatable:
		var app model.Application
		ok, err := l.r.getJSON(fmt.Sprintf("/v2/applications/%d?round=%d", cidx, rnd), &app)
		if err != nil || !ok || app.Params == nil {
			return basics.Address{}, false, err
		}
		return addrOf(&app.Params.Creator), true, nil
	case basics.AssetCreatable:
		var asset model.Asset
		ok, err := l.r.getJSON(fmt.Sprintf("/v2/assets/%d?round=%d", cidx, rnd), &asset)
		if err != nil || !ok || asset.Params == nil {
			return basics.Address{}, false, err
		}
		return addrOf(&asset.Params.Creator), true, nil
	}
	return basics.Address{}, false, fmt.Errorf("unknown creatable type %v", ctype)
}

func (l *remoteLedger) GetStateProofVerificationContext(basics.Round) (*ledgercore.StateProofVerificationContext, error) {
	l.note("state proof verification context")
	return nil, errors.New("ttreplay: state proofs are not supported")
}

func (l *remoteLedger) supply(rnd basics.Round) (model.SupplyResponse, error) {
	var s model.SupplyResponse
	ok, err := l.r.getJSON(fmt.Sprintf("/v2/ledger/supply?round=%d", rnd), &s)
	if err == nil && !ok {
		err = fmt.Errorf("supply at round %d not recorded", rnd)
	}
	return s, err
}

func (l *remoteLedger) OnlineCirculation(rnd basics.Round, voteRnd basics.Round) (basics.MicroAlgos, error) {
	l.note("online circulation (online_stake)")
	s, err := l.supply(rnd)
	return basics.MicroAlgos{Raw: s.OnlineMoney}, err
}

func (l *remoteLedger) LatestTotals() (basics.Round, ledgercore.AccountTotals, error) {
	// Only the cow's running totals use this; with Validate and Generate off
	// the evaluator takes the block header's rewards state as given.
	s, err := l.supply(l.prev)
	if err != nil {
		return l.prev, ledgercore.AccountTotals{}, nil
	}
	var t ledgercore.AccountTotals
	t.Online.Money = basics.MicroAlgos{Raw: s.OnlineMoney}
	t.Offline.Money = basics.MicroAlgos{Raw: s.TotalMoney - s.OnlineMoney}
	return l.prev, t, nil
}

func (l *remoteLedger) VotersForStateProof(basics.Round) (*ledgercore.VotersForRound, error) {
	return nil, nil
}

func (l *remoteLedger) FlushCaches() {}

// ---------------------------------------------------------------- tracer

// tracer records, per top-level transaction, the computed ApplyData and error,
// the top-level group's state delta (box writes are not in ApplyData), and the
// program counters each app executed (coverage).
type tracer struct {
	logic.NullEvalTracer
	depth    int
	ads      map[int]transactions.ApplyData
	errs     map[int]string
	kvMods   map[string]ledgercore.KvValueDelta
	groupErr string
	coverage map[basics.AppIndex]map[int]bool
	ops      map[basics.AppIndex]int // opcodes executed per app
	extra    int                     // opcode budget added to each top-level group's pool
	// Pooled app budget accounting, as simulate's AppBudgetAdded/Consumed:
	// the pool at the top-level group's start (+extra), plus one
	// MaxAppProgramCost per inner group, minus what is left at the end.
	budgetAdded    int
	budgetConsumed int
}

func newTracer() *tracer {
	return &tracer{ads: map[int]transactions.ApplyData{}, errs: map[int]string{},
		coverage: map[basics.AppIndex]map[int]bool{}, ops: map[basics.AppIndex]int{}}
}

// BeforeTxnGroup adds the variant's extra budget to the top-level group's pool,
// as simulate's extra-opcode-budget does (inner groups draw from that pool).
func (t *tracer) BeforeTxnGroup(ep *logic.EvalParams) {
	t.depth++
	if ep.GetCaller() != nil {
		t.budgetAdded += ep.Proto.MaxAppProgramCost
	}
	if t.depth == 1 && ep.PooledApplicationBudget != nil {
		*ep.PooledApplicationBudget += t.extra
		t.budgetAdded += *ep.PooledApplicationBudget
	}
}

func (t *tracer) AfterTxnGroup(ep *logic.EvalParams, deltas *ledgercore.StateDelta, evalError error) {
	if t.depth == 1 {
		if ep.PooledApplicationBudget != nil {
			t.budgetConsumed = t.budgetAdded - *ep.PooledApplicationBudget
		}
		if deltas != nil {
			t.kvMods = deltas.KvMods
		}
		if evalError != nil {
			t.groupErr = evalError.Error()
		}
	}
	t.depth--
}

func (t *tracer) AfterTxn(ep *logic.EvalParams, gi int, ad transactions.ApplyData, evalError error) {
	if t.depth != 1 {
		return
	}
	t.ads[gi] = ad
	if evalError != nil {
		t.errs[gi] = evalError.Error()
	}
}

func (t *tracer) BeforeOpcode(cx *logic.EvalContext) {
	if cx.RunMode() != logic.ModeApp {
		return
	}
	app := cx.AppID()
	t.ops[app]++
	m := t.coverage[app]
	if m == nil {
		m = map[int]bool{}
		t.coverage[app] = m
	}
	m[cx.PC()] = true
}

// ---------------------------------------------------------------- replay

// Request selects a block and which of its groups to report. Every group before
// the last reported one is evaluated too (when Prefix is set), so the reported
// groups see exactly the state they saw on chain. Each Variant re-evaluates the
// block with its own program overrides; variants share one HTTP cache, since
// they all read the same round.
type Request struct {
	Node     string    `json:"node"`
	Round    uint64    `json:"round"`
	Apps     []uint64  `json:"apps"`   // report groups that call any of these (inner calls included)
	Groups   []int     `json:"groups"` // or explicit group indices in the block
	Prefix   bool      `json:"prefix"`
	Coverage bool      `json:"coverage"`
	Variants []Variant `json:"variants"` // default: one variant, no overrides
	CacheDir string    `json:"cache_dir"`
	// Protocol, when set, evaluates the block under this consensus version
	// instead of the block's own (e.g. mainnet's current one, so a program at a
	// newer AVM version than the block allowed can run). The chain comparison of
	// the unmodified programs shows whether that changed anything.
	Protocol string `json:"protocol"`
}

type Variant struct {
	Name        string                       `json:"name"`
	ExtraBudget int                          `json:"extra_budget"`
	Overrides map[string]map[string]string `json:"overrides"` // app id -> {"approval": b64, "clear": b64}
}

type TxnResult struct {
	Index      int    `json:"index"`
	TxID       string `json:"txid"`
	Type       string `json:"type"`
	AppID      uint64 `json:"app_id,omitempty"`
	Error      string `json:"error,omitempty"`
	MatchChain bool   `json:"match_chain"`
	ApplyData  string `json:"apply_data,omitempty"` // b64 msgpack of the computed ApplyData
	ApplyJSON  string `json:"apply_json,omitempty"` // only when it differs from the chain
	ChainJSON  string `json:"chain_json,omitempty"`
}

type GroupResult struct {
	Group      int               `json:"group"`
	Error      string            `json:"error,omitempty"`
	Txns       []TxnResult       `json:"txns"`
	BoxWrites  map[string]string `json:"box_writes"` // b64 key -> b64 value ("" = deleted)
	Coverage   map[string][]int  `json:"coverage,omitempty"`
	Ops        map[string]int    `json:"ops"`
	Cost       int               `json:"cost"` // pooled app budget consumed by the whole group
	MatchChain bool              `json:"match_chain"`
}

type VariantResult struct {
	Name        string        `json:"name"`
	Groups      []GroupResult `json:"groups"`
	Unsupported []string      `json:"unsupported,omitempty"`
	Error       string        `json:"error,omitempty"`
}

type Response struct {
	Round     uint64          `json:"round"`
	Variants  []VariantResult `json:"variants"`
	HTTPCalls int             `json:"http_calls"`
	Error     string          `json:"error,omitempty"`
}

// callsApp reports whether a transaction, or any inner transaction the chain
// recorded under it, calls one of apps. App creation counts via ApplicationID
// in ApplyData.
func callsApp(txn transactions.Transaction, ad transactions.ApplyData, apps map[basics.AppIndex]bool) bool {
	if txn.Type == protocol.ApplicationCallTx && (apps[txn.ApplicationID] || apps[ad.ApplicationID]) {
		return true
	}
	for _, inner := range ad.EvalDelta.InnerTxns {
		if callsApp(inner.Txn, inner.ApplyData, apps) {
			return true
		}
	}
	return false
}

func decodeOverrides(in map[string]map[string]string) (map[basics.AppIndex]programs, error) {
	out := map[basics.AppIndex]programs{}
	for id, progs := range in {
		var aid uint64
		if _, err := fmt.Sscan(id, &aid); err != nil {
			return nil, fmt.Errorf("bad app id %q", id)
		}
		var p programs
		var err error
		if s := progs["approval"]; s != "" {
			if p.Approval, err = base64.StdEncoding.DecodeString(s); err != nil {
				return nil, err
			}
		}
		if s := progs["clear"]; s != "" {
			if p.Clear, err = base64.StdEncoding.DecodeString(s); err != nil {
				return nil, err
			}
		}
		out[basics.AppIndex(aid)] = p
	}
	return out, nil
}

func replay(req Request) (resp Response) {
	resp.Round = req.Round
	rem := &remote{base: strings.TrimRight(req.Node, "/"), client: &http.Client{Timeout: 60 * time.Second}, cache: map[string]cached{}, cacheDir: req.CacheDir}
	defer func() { resp.HTTPCalls = rem.calls }()

	status, body, err := rem.get(fmt.Sprintf("/v2/blocks/%d?format=msgpack", req.Round))
	if err != nil || status != 200 {
		resp.Error = fmt.Sprintf("fetch block %d: status %d err %v", req.Round, status, err)
		return
	}
	var wrapped struct {
		_struct struct{}          `codec:""`
		Block   bookkeeping.Block `codec:"block"`
		Cert    interface{}       `codec:"cert"`
	}
	if err := protocol.DecodeReflect(body, &wrapped); err != nil {
		resp.Error = "decode block: " + err.Error()
		return
	}
	blk := wrapped.Block
	groups, err := blk.DecodePaysetGroups()
	if err != nil {
		resp.Error = "decode payset: " + err.Error()
		return
	}
	if req.Protocol != "" {
		if _, ok := config.Consensus[protocol.ConsensusVersion(req.Protocol)]; !ok {
			resp.Error = "unknown consensus version " + req.Protocol
			return
		}
		blk.BlockHeader.CurrentProtocol = protocol.ConsensusVersion(req.Protocol)
	}

	want := map[int]bool{}
	for _, g := range req.Groups {
		want[g] = true
	}
	appSet := map[basics.AppIndex]bool{}
	for _, a := range req.Apps {
		appSet[basics.AppIndex(a)] = true
	}
	for gi, g := range groups {
		for _, t := range g {
			if callsApp(t.Txn, t.ApplyData, appSet) {
				want[gi] = true
			}
		}
	}
	if len(want) == 0 {
		resp.Error = "no matching group in block"
		return
	}
	warm(rem, blk, groups, want, req)
	variants := req.Variants
	if len(variants) == 0 {
		variants = []Variant{{Name: "chain-programs"}}
	}
	for _, v := range variants {
		overrides, err := decodeOverrides(v.Overrides)
		if err != nil {
			resp.Variants = append(resp.Variants, VariantResult{Name: v.Name, Error: err.Error()})
			continue
		}
		resp.Variants = append(resp.Variants, evaluate(rem, blk, groups, want, req, v, overrides))
	}
	return
}

// warm runs go-algorand's own block prefetcher over the evaluated groups so the
// named accounts and resources load concurrently instead of one HTTP round trip
// at a time inside the evaluator. Results are discarded; the cache keeps them.
func warm(rem *remote, blk bookkeeping.Block, groups [][]transactions.SignedTxnWithAD, want map[int]bool, req Request) {
	last := -1
	for g := range want {
		if g > last {
			last = g
		}
	}
	led := &remoteLedger{r: rem, prev: basics.Round(req.Round - 1), hdrs: map[basics.Round]bookkeeping.BlockHeader{}, unsupported: map[string]bool{}}
	defer func() { recover() }()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	proto := config.Consensus[blk.CurrentProtocol]
	for range prefetcher.BlockReferences(ctx, led, led.prev, groups[:last+1], blk.FeeSink, proto) {
	}
}

func evaluate(rem *remote, blk bookkeeping.Block, groups [][]transactions.SignedTxnWithAD,
	want map[int]bool, req Request, v Variant, overrides map[basics.AppIndex]programs) (out VariantResult) {
	out.Name = v.Name
	defer func() {
		if r := recover(); r != nil {
			out.Error = fmt.Sprintf("panic: %v", r)
		}
	}()
	last := -1
	for g := range want {
		if g > last {
			last = g
		}
	}
	led := &remoteLedger{r: rem, prev: basics.Round(req.Round - 1), overrides: overrides,
		hdrs: map[basics.Round]bookkeeping.BlockHeader{}, unsupported: map[string]bool{}}
	tr := newTracer()
	ev, err := eval.StartEvaluator(led, blk.BlockHeader, eval.EvaluatorOptions{
		PaysetHint: last + 1, Validate: false, Generate: false, Tracer: tr,
	})
	if err != nil {
		out.Error = "start evaluator: " + err.Error()
		return
	}
	for gi := 0; gi <= last; gi++ {
		if !want[gi] && !req.Prefix {
			continue
		}
		chain := groups[gi]
		group := make([]transactions.SignedTxnWithAD, len(chain))
		for i, t := range chain {
			group[i] = transactions.SignedTxnWithAD{SignedTxn: t.SignedTxn}
		}
		*tr = *newTracer()
		if want[gi] {
			// Only reported groups: prefix programs that read global
			// OpcodeBudget (OpUp loops) would otherwise create fewer inner
			// apps and shift every later created ID in the block.
			tr.extra = v.ExtraBudget
		}
		evalErr := ev.TransactionGroup(group...)
		if !want[gi] {
			if evalErr != nil {
				// The prefix never touches an overridden app, so this is the
				// remote ledger disagreeing with the chain: stop, the rest of
				// the block would be evaluated against the wrong state.
				out.Error = fmt.Sprintf("prefix group %d failed: %v", gi, evalErr)
				return
			}
			continue
		}
		res := GroupResult{Group: gi, BoxWrites: map[string]string{}, Ops: map[string]int{}, MatchChain: evalErr == nil}
		for app, n := range tr.ops {
			res.Ops[fmt.Sprint(uint64(app))] = n
		}
		res.Cost = tr.budgetConsumed
		if evalErr != nil {
			res.Error = evalErr.Error()
		}
		for i, t := range chain {
			tx := TxnResult{Index: i, TxID: t.ID().String(), Type: string(t.Txn.Type), AppID: uint64(t.Txn.ApplicationID)}
			ad, ran := tr.ads[i]
			tx.Error = tr.errs[i]
			if ran {
				tx.ApplyData = base64.StdEncoding.EncodeToString(protocol.Encode(&ad))
				tx.MatchChain = tx.Error == "" && ad.Equal(t.ApplyData)
			}
			if !tx.MatchChain {
				res.MatchChain = false
				tx.ChainJSON = string(protocol.EncodeJSONStrict(&t.ApplyData))
				if ran {
					tx.ApplyJSON = string(protocol.EncodeJSONStrict(&ad))
				}
			}
			res.Txns = append(res.Txns, tx)
		}
		keys := make([]string, 0, len(tr.kvMods))
		for k := range tr.kvMods {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, k := range keys {
			v := tr.kvMods[k]
			val := ""
			if v.Data != nil {
				val = base64.StdEncoding.EncodeToString(v.Data)
			}
			res.BoxWrites[base64.StdEncoding.EncodeToString([]byte(k))] = val
		}
		if req.Coverage {
			res.Coverage = map[string][]int{}
			for app, pcs := range tr.coverage {
				list := make([]int, 0, len(pcs))
				for pc := range pcs {
					list = append(list, pc)
				}
				sort.Ints(list)
				res.Coverage[fmt.Sprint(uint64(app))] = list
			}
		}
		out.Groups = append(out.Groups, res)
	}
	for k := range led.unsupported {
		out.Unsupported = append(out.Unsupported, k)
	}
	sort.Strings(out.Unsupported)
	return
}

// ---------------------------------------------------------------- main

func main() {
	if len(os.Args) < 2 {
		fmt.Fprintln(os.Stderr, "usage: ttreplay asm|disasm|replay < input")
		os.Exit(2)
	}
	in, _ := io.ReadAll(bufio.NewReader(os.Stdin))
	out := json.NewEncoder(os.Stdout)
	switch os.Args[1] {
	case "asm":
		ops, err := logic.AssembleString(string(in))
		if err != nil {
			msg := err.Error()
			if ops != nil && len(ops.Errors) > 0 {
				var b bytes.Buffer
				for _, e := range ops.Errors {
					fmt.Fprintln(&b, e.Error())
				}
				msg = b.String()
			}
			out.Encode(map[string]string{"error": msg})
			os.Exit(1)
		}
		out.Encode(map[string]string{"program": base64.StdEncoding.EncodeToString(ops.Program)})
	case "disasm":
		prog, err := base64.StdEncoding.DecodeString(strings.TrimSpace(string(in)))
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		text, err := logic.Disassemble(prog)
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		fmt.Print(text)
	case "replay":
		var req Request
		if err := json.Unmarshal(in, &req); err != nil {
			out.Encode(Response{Error: "bad request: " + err.Error()})
			os.Exit(1)
		}
		out.Encode(replay(req))
	default:
		fmt.Fprintln(os.Stderr, "unknown command", os.Args[1])
		os.Exit(2)
	}
}
