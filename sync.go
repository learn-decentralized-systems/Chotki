package chotki

import (
	"bytes"
	"context"
	"crypto/sha1"
	"encoding/hex"
	"errors"
	"io"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/cockroachdb/pebble"
	"github.com/drpcorg/chotki/protocol"
	"github.com/drpcorg/chotki/rdx"
	"github.com/drpcorg/chotki/utils"
	"github.com/google/uuid"
)

const SyncBlockBits = 28
const SyncBlockMask = (rdx.ID(1) << SyncBlockBits) - 1

type SyncHost interface {
	protocol.Drainer
	Snapshot() pebble.Reader
	Broadcast(ctx context.Context, records protocol.Records, except string)
}

type SyncMode byte

const (
	SyncRead   SyncMode = 1
	SyncWrite  SyncMode = 2
	SyncLive   SyncMode = 4
	SyncRW     SyncMode = SyncRead | SyncWrite
	SyncRL     SyncMode = SyncRead | SyncLive
	SyncRWLive SyncMode = SyncRead | SyncWrite | SyncLive
)

func (m *SyncMode) Zip() []byte {
	return rdx.ZipUint64(uint64(*m))
}

func (m *SyncMode) Unzip(raw []byte) error {
	parsed := rdx.UnzipUint64(raw)
	if parsed > 0b111 {
		return errors.New("invalid mode")
	}

	*m = SyncMode(parsed)
	return nil
}

const PingVal = "ping"
const PongVal = "pong"

type SyncState int

const (
	SendHandshake SyncState = iota
	SendDiff
	SendLive
	SendEOF
	SendNone
	SendPing
	SendPong
)

type PingState int

const (
	Inactive PingState = iota
	Ping
	Pong
	PingBroken
)

func (s SyncState) String() string {
	return []string{"SendHandshake", "SendDiff", "SendLive", "SendEOF", "SendNone", "SendPing", "SendPong"}[s]
}

const TraceSize = 10

type Syncer struct {
	Src        uint64
	Name       string
	Host       SyncHost
	Mode       SyncMode
	PingPeriod time.Duration
	PingWait   time.Duration

	log        utils.Logger
	vvit, ffit *pebble.Iterator
	snap       pebble.Reader
	snaplast   rdx.ID
	feedState  SyncState
	drainState SyncState
	oqueue     protocol.FeedCloser

	hostvv, peervv rdx.VV
	vpack          []byte
	reason         error
	myTraceId      atomic.Pointer[[TraceSize]byte]
	theirsTraceid  atomic.Pointer[[TraceSize]byte]

	lock      sync.Mutex
	cond      sync.Cond
	pingTimer *time.Timer
	pingStage atomic.Int32
}

func (sync *Syncer) withDefaultArgs(args ...any) []any {
	return append([]any{"name", sync.Name, "trace_id", sync.GetTraceId()}, args...)
}

func (sync *Syncer) Close() error {
	sync.SetFeedState(context.Background(), SendEOF)

	if sync.Host == nil {
		return utils.ErrClosed
	}

	sync.lock.Lock()
	defer sync.lock.Unlock()

	if sync.snap != nil {
		if err := sync.snap.Close(); err != nil {
			sync.log.Error("failed closing snapshot", sync.withDefaultArgs("err", err)...)
		}
		sync.snap = nil
	}

	if sync.ffit != nil {
		if err := sync.ffit.Close(); err != nil {
			sync.log.Error("failed closing ffit", sync.withDefaultArgs("err", err)...)
		}
		sync.ffit = nil
	}

	if sync.vvit != nil {
		if err := sync.vvit.Close(); err != nil {
			sync.log.Error("failed closing vvit", sync.withDefaultArgs("err", err)...)
		}
		sync.vvit = nil
	}

	sync.log.Info("sync: connection %s closed: %v\n", sync.withDefaultArgs(sync.Name, sync.reason)...)

	return nil
}
func (sync *Syncer) GetFeedState() SyncState {
	sync.lock.Lock()
	defer sync.lock.Unlock()
	return sync.feedState
}

func (sync *Syncer) pingTransition(ctx context.Context) {
	//nolint:exhaustive
	switch PingState(sync.pingStage.Load()) {
	case Ping:
		sync.SetFeedState(ctx, SendPing)
	case Pong:
		sync.SetFeedState(ctx, SendPong)
	case PingBroken:
		sync.SetFeedState(ctx, SendEOF)
	}
}

func (sync *Syncer) GetDrainState() SyncState {
	sync.lock.Lock()
	defer sync.lock.Unlock()
	return sync.drainState
}

func (sync *Syncer) Feed(ctx context.Context) (recs protocol.Records, err error) {
	// other side closed the connection already
	if sync.GetDrainState() == SendNone {
		sync.SetFeedState(ctx, SendNone)
	}
	switch sync.GetFeedState() {
	case SendHandshake:
		recs, err = sync.FeedHandshake()
		sync.SetFeedState(ctx, SendDiff)

	case SendDiff:
		ctx, cancel := context.WithCancel(ctx)
		defer cancel()
		select {
		case <-time.After(sync.PingWait):
			sync.log.ErrorCtx(ctx, "sync: handshake took too long", sync.withDefaultArgs()...)
			sync.SetFeedState(ctx, SendEOF)
			return
		case <-sync.WaitDrainState(ctx, SendDiff):
		}
		recs, err = sync.FeedBlockDiff()
		if err == io.EOF {
			recs2, _ := sync.FeedDiffVV()
			recs = append(recs, recs2...)
			if (sync.Mode & SyncLive) != 0 {
				sync.SetFeedState(ctx, SendLive)
				sync.resetPingTimer()
			} else {
				sync.SetFeedState(ctx, SendEOF)
			}
			_ = sync.snap.Close()
			sync.snap = nil
			err = nil
		}
	case SendPing:
		recs = protocol.Records{
			protocol.Record('P', rdx.Stlv(PingVal)),
		}
		sync.SetFeedState(ctx, SendLive)
		sync.pingStage.Store(int32(Inactive))
		sync.pingTimer.Stop()
		sync.pingTimer = time.AfterFunc(sync.PingWait, func() {
			sync.pingStage.Store(int32(PingBroken))
			sync.log.ErrorCtx(ctx, "sync: peer did not respond to ping", sync.withDefaultArgs()...)
		})
	case SendPong:
		recs = protocol.Records{
			protocol.Record('P', rdx.Stlv(PongVal)),
		}
		sync.pingStage.Store(int32(Inactive))
		sync.SetFeedState(ctx, SendLive)
	case SendLive:
		recs, err = sync.oqueue.Feed(ctx)
		if err == utils.ErrClosed {
			sync.log.InfoCtx(ctx, "sync: queue closed", sync.withDefaultArgs()...)
			sync.SetFeedState(ctx, SendEOF)
			err = nil
		}
		sync.pingTransition(ctx)

	case SendEOF:
		reason := []byte("closing")
		if sync.reason != nil {
			reason = []byte(sync.reason.Error())
		}
		recs = protocol.Records{protocol.Record('B',
			protocol.TinyRecord('T', sync.snaplast.ZipBytes()),
			reason,
		)}
		if sync.snap != nil {
			_ = sync.snap.Close()
			sync.snap = nil
		}
		sync.SetFeedState(ctx, SendNone)

	case SendNone:
		timer := time.AfterFunc(time.Second, func() {
			sync.SetDrainState(ctx, SendNone)
		})
		<-sync.WaitDrainState(context.Background(), SendNone)
		timer.Stop()
		err = io.EOF
	}

	return
}

func (sync *Syncer) FeedHandshake() (vv protocol.Records, err error) {
	sync.snap = sync.Host.Snapshot()
	sync.vvit = sync.snap.NewIter(&pebble.IterOptions{
		LowerBound: []byte{'V'},
		UpperBound: []byte{'W'},
	})
	sync.ffit = sync.snap.NewIter(&pebble.IterOptions{
		LowerBound: []byte{'O'},
		UpperBound: []byte{'P'},
	})

	ok := sync.vvit.SeekGE(VKey0)
	if !ok || 0 != bytes.Compare(sync.vvit.Key(), VKey0) {
		return nil, rdx.ErrBadV0Record
	}
	sync.hostvv = make(rdx.VV)
	err = sync.hostvv.PutTLV(sync.vvit.Value())
	if err != nil {
		return nil, err
	}
	sync.snaplast = sync.hostvv.GetID(sync.Src)

	sync.vpack = make([]byte, 0, 4096)
	_, sync.vpack = protocol.OpenHeader(sync.vpack, 'V') // 5
	sync.vpack = append(sync.vpack, protocol.Record('T', sync.snaplast.ZipBytes())...)

	sync.lock.Lock()
	mode := sync.Mode.Zip()
	sync.lock.Unlock()
	uuid, err := uuid.NewV7()
	if err != nil {
		return nil, err
	}
	hash := sha1.Sum(uuid[:])
	tracePart := [TraceSize]byte(hash[:TraceSize])
	sync.myTraceId.Store(&tracePart)

	// handshake: H(T{pro,src} M(mode) V(V{p,s}+), T(trace_ids))
	hs := protocol.Record('H',
		protocol.TinyRecord('T', sync.snaplast.ZipBytes()),
		protocol.TinyRecord('M', mode),
		protocol.Record('V', sync.vvit.Value()),
		protocol.Record('S', tracePart[:]),
	)

	return protocol.Records{hs}, nil
}

func (sync *Syncer) FeedBlockDiff() (diff protocol.Records, err error) {
	if !sync.vvit.Next() {
		return nil, io.EOF
	}
	vv := make(rdx.VV)
	err = vv.PutTLV(sync.vvit.Value())
	if err != nil {
		return nil, rdx.ErrBadVRecord
	}
	sendvv := make(rdx.VV)
	// check for any changes
	hasChanges := false // fixme up & repeat
	for src, pro := range vv {
		peerpro, ok := sync.peervv[src]
		if !ok || pro > peerpro {
			sendvv[src] = peerpro
			hasChanges = true
		}
	}
	if !hasChanges {
		return protocol.Records{}, nil
	}
	block := VKeyId(sync.vvit.Key()).ZeroOff()
	key := OKey(block, 0)
	sync.ffit.SeekGE(key)
	bmark, parcel := protocol.OpenHeader(nil, 'D')
	parcel = append(parcel, protocol.Record('T', sync.snaplast.ZipBytes())...)
	parcel = append(parcel, protocol.Record('R', block.ZipBytes())...)
	till := block + SyncBlockMask + 1
	for ; sync.ffit.Valid(); sync.ffit.Next() {
		id, rdt := OKeyIdRdt(sync.ffit.Key())
		if id == rdx.BadId || id >= till {
			break
		}
		lim, ok := sendvv[id.Src()]
		if ok && (id.Pro() > lim || lim == 0) {
			parcel = append(parcel, protocol.Record('F', rdx.ZipUint64(uint64(id-block)))...)
			parcel = append(parcel, protocol.Record(rdt, sync.ffit.Value())...)
			continue
		}
		diff := rdx.Xdiff(rdt, sync.ffit.Value(), sendvv)
		if len(diff) != 0 {
			parcel = append(parcel, protocol.Record('F', rdx.ZipUint64(uint64(id-block)))...)
			parcel = append(parcel, protocol.Record(rdt, diff)...)
		}
	}
	protocol.CloseHeader(parcel, bmark)
	v := protocol.Record('V',
		protocol.Record('R', block.ZipBytes()),
		sync.vvit.Value()) // todo brief
	sync.vpack = append(sync.vpack, v...)
	return protocol.Records{parcel}, err
}

func (sync *Syncer) FeedDiffVV() (vv protocol.Records, err error) {
	protocol.CloseHeader(sync.vpack, 5)
	vv = append(vv, sync.vpack)
	sync.vpack = nil
	_ = sync.ffit.Close()
	sync.ffit = nil
	_ = sync.vvit.Close()
	sync.vvit = nil
	return
}

func (sync *Syncer) SetFeedState(ctx context.Context, state SyncState) {
	sync.log.InfoCtx(ctx, "sync: feed state", sync.withDefaultArgs("state", state.String())...)
	sync.lock.Lock()
	sync.feedState = state
	sync.lock.Unlock()
}

func (sync *Syncer) SetDrainState(ctx context.Context, state SyncState) {
	sync.log.InfoCtx(ctx, "sync: drain state", sync.withDefaultArgs("state", state.String())...)
	sync.lock.Lock()
	sync.drainState = state
	if sync.cond.L == nil {
		sync.cond.L = &sync.lock
	}
	sync.cond.Broadcast()
	sync.lock.Unlock()
}

func (sync *Syncer) WaitDrainState(ctx context.Context, state SyncState) chan SyncState {
	res := make(chan SyncState)
	go func() {
		<-ctx.Done()
		sync.cond.Broadcast()
	}()
	go func() {
		defer close(res)
		sync.lock.Lock()
		defer sync.lock.Unlock()
		if sync.cond.L == nil {
			sync.cond.L = &sync.lock
		}
		for sync.drainState < state {
			if ctx.Err() != nil {
				return
			}
			sync.cond.Wait()
		}
		ds := sync.drainState

		res <- ds
	}()
	return res
}

func LastLit(recs protocol.Records) byte {
	if len(recs) == 0 {
		return 0
	}
	return protocol.Lit(recs[len(recs)-1])
}

func (sync *Syncer) resetPingTimer() {
	sync.lock.Lock()
	defer sync.lock.Unlock()
	if sync.pingTimer != nil {
		sync.pingTimer.Stop()
	}
	sync.pingTimer = time.AfterFunc(sync.PingPeriod, func() {
		sync.pingStage.Store(int32(Ping))
	})
}

func (sync *Syncer) processPings(recs protocol.Records) protocol.Records {
	for i, rec := range recs {
		if protocol.Lit(rec) == 'P' {
			body, _ := protocol.Take('P', rec)
			recs = append(recs[:i], recs[i+1:]...)
			switch rdx.Snative(body) {
			case PingVal:
				sync.log.Info("ping received", sync.withDefaultArgs()...)
				// go to pong state next time
				sync.pingStage.Store(int32(Pong))
			case PongVal:
				sync.log.Info("pong received", sync.withDefaultArgs()...)
			}
		}
	}
	return recs
}

func (sync *Syncer) Drain(ctx context.Context, recs protocol.Records) (err error) {
	if len(recs) == 0 {
		return nil
	}

	recs = sync.processPings(recs)

	switch sync.drainState {
	case SendHandshake:
		if len(recs) == 0 {
			return ErrBadHPacket
		}
		err = sync.DrainHandshake(recs[0:1])
		if err == nil {
			err = sync.Host.Drain(sync.log.WithDefaultArgs(ctx, sync.withDefaultArgs()...), recs[0:1])
		}
		if err != nil {
			return
		}
		sync.Host.Broadcast(sync.log.WithDefaultArgs(ctx, sync.withDefaultArgs()...), recs[0:1], sync.Name)
		recs = recs[1:]
		sync.SetDrainState(ctx, SendDiff)
		if len(recs) == 0 {
			break
		}
		fallthrough

	case SendDiff:
		lit := LastLit(recs)
		if lit != 'D' && lit != 'V' {
			if lit == 'B' {
				sync.SetDrainState(ctx, SendNone)
			} else {
				sync.SetDrainState(ctx, SendLive)
			}
		}
		if sync.Mode&SyncLive != 0 {
			sync.resetPingTimer()
		}
		err = sync.Host.Drain(sync.log.WithDefaultArgs(ctx, sync.withDefaultArgs()...), recs)
		if err == nil {
			sync.Host.Broadcast(sync.log.WithDefaultArgs(ctx, sync.withDefaultArgs()...), recs, sync.Name)
		}

	case SendLive:
		sync.resetPingTimer()
		lit := LastLit(recs)
		if lit == 'B' {
			sync.SetDrainState(ctx, SendNone)
		}
		err = sync.Host.Drain(sync.log.WithDefaultArgs(ctx, sync.withDefaultArgs()...), recs)
		if err == nil {
			sync.Host.Broadcast(sync.log.WithDefaultArgs(ctx, sync.withDefaultArgs()...), recs, sync.Name)
		}

	case SendPong, SendPing:
		panic("chotki: unacceptable sync-state")

	case SendEOF, SendNone:
		return ErrClosed

	default:
		panic("chotki: unacceptable sync-state")
	}

	if err != nil { // todo send the error msg
		sync.SetDrainState(ctx, SendEOF)
	}

	return
}

func (sync *Syncer) GetTraceId() string {
	theirsP := sync.theirsTraceid.Load()
	if theirsP == nil {
		theirsP = &[TraceSize]byte{}
	}
	theirs := hex.EncodeToString((*theirsP)[:])
	mineP := sync.myTraceId.Load()
	if mineP == nil {
		mineP = &[TraceSize]byte{}
	}
	mine := hex.EncodeToString((*mineP)[:])
	if strings.Compare(mine, theirs) >= 0 {
		return mine + "-" + theirs
	} else {
		return theirs + "-" + mine
	}
}

func (sync *Syncer) DrainHandshake(recs protocol.Records) (err error) {
	lit, _, _, body, e := ParsePacket(recs[0])
	if lit != 'H' || e != nil {
		return ErrBadHPacket
	}
	var mode SyncMode
	var trace_id []byte
	mode, sync.peervv, trace_id, err = ParseHandshake(body)
	sync.lock.Lock()
	if trace_id != nil {
		if len(trace_id) != TraceSize {
			err = ErrBadHPacket
		} else {
			traceId := [TraceSize]byte(trace_id)
			sync.theirsTraceid.Store(&traceId)
		}
	}
	sync.Mode &= mode
	sync.lock.Unlock()
	return
}
