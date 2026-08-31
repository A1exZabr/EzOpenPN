package supervisor

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
)

const (
	ChildBinary = "/usr/local/bin/xray"
	ChildConfig = "/etc/xray/config.json"
)

var (
	ErrAlreadyRunning   = errors.New("process manager already running")
	ErrChildStart       = errors.New("child process could not start")
	ErrChildStop        = errors.New("child process could not stop")
	ErrChildUnstable    = errors.New("child process did not remain stable")
	ErrRepeatedFailures = errors.New("child process failed repeatedly")
	ErrRestartCanceled  = errors.New("restart request was canceled")
	ErrInvalidSignal    = errors.New("shutdown signal is not allowed")
)

type Child interface {
	Signal(os.Signal) error
	Kill() error
	Wait() error
}

type ChildStarter interface {
	Start() (Child, error)
}

type commandChild struct {
	command *exec.Cmd
}

func (child *commandChild) Signal(signal os.Signal) error {
	return child.command.Process.Signal(signal)
}

func (child *commandChild) Kill() error {
	return child.command.Process.Kill()
}

func (child *commandChild) Wait() error {
	return child.command.Wait()
}

type xrayStarter struct{}

func NewXrayStarter() ChildStarter {
	return &xrayStarter{}
}

func (starter *xrayStarter) Start() (Child, error) {
	command := exec.Command(ChildBinary, "run", "-config", ChildConfig)
	command.Stdin = nil
	command.Stdout = os.Stdout
	command.Stderr = os.Stderr
	if err := command.Start(); err != nil {
		return nil, ErrChildStart
	}
	return &commandChild{command: command}, nil
}

type processPolicy struct {
	stopTimeout    time.Duration
	stableDuration time.Duration
	failureWindow  time.Duration
	maxFailures    int
}

func defaultProcessPolicy() processPolicy {
	return processPolicy{
		stopTimeout:    3 * time.Second,
		stableDuration: 500 * time.Millisecond,
		failureWindow:  time.Minute,
		maxFailures:    5,
	}
}

type restartRequest struct {
	ctx      context.Context
	response chan error
}

type shutdownRequest struct {
	signal   os.Signal
	response chan error
}

type ProcessManager struct {
	starter          ChildStarter
	policy           processPolicy
	restartRequests  chan restartRequest
	shutdownRequests chan shutdownRequest
	healthy          atomic.Bool
	running          atomic.Bool
}

func NewProcessManager(starter ChildStarter) *ProcessManager {
	return newProcessManager(starter, defaultProcessPolicy())
}

func newProcessManager(starter ChildStarter, policy processPolicy) *ProcessManager {
	return &ProcessManager{
		starter:          starter,
		policy:           policy,
		restartRequests:  make(chan restartRequest),
		shutdownRequests: make(chan shutdownRequest),
	}
}

func (manager *ProcessManager) Healthy() bool {
	return manager.healthy.Load()
}

func (manager *ProcessManager) Restart(ctx context.Context) error {
	request := restartRequest{ctx: ctx, response: make(chan error, 1)}
	select {
	case manager.restartRequests <- request:
	case <-ctx.Done():
		return ErrRestartCanceled
	}
	select {
	case err := <-request.response:
		return err
	case <-ctx.Done():
		return ErrRestartCanceled
	}
}

func (manager *ProcessManager) Shutdown(ctx context.Context, signal os.Signal) error {
	if signal != os.Interrupt && signal != syscall.SIGTERM {
		return ErrInvalidSignal
	}
	request := shutdownRequest{signal: signal, response: make(chan error, 1)}
	select {
	case manager.shutdownRequests <- request:
	case <-ctx.Done():
		return ErrChildStop
	}
	select {
	case err := <-request.response:
		return err
	case <-ctx.Done():
		return ErrChildStop
	}
}

func waitForChild(child Child) <-chan error {
	result := make(chan error, 1)
	go func() {
		result <- child.Wait()
	}()
	return result
}

func (manager *ProcessManager) startChild() (Child, <-chan error, error) {
	child, err := manager.starter.Start()
	if err != nil {
		return nil, nil, ErrChildStart
	}
	return child, waitForChild(child), nil
}

func (manager *ProcessManager) stopChild(
	child Child,
	exited <-chan error,
	signal os.Signal,
) error {
	manager.healthy.Store(false)
	_ = child.Signal(signal)
	timer := time.NewTimer(manager.policy.stopTimeout)
	defer timer.Stop()
	select {
	case <-exited:
		return nil
	case <-timer.C:
	}
	_ = child.Kill()
	killTimer := time.NewTimer(time.Second)
	defer killTimer.Stop()
	select {
	case <-exited:
		return nil
	case <-killTimer.C:
		return ErrChildStop
	}
}

func (manager *ProcessManager) recordFailure(failures []time.Time) ([]time.Time, bool) {
	now := time.Now()
	cutoff := now.Add(-manager.policy.failureWindow)
	kept := failures[:0]
	for _, failure := range failures {
		if failure.After(cutoff) {
			kept = append(kept, failure)
		}
	}
	kept = append(kept, now)
	return kept, len(kept) > manager.policy.maxFailures
}

func (manager *ProcessManager) Run(ctx context.Context) error {
	if !manager.running.CompareAndSwap(false, true) {
		return ErrAlreadyRunning
	}
	defer manager.running.Store(false)
	child, exited, err := manager.startChild()
	if err != nil {
		return err
	}
	manager.healthy.Store(true)
	defer manager.healthy.Store(false)
	failures := make([]time.Time, 0, manager.policy.maxFailures+1)

	for {
		select {
		case <-ctx.Done():
			return manager.stopChild(child, exited, syscall.SIGTERM)
		case request := <-manager.shutdownRequests:
			err = manager.stopChild(child, exited, request.signal)
			request.response <- err
			return err
		case request := <-manager.restartRequests:
			if request.ctx.Err() != nil {
				request.response <- ErrRestartCanceled
				continue
			}
			if err = manager.stopChild(child, exited, syscall.SIGTERM); err != nil {
				request.response <- err
				return err
			}
			child, exited, err = manager.startChild()
			if err != nil {
				request.response <- err
				return err
			}
			stableTimer := time.NewTimer(manager.policy.stableDuration)
			select {
			case <-stableTimer.C:
				manager.healthy.Store(true)
				request.response <- nil
			case <-exited:
				if !stableTimer.Stop() {
					select {
					case <-stableTimer.C:
					default:
					}
				}
				manager.healthy.Store(false)
				request.response <- ErrChildUnstable
				var exceeded bool
				failures, exceeded = manager.recordFailure(failures)
				if exceeded {
					return ErrRepeatedFailures
				}
				child, exited, err = manager.startChild()
				if err != nil {
					return err
				}
				manager.healthy.Store(true)
			case <-ctx.Done():
				if !stableTimer.Stop() {
					select {
					case <-stableTimer.C:
					default:
					}
				}
				request.response <- ErrRestartCanceled
				return manager.stopChild(child, exited, syscall.SIGTERM)
			}
		case <-exited:
			manager.healthy.Store(false)
			var exceeded bool
			failures, exceeded = manager.recordFailure(failures)
			if exceeded {
				return ErrRepeatedFailures
			}
			child, exited, err = manager.startChild()
			if err != nil {
				return err
			}
			manager.healthy.Store(true)
		}
	}
}

type Controller interface {
	Restart(context.Context) error
	Healthy() bool
}

type Restarter struct {
	process Controller
	mu      sync.Mutex
}

func NewRestarter(process Controller) *Restarter {
	return &Restarter{process: process}
}

func (restarter *Restarter) Restart(ctx context.Context) error {
	restarter.mu.Lock()
	defer restarter.mu.Unlock()
	return restarter.process.Restart(ctx)
}

func (restarter *Restarter) Healthy() bool {
	return restarter.process.Healthy()
}
