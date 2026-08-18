// Package gateeval composes deterministic gate policy with typed durable storage.
package gateeval

import (
	"context"
	"errors"
	"slices"
	"time"

	"github.com/mandloideep/inboxgate/internal/config"
	"github.com/mandloideep/inboxgate/internal/gate"
	"github.com/mandloideep/inboxgate/internal/mail"
	"github.com/mandloideep/inboxgate/internal/storage"
)

var (
	ErrInvalidRequest   = errors.New("gate evaluation: invalid request")
	ErrMessageNotFound  = errors.New("gate evaluation: message not found")
	ErrConflict         = errors.New("gate evaluation: conflict")
	ErrRecoveryRequired = errors.New("gate evaluation: recovery required")
)

// Store is the narrow persistence surface required by one gate evaluation.
type Store interface {
	GetDiscoveredMessage(context.Context, storage.AccountID, string) (mail.Message, error)
	GetGateDecision(context.Context, storage.AccountID, string) (storage.GateDecisionState, error)
	CommitGateDecision(context.Context, storage.GateDecisionCommit) error
}

// Evaluator performs one inert deterministic evaluation.
type Evaluator struct {
	policy config.Gate
	store  Store
	now    func() time.Time
}

func New(policy config.Gate, store Store, now func() time.Time) (*Evaluator, error) {
	if gate.ValidatePolicy(policy) != nil || store == nil || now == nil {
		return nil, ErrInvalidRequest
	}
	policy.ExcludedLabels = slices.Clone(policy.ExcludedLabels)
	policy.SuppressGmailCategories = slices.Clone(policy.SuppressGmailCategories)
	policy.SenderAllowDomains = slices.Clone(policy.SenderAllowDomains)
	policy.SenderBlockDomains = slices.Clone(policy.SenderBlockDomains)
	policy.SubjectCandidateTerms = slices.Clone(policy.SubjectCandidateTerms)
	policy.SubjectUrgentTerms = slices.Clone(policy.SubjectUrgentTerms)
	return &Evaluator{policy: policy, store: store, now: now}, nil
}

func (e *Evaluator) Evaluate(ctx context.Context, accountID storage.AccountID, gmailMessageID string) (storage.GateDecision, error) {
	if e == nil || e.store == nil || e.now == nil || ctx == nil {
		return storage.GateDecision{}, ErrInvalidRequest
	}
	if parsed, err := storage.ParseAccountID(accountID.String()); err != nil || parsed != accountID || storage.ValidateGmailMessageID(gmailMessageID) != nil {
		return storage.GateDecision{}, ErrInvalidRequest
	}
	message, err := e.store.GetDiscoveredMessage(ctx, accountID, gmailMessageID)
	if err != nil {
		if errors.Is(err, storage.ErrAccountNotFound) || errors.Is(err, storage.ErrMessageNotFound) {
			return storage.GateDecision{}, ErrMessageNotFound
		}
		if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
			return storage.GateDecision{}, err
		}
		return storage.GateDecision{}, ErrRecoveryRequired
	}
	state, stateErr := e.store.GetGateDecision(ctx, accountID, gmailMessageID)
	if stateErr != nil && !errors.Is(stateErr, storage.ErrGateDecisionNotFound) {
		if errors.Is(stateErr, context.Canceled) || errors.Is(stateErr, context.DeadlineExceeded) {
			return storage.GateDecision{}, stateErr
		}
		return storage.GateDecision{}, ErrRecoveryRequired
	}
	classification, err := gate.Classify(message, e.policy)
	if err != nil {
		return storage.GateDecision{}, ErrInvalidRequest
	}
	if stateErr == nil && state.Current && decisionMatchesClassification(state.Decision, classification) {
		return state.Decision, nil
	}
	timestamp := e.now().UnixMilli()
	next, err := storage.NewGateDecision(classification, timestamp)
	if err != nil {
		return storage.GateDecision{}, ErrInvalidRequest
	}
	commit := storage.GateDecisionCommit{Source: message, Next: next}
	if stateErr == nil {
		revision := state.Decision.Revision()
		commit.Expected = &revision
	}
	if err := e.store.CommitGateDecision(ctx, commit); err != nil {
		switch {
		case errors.Is(err, storage.ErrGateDecisionConflict), errors.Is(err, storage.ErrGateDecisionStaleSource):
			return storage.GateDecision{}, ErrConflict
		case errors.Is(err, context.Canceled), errors.Is(err, context.DeadlineExceeded):
			return storage.GateDecision{}, err
		default:
			return storage.GateDecision{}, ErrRecoveryRequired
		}
	}
	durable, err := e.store.GetGateDecision(ctx, accountID, gmailMessageID)
	if err != nil {
		if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
			return storage.GateDecision{}, err
		}
		return storage.GateDecision{}, ErrRecoveryRequired
	}
	if !durable.Current || !decisionMatchesClassification(durable.Decision, classification) {
		return storage.GateDecision{}, ErrRecoveryRequired
	}
	return durable.Decision, nil
}

func decisionMatchesClassification(decision storage.GateDecision, classification gate.Classification) bool {
	return decision.Version() == classification.Version() && decision.SourceMetadataHash() == classification.SourceMetadataHash() && decision.InputHash() == classification.InputHash() && decision.Outcome() == classification.Outcome() && slices.Equal(decision.ReasonCodes(), classification.ReasonCodes())
}
