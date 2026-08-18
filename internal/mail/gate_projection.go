package mail

import "slices"

// GateProjection is the bounded untrusted metadata available to gate policy.
type GateProjection struct {
	senderAddress   string
	to              []string
	cc              []string
	deliveredTo     []string
	subject         string
	labels          []string
	listID          string
	listUnsubscribe bool
	autoSubmitted   string
	precedence      string
}

// GateProjection returns a defensive typed view of gate-relevant metadata.
func (message Message) GateProjection() (GateProjection, error) {
	if !message.Valid() {
		return GateProjection{}, ErrInvalidMetadata
	}
	return GateProjection{
		senderAddress:   message.metadata.SenderAddress,
		to:              slices.Clone(message.metadata.To),
		cc:              slices.Clone(message.metadata.CC),
		deliveredTo:     slices.Clone(message.metadata.DeliveredTo),
		subject:         message.metadata.Subject,
		labels:          slices.Clone(message.metadata.Labels),
		listID:          message.metadata.ListID,
		listUnsubscribe: message.metadata.ListUnsubscribe,
		autoSubmitted:   message.metadata.AutoSubmitted,
		precedence:      message.metadata.Precedence,
	}, nil
}

func (projection GateProjection) SenderAddress() string { return projection.senderAddress }
func (projection GateProjection) To() []string          { return slices.Clone(projection.to) }
func (projection GateProjection) CC() []string          { return slices.Clone(projection.cc) }
func (projection GateProjection) DeliveredTo() []string { return slices.Clone(projection.deliveredTo) }
func (projection GateProjection) Subject() string       { return projection.subject }
func (projection GateProjection) Labels() []string      { return slices.Clone(projection.labels) }
func (projection GateProjection) ListID() string        { return projection.listID }
func (projection GateProjection) ListUnsubscribe() bool { return projection.listUnsubscribe }
func (projection GateProjection) AutoSubmitted() string { return projection.autoSubmitted }
func (projection GateProjection) Precedence() string    { return projection.precedence }
