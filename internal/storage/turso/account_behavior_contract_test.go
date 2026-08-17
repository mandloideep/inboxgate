//go:build !contractred

package turso

import (
	"testing"

	storagefake "github.com/mandloideep/inboxgate/internal/storage/fake"
)

func TestAccountCursorBehaviorContractAcrossFakeAndExactDriver(t *testing.T) {
	t.Run("fake", func(t *testing.T) {
		runAccountCursorBehaviorContract(t, storagefake.New())
	})
	t.Run("exact driver", func(t *testing.T) {
		server := newMigrationProtocolServer(t)
		runAccountCursorBehaviorContract(t, openPersistenceContractHandle(t, server.URL))
	})
}
