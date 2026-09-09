// ABOUTME: Refuses inherited network observer descriptors off Linux.
// ABOUTME: Keeps the portable runner build honest about unsupported collection.
//go:build !linux

package runner

import (
	"fmt"

	"github.com/2389-research/observatory/internal/privd"
)

func adoptNetworkObservers(*privd.NetworkObserverBundle) (*privd.NetworkObserverBundle, error) {
	return nil, fmt.Errorf("network observers require Linux")
}
func dupNetworkObservers(*privd.NetworkObserverBundle) (*privd.NetworkObserverBundle, error) {
	return nil, fmt.Errorf("network observers require Linux")
}
