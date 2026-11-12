package main

import (
	"reflect"
	"testing"
)

func TestSavedOrderHasNoFailureBudget(t *testing.T) {
	c := Config{Policy: Policy{Route: "auto"}}
	ranks := []Rank{{ID: "ru-tcp", Good: true}, {ID: "ru-wg", Good: true}, {ID: "ru-xhttp", Good: false}}
	saved := append([]Rank{}, ranks...)
	for cycle := 0; cycle < 15; cycle++ {
		if choose(c, ranks) != "ru-tcp" {
			t.Fatal("restart did not start at first place")
		}
		route := "ru-tcp"
		for _, expected := range []string{"ru-wg", "ru-xhttp", "ru-tcp"} {
			route = following(c, ranks, route)
			if route != expected {
				t.Fatal(route, expected)
			}
		}
	}
	if !reflect.DeepEqual(ranks, saved) {
		t.Fatal("recovery changed measurement order")
	}
}
func TestFixedRouteNeverUsesAnotherTransport(t *testing.T) {
	c := Config{Policy: Policy{Route: "ru-xhttp"}}
	ranks := []Rank{{ID: "ru-tcp", Good: true}, {ID: "ru-xhttp", Good: false}}
	if choose(c, ranks) != "ru-xhttp" || following(c, ranks, "ru-xhttp") != "ru-xhttp" {
		t.Fatal("manual route was overridden")
	}
}
func TestRankingRejectsMissingDuplicateOrRemovedRoutes(t *testing.T) {
	var ranks []Rank
	for _, r := range transports {
		ranks = append(ranks, Rank{ID: r.ID})
	}
	if !rankingCurrent(ranks) {
		t.Fatal("complete order rejected")
	}
	if rankingCurrent(ranks[:1]) {
		t.Fatal("partial order accepted")
	}
	ranks[1] = ranks[0]
	if rankingCurrent(ranks) {
		t.Fatal("duplicate accepted")
	}
}

func TestReloadedHostAddressesDoNotLookLikeANetworkChange(t *testing.T) {
	fromSettings := []string{"192.168.0.10/24", "10.20.0.8/16", "192.168.0.25/24"}
	fromAdapter := []string{"10.20.0.0/16", "192.168.0.0/24"}
	if !reflect.DeepEqual(canonicalLAN(fromSettings), canonicalLAN(fromAdapter)) {
		t.Fatal("policy reload invented a network change")
	}
	if fromSettings[0] != "192.168.0.10/24" {
		t.Fatal("normalization mutated saved settings")
	}
	changed := []string{"192.168.1.10/24", "10.20.0.8/16"}
	if reflect.DeepEqual(canonicalLAN(fromSettings), canonicalLAN(changed)) {
		t.Fatal("real network change hidden")
	}
}
