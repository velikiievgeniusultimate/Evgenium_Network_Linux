package main

type Rank struct {
	ID    string  `json:"id"`
	Label string  `json:"label"`
	Mbps  float64 `json:"download_mbps"`
	RTT   int64   `json:"rtt_ms"`
	Good  bool    `json:"good"`
	Error string  `json:"error,omitempty"`
}

// The saved measurement order never changes when a route fails.
func rankingCurrent(ranks []Rank) bool {
	if len(ranks) != len(transports) {
		return false
	}
	seen := map[string]bool{}
	for _, r := range ranks {
		if seen[r.ID] {
			return false
		}
		seen[r.ID] = true
	}
	for _, t := range transports {
		if !seen[t.ID] {
			return false
		}
	}
	return true
}

func choose(c Config, ranks []Rank) string {
	if c.Policy.Route != "" && c.Policy.Route != "auto" {
		return c.Policy.Route
	}
	if len(ranks) == 0 {
		return ""
	}
	return ranks[0].ID
}

func following(c Config, ranks []Rank, current string) string {
	if c.Policy.Route != "" && c.Policy.Route != "auto" {
		return c.Policy.Route
	}
	position := -1
	for i, r := range ranks {
		if r.ID == current {
			position = i
		}
	}
	if len(ranks) == 0 {
		return ""
	}
	return ranks[(position+1)%len(ranks)].ID
}
