package learn

import "testing"

func TestAttackCatalogHasDefenderContext(t *testing.T) {
	items := Attacks()
	if len(items) < 15 {
		t.Fatalf("attack catalog has only %d entries", len(items))
	}
	seen := make(map[string]bool)
	for _, attack := range items {
		if seen[attack.ID] {
			t.Fatalf("duplicate attack ID %q", attack.ID)
		}
		seen[attack.ID] = true
		if len(attack.Mechanism) == 0 || len(attack.Signals) == 0 || len(attack.Defenses) == 0 || attack.Ethics == "" {
			t.Fatalf("attack %s lacks required learning context", attack.ID)
		}
	}
}
