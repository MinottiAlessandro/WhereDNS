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
		if attack.Flow.Title == "" || attack.Flow.Caption == "" || len(attack.Flow.Actors) < 3 || len(attack.Flow.Events) < 3 {
			t.Fatalf("attack %s lacks a complete visualization", attack.ID)
		}
		actors := make(map[string]bool)
		for _, actor := range attack.Flow.Actors {
			if actor.ID == "" || actor.Label == "" || actor.Role == "" || actor.Kind == "" || actors[actor.ID] {
				t.Fatalf("attack %s has an invalid visualization actor %#v", attack.ID, actor)
			}
			actors[actor.ID] = true
		}
		for _, event := range attack.Flow.Events {
			if !actors[event.From] || !actors[event.To] || event.Label == "" || event.Detail == "" || event.Kind == "" {
				t.Fatalf("attack %s has an invalid visualization event %#v", attack.ID, event)
			}
		}
	}
}
