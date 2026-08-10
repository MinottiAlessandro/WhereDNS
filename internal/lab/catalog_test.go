package lab

import "testing"

func TestEveryScenarioIsRunnableAndSafe(t *testing.T) {
	for _, scenario := range Scenarios() {
		if scenario.Safety == "" || len(scenario.Steps) < 3 {
			t.Fatalf("scenario %s lacks safety text or useful steps", scenario.ID)
		}
		run, err := Run(scenario.ID)
		if err != nil {
			t.Fatalf("Run(%s): %v", scenario.ID, err)
		}
		if run.Scenario.ID != scenario.ID || len(run.StudentChecks) == 0 {
			t.Fatalf("scenario %s returned incomplete exercise", scenario.ID)
		}
	}
}

func TestLiveServerRejectsNonLoopback(t *testing.T) {
	if err := Serve(t.Context(), "basic", "0.0.0.0:15353"); err == nil {
		t.Fatal("expected non-loopback listen address to be rejected")
	}
}
