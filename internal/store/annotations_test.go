// ABOUTME: Tests annotations: immutable, author-attributed, redacted before
// ABOUTME: persistence, queryable by target ref, durable across reopen (AT-100).
package store_test

import (
	"errors"
	"strings"
	"testing"

	"github.com/2389-research/observatory-v2/internal/redact"
	"github.com/2389-research/observatory-v2/internal/store"
)

func TestAnnotationCreateAndQueryByRef(t *testing.T) {
	s := openStore(t)
	ctx := t.Context()
	vmRef := "vm:" + testUUID(1)

	ann, err := s.CreateAnnotation(ctx, store.AnnotationInput{
		TargetRef: vmRef,
		Author:    "local_operator",
		Text:      "build looked healthy; concluding early",
		Tags:      map[string]string{"verdict": "pass"},
	})
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	if ann.AnnotationID == 0 || ann.Author != "local_operator" || ann.CreatedAt == "" {
		t.Errorf("annotation = %+v", ann)
	}
	if ann.Redacted {
		t.Error("plain text marked redacted")
	}

	// Also annotate an event and a run; query filters by ref (AT-100).
	for _, ref := range []string{"event:1", "run:" + testUUID(2)} {
		if _, err := s.CreateAnnotation(ctx, store.AnnotationInput{
			TargetRef: ref, Author: "local_operator", Text: "note on " + ref,
		}); err != nil {
			t.Fatalf("create %s: %v", ref, err)
		}
	}

	byVM, err := s.ListAnnotations(ctx, store.AnnotationQuery{Ref: vmRef, Limit: 10})
	if err != nil || len(byVM) != 1 || byVM[0].AnnotationID != ann.AnnotationID {
		t.Fatalf("by ref: %+v, %v", byVM, err)
	}
	all, err := s.ListAnnotations(ctx, store.AnnotationQuery{Limit: 10})
	if err != nil || len(all) != 3 {
		t.Fatalf("all: %d, %v", len(all), err)
	}

	// Every annotation is also a durable annotation.created event.
	res, err := s.Query(ctx, store.Query{Kind: "annotation.created"})
	if err != nil || len(res.Events) != 3 {
		t.Fatalf("annotation events: %v, %v", res, err)
	}
	if got, _ := res.Events[0].Data["target_ref"].(string); got != vmRef {
		t.Errorf("event data = %+v", res.Events[0].Data)
	}
}

func TestAnnotationRedactedBeforePersistence(t *testing.T) {
	s := openStore(t)
	ctx := t.Context()

	ann, err := s.CreateAnnotation(ctx, store.AnnotationInput{
		TargetRef: "host:self",
		Author:    "local_operator",
		Text:      "the request used Authorization: Bearer sk-live-verysecret123",
	})
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(ann.Text, "sk-live-verysecret123") {
		t.Fatalf("secret persisted in annotation row: %q", ann.Text)
	}
	if !ann.Redacted || ann.RedactionPolicyID != redact.PolicyID {
		t.Errorf("redaction not recorded: %+v", ann)
	}

	// The durable event must not carry the secret either (SPEC §15.3: redact
	// before persistence, and never store the secret that triggered it).
	res, err := s.Query(ctx, store.Query{Kind: "annotation.created"})
	if err != nil || len(res.Events) != 1 {
		t.Fatal(err)
	}
	ev := res.Events[0]
	if got, _ := ev.Data["text"].(string); strings.Contains(got, "sk-live-verysecret123") {
		t.Errorf("secret persisted in event payload: %q", got)
	}
	if !ev.Quality.Redacted || ev.Quality.RedactionPolicyID != redact.PolicyID {
		t.Errorf("event quality does not record redaction: %+v", ev.Quality)
	}
}

func TestAnnotationBoundsAndRefValidation(t *testing.T) {
	s := openStore(t)
	ctx := t.Context()
	valid := store.AnnotationInput{TargetRef: "vm:" + testUUID(1), Author: "local_operator"}

	long := valid
	long.Text = strings.Repeat("x", store.AnnotationTextMaxBytes+1)
	var bound *store.AnnotationBoundError
	if _, err := s.CreateAnnotation(ctx, long); !errors.As(err, &bound) {
		t.Errorf("oversized text error = %v", err)
	} else if bound.Max != store.AnnotationTextMaxBytes {
		t.Errorf("bound teaches max %d", bound.Max)
	}

	tags := valid
	tags.Text = "ok"
	tags.Tags = map[string]string{}
	for i := 0; i < store.AnnotationMaxTags+1; i++ {
		tags.Tags[strings.Repeat("k", 3)+string(rune('a'+i))] = "v"
	}
	if _, err := s.CreateAnnotation(ctx, tags); !errors.As(err, &bound) {
		t.Errorf("too many tags error = %v", err)
	}

	for _, ref := range []string{"", "vm", "vm:", "spaceship:1", "vm:with space", strings.Repeat("vm:x", 200)} {
		in := valid
		in.Text = "ok"
		in.TargetRef = ref
		if _, err := s.CreateAnnotation(ctx, in); !errors.Is(err, store.ErrInvalidTargetRef) {
			t.Errorf("ref %q error = %v", ref, err)
		}
	}
}

func TestAnnotationsSurviveReopenNoUpdatePath(t *testing.T) {
	dir := t.TempDir()
	path := dir + "/events.sqlite"
	s, err := store.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	ctx := t.Context()
	ann, err := s.CreateAnnotation(ctx, store.AnnotationInput{
		TargetRef: "run:" + testUUID(3), Author: "local_operator", Text: "verdict: fail",
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}

	s2, err := store.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = s2.Close() }()
	got, err := s2.ListAnnotations(ctx, store.AnnotationQuery{Ref: ann.TargetRef, Limit: 10})
	if err != nil || len(got) != 1 {
		t.Fatalf("after reopen: %+v, %v", got, err)
	}
	if got[0].Text != "verdict: fail" || got[0].CreatedAt != ann.CreatedAt {
		t.Errorf("annotation changed across reopen: %+v vs %+v", got[0], ann)
	}
}
