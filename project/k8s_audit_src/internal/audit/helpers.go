package audit

import (
	"sort"
	"strings"
)

func uniqStrings(in []string) []string {
	m := map[string]struct{}{}
	for _, s := range in {
		s = strings.TrimSpace(s)
		if s == "" {
			continue
		}
		m[s] = struct{}{}
	}
	out := make([]string, 0, len(m))
	for s := range m {
		out = append(out, s)
	}
	sort.Strings(out)
	return out
}

func containsAny(hay []string, needles ...string) bool {
	set := map[string]struct{}{}
	for _, h := range hay {
		set[h] = struct{}{}
	}
	for _, n := range needles {
		if _, ok := set[n]; ok {
			return true
		}
	}
	return false
}

func hasStar(list []string) bool {
	for _, s := range list {
		if s == "*" {
			return true
		}
	}
	return false
}
