<!--
PR description goes here. Reference the spec / design doc / FOLLOWUPS
item / audit finding / phase task the PR addresses; one or two
sentences focused on the "why" rather than the "what". See
`.cursor/rules/90-commits.mdc` for commit-message discipline.
-->

## Summary

<!-- 1–3 bullets describing what this PR does and why. -->

## Test plan

<!-- Checklist of what you ran locally / what CI is asserting. -->

## RandomX v2 differential-harness discipline (per `docs/design/RANDOMX_V2_PHASE2G_PLAN.md` §4.6 M3)

The three checkboxes below activate on PRs that modify any of:

- `rust/shekyl-randomx-differential/**`
- `rust/randomx-v2-sys/**`
- `.github/workflows/randomx-v2-*.yml`
- `rust/shekyl-pow-randomx/**` (verifier — second + third items only)

If your PR touches none of these paths, mark "N/A" and skip the
section. Otherwise cite the substrate the modification rests on.

- [ ] **Harness-modification amendment cite.** If this PR modifies
      `rust/shekyl-randomx-differential/`, `rust/randomx-v2-sys/`,
      `external/randomx-v2/`, `.github/workflows/randomx-v2-*.yml`,
      or any harness-canonical-output / assertion / corpus /
      dispatch surface, cite the design-doc amendment authorizing
      the modification (e.g., `RANDOMX_V2_PHASE2G_PLAN.md §<#>
      R<round>-D<#>` or a forthcoming Phase 2h / V3.x amendment).
      Per §5.7 + §8.3 drift-prevention, any surface beyond the
      §5.1–§5.5 contract requires a substrate amendment before
      the implementation lands.

- [ ] **Verifier-modification audit-line-range cite.** If this PR
      modifies the verifier crate (`rust/shekyl-pow-randomx/`),
      cite the `external/randomx-v2/` line range that the change
      matches against (per §4.5 T-A11 + §4.3 three-leg audit-
      posture discharge). The audit cite is the substrate; the
      Rust change is the consequence. PRs without a line-range
      cite are not audit-against-actual-code-discharged and
      cannot claim spec-faithfulness on the verifier surface.

- [ ] **Harness-pass-as-evidence caveat.** If this PR cites "the
      differential harness passes" as evidence for a change, also
      cite the audit-against-actual-code line range. The harness
      is the leg-3 backstop (per §2.5 + §4.3 three-leg framing);
      it is **not** spec-faithfulness evidence by itself. A
      passing harness with no audit-line-range cite is a §4.5
      T-A11-class discipline failure auditable at review time.

<!--
Note for non-RandomX-touching PRs: the section is convention-
enforced and intended to surface the discipline at PR-open time.
If your PR doesn't touch the RandomX v2 differential-harness
surface, deleting the entire section is acceptable; leaving it
with "N/A" boxes is also acceptable. Reviewers will flag PRs
that touch the listed paths but elide the discipline section.
-->
