"""Repetition roll-up and comparison semantics."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from uuid import UUID, uuid7

import pytest
from pydantic import ValidationError

from privacy_benchmark.harness.analysis import (
    AnalysisError,
    build_check_rollup,
    classify_outcome,
    compare_rollups,
    wilson_interval,
)
from privacy_benchmark.spec.models import (
    CheckDelta,
    CheckRef,
    CheckResult,
    CheckRollup,
    ComparisonVerdict,
    CompletionState,
    ResultStatus,
    RollupOutcome,
    RunComparison,
    RunRollup,
    StatusTally,
    SubjectRef,
    SubjectRollup,
)

CHECK = CheckRef(check_id="email.remote-content", version="1.0.0")
SUBJECT = SubjectRef(subject_id="apple-mail-gmail", subject_version="1.0.0")
EARLIER = datetime(2026, 9, 25, 12, 30, tzinfo=UTC)
LATER = datetime(2026, 9, 26, 12, 30, tzinfo=UTC)


def _result(
    status: ResultStatus,
    *,
    check_id: str = "email.remote-content",
    subject_id: str = "apple-mail-gmail",
) -> CheckResult:
    started = datetime(2026, 9, 25, 12, 0, tzinfo=UTC)
    return CheckResult(
        result_id=uuid7(),
        run_id=uuid7(),
        execution_id=uuid7(),
        check=CheckRef(check_id=check_id, version="1.0.0"),
        subject=SubjectRef(subject_id=subject_id, subject_version="1.0.0"),
        adapter={"id": "fake", "version": "1.0.0"},
        status=status,
        reason_code="probe.completed",
        summary="Synthetic result for roll-up tests.",
        started_at=started,
        completed_at=started + timedelta(seconds=30),
    )


def _check_rollup(
    *statuses: ResultStatus,
    check: CheckRef = CHECK,
    subject: SubjectRef = SUBJECT,
    expected: int | None = None,
) -> CheckRollup:
    return build_check_rollup(
        check=check,
        subject=subject,
        results=tuple(_result(status) for status in statuses),
        expected_observations=len(statuses) if expected is None else expected,
    )


def _rollup(
    *statuses: ResultStatus,
    check_id: str = "email.remote-content",
    subject_id: str = "apple-mail-gmail",
    subject_version: str = "1.0.0",
    check_version: str = "1.0.0",
    bundle_created_at: datetime = EARLIER,
    bundle_id: UUID | None = None,
) -> RunRollup:
    subject = SubjectRef(subject_id=subject_id, subject_version=subject_version)
    check = _check_rollup(
        *statuses,
        check=CheckRef(check_id=check_id, version=check_version),
        subject=subject,
    )
    return RunRollup(
        rollup_id=uuid7(),
        bundle_id=uuid7() if bundle_id is None else bundle_id,
        suite_id="email.pilot",
        suite_version="1.0.0",
        plan_id=uuid7(),
        created_at=LATER,
        bundle_created_at=bundle_created_at,
        bundle_completion=CompletionState.COMPLETE,
        repetitions=len(statuses),
        subjects=(
            SubjectRollup(
                subject=subject,
                client_version="141.0",
                checks=(check,),
            ),
        ),
    )


class TestClassifyOutcome:
    @pytest.mark.parametrize(
        ("status", "expected"),
        [
            (ResultStatus.PASS, RollupOutcome.PASS),
            (ResultStatus.FAIL, RollupOutcome.FAIL),
            (ResultStatus.NOT_APPLICABLE, RollupOutcome.NOT_APPLICABLE),
            (ResultStatus.UNSUPPORTED, RollupOutcome.UNSUPPORTED),
        ],
    )
    def test_unanimous_status_is_stable(
        self, status: ResultStatus, expected: RollupOutcome
    ) -> None:
        assert classify_outcome((status, status, status)) is expected

    def test_mixed_pass_and_fail_is_flaky(self) -> None:
        assert classify_outcome((ResultStatus.PASS, ResultStatus.FAIL)) is RollupOutcome.FLAKY

    @pytest.mark.parametrize(
        "statuses",
        [
            (ResultStatus.PASS, ResultStatus.INCONCLUSIVE),
            (ResultStatus.FAIL, ResultStatus.ERROR),
            (ResultStatus.PASS, ResultStatus.PARTIAL),
            (ResultStatus.PASS, ResultStatus.NOT_APPLICABLE),
            (ResultStatus.INCONCLUSIVE, ResultStatus.NOT_TESTED),
        ],
    )
    def test_mixed_decisive_and_non_decisive_is_inconclusive(
        self, statuses: tuple[ResultStatus, ResultStatus]
    ) -> None:
        assert classify_outcome(statuses) is RollupOutcome.INCONCLUSIVE

    def test_no_observations_is_incomplete(self) -> None:
        assert classify_outcome(()) is RollupOutcome.INCOMPLETE


class TestUnderSampledGuard:
    def test_missing_repetitions_override_an_otherwise_stable_pass(self) -> None:
        rollup = _check_rollup(ResultStatus.PASS, ResultStatus.PASS, expected=3)
        assert rollup.outcome is RollupOutcome.INCOMPLETE
        assert rollup.pass_rate == 1.0

    def test_observations_are_still_reported_for_an_under_sampled_run(self) -> None:
        rollup = _check_rollup(ResultStatus.PASS, expected=3)
        assert rollup.observations == 1
        assert rollup.expected_observations == 3
        assert rollup.pass_count == 1

    def test_an_under_sampled_failure_is_also_incomplete(self) -> None:
        assert _check_rollup(ResultStatus.FAIL, expected=3).outcome is RollupOutcome.INCOMPLETE


class TestPassRate:
    def test_rate_is_absent_without_a_decisive_observation(self) -> None:
        rollup = _check_rollup(ResultStatus.INCONCLUSIVE)
        assert rollup.pass_rate is None
        assert rollup.pass_rate_low is None
        assert rollup.pass_rate_high is None

    def test_rate_ignores_non_decisive_repetitions(self) -> None:
        rollup = _check_rollup(ResultStatus.PASS, ResultStatus.FAIL, ResultStatus.INCONCLUSIVE)
        assert rollup.decisive_count == 2
        assert rollup.pass_rate == 0.5

    def test_confidence_interval_brackets_the_rate(self) -> None:
        rollup = _check_rollup(ResultStatus.PASS, ResultStatus.FAIL)
        assert rollup.pass_rate_low is not None
        assert rollup.pass_rate_high is not None
        assert rollup.pass_rate_low < 0.5 < rollup.pass_rate_high

    def test_tallies_and_reason_codes_are_collected(self) -> None:
        rollup = _check_rollup(ResultStatus.PASS, ResultStatus.FAIL, ResultStatus.PASS)
        assert {tally.status: tally.count for tally in rollup.statuses} == {
            ResultStatus.PASS: 2,
            ResultStatus.FAIL: 1,
        }
        assert rollup.reason_codes == ("probe.completed",)

    def test_interval_stays_within_the_unit_range(self) -> None:
        low, high = wilson_interval(0, 3)
        assert low == 0.0
        assert 0.0 < high < 1.0
        low, high = wilson_interval(3, 3)
        assert high == 1.0
        assert 0.0 < low < 1.0

    def test_interval_rejects_impossible_counts(self) -> None:
        with pytest.raises(ValueError, match="at least one trial"):
            wilson_interval(0, 0)
        with pytest.raises(ValueError, match="within the trial count"):
            wilson_interval(4, 3)


class TestComparisonVerdicts:
    def test_fail_to_pass_is_an_improvement(self) -> None:
        comparison = compare_rollups(
            _rollup(ResultStatus.FAIL, ResultStatus.FAIL),
            _rollup(ResultStatus.PASS, ResultStatus.PASS, bundle_created_at=LATER),
        )
        assert comparison.improved == 1
        assert comparison.regressed == 0

    def test_pass_to_fail_is_a_regression(self) -> None:
        comparison = compare_rollups(
            _rollup(ResultStatus.PASS, ResultStatus.PASS),
            _rollup(ResultStatus.FAIL, ResultStatus.FAIL, bundle_created_at=LATER),
        )
        assert comparison.regressed == 1
        assert comparison.improved == 0

    def test_stable_equal_outcomes_are_unchanged(self) -> None:
        comparison = compare_rollups(
            _rollup(ResultStatus.FAIL, ResultStatus.FAIL),
            _rollup(ResultStatus.FAIL, ResultStatus.FAIL, bundle_created_at=LATER),
        )
        assert comparison.unchanged == 1

    def test_a_flaky_baseline_is_never_treated_as_an_improvement(self) -> None:
        comparison = compare_rollups(
            _rollup(ResultStatus.PASS, ResultStatus.FAIL),
            _rollup(ResultStatus.PASS, ResultStatus.PASS, bundle_created_at=LATER),
        )
        assert comparison.unorderable == 1
        assert comparison.improved == 0
        assert comparison.regressed == 0

    def test_unsupported_to_pass_is_not_claimed_as_an_improvement(self) -> None:
        comparison = compare_rollups(
            _rollup(ResultStatus.UNSUPPORTED, ResultStatus.UNSUPPORTED),
            _rollup(ResultStatus.PASS, ResultStatus.PASS, bundle_created_at=LATER),
        )
        assert comparison.unorderable == 1

    def test_a_new_check_is_reported_as_added(self) -> None:
        comparison = compare_rollups(
            _rollup(ResultStatus.PASS, check_id="email.remote-content"),
            _rollup(ResultStatus.PASS, check_id="email.dns-prefetch", bundle_created_at=LATER),
        )
        assert comparison.added == 1
        assert comparison.removed == 1

    def test_a_dropped_check_is_reported_as_removed(self) -> None:
        comparison = compare_rollups(
            _rollup(ResultStatus.PASS, check_id="email.remote-content"),
            _rollup(ResultStatus.PASS, check_id="email.dns-prefetch", bundle_created_at=LATER),
        )
        removed = [
            delta for delta in comparison.deltas if delta.verdict is ComparisonVerdict.REMOVED
        ]
        assert [delta.check.check_id for delta in removed] == ["email.remote-content"]

    def test_a_client_version_bump_is_compared_rather_than_split(self) -> None:
        comparison = compare_rollups(
            _rollup(ResultStatus.FAIL, subject_version="1.0.0"),
            _rollup(ResultStatus.PASS, subject_version="1.1.0", bundle_created_at=LATER),
        )
        assert len(comparison.deltas) == 1
        delta = comparison.deltas[0]
        assert delta.verdict is ComparisonVerdict.IMPROVED
        assert delta.version_changed is True
        assert delta.baseline_subject_version == "1.0.0"
        assert delta.candidate_subject_version == "1.1.0"

    def test_differing_check_versions_are_flagged(self) -> None:
        comparison = compare_rollups(
            _rollup(ResultStatus.FAIL, check_version="1.0.0"),
            _rollup(ResultStatus.PASS, check_version="1.1.0", bundle_created_at=LATER),
        )
        assert comparison.deltas[0].version_changed is True

    def test_pass_rates_are_carried_into_the_delta(self) -> None:
        comparison = compare_rollups(
            _rollup(ResultStatus.PASS, ResultStatus.FAIL, ResultStatus.FAIL),
            _rollup(ResultStatus.FAIL, ResultStatus.FAIL, bundle_created_at=LATER),
        )
        delta = comparison.deltas[0]
        assert delta.baseline_pass_rate == pytest.approx(1 / 3, abs=1e-6)
        assert delta.candidate_pass_rate == 0.0

    def test_reverting_the_run_order_is_rejected(self) -> None:
        with pytest.raises(AnalysisError, match="baseline bundle cannot be newer"):
            compare_rollups(
                _rollup(ResultStatus.PASS, bundle_created_at=LATER), _rollup(ResultStatus.PASS)
            )

    def test_comparing_one_bundle_with_itself_is_rejected(self) -> None:
        bundle_id = uuid7()
        with pytest.raises(ValidationError, match="two distinct bundles"):
            compare_rollups(
                _rollup(ResultStatus.PASS, bundle_id=bundle_id),
                _rollup(ResultStatus.PASS, bundle_id=bundle_id, bundle_created_at=LATER),
            )


def _delta(verdict: ComparisonVerdict) -> CheckDelta:
    return CheckDelta(
        check=CHECK,
        subject=SUBJECT,
        verdict=verdict,
        baseline_outcome=RollupOutcome.PASS,
        candidate_outcome=RollupOutcome.FAIL,
    )


def _comparison(
    *deltas: CheckDelta,
    improved: int = 0,
    regressed: int = 0,
    unchanged: int = 0,
    unorderable: int = 0,
    added: int = 0,
    removed: int = 0,
    baseline_created_at: datetime = EARLIER,
    candidate_created_at: datetime = LATER,
) -> dict[str, object]:
    return {
        "comparison_id": uuid7(),
        "created_at": LATER,
        "baseline_bundle_id": uuid7(),
        "candidate_bundle_id": uuid7(),
        "baseline_created_at": baseline_created_at,
        "candidate_created_at": candidate_created_at,
        "baseline_suite": "email.pilot@1.0.0",
        "candidate_suite": "email.pilot@1.0.0",
        "improved": improved,
        "regressed": regressed,
        "unchanged": unchanged,
        "unorderable": unorderable,
        "added": added,
        "removed": removed,
        "deltas": deltas,
    }


class TestComparisonContract:
    def test_verdict_counts_must_match_the_deltas(self) -> None:
        with pytest.raises(ValidationError, match="verdict counts must match"):
            RunComparison.model_validate(_comparison(_delta(ComparisonVerdict.REGRESSED)))

    def test_a_newer_baseline_is_rejected(self) -> None:
        with pytest.raises(ValidationError, match="baseline bundle cannot be newer"):
            RunComparison.model_validate(
                _comparison(
                    _delta(ComparisonVerdict.UNCHANGED),
                    baseline_created_at=LATER,
                    candidate_created_at=EARLIER,
                )
            )

    def test_a_repeated_subject_and_check_pair_is_rejected(self) -> None:
        with pytest.raises(ValidationError, match="may appear only once"):
            RunComparison.model_validate(
                _comparison(
                    _delta(ComparisonVerdict.UNCHANGED),
                    _delta(ComparisonVerdict.UNCHANGED),
                    unchanged=2,
                )
            )

    def test_a_run_must_contain_at_least_one_delta(self) -> None:
        with pytest.raises(ValidationError):
            RunComparison.model_validate(_comparison())

    def test_a_valid_comparison_is_accepted(self) -> None:
        comparison = RunComparison.model_validate(
            _comparison(_delta(ComparisonVerdict.REGRESSED), regressed=1)
        )
        assert comparison.regressed == 1


class TestRollupContract:
    def test_status_tallies_must_sum_to_observations(self) -> None:
        with pytest.raises(ValidationError, match="status tallies must sum"):
            CheckRollup(
                check=CHECK,
                subject=SUBJECT,
                outcome=RollupOutcome.PASS,
                observations=2,
                expected_observations=2,
                pass_count=2,
                fail_count=0,
                decisive_count=2,
                pass_rate=1.0,
                statuses=(StatusTally(status=ResultStatus.PASS, count=1),),
            )

    def test_pass_rate_must_match_the_decisive_counts(self) -> None:
        with pytest.raises(ValidationError, match="pass_rate must equal"):
            CheckRollup(
                check=CHECK,
                subject=SUBJECT,
                outcome=RollupOutcome.PASS,
                observations=2,
                expected_observations=2,
                pass_count=1,
                fail_count=1,
                decisive_count=2,
                pass_rate=1.0,
                statuses=(
                    StatusTally(status=ResultStatus.PASS, count=1),
                    StatusTally(status=ResultStatus.FAIL, count=1),
                ),
            )

    def test_a_rate_without_a_decisive_observation_is_rejected(self) -> None:
        with pytest.raises(ValidationError, match="pass_rate must be absent"):
            CheckRollup(
                check=CHECK,
                subject=SUBJECT,
                outcome=RollupOutcome.INCONCLUSIVE,
                observations=1,
                expected_observations=1,
                pass_count=0,
                fail_count=0,
                decisive_count=0,
                pass_rate=0.0,
                statuses=(StatusTally(status=ResultStatus.INCONCLUSIVE, count=1),),
            )

    def test_confidence_bounds_must_accompany_the_rate(self) -> None:
        with pytest.raises(ValidationError, match="confidence bounds"):
            CheckRollup(
                check=CHECK,
                subject=SUBJECT,
                outcome=RollupOutcome.PASS,
                observations=1,
                expected_observations=1,
                pass_count=1,
                fail_count=0,
                decisive_count=1,
                pass_rate=1.0,
                statuses=(StatusTally(status=ResultStatus.PASS, count=1),),
            )

    def test_decisive_counts_must_reconcile(self) -> None:
        with pytest.raises(ValidationError, match="pass_count plus fail_count"):
            CheckRollup(
                check=CHECK,
                subject=SUBJECT,
                outcome=RollupOutcome.PASS,
                observations=1,
                expected_observations=1,
                pass_count=1,
                fail_count=0,
                decisive_count=2,
            )

    def test_decisive_counts_cannot_exceed_observations(self) -> None:
        with pytest.raises(ValidationError, match="cannot exceed observations"):
            CheckRollup(
                check=CHECK,
                subject=SUBJECT,
                outcome=RollupOutcome.PASS,
                observations=0,
                expected_observations=1,
                pass_count=1,
                fail_count=0,
                decisive_count=1,
                statuses=(StatusTally(status=ResultStatus.PASS, count=1),),
            )

    def test_rollup_expectations_must_match_planned_repetitions(self) -> None:
        check = _check_rollup(ResultStatus.PASS, expected=3)
        with pytest.raises(ValidationError, match="match planned repetitions"):
            RunRollup(
                rollup_id=uuid7(),
                bundle_id=uuid7(),
                suite_id="email.pilot",
                suite_version="1.0.0",
                plan_id=uuid7(),
                created_at=LATER,
                bundle_created_at=EARLIER,
                bundle_completion=CompletionState.COMPLETE,
                repetitions=2,
                subjects=(SubjectRollup(subject=SUBJECT, checks=(check,)),),
            )
