from base64 import urlsafe_b64decode
from collections.abc import Callable, Iterator
from contextlib import contextmanager
from datetime import UTC, datetime, timedelta
from hashlib import sha256
from uuid import UUID, uuid4

import pytest
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session, sessionmaker

from threat_sentinel_api.db import session as database_session
from threat_sentinel_api.modules.audit.models import SecurityAuditEvent
from threat_sentinel_api.modules.identity.models import ExternalIdentity, User
from threat_sentinel_api.modules.identity.schemas import AuthenticatedPrincipal
from threat_sentinel_api.modules.targets.dns_verification import DNSVerificationError
from threat_sentinel_api.modules.targets.hostname import HostnameCanonicalizationError
from threat_sentinel_api.modules.targets.models import (
    SecurityTarget,
    TargetVerificationChallenge,
)
from threat_sentinel_api.modules.targets.service import (
    TargetConflict,
    TargetVerificationFailed,
    TargetService,
)
from threat_sentinel_api.modules.tenants.authorization import (
    OrganizationScanAction,
    OrganizationTargetAction,
    allows_organization_scan_action,
    allows_organization_target_action,
)
from threat_sentinel_api.modules.tenants.enums import (
    MembershipStatus,
    OrganizationRole,
)
from threat_sentinel_api.modules.tenants.models import Organization, OrganizationMembership
from threat_sentinel_api.modules.tenants.service import (
    OrganizationPermissionDenied,
    OrganizationScopeUnavailable,
)

ISSUER = "https://target-tests.example"


class FakeDNSVerifier:
    def __init__(self, challenge_value: str) -> None:
        self.challenge_hash = sha256(challenge_value.encode("ascii")).hexdigest()
        self.calls: list[tuple[str, str]] = []

    def verify_challenge(self, hostname: str, expected_hash: str) -> None:
        self.calls.append((hostname, expected_hash))
        if expected_hash != self.challenge_hash:
            raise DNSVerificationError()


class CallbackDNSVerifier:
    def __init__(self, callback: Callable[[], None]) -> None:
        self._callback = callback
        self.calls: list[tuple[str, str]] = []

    def verify_challenge(self, hostname: str, expected_hash: str) -> None:
        self.calls.append((hostname, expected_hash))
        self._callback()


class UnexpectedDNSVerifier:
    def verify_challenge(self, hostname: str, expected_hash: str) -> None:
        raise RuntimeError("resolver internal detail")


class FatalDNSVerifier:
    def verify_challenge(self, hostname: str, expected_hash: str) -> None:
        raise KeyboardInterrupt


def create_organization_principal(
    session: Session,
    make_user: Callable[..., User],
    *,
    role: OrganizationRole = OrganizationRole.OWNER,
) -> tuple[Organization, AuthenticatedPrincipal, User]:
    subject = f"target-user-{uuid4()}"
    user = make_user(issuer=ISSUER, subject=subject)
    identity_id = session.scalar(
        select(ExternalIdentity.id).where(ExternalIdentity.user_id == user.id)
    )
    assert identity_id is not None
    principal = AuthenticatedPrincipal(
        user_id=user.id,
        external_identity_id=identity_id,
        issuer=ISSUER,
        subject=subject,
    )
    organization = Organization(
        name=f"Target organization {uuid4()}",
        slug=f"target-{uuid4()}",
        created_by_user_id=user.id,
    )
    session.add(organization)
    session.flush()
    session.add(
        OrganizationMembership(
            organization_id=organization.id,
            user_id=user.id,
            role=role,
            status=MembershipStatus.ACTIVE,
        )
    )
    session.flush()
    return organization, principal, user


def target_service(
    session: Session,
    dns_verifier: (
        FakeDNSVerifier | CallbackDNSVerifier | UnexpectedDNSVerifier | FatalDNSVerifier | None
    ) = None,
) -> TargetService:
    return TargetService(
        sessionmaker(bind=session.get_bind(), expire_on_commit=False),
        dns_verifier=dns_verifier,
    )


def get_challenge(
    session: Session,
    target_id: UUID,
) -> TargetVerificationChallenge:
    challenge = session.scalar(
        select(TargetVerificationChallenge).where(
            TargetVerificationChallenge.target_id == target_id
        )
    )
    assert challenge is not None
    return challenge


def add_target_row(
    session: Session,
    organization: Organization,
    user: User,
    hostname: str = "example.com",
) -> SecurityTarget:
    target = SecurityTarget(
        organization_id=organization.id,
        hostname=hostname,
        created_by_user_id=user.id,
    )
    session.add(target)
    session.flush()
    return target


@pytest.mark.parametrize(
    "role",
    [OrganizationRole.OWNER, OrganizationRole.ADMIN],
    ids=["owner", "admin"],
)
def test_target_creation_canonicalizes_and_stores_only_challenge_hash(
    session: Session,
    make_user: Callable[..., User],
    role: OrganizationRole,
) -> None:
    organization, principal, _ = create_organization_principal(
        session,
        make_user,
        role=role,
    )
    session.commit()

    issued = target_service(session).create_organization_target(
        principal,
        organization.id,
        "BÜCHER.example.",
    )

    assert issued.hostname == "xn--bcher-kva.example"
    assert len(urlsafe_b64decode(issued.challenge_value + "==")) == 32
    assert issued.challenge_value not in repr(issued)
    with Session(session.get_bind()) as verification_session:
        target = verification_session.get(SecurityTarget, issued.target_id)
        assert target is not None
        assert target.verified_at is None
        challenge = get_challenge(verification_session, issued.target_id)
        assert (
            challenge.challenge_hash == sha256(issued.challenge_value.encode("ascii")).hexdigest()
        )
        assert challenge.challenge_hash != issued.challenge_value
        assert issued.challenge_value not in repr(challenge)
        event = verification_session.scalar(
            select(SecurityAuditEvent).where(
                SecurityAuditEvent.target_id == issued.target_id,
                SecurityAuditEvent.action == "organization.target.created",
            )
        )
        assert event is not None
        assert event.details is None
        assert issued.challenge_value not in repr(event)


def test_persisted_challenge_expires_one_hour_after_creation(
    session: Session,
    make_user: Callable[..., User],
) -> None:
    organization, principal, _ = create_organization_principal(session, make_user)
    session.commit()
    clock_before_issue = datetime.now(UTC)
    issued = target_service(session).create_organization_target(
        principal,
        organization.id,
        "example.com",
    )
    clock_after_issue = datetime.now(UTC)

    with Session(session.get_bind()) as verification_session:
        challenge = get_challenge(verification_session, issued.target_id)
        created_at = challenge.created_at.replace(tzinfo=UTC)
        expires_at = challenge.expires_at.replace(tzinfo=UTC)

    assert expires_at - created_at == timedelta(hours=1)
    clock_tolerance = timedelta(seconds=5)
    assert clock_before_issue - clock_tolerance <= created_at
    assert created_at <= clock_after_issue + clock_tolerance


@pytest.mark.parametrize("hash_length", [63, 65], ids=["too-short", "too-long"])
def test_challenge_hash_must_have_exactly_64_characters(
    session: Session,
    make_user: Callable[..., User],
    hash_length: int,
) -> None:
    organization, _, user = create_organization_principal(session, make_user)
    target = add_target_row(session, organization, user)
    created_at = datetime.now(UTC)
    session.add(
        TargetVerificationChallenge(
            organization_id=organization.id,
            target_id=target.id,
            issued_by_user_id=user.id,
            challenge_hash="a" * hash_length,
            created_at=created_at,
            expires_at=created_at + timedelta(hours=1),
        )
    )

    with pytest.raises(IntegrityError):
        session.flush()


@pytest.mark.parametrize(
    "expiry_offset",
    [timedelta(0), timedelta(seconds=-1)],
    ids=["equal-to-creation", "earlier-than-creation"],
)
def test_challenge_expiry_must_be_after_creation(
    session: Session,
    make_user: Callable[..., User],
    expiry_offset: timedelta,
) -> None:
    organization, _, user = create_organization_principal(session, make_user)
    target = add_target_row(session, organization, user)
    created_at = datetime.now(UTC)
    session.add(
        TargetVerificationChallenge(
            organization_id=organization.id,
            target_id=target.id,
            issued_by_user_id=user.id,
            challenge_hash="a" * 64,
            created_at=created_at,
            expires_at=created_at + expiry_offset,
        )
    )

    with pytest.raises(IntegrityError):
        session.flush()


def test_target_cannot_have_multiple_challenge_rows(
    session: Session,
    make_user: Callable[..., User],
) -> None:
    organization, _, user = create_organization_principal(session, make_user)
    target = add_target_row(session, organization, user)
    created_at = datetime.now(UTC)
    session.add(
        TargetVerificationChallenge(
            organization_id=organization.id,
            target_id=target.id,
            issued_by_user_id=user.id,
            challenge_hash="a" * 64,
            created_at=created_at,
            expires_at=created_at + timedelta(hours=1),
        )
    )
    session.flush()
    session.add(
        TargetVerificationChallenge(
            organization_id=organization.id,
            target_id=target.id,
            issued_by_user_id=user.id,
            challenge_hash="b" * 64,
            created_at=created_at,
            expires_at=created_at + timedelta(hours=1),
        )
    )

    with pytest.raises(IntegrityError):
        session.flush()


def test_challenge_hash_must_be_unique(
    session: Session,
    make_user: Callable[..., User],
) -> None:
    organization, _, user = create_organization_principal(session, make_user)
    first_target = add_target_row(session, organization, user, "first.example.com")
    second_target = add_target_row(session, organization, user, "second.example.com")
    created_at = datetime.now(UTC)
    for target in (first_target, second_target):
        session.add(
            TargetVerificationChallenge(
                organization_id=organization.id,
                target_id=target.id,
                issued_by_user_id=user.id,
                challenge_hash="a" * 64,
                created_at=created_at,
                expires_at=created_at + timedelta(hours=1),
            )
        )

    with pytest.raises(IntegrityError):
        session.flush()


@pytest.mark.parametrize(
    "hostname",
    [
        "https://example.com",
        "*.example.com",
        "127.0.0.1",
        "0177.0.0.1",
        "example.com/path",
    ],
)
def test_target_creation_rejects_non_hostname_input_without_persisting(
    session: Session,
    make_user: Callable[..., User],
    hostname: str,
) -> None:
    organization, principal, _ = create_organization_principal(session, make_user)
    session.commit()

    with pytest.raises(HostnameCanonicalizationError) as error:
        target_service(session).create_organization_target(
            principal,
            organization.id,
            hostname,
        )

    assert hostname not in str(error.value)
    with Session(session.get_bind()) as verification_session:
        assert (
            verification_session.scalar(
                select(SecurityTarget.id).where(SecurityTarget.organization_id == organization.id)
            )
            is None
        )


def test_owner_and_admin_can_manage_targets_but_phase_two_scan_policy_is_unchanged() -> None:
    for action in OrganizationTargetAction:
        assert all(
            allows_organization_target_action(role, action)
            for role in (OrganizationRole.OWNER, OrganizationRole.ADMIN)
        )
        assert not allows_organization_target_action(OrganizationRole.MEMBER, action)
        assert not allows_organization_target_action(OrganizationRole.VIEWER, action)
    assert allows_organization_scan_action(
        OrganizationRole.MEMBER,
        OrganizationScanAction.CREATE,
    )
    assert allows_organization_scan_action(
        OrganizationRole.VIEWER,
        OrganizationScanAction.READ,
    )


def test_member_cannot_create_organization_target(
    session: Session,
    make_user: Callable[..., User],
) -> None:
    organization, principal, _ = create_organization_principal(
        session,
        make_user,
        role=OrganizationRole.MEMBER,
    )
    session.commit()

    with pytest.raises(OrganizationPermissionDenied):
        target_service(session).create_organization_target(
            principal,
            organization.id,
            "example.com",
        )

    with Session(session.get_bind()) as verification_session:
        assert (
            verification_session.scalar(
                select(SecurityTarget.id).where(SecurityTarget.organization_id == organization.id)
            )
            is None
        )


def test_duplicate_canonical_hostname_is_unique_within_organization(
    session: Session,
    make_user: Callable[..., User],
) -> None:
    organization, principal, user = create_organization_principal(session, make_user)
    session.commit()
    service = target_service(session)
    service.create_organization_target(principal, organization.id, "Example.COM.")

    with pytest.raises(TargetConflict):
        service.create_organization_target(principal, organization.id, "example.com")

    with Session(session.get_bind()) as verification_session:
        verification_session.add(
            SecurityTarget(
                organization_id=organization.id,
                hostname="example.com",
                created_by_user_id=user.id,
            )
        )
        with pytest.raises(IntegrityError):
            verification_session.flush()


def test_rotation_invalidates_old_challenge_and_dns_verification_is_one_time(
    session: Session,
    make_user: Callable[..., User],
) -> None:
    organization, principal, _ = create_organization_principal(session, make_user)
    session.commit()
    service = target_service(session)
    initial = service.create_organization_target(principal, organization.id, "example.com")
    rotated = service.rotate_challenge(principal, organization.id, initial.target_id)

    with Session(session.get_bind()) as verification_session:
        challenges = list(
            verification_session.scalars(
                select(TargetVerificationChallenge).where(
                    TargetVerificationChallenge.target_id == initial.target_id
                )
            ).all()
        )
        assert len(challenges) == 1
        assert (
            challenges[0].challenge_hash
            == sha256(rotated.challenge_value.encode("ascii")).hexdigest()
        )
        assert (
            challenges[0].challenge_hash
            != sha256(initial.challenge_value.encode("ascii")).hexdigest()
        )

    stale_verifier = FakeDNSVerifier(initial.challenge_value)
    stale_service = target_service(session, stale_verifier)
    with pytest.raises(TargetVerificationFailed):
        stale_service.verify_organization_target(principal, organization.id, initial.target_id)

    successful_service = target_service(session, FakeDNSVerifier(rotated.challenge_value))
    verified_at = successful_service.verify_organization_target(
        principal,
        organization.id,
        initial.target_id,
    )
    with pytest.raises(TargetVerificationFailed):
        successful_service.verify_organization_target(
            principal,
            organization.id,
            initial.target_id,
        )

    with Session(session.get_bind()) as verification_session:
        target = verification_session.get(SecurityTarget, initial.target_id)
        assert target is not None
        assert target.verified_at is not None
        assert target.verified_at.replace(tzinfo=UTC) == verified_at
        verification_event = verification_session.scalar(
            select(SecurityAuditEvent).where(
                SecurityAuditEvent.target_id == initial.target_id,
                SecurityAuditEvent.action == "organization.target.verified",
            )
        )
        assert verification_event is not None
        assert verification_event.details is None
        assert rotated.challenge_value not in repr(verification_event)
        assert (
            verification_session.scalar(
                select(TargetVerificationChallenge.id).where(
                    TargetVerificationChallenge.target_id == initial.target_id
                )
            )
            is None
        )


def test_expired_challenge_is_rejected_before_dns_resolution(
    session: Session,
    make_user: Callable[..., User],
) -> None:
    organization, principal, _ = create_organization_principal(session, make_user)
    session.commit()
    service = target_service(session)
    issued = service.create_organization_target(principal, organization.id, "example.com")
    with Session(session.get_bind()) as update_session:
        challenge = get_challenge(update_session, issued.target_id)
        challenge.created_at = datetime.now(UTC) - timedelta(days=2)
        challenge.expires_at = datetime.now(UTC) - timedelta(seconds=1)
        update_session.commit()
    verifier = FakeDNSVerifier(issued.challenge_value)
    service = target_service(session, verifier)

    with pytest.raises(TargetVerificationFailed):
        service.verify_organization_target(principal, organization.id, issued.target_id)
    assert verifier.calls == []

    with Session(session.get_bind()) as verification_session:
        target = verification_session.get(SecurityTarget, issued.target_id)
        assert target is not None
        assert target.verified_at is None
        assert (
            verification_session.scalar(
                select(TargetVerificationChallenge.id).where(
                    TargetVerificationChallenge.target_id == issued.target_id
                )
            )
            is not None
        )


def test_unexpected_dns_verifier_exception_becomes_generic_service_error(
    session: Session,
    make_user: Callable[..., User],
) -> None:
    organization, principal, _ = create_organization_principal(session, make_user)
    session.commit()
    issued = target_service(session).create_organization_target(
        principal,
        organization.id,
        "example.com",
    )

    with pytest.raises(TargetVerificationFailed) as error:
        target_service(session, UnexpectedDNSVerifier()).verify_organization_target(
            principal,
            organization.id,
            issued.target_id,
        )

    assert str(error.value) == "DNS ownership verification failed."
    assert error.value.__cause__ is None
    assert error.value.__suppress_context__
    assert "resolver internal detail" not in str(error.value)


def test_dns_verifier_does_not_catch_base_exception(
    session: Session,
    make_user: Callable[..., User],
) -> None:
    organization, principal, _ = create_organization_principal(session, make_user)
    session.commit()
    issued = target_service(session).create_organization_target(
        principal,
        organization.id,
        "example.com",
    )

    with pytest.raises(KeyboardInterrupt):
        target_service(session, FatalDNSVerifier()).verify_organization_target(
            principal,
            organization.id,
            issued.target_id,
        )


def test_revoked_challenge_cannot_be_verified(
    session: Session,
    make_user: Callable[..., User],
) -> None:
    organization, principal, _ = create_organization_principal(session, make_user)
    session.commit()
    service = target_service(session)
    issued = service.create_organization_target(principal, organization.id, "example.com")
    with Session(session.get_bind()) as verification_session:
        challenge_id = get_challenge(verification_session, issued.target_id).id

    assert service.revoke_challenge(
        principal,
        organization.id,
        issued.target_id,
        challenge_id,
    )
    verifier = FakeDNSVerifier(issued.challenge_value)
    with pytest.raises(TargetVerificationFailed):
        target_service(session, verifier).verify_organization_target(
            principal,
            organization.id,
            issued.target_id,
        )
    assert verifier.calls == []
    with Session(session.get_bind()) as verification_session:
        assert (
            verification_session.scalar(
                select(TargetVerificationChallenge.id).where(
                    TargetVerificationChallenge.target_id == issued.target_id
                )
            )
            is None
        )


@pytest.mark.parametrize("during_dns", ["rotate", "revoke", "expire"])
def test_challenge_changes_during_dns_invalidate_verification_without_open_transaction(
    session: Session,
    make_user: Callable[..., User],
    monkeypatch: pytest.MonkeyPatch,
    during_dns: str,
) -> None:
    organization, principal, _ = create_organization_principal(session, make_user)
    session.commit()
    service = target_service(session)
    issued = service.create_organization_target(principal, organization.id, "example.com")
    with Session(session.get_bind()) as verification_session:
        challenge_id = get_challenge(verification_session, issued.target_id).id

    original_unit_of_work = database_session.unit_of_work
    active_transactions = 0

    @contextmanager
    def tracked_unit_of_work(session_factory=None) -> Iterator[Session]:
        nonlocal active_transactions
        with original_unit_of_work(session_factory) as work_session:
            active_transactions += 1
            try:
                yield work_session
            finally:
                active_transactions -= 1

    monkeypatch.setattr(
        "threat_sentinel_api.modules.targets.service.unit_of_work",
        tracked_unit_of_work,
    )

    def change_challenge() -> None:
        assert active_transactions == 0
        if during_dns == "rotate":
            service.rotate_challenge(principal, organization.id, issued.target_id)
        elif during_dns == "revoke":
            assert service.revoke_challenge(
                principal,
                organization.id,
                issued.target_id,
                challenge_id,
            )
        else:
            with Session(session.get_bind()) as update_session:
                challenge = get_challenge(update_session, issued.target_id)
                challenge.created_at = datetime.now(UTC) - timedelta(days=2)
                challenge.expires_at = datetime.now(UTC) - timedelta(seconds=1)
                update_session.commit()

    verifier = CallbackDNSVerifier(change_challenge)
    verification_service = target_service(session, verifier)
    with pytest.raises(TargetVerificationFailed):
        verification_service.verify_organization_target(
            principal,
            organization.id,
            issued.target_id,
        )

    assert verifier.calls == [
        ("example.com", sha256(issued.challenge_value.encode("ascii")).hexdigest())
    ]
    with Session(session.get_bind()) as verification_session:
        target = verification_session.get(SecurityTarget, issued.target_id)
        assert target is not None
        assert target.verified_at is None
        challenge = verification_session.scalar(
            select(TargetVerificationChallenge).where(
                TargetVerificationChallenge.target_id == issued.target_id
            )
        )
        if during_dns == "rotate":
            assert challenge is not None
            assert (
                challenge.challenge_hash
                != sha256(issued.challenge_value.encode("ascii")).hexdigest()
            )
        elif during_dns == "revoke":
            assert challenge is None
        else:
            assert challenge is not None


def test_member_cannot_verify_an_organization_target(
    session: Session,
    make_user: Callable[..., User],
) -> None:
    organization, owner_principal, _ = create_organization_principal(session, make_user)
    session.commit()
    issued = target_service(session).create_organization_target(
        owner_principal,
        organization.id,
        "example.com",
    )
    subject = f"target-member-{uuid4()}"
    member = make_user(issuer=ISSUER, subject=subject)
    identity_id = session.scalar(
        select(ExternalIdentity.id).where(ExternalIdentity.user_id == member.id)
    )
    assert identity_id is not None
    session.add(
        OrganizationMembership(
            organization_id=organization.id,
            user_id=member.id,
            role=OrganizationRole.MEMBER,
            status=MembershipStatus.ACTIVE,
        )
    )
    session.commit()
    member_principal = AuthenticatedPrincipal(
        user_id=member.id,
        external_identity_id=identity_id,
        issuer=ISSUER,
        subject=subject,
    )
    verifier = FakeDNSVerifier(issued.challenge_value)

    with pytest.raises(OrganizationPermissionDenied):
        target_service(session, verifier).verify_organization_target(
            member_principal,
            organization.id,
            issued.target_id,
        )

    assert verifier.calls == []


def test_challenge_and_target_queries_are_organization_scoped(
    session: Session,
    make_user: Callable[..., User],
) -> None:
    first_organization, principal, user = create_organization_principal(session, make_user)
    second_organization, _, _ = create_organization_principal(session, make_user)
    session.commit()
    issued = target_service(session).create_organization_target(
        principal,
        first_organization.id,
        "example.com",
    )

    with Session(session.get_bind()) as verification_session:
        from threat_sentinel_api.modules.targets.repository import TargetRepository

        repository = TargetRepository(verification_session)
        assert repository.find_by_id(issued.target_id, second_organization.id) is None
        verification_session.add(
            TargetVerificationChallenge(
                organization_id=second_organization.id,
                target_id=issued.target_id,
                issued_by_user_id=user.id,
                challenge_hash="a" * 64,
                expires_at=datetime.now(UTC) + timedelta(hours=1),
            )
        )
        with pytest.raises(IntegrityError):
            verification_session.flush()


def test_same_canonical_hostname_can_be_owned_by_different_organizations(
    session: Session,
    make_user: Callable[..., User],
) -> None:
    first_organization, first_principal, _ = create_organization_principal(session, make_user)
    second_organization, second_principal, _ = create_organization_principal(session, make_user)
    session.commit()
    service = target_service(session)

    first = service.create_organization_target(
        first_principal,
        first_organization.id,
        "example.com",
    )
    second = service.create_organization_target(
        second_principal,
        second_organization.id,
        "example.com",
    )

    assert first.target_id != second.target_id


def test_verification_does_not_accept_another_organizations_scope(
    session: Session,
    make_user: Callable[..., User],
) -> None:
    first_organization, principal, _ = create_organization_principal(session, make_user)
    second_organization, _, _ = create_organization_principal(session, make_user)
    session.commit()
    issued = target_service(session).create_organization_target(
        principal,
        first_organization.id,
        "example.com",
    )
    with pytest.raises(OrganizationScopeUnavailable):
        target_service(session, FakeDNSVerifier(issued.challenge_value)).verify_organization_target(
            principal,
            second_organization.id,
            issued.target_id,
        )
