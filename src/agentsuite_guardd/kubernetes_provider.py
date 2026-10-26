"""Orka's generic RPC backed by independently resolved native container controls."""
import base64
import hashlib
import json
import logging
import os
import sqlite3

import grpc
from orka_enforcement.v1 import enforcement_pb2 as wire
from orka_enforcement.v1 import enforcement_pb2_grpc as rpc

from .enforcement_protocol import requirement_digest, target_facts_digest, validate_request
from .container_policy import FORMAT as CONTAINER_FORMAT
from .kubernetes_target import PHYSICAL_FORMAT, TargetPending
from .model import policy_digest
from .neutral_service import canonical, requirement, same_cgroup_object, TargetNotStopped
from .target import boot_id


def refusal_reason(error):
    reason = str(error).strip() or type(error).__name__
    # The wire bound is bytes, not characters; discard only a split UTF-8 tail.
    return reason.encode("utf-8", errors="replace")[:4096].decode("utf-8", errors="ignore").rstrip()


def log_refusal(operation, binding, error):
    trace = error.__traceback__
    while trace is not None and trace.tb_next is not None:
        trace = trace.tb_next
    site = None if trace is None else (
        os.path.basename(trace.tb_frame.f_code.co_filename),
        trace.tb_frame.f_code.co_name, trace.tb_lineno,
    )
    logging.getLogger(__name__).warning(
        "enforcement %s refused binding=%r error_type=%s site=%r",
        operation, binding[:128], type(error).__name__, site,
    )


class RequirementRefused(ValueError):
    def __init__(self, message, needs):
        super().__init__(message)
        self.needs = needs


def same_native_target(left, right):
    return (
        same_cgroup_object(
            {key: left[key] for key in ("boot", "cgroup")},
            {key: right[key] for key in ("boot", "cgroup")},
        )
        and all(left[key] == right[key] for key in ("pid", "start", "netns", "generation"))
    )


class KubernetesEnforcementProvider(rpc.EnforcementProviderServicer):
    def __init__(self, service, resolver, allowed_client_identities):
        if not allowed_client_identities:
            raise ValueError("explicit controller certificate SAN allowlist required")
        self.service, self.resolver = service, resolver
        self.allowed_clients = {item.encode("utf-8") for item in allowed_client_identities}
        self.handles = {}
        with service.db:
            service.db.execute(
                "CREATE TABLE IF NOT EXISTS provider_bindings ("
                "binding TEXT PRIMARY KEY, request BLOB, native_request BLOB, "
                "physical BLOB, phase TEXT NOT NULL, stop_proof BLOB)"
            )

    def close(self):
        for fd in self.handles.values():
            os.close(fd)
        self.handles.clear()

    def row(self, binding):
        return self.service.db.execute(
            "SELECT request,native_request,physical,phase FROM provider_bindings WHERE binding=?",
            (binding,),
        ).fetchone()

    def authorize(self, context):
        identities = context.auth_context().get("x509_subject_alternative_name", ())
        if not self.allowed_clients.intersection(identities):
            context.abort(grpc.StatusCode.PERMISSION_DENIED, "controller certificate identity required")

    def EnsureEnforced(self, request, context):
        self.authorize(context)
        try:
            return self.ensure(request)
        except TargetPending as error:
            return wire.EnsureResponse(pending=wire.Pending(reason=str(error)))
        except ValueError as error:
            log_refusal("ensure", request.binding_id, error)
            needs = error.needs if isinstance(error, RequirementRefused) else ("operator-configuration",)
            return wire.EnsureResponse(refused=wire.Refused(reason=refusal_reason(error), needs=needs))
        except (OSError, RuntimeError, sqlite3.Error) as error:
            logging.getLogger(__name__).error(
                "enforcement ensure uncertain binding=%s error_type=%s",
                request.binding_id, type(error).__name__, exc_info=True,
            )
            context.abort(grpc.StatusCode.UNAVAILABLE, "native enforcement state uncertain; retry the same binding")

    def ensure(self, request):
        validate_request(request)
        if request.requirement.format not in {"agentsuite.policy/v1", CONTAINER_FORMAT}:
            raise RequirementRefused("unsupported complete policy format", ("supported-format",))
        if self.service.backend({"format": request.requirement.format}) is None:
            raise RequirementRefused("complete policy requires its configured native backend", ("configured-backend",))
        blob = request.SerializeToString(deterministic=True)
        native_requirement = dict(
            format=request.requirement.format,
            bytes=base64.b64encode(request.requirement.policy).decode("ascii"),
            digest=policy_digest(request.requirement.policy),
            capabilities=list(request.requirement.required_capabilities),
        )
        # Validate the complete submitted policy; never split or rewrite it.
        try:
            requirement(native_requirement)
        except ValueError as error:
            raise RequirementRefused(str(error), ("complete-policy",)) from error
        with self.service.lock:
            prior = self.row(request.binding_id)
            if prior is not None:
                if prior[3] == "RETIRED":
                    raise ValueError("retired binding is permanently cleanup-only")
                if bytes(prior[0]) != blob:
                    raise ValueError("binding cannot change its complete requirement or target facts")
            with self.resolver.resolve(request.target_facts) as resolved, resolved.live():
                native_request = dict(
                    version="execution-enforcement/v1", method="activate",
                    operation=request.binding_id, requirement=native_requirement, target=resolved.target,
                )
                if prior is None:
                    if self.service.row(request.binding_id) is not None:
                        raise ValueError("binding already belongs to another native association")
                    with self.service.db:
                        self.service.db.execute(
                            "INSERT INTO provider_bindings VALUES(?,?,?,?,?,NULL)",
                            (request.binding_id, blob, canonical(native_request),
                             canonical(resolved.physical()), "BOUND"),
                        )
                else:
                    native_request = json.loads(prior[1])
                    if not same_native_target(native_request["target"], resolved.target):
                        raise ValueError("physical container incarnation changed")
                if request.binding_id not in self.handles:
                    self.handles[request.binding_id] = os.dup(resolved.fds[0])
                native = self.service.row(request.binding_id)
                if native is None:
                    self.service.dispatch(native_request, list(resolved.fds))
                elif native[2] != "ACTIVE":
                    raise ValueError("uncertain or retired native binding requires stopped-target cleanup")
                # Activation's small acknowledgement is not current physical proof.
                current = self.service.dispatch(
                    dict(native_request, method="lookup"), [resolved.fds[0]],
                )
                if not current.get("active") or not current.get("readback"):
                    raise ValueError("native provider did not verify complete container enforcement")
                return wire.EnsureResponse(enforced=wire.Enforced(
                    binding_id=request.binding_id,
                    requirement_digest=requirement_digest(request.requirement),
                    target_facts_digest=target_facts_digest(request.target_facts),
                    enforced_capabilities=request.requirement.required_capabilities,
                    resolved_target=wire.TargetFacts(
                        format=PHYSICAL_FORMAT, value=canonical(resolved.physical()),
                    ),
                    evidence=canonical(current["readback"]),
                ))

    def RetireEnforcement(self, request, context):
        self.authorize(context)
        try:
            return self.retire(request)
        except TargetPending as error:
            return wire.RetireResponse(pending=wire.Pending(reason=str(error)))
        except ValueError as error:
            log_refusal("retirement", request.binding_id, error)
            return wire.RetireResponse(refused=wire.Refused(reason=refusal_reason(error)))
        except (OSError, RuntimeError, sqlite3.Error) as error:
            logging.getLogger(__name__).error(
                "enforcement retirement uncertain binding=%s error_type=%s",
                request.binding_id, type(error).__name__, exc_info=True,
            )
            context.abort(grpc.StatusCode.UNAVAILABLE, "native retirement uncertain; retry the same binding")

    def retire(self, request):
        binding = request.binding_id
        if not binding or len(binding.encode("utf-8")) > 128 or "\0" in binding:
            raise ValueError("retirement requires the immutable binding ID")
        with self.service.lock:
            prior = self.row(binding)
            if prior is None:
                pins = self.service.pins / hashlib.sha256(binding.encode()).hexdigest()
                if self.service.row(binding) is not None or pins.exists():
                    raise ValueError("unknown binding has native ownership or residue")
                # Intent is always written before native installation, so this
                # absence can seal the delayed-Ensure race without removing anything.
                with self.service.db:
                    self.service.db.execute(
                        "INSERT INTO provider_bindings VALUES(?,NULL,NULL,NULL,'RETIRED',NULL)",
                        (binding,),
                    )
            elif prior[3] != "RETIRED":
                native_request = json.loads(prior[1])
                native = self.service.row(binding)
                if native is not None:
                    self.retire_native(binding, native_request, json.loads(prior[2]))
                # No native intent means installation never began.
                with self.service.db:
                    self.service.db.execute(
                        "UPDATE provider_bindings SET phase='RETIRED' WHERE binding=?", (binding,),
                    )
            fd = self.handles.pop(binding, None)
            if fd is not None:
                os.close(fd)
            return wire.RetireResponse(retired=wire.Retired(binding_id=binding))

    def retire_native(self, binding, native_request, physical):
        native_request = dict(native_request, method="retire")
        fd = self.handles.get(binding)
        if fd is not None:
            try:
                self.service.dispatch(native_request, [fd])
            except TargetNotStopped as error:
                raise TargetPending("runtime must stop the physical container before retirement") from error
            return
        row = self.service.row(binding)
        if row[2] in {"EMPTY_CONFIRMED", "RETIRED"}:
            self.service.dispatch(native_request, [])
            return
        if native_request["target"]["boot"] != boot_id():
            self.service.dispatch(native_request, [])
            return
        # After restart the original handle may be lost. A successful CRI
        # exact-ID stopped/absent result is required, never an inspect/RPC error.
        facts = physical["container"]
        stopped, proof = self.resolver.stopped(facts)
        if not stopped:
            raise TargetPending("runtime must stop the physical container before retirement")
        with self.service.db:
            self.service.db.execute(
                "UPDATE provider_bindings SET stop_proof=? WHERE binding=?", (canonical(proof), binding),
            )
        path = self.resolver.cgroup_root / physical["cgroupPath"].lstrip("/")
        try:
            fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW)
        except FileNotFoundError:
            fd = None
        try:
            if fd is not None:
                # The exact kernel empty-target fence still applies if present.
                self.service.dispatch(native_request, [fd], verified_stopped=True)
                return
            with self.service.db:
                self.service.db.execute(
                    "UPDATE bindings SET phase='EMPTY_CONFIRMED' WHERE operation=?", (binding,),
                )
            self.service.dispatch(native_request, [])
        finally:
            if fd is not None:
                os.close(fd)
