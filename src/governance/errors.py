"""授权与回避治理服务向 API 和 CLI 暴露的稳定错误。"""


class GovernanceError(RuntimeError):
    code = "governance_error"
    status = 400


class NotFound(GovernanceError):
    code = "not_found"
    status = 404


class Conflict(GovernanceError):
    code = "conflict"
    status = 409


class Forbidden(GovernanceError):
    code = "forbidden"
    status = 403


class InvalidState(GovernanceError):
    code = "invalid_state"
    status = 409


class ValidationFailed(GovernanceError):
    code = "validation_failed"
    status = 422
