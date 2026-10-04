"""授权与回避治理的输入契约与值对象。"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Mapping, Sequence

from .errors import ValidationFailed


def _require_mapping(value: object, path: str) -> Mapping[str, Any]:
    if not isinstance(value, Mapping):
        raise ValidationFailed(f"{path} 必须是对象")
    return value


def _required_text(value: object, path: str, maximum: int = 128) -> str:
    if not isinstance(value, str) or not value.strip():
        raise ValidationFailed(f"{path} 必须是非空字符串")
    result = value.strip()
    if len(result) > maximum:
        raise ValidationFailed(f"{path} 不能超过 {maximum} 个字符")
    return result


def _optional_text(value: object, path: str, maximum: int = 128) -> str | None:
    if value is None:
        return None
    return _required_text(value, path, maximum)


@dataclass(frozen=True, slots=True)
class Scope:
    """业务范围：在哪个评审/项目环节、针对哪个对象集可以行动。

    以规范化 JSON 作为同一性键：内容相同的范围在数据库中视为同一席位维度。
    范围只描述"做什么、对哪些事项"；"代表谁"是授权的委托主体，
    "评审对象是谁（利益相对方）"在事项与动作上单独给出，三者互不混淆。
    """

    domain: str
    item_keys: tuple[str, ...]

    @classmethod
    def from_dict(cls, raw: object, path: str = "scope") -> "Scope":
        data = _require_mapping(raw, path)
        domain = _required_text(data.get("domain"), f"{path}.domain", 64)
        raw_items = data.get("item_keys", [])
        if not isinstance(raw_items, Sequence) or isinstance(raw_items, (str, bytes)):
            raise ValidationFailed(f"{path}.item_keys 必须是数组")
        items = tuple(
            _required_text(item, f"{path}.item_keys[]", 128) for item in raw_items
        )
        if len(items) != len(set(items)):
            raise ValidationFailed(f"{path}.item_keys 不能重复")
        if not items:
            raise ValidationFailed(f"{path}.item_keys 不能为空")
        return cls(domain=domain, item_keys=tuple(sorted(items)))

    def to_dict(self) -> dict[str, Any]:
        return {"domain": self.domain, "item_keys": list(self.item_keys)}

    def contains_item(self, item_key: str) -> bool:
        return item_key in self.item_keys

    def contains(self, other: "Scope") -> bool:
        """本范围是否覆盖另一范围（域相同、事项集合包含）。"""

        if self.domain != other.domain:
            return False
        return set(other.item_keys) <= set(self.item_keys)


@dataclass(frozen=True, slots=True)
class MaterialRef:
    """对某一材料版本的精确引用；version 为 None 时不绑定材料版本。"""

    material_id: str
    version: str | None

    @classmethod
    def from_dict(cls, raw: object, path: str) -> "MaterialRef":
        data = _require_mapping(raw, path)
        return cls(
            material_id=_required_text(data.get("material_id"), f"{path}.material_id", 64),
            version=_optional_text(data.get("version"), f"{path}.version", 64),
        )

    def to_dict(self) -> dict[str, Any]:
        result: dict[str, Any] = {"material_id": self.material_id}
        if self.version is not None:
            result["version"] = self.version
        return result

    def covers(self, material_id: str, version: str | None) -> bool:
        if self.material_id != material_id:
            return False
        if self.version is None:
            return True
        return self.version == version


def parse_material_refs(raw: object, path: str = "materials") -> tuple[MaterialRef, ...]:
    if not isinstance(raw, Sequence) or isinstance(raw, (str, bytes)):
        raise ValidationFailed(f"{path} 必须是数组")
    refs = tuple(MaterialRef.from_dict(item, f"{path}[{index}]") for index, item in enumerate(raw))
    if not refs:
        raise ValidationFailed(f"{path} 至少绑定一个材料版本")
    identities = {(ref.material_id, ref.version) for ref in refs}
    if len(identities) != len(refs):
        raise ValidationFailed(f"{path} 中材料版本不能重复")
    return tuple(sorted(refs, key=lambda ref: (ref.material_id, ref.version or "")))


def material_covers(
    refs: Sequence[MaterialRef], material_id: str, version: str | None
) -> bool:
    """授权的材料集合是否覆盖某次操作引用的材料版本。

    授权不绑定具体版本（version=None）表示该材料的任意版本均覆盖；
    操作不引用材料（version=None）时只需存在同一材料的授权。
    """

    return any(ref.covers(material_id, version) for ref in refs)
