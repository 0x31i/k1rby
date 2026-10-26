"""Self-relative SECURITY_DESCRIPTOR / DACL parser for k1rby's off-host ACL analysis.

The Windows pivot collector (windows/collect.ps1) captures nTSecurityDescriptor blobs
(Owner+Group+DACL, SACL omitted via SD-flags control = 7 so a non-privileged bind succeeds) and
base64s them into the dump. This module decodes those blobs entirely off-host: no live DC, no
Windows, pure stdlib struct parsing. It yields the owner/group SIDs and every DACL ACE with its
access mask decoded into named rights and its object-type GUID resolved against the well-known
control-access-right GUIDs that matter for AD attack paths (DCSync, force-password-reset, etc.).

Binary layouts (all little-endian unless noted):
  SECURITY_DESCRIPTOR (self-relative): Revision(1) Sbz1(1) Control(2) OffOwner(4) OffGroup(4)
      OffSacl(4) OffDacl(4), then the referenced SID/ACL structures.
  ACL: Revision(1) Sbz1(1) AclSize(2) AceCount(2) Sbz2(2), then AceCount ACEs.
  ACE header: AceType(1) AceFlags(1) AceSize(2).
  ACCESS_ALLOWED/DENIED_ACE body: Mask(4) Sid.
  ACCESS_ALLOWED/DENIED_OBJECT_ACE body: Mask(4) Flags(4) [ObjectType GUID(16) if Flags&1]
      [InheritedObjectType GUID(16) if Flags&2] Sid.
  SID: Revision(1) SubAuthCount(1) IdentifierAuthority(6, big-endian) SubAuthority[](4 each).
"""

from __future__ import annotations

import struct

# ---- AD access-mask bits --------------------------------------------------------------------
RIGHT_DS_CREATE_CHILD = 0x00000001
RIGHT_DS_DELETE_CHILD = 0x00000002
RIGHT_DS_LIST = 0x00000004
RIGHT_DS_SELF = 0x00000008          # validated write (e.g. self-membership)
RIGHT_DS_READ_PROP = 0x00000010
RIGHT_DS_WRITE_PROP = 0x00000020
RIGHT_DS_DELETE_TREE = 0x00000040
RIGHT_DS_LIST_OBJECT = 0x00000080
RIGHT_DS_CONTROL_ACCESS = 0x00000100  # extended right (GUID-scoped, or all if no GUID)
RIGHT_DELETE = 0x00010000
RIGHT_READ_CONTROL = 0x00020000
RIGHT_WRITE_DAC = 0x00040000
RIGHT_WRITE_OWNER = 0x00080000
RIGHT_GENERIC_ALL = 0x10000000
RIGHT_GENERIC_EXECUTE = 0x20000000
RIGHT_GENERIC_WRITE = 0x40000000
RIGHT_GENERIC_READ = 0x80000000

# name -> bit, for decoding a mask into a readable set (only the attack-relevant bits)
_MASK_NAMES = [
    ("GenericAll", RIGHT_GENERIC_ALL),
    ("GenericWrite", RIGHT_GENERIC_WRITE),
    ("WriteDacl", RIGHT_WRITE_DAC),
    ("WriteOwner", RIGHT_WRITE_OWNER),
    ("WriteProperty", RIGHT_DS_WRITE_PROP),
    ("Self", RIGHT_DS_SELF),
    ("ExtendedRight", RIGHT_DS_CONTROL_ACCESS),
    ("CreateChild", RIGHT_DS_CREATE_CHILD),
    ("DeleteChild", RIGHT_DS_DELETE_CHILD),
    ("DeleteTree", RIGHT_DS_DELETE_TREE),
    ("Delete", RIGHT_DELETE),
]

# Control-access / validated-write GUIDs worth calling out by name.
EXTENDED_RIGHTS = {
    "1131f6aa-9c07-11d1-f79f-00c04fc2dcd2": "DS-Replication-Get-Changes",
    "1131f6ad-9c07-11d1-f79f-00c04fc2dcd2": "DS-Replication-Get-Changes-All",
    "89e95b76-444d-4c62-991a-0facbeda640c": "DS-Replication-Get-Changes-In-Filtered-Set",
    "00299570-246d-11d0-a768-00aa006e0529": "User-Force-Change-Password",
    "ab721a53-1e2f-11d0-9819-00aa0040529b": "User-Change-Password",
    "bf9679c0-0de6-11d0-a285-00aa003049e2": "Self-Membership",
    "e362ed86-b728-0842-b27d-2dea7a9df218": "ms-Mcs-AdmPwd (LAPS legacy, if schema matches)",
}

# The two GUIDs whose *combination* on the domain head = DCSync.
DCSYNC_GUIDS = {"1131f6aa-9c07-11d1-f79f-00c04fc2dcd2",
                "1131f6ad-9c07-11d1-f79f-00c04fc2dcd2"}

ACE_ALLOWED = 0x00
ACE_ALLOWED_OBJECT = 0x05
_ACE_HAS_OBJECT_TYPE = 0x01
_ACE_HAS_INHERITED_OBJECT_TYPE = 0x02

# SIDs that holding broad control is *expected* for — excluded from "non-default principal" findings.
WELLKNOWN_EXPECTED = {
    "S-1-5-18",    # Local System
    "S-1-5-32-544",  # BUILTIN\Administrators
    "S-1-5-9",     # Enterprise Domain Controllers
    "S-1-5-10",    # Principal Self
    "S-1-3-0",     # Creator Owner
    "S-1-5-32-548",  # Account Operators (default; PK flags separately)
}
# domain-relative RIDs whose control over sensitive objects is expected (DA/EA/schema/DCs/admin).
EXPECTED_RIDS = {512, 516, 518, 519, 500, 526, 527, 498}


def fmt_sid(blob: bytes, off: int) -> tuple[str, int]:
    """Parse a binary SID at `off`; return (S-1-... string, bytes consumed)."""
    if off + 8 > len(blob):
        return "", 0
    rev = blob[off]
    sub_count = blob[off + 1]
    authority = int.from_bytes(blob[off + 2:off + 8], "big")
    sid = f"S-{rev}-{authority}"
    p = off + 8
    for _ in range(sub_count):
        if p + 4 > len(blob):
            break
        sid += "-" + str(struct.unpack_from("<I", blob, p)[0])
        p += 4
    return sid, p - off


def fmt_guid(blob: bytes, off: int) -> str:
    """16-byte little-endian GUID -> canonical string."""
    if off + 16 > len(blob):
        return ""
    d1 = struct.unpack_from("<I", blob, off)[0]
    d2 = struct.unpack_from("<H", blob, off + 4)[0]
    d3 = struct.unpack_from("<H", blob, off + 6)[0]
    d4 = blob[off + 8:off + 16]
    return f"{d1:08x}-{d2:04x}-{d3:04x}-{d4[0]:02x}{d4[1]:02x}-" + \
           "".join(f"{b:02x}" for b in d4[2:8])


def decode_mask(mask: int) -> list[str]:
    return [name for name, bit in _MASK_NAMES if mask & bit]


def rid_of(sid: str) -> int | None:
    try:
        return int(sid.rsplit("-", 1)[1])
    except (ValueError, IndexError):
        return None


def is_expected_sid(sid: str) -> bool:
    """SID-only test (no directory lookup) for holders whose broad rights are expected: the
    well-known admin SIDs and the standard privileged domain RIDs. Used to keep the raw ACL sheet
    focused on *anomalous* grants; the findings layer additionally resolves names."""
    if not sid:
        return True
    if sid in WELLKNOWN_EXPECTED:
        return True
    return rid_of(sid) in EXPECTED_RIDS


def parse(blob: bytes) -> dict | None:
    """Parse a self-relative SD. Returns {owner, group, aces:[{type, flags, mask, rights,
    objectType (GUID str or ''), objectRightName, sid}]} or None if it isn't a usable SD."""
    if not blob or len(blob) < 20:
        return None
    try:
        rev = blob[0]
        if rev != 1:
            return None
        off_owner, off_group, _off_sacl, off_dacl = struct.unpack_from("<IIII", blob, 4)
    except struct.error:
        return None
    owner = fmt_sid(blob, off_owner)[0] if off_owner else ""
    group = fmt_sid(blob, off_group)[0] if off_group else ""
    aces: list[dict] = []
    if off_dacl and off_dacl + 8 <= len(blob):
        try:
            ace_count = struct.unpack_from("<H", blob, off_dacl + 4)[0]
        except struct.error:
            ace_count = 0
        p = off_dacl + 8
        for _ in range(ace_count):
            if p + 4 > len(blob):
                break
            ace_type, ace_flags, ace_size = struct.unpack_from("<BBH", blob, p)
            if ace_size < 4 or p + ace_size > len(blob):
                break
            body = p + 4
            obj_guid = ""
            obj_right = ""
            if ace_type in (ACE_ALLOWED_OBJECT, 0x06):  # object ACE (allowed/denied)
                if body + 8 > len(blob):
                    p += ace_size
                    continue
                mask = struct.unpack_from("<I", blob, body)[0]
                flags = struct.unpack_from("<I", blob, body + 4)[0]
                q = body + 8
                if flags & _ACE_HAS_OBJECT_TYPE:
                    obj_guid = fmt_guid(blob, q)
                    obj_right = EXTENDED_RIGHTS.get(obj_guid, "")
                    q += 16
                if flags & _ACE_HAS_INHERITED_OBJECT_TYPE:
                    q += 16
                sid = fmt_sid(blob, q)[0]
            else:  # plain ALLOWED/DENIED ACE
                if body + 4 > len(blob):
                    p += ace_size
                    continue
                mask = struct.unpack_from("<I", blob, body)[0]
                sid = fmt_sid(blob, body + 4)[0]
            aces.append({"type": ace_type, "flags": ace_flags, "mask": mask,
                         "rights": decode_mask(mask), "objectType": obj_guid,
                         "objectRightName": obj_right, "sid": sid})
            p += ace_size
    return {"owner": owner, "group": group, "aces": aces}


# bits that constitute "control" of an object (full takeover primitives)
_CONTROL_BITS = (RIGHT_GENERIC_ALL | RIGHT_GENERIC_WRITE | RIGHT_WRITE_DAC | RIGHT_WRITE_OWNER)


def dangerous_aces(sd: dict) -> list[dict]:
    """From a parsed SD, the ALLOW ACEs that grant takeover-relevant rights. Each: {sid, rights,
    objectRightName}. WriteProperty/Self/ExtendedRight are included only when they carry no object
    GUID (apply to ALL properties/rights) or a GUID we recognise as dangerous (DCSync pair,
    force-password-reset) — a scoped write to one benign attribute is not reported."""
    out = []
    for a in sd.get("aces", []):
        if a["type"] not in (ACE_ALLOWED, ACE_ALLOWED_OBJECT):
            continue
        mask = a["mask"]
        rights = set(a["rights"])
        keep = set()
        if mask & _CONTROL_BITS:
            keep |= rights & {"GenericAll", "GenericWrite", "WriteDacl", "WriteOwner"}
        guid = a["objectType"]
        rname = a["objectRightName"]
        # ExtendedRight / WriteProperty / Self: dangerous when unscoped (no GUID) or a known-bad GUID
        if (mask & RIGHT_DS_CONTROL_ACCESS):
            if not guid or (rname and "LAPS" not in rname and "User-Change-Password" not in rname):
                keep.add("ExtendedRight" + (f"({rname})" if rname else "(all)"))
        if (mask & RIGHT_DS_WRITE_PROP) and not guid:
            keep.add("WriteProperty(all)")
        if (mask & RIGHT_DS_SELF) and not guid:
            keep.add("Self(all)")
        if keep:
            out.append({"sid": a["sid"], "rights": sorted(keep),
                        "objectRightName": rname, "objectType": guid})
    return out
