"""k1rby offline ingest — build the report from a raw LDAP dump, no live DC.

Why this exists
---------------
On some authorized internal engagements the operator only has a *Windows* pivot and cannot
run the Linux collector against the DC (no Linux box in-path, no tunnel). ADRecon.ps1 is
auto-quarantined on sight (signature/name/hash), so it never even runs. The answer is to do
only the read-only LDAP SEARCH on the pivot with a small, non-signatured PowerShell collector
(`windows/collect.ps1`) that writes a raw JSON dump and does NO analysis — then bring the
dump back and let THIS module produce the exact same xlsx/HTML/findings k1rby always produces.

Design: zero logic drift
-------------------------
We do NOT re-implement any collection/decoding/finding logic here. Instead we hand the real
`ldapcollect.Collector` a *fake* connection + server that replay the dump's entries. Every
transform method (users(), computers(), delegation(), the dnsRecord parser, the 19 finding
rules, the posture score, the report/HTML renderers) runs verbatim against the replayed data.
The PowerShell collector's only job is to emit entries in the shape documented below.

Dump schema (JSON, produced by windows/collect.ps1)
---------------------------------------------------------
{
  "meta":   {"domain": "corp.local", "base": "DC=corp,DC=local",
             "collectedAt": "2026-10-25T18:00:00Z", "dc": "10.0.0.10",
             "collector": "k1rby-collect.ps1 <ver>"},
  "rootdse": {                      # RootDSE / forest info (strings or 1-elem lists)
     "forestFunctionality": "7", "domainFunctionality": "7",
     "domainControllerFunctionality": "7", "rootDomainNamingContext": "DC=corp,DC=local",
     "schemaNamingContext": "CN=Schema,CN=Configuration,DC=corp,DC=local",
     "namingContexts": ["DC=corp,DC=local", ...], "dnsHostName": "dc01.corp.local"},

  # --- buckets consumed via the paged (SUBTREE) search path ---
  # each is a LIST of flat dicts whose keys are the EXACT attribute names k1rby requests
  # (case-sensitive) plus "_dn". Multi-valued attrs = JSON arrays. LargeInteger/FILETIME attrs
  # (pwdLastSet, lastLogonTimestamp, accountExpires, maxPwdAge, ...) = STRINGS (never JSON
  # numbers: they exceed 2^53 and would lose precision). SID attrs (objectSid, sIDHistory,
  # mS-DS-CreatorSID) = "S-1-5-..." strings. Binary blobs you only need truthiness for
  # (msDS-AllowedToActOnBehalfOfOtherIdentity) = any non-empty string when present.
  "fgpp": [...], "domain_controllers": [...], "trusts": [...], "users": [...],
  "computers": [...], "groups": [...], "ous": [...], "gpos": [...], "sites": [...],
  "subnets": [...], "laps": [...],                 # laps entries carry all 4 LAPS attrs
  "printers": [...],              # printQueue objects (printerName/serverName/driverName/...)
  "schema_history": [...],        # classSchema/attributeSchema w/ name,lDAPDisplayName,whenCreated
  "bitlocker": [...],             # msFVE-RecoveryInformation (DA-gated; empty on a user run)
  "gpo_containers": [...],        # OUs + domainDNS carrying gPLink/gPOptions/name
  "gpo_site_containers": [...],   # site objects carrying gPLink/gPOptions/name

  # --- buckets consumed via the BASE/explicit search path ---
  "domain": [ {"_dn": "DC=corp,DC=local", "objectSid": "S-1-5-21-...",
               "minPwdLength": "7", "maxPwdAge": "-37108517437440000", ...} ],   # 1 entry
  "fsmo_owners": { "<exact base DN k1rby queries>": "<fSMORoleOwner DN>", ... },  # 5 keys
  "dc_servers": [ {"_dn": "CN=DC01,CN=Servers,CN=Default-First-Site-Name,CN=Sites,...",
                   "cn": "DC01"}, ... ],
  "gpo_objs":   [ {"_dn": "...", "cn": "{GUID}", "displayName": "Default Domain Policy"}, ... ],
  "priv_members": { "Domain Admins": ["CN=Administrator,...", ...], ... },
  "dns_nodes":  [ {"zoneBase": "CN=MicrosoftDNS,DC=DomainDnsZones,DC=corp,DC=local",
                   "_dn": "DC=dc01,DC=corp.local,CN=MicrosoftDNS,DC=DomainDnsZones,DC=corp,DC=local",
                   "name": "dc01", "dnsRecord": ["<base64 blob>", ...]} ]
}

Run:  k1rby offline corp-dump.json -o corp-AD-Assessment.xlsx
"""

from __future__ import annotations

import base64
import json
from typing import Any

from . import ldapcollect

PAGE_COOKIE_OID = "1.2.840.113556.1.4.319"


# --------------------------------------------------------------------------------------------
# ldap3-entry emulation: just enough of the Entry / Attribute surface the Collector touches
# (e["attr"].value, e["attr"].raw_values, "attr" in e, e.entry_dn).
# --------------------------------------------------------------------------------------------
class _Attr:
    __slots__ = ("_v",)

    def __init__(self, v: Any):
        self._v = v

    @property
    def value(self) -> Any:
        return self._v

    @property
    def raw_values(self) -> list:
        return self._v if isinstance(self._v, list) else ([] if self._v is None else [self._v])


class _Entry:
    """Case-insensitive attribute access, like an ldap3 Entry."""

    def __init__(self, dn: str, attrs: dict):
        self.entry_dn = dn or ""
        self._a = {k.lower(): v for k, v in (attrs or {}).items()}

    def __contains__(self, k: str) -> bool:
        return k.lower() in self._a and self._a[k.lower()] is not None

    def __getitem__(self, k: str) -> _Attr:
        return _Attr(self._a.get(k.lower()))


class _Std:
    def __init__(self, conn: "_FakeConn"):
        self._c = conn

    def paged_search(self, base, flt, search_scope=None, attributes=None,
                     paged_size=500, generator=False, **_kw):
        return self._c._paged(flt, attributes or [])


class _Extend:
    def __init__(self, conn: "_FakeConn"):
        self.standard = _Std(conn)


class _FakeServer:
    class _Info:
        def __init__(self, rootdse: dict):
            # k1rby reads: info.other.get(k, [""])[0], info.naming_contexts, info.schema_entry
            self.other = {}
            for k, v in (rootdse or {}).items():
                self.other[k] = v if isinstance(v, list) else [v]
            self.naming_contexts = (rootdse or {}).get("namingContexts", "")
            self.schema_entry = (rootdse or {}).get("schemaNamingContext", "")

    def __init__(self, rootdse: dict):
        self.info = _FakeServer._Info(rootdse)


class _FakeConn:
    """Replays dump buckets through the same call surface ldapcollect.Collector uses."""

    def __init__(self, dump: dict, base: str):
        self._d = dump
        self._base = base
        self.extend = _Extend(self)
        self.entries: list = []
        self.result: dict = {"controls": {}}

    # -- SUBTREE paged path: Collector._search() -> conn.extend.standard.paged_search() --------
    def _paged(self, flt: str, attrs: list) -> list:
        bucket = self._bucket_for(flt, attrs)
        rows = self._d.get(bucket, []) if bucket else []
        return [{"type": "searchResEntry", "dn": r.get("_dn", ""), "attributes": r} for r in rows]

    @staticmethod
    def _bucket_for(flt: str, attrs: list) -> str | None:
        a = set(attrs or [])
        if flt == "(objectClass=msDS-PasswordSettings)":
            return "fgpp"
        if "userAccountControl:1.2.840.113556.1.4.803:=8192" in flt:
            return "domain_controllers"
        if flt == "(objectClass=trustedDomain)":
            return "trusts"
        if flt == "(&(objectCategory=person)(objectClass=user))":
            return "users"
        if flt == "(objectClass=computer)":
            return "laps" if ("ms-Mcs-AdmPwd" in a or "msLAPS-Password" in a) else "computers"
        if flt == "(objectClass=group)":
            return "groups"
        if flt == "(objectClass=organizationalUnit)":
            return "ous"
        if flt == "(objectClass=groupPolicyContainer)":
            return "gpos"
        if flt.startswith("(|(objectClass=organizationalUnit)"):
            return "gpo_containers"
        if flt == "(objectClass=site)":
            return "gpo_site_containers" if "gPLink" in a else "sites"
        if flt == "(objectClass=subnet)":
            return "subnets"
        if flt == "(objectClass=printQueue)":
            return "printers"
        if flt == "(|(objectClass=classSchema)(objectClass=attributeSchema))":
            return "schema_history"
        if flt == "(objectClass=msFVE-RecoveryInformation)":
            return "bitlocker"
        return None

    # -- BASE / explicit path: Collector.*() -> conn.search(); then reads conn.entries ---------
    def search(self, base, flt, search_scope=None, attributes=None, paged_size=500,
               paged_cookie=None, **_kw):
        attrs = attributes or []
        self.result = {"controls": {}}  # single page; dump is already complete

        if flt == "(objectClass=domain)":
            dom = self._d.get("domain") or [{}]
            self.entries = [_Entry(dom[0].get("_dn", base), dom[0])]

        elif flt == "(objectClass=*)" and list(attrs) == ["fSMORoleOwner"]:
            owner = (self._d.get("fsmo_owners") or {}).get(base, "")
            self.entries = [_Entry(base, {"fSMORoleOwner": owner})]

        elif flt == "(objectClass=server)":
            self.entries = [_Entry(r.get("_dn", ""), {"cn": r.get("cn")})
                            for r in self._d.get("dc_servers", [])]

        elif flt.startswith("(&(objectClass=group)(cn="):
            g = flt[len("(&(objectClass=group)(cn="):].rstrip(")")
            members = (self._d.get("priv_members") or {}).get(g, [])
            self.entries = [_Entry("", {"member": members})] if members else []

        elif flt == "(objectClass=groupPolicyContainer)":
            self.entries = [_Entry(r.get("_dn", ""),
                                   {"cn": r.get("cn"), "displayName": r.get("displayName")})
                            for r in self._d.get("gpo_objs", [])]

        elif flt == "(objectClass=dnsNode)":
            out = []
            for r in self._d.get("dns_nodes", []):
                if r.get("zoneBase") != base:
                    continue
                blobs = [base64.b64decode(b) for b in (r.get("dnsRecord") or [])]
                out.append(_Entry(r.get("_dn", ""), {"name": r.get("name"), "dnsRecord": blobs}))
            self.entries = out

        else:
            self.entries = []

    def unbind(self):
        pass


# --------------------------------------------------------------------------------------------
class OfflineCollector(ldapcollect.Collector):
    """A Collector that never opens a socket: it replays a dump through the real transforms."""

    def __init__(self, dump: dict):
        meta = dump.get("meta", {})
        self.domain = meta.get("domain", "")
        self.base = meta.get("base") or ("DC=" + ",DC=".join(self.domain.split("."))
                                         if self.domain else "")
        self.conn = _FakeConn(dump, self.base)
        self.server = _FakeServer(dump.get("rootdse", {}))
        self._users_cache = None
        self._computers_cache = None
        self._groups_cache = None
        self._dns_a_cache = None
        self._domain_sid = None
        self.smb = False  # the pivot collector does not do the active SMB negotiate probe
        self._dump = dump


def load_dump(path: str) -> dict:
    with open(path, "r", encoding="utf-8-sig") as fh:
        return json.load(fh)
