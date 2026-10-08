"""k1rby LDAP collector — read-only Active Directory enumeration.

Every operation here is an LDAP SEARCH. There are NO writes (the ldap3 connection is opened
read_only=True, which makes the library refuse add/modify/delete), NO authentication attempts
against user accounts (a single bind with the operator's own credentials), and NO exploitation.
So: no account lockout, no changes to the directory — the safe-recon floor by construction.

The data collected mirrors (and, per attribute, meets or exceeds) what ADRecon gathers, straight
from AD attributes — plus derived analysis ADRecon doesn't do.
"""

from __future__ import annotations

import datetime
import struct
from typing import Any

import ssl as _ssl

from ldap3 import ALL, NTLM, SIMPLE, SUBTREE, Connection, Server, Tls

# ---- userAccountControl bit flags (the ones that matter for recon) ----------------------------
_UAC = {
    "ACCOUNTDISABLE": 0x2,
    "LOCKOUT": 0x10,
    "PASSWD_NOTREQD": 0x20,
    "PASSWD_CANT_CHANGE": 0x40,
    "ENCRYPTED_TEXT_PWD_ALLOWED": 0x80,
    "NORMAL_ACCOUNT": 0x200,
    "WORKSTATION_TRUST_ACCOUNT": 0x1000,
    "SERVER_TRUST_ACCOUNT": 0x2000,
    "DONT_EXPIRE_PASSWORD": 0x10000,
    "SMARTCARD_REQUIRED": 0x40000,
    "TRUSTED_FOR_DELEGATION": 0x80000,       # unconstrained delegation
    "NOT_DELEGATED": 0x100000,
    "USE_DES_KEY_ONLY": 0x200000,
    "DONT_REQ_PREAUTH": 0x400000,            # AS-REP roastable
    "PASSWORD_EXPIRED": 0x800000,
    "TRUSTED_TO_AUTH_FOR_DELEGATION": 0x1000000,  # constrained w/ protocol transition
}

# well-known primary-group RIDs (primaryGroupID -> group), so primary membership resolves even
# when the group isn't resolvable by SID in this slice of the directory.
_WELL_KNOWN_PRIMARY = {
    512: "Domain Admins", 513: "Domain Users", 514: "Domain Guests",
    515: "Domain Computers", 516: "Domain Controllers", 521: "Read-only Domain Controllers",
}


def uac_flags(v: Any) -> list[str]:
    try:
        v = int(v or 0)
    except (TypeError, ValueError):
        return []
    return [name for name, bit in _UAC.items() if v & bit]


def _has(v: Any, flag: str) -> bool:
    try:
        return bool(int(v or 0) & _UAC[flag])
    except (TypeError, ValueError, KeyError):
        return False


def _dt(v: Any) -> datetime.datetime | None:
    """Return a tz-naive UTC datetime for an AD FILETIME / datetime, else None."""
    if isinstance(v, datetime.datetime):
        return v.replace(tzinfo=None) - (v.utcoffset() or datetime.timedelta()) \
            if v.tzinfo else v
    try:
        t = int(v)
    except (TypeError, ValueError):
        return None
    if t in (0, 9223372036854775807):
        return None
    try:
        return datetime.datetime(1601, 1, 1) + datetime.timedelta(seconds=t / 1e7)
    except (OverflowError, OSError):
        return None


def _ft(v: Any) -> str:
    """AD FILETIME or datetime -> 'YYYY-MM-DD HH:MM' ('never' for the sentinel)."""
    if isinstance(v, datetime.datetime):
        return v.strftime("%Y-%m-%d %H:%M")
    try:
        t = int(v)
    except (TypeError, ValueError):
        return str(v or "")
    if t in (0, 9223372036854775807):
        return "never" if t else ""
    d = _dt(v)
    return d.strftime("%Y-%m-%d %H:%M") if d else str(t)


def _age_days(v: Any) -> Any:
    """Whole days between an AD timestamp and now (UTC). '' if unknown/never."""
    d = _dt(v)
    if not d:
        return ""
    return max(0, (datetime.datetime.utcnow() - d).days)


def _s(v: Any) -> str:
    if isinstance(v, (list, tuple)):
        return "; ".join(str(x) for x in v)
    return "" if v is None else str(v)


def _sid(v: Any) -> str:
    """objectSid as string. ldap3 usually pre-formats to 'S-1-5-...'; handle raw bytes too."""
    if v is None:
        return ""
    if isinstance(v, (list, tuple)):
        v = v[0] if v else ""
    if isinstance(v, str):
        return v
    if isinstance(v, (bytes, bytearray)) and len(v) >= 8:
        try:
            rev = v[0]
            cnt = v[1]
            auth = int.from_bytes(v[2:8], "big")
            subs = [int.from_bytes(v[8 + 4 * i:12 + 4 * i], "little") for i in range(cnt)]
            return "S-%d-%d-%s" % (rev, auth, "-".join(str(s) for s in subs))
        except Exception:  # noqa: BLE001
            return ""
    return str(v)


def _rid(sid: str) -> int | None:
    try:
        return int(sid.rsplit("-", 1)[1])
    except (ValueError, IndexError, AttributeError):
        return None


def _canonical(dn: str) -> str:
    """'CN=a,OU=b,DC=x,DC=y' -> 'x.y/b/a' (ADRecon's CanonicalName)."""
    if not dn:
        return ""
    parts = [p for p in dn.split(",")]
    dcs = [p[3:] for p in parts if p.upper().startswith("DC=")]
    rest = [p.split("=", 1)[1] for p in parts if not p.upper().startswith("DC=")]
    return ".".join(dcs) + ("/" + "/".join(reversed(rest)) if rest else "")


def _cn(dn: str) -> str:
    """leading RDN value of a DN."""
    if not dn:
        return ""
    first = dn.split(",", 1)[0]
    return first.split("=", 1)[1] if "=" in first else first


def _maxpwdage_days(v: Any) -> str:
    if isinstance(v, datetime.timedelta):
        d = abs(v.total_seconds()) / 86400
        return "never" if d == 0 else str(round(d, 1))
    try:
        t = abs(int(v))
        return "never" if t == 0 else str(round(t / 1e7 / 86400, 1))
    except (TypeError, ValueError):
        return ""


def _dur_min(v: Any) -> Any:
    """Lockout/duration as minutes. ldap3 may hand back a timedelta or a raw 100-ns int."""
    if isinstance(v, datetime.timedelta):
        return int(abs(v.total_seconds()) // 60)
    try:
        return abs(int(v)) // 10_000_000 // 60
    except (TypeError, ValueError):
        return ""


def _grouptype(v: Any) -> tuple[str, str]:
    """groupType bitmask -> (category, scope)."""
    try:
        g = int(v)
    except (TypeError, ValueError):
        return ("", "")
    cat = "Security" if g & 0x80000000 else "Distribution"
    scope = "Global" if g & 0x2 else "DomainLocal" if g & 0x4 else "Universal" if g & 0x8 \
        else "BuiltinLocal" if g & 0x1 else ""
    return (cat, scope)


# ---- AD-integrated DNS record blob parser (dnsRecord attribute) --------------------------------
_DNS_TYPE = {1: "A", 2: "NS", 5: "CNAME", 6: "SOA", 12: "PTR", 15: "MX",
             16: "TXT", 28: "AAAA", 33: "SRV", 0: "TOMBSTONE"}


def _dns_name(data: bytes, off: int) -> str:
    """Parse a DNS_COUNT_NAME (len byte, label-count byte, then len-prefixed labels)."""
    try:
        if off + 2 > len(data):
            return ""
        count = data[off + 1]
        p = off + 2
        labels = []
        for _ in range(count):
            if p >= len(data):
                break
            ln = data[p]
            p += 1
            labels.append(data[p:p + ln].decode("ascii", "replace"))
            p += ln
        return ".".join(labels)
    except Exception:  # noqa: BLE001
        return ""


def _parse_dnsrecord(blob: bytes) -> tuple[str, str]:
    """AD dnsRecord blob -> (RecordType, Data). Covers the common record types."""
    if not isinstance(blob, (bytes, bytearray)) or len(blob) < 24:
        return ("?", "")
    try:
        dlen, rtype = struct.unpack_from("<HH", blob, 0)
    except struct.error:
        return ("?", "")
    data = blob[24:24 + dlen] if dlen else blob[24:]
    t = _DNS_TYPE.get(rtype, f"TYPE{rtype}")
    try:
        if rtype == 1 and len(data) >= 4:                     # A
            return (t, ".".join(str(b) for b in data[:4]))
        if rtype == 28 and len(data) >= 16:                   # AAAA
            return (t, ":".join("%x" % int.from_bytes(data[i:i + 2], "big")
                                for i in range(0, 16, 2)))
        if rtype in (2, 5, 12):                                # NS / CNAME / PTR
            return (t, _dns_name(data, 0))
        if rtype == 16 and data:                              # TXT
            return (t, data[1:1 + data[0]].decode("ascii", "replace"))
        if rtype == 33 and len(data) >= 6:                    # SRV
            pri, wt, port = struct.unpack_from(">HHH", data, 0)
            return (t, f"{_dns_name(data, 6)}:{port} (pri {pri} wt {wt})")
        if rtype == 15 and len(data) >= 2:                    # MX
            pref = struct.unpack_from(">H", data, 0)[0]
            return (t, f"{_dns_name(data, 2)} (pref {pref})")
        if rtype == 6:                                        # SOA
            return (t, _dns_name(data, 0))
    except Exception:  # noqa: BLE001
        return (t, "")
    return (t, "")


class Collector:
    """Opens ONE read-only bind and runs a battery of searches."""

    def __init__(self, dc: str, domain: str, username: str, password: str,
                 use_ssl: bool = False, port: int | None = None,
                 auth: str = "ntlm", tls_verify: bool = True):
        self.dc = dc
        self.domain = domain
        self.base = "DC=" + ",DC=".join(domain.split("."))
        tls = Tls(validate=_ssl.CERT_NONE) if (use_ssl and not tls_verify) else None
        server = Server(dc, port=port, use_ssl=use_ssl, tls=tls, get_info=ALL)
        if auth.lower() == "simple":
            user = username if ("@" in username or "," in username) else f"{username}@{domain}"
            self.conn = Connection(server, user=user, password=password,
                                   authentication=SIMPLE, read_only=True, auto_bind=True)
        else:
            from . import md4compat
            md4compat.install()   # make NTLM's MD4 work on OpenSSL-3 Python (no-op if native MD4 ok)
            self.conn = Connection(server, user=f"{domain}\\{username}", password=password,
                                   authentication=NTLM, read_only=True, auto_bind=True)
        self.server = server
        self._users_cache: list[dict] | None = None
        self._computers_cache: list[dict] | None = None
        self._groups_cache: list[dict] | None = None
        self._dns_a_cache: dict[str, str] | None = None
        self._domain_sid: str | None = None

    def close(self) -> None:
        try:
            self.conn.unbind()
        except Exception:  # noqa: BLE001
            pass

    # ---- generic COOKIE-paged search (never truncates; this fixes the old 1-page cap) ---------
    def _search(self, flt: str, attrs: list[str], base: str | None = None) -> list[dict]:
        out = []
        try:
            entries = self.conn.extend.standard.paged_search(
                base or self.base, flt, search_scope=SUBTREE, attributes=attrs,
                paged_size=500, generator=False)
        except Exception:  # noqa: BLE001
            # fall back to a single search if paged_search is unavailable
            self.conn.search(base or self.base, flt, search_scope=SUBTREE,
                             attributes=attrs, paged_size=500)
            entries = [{"dn": str(e.entry_dn), "attributes": {a: (e[a].value if a in e else None)
                                                              for a in attrs}}
                       for e in self.conn.entries]
        for e in entries:
            if e.get("type") not in (None, "searchResEntry"):
                continue
            a = e.get("attributes", {})
            d = {k: a.get(k) for k in attrs}
            d["_dn"] = e.get("dn") or ""
            out.append(d)
        return out

    def _domain_sid_val(self) -> str:
        if self._domain_sid is None:
            self.conn.search(self.base, "(objectClass=domain)", search_scope="BASE",
                             attributes=["objectSid"])
            self._domain_sid = _sid(self.conn.entries[0]["objectSid"].value) \
                if self.conn.entries else ""
        return self._domain_sid

    # ---- domain / policy ----------------------------------------------------------------------
    def domain_info(self) -> list[dict]:
        self.conn.search(self.base, "(objectClass=domain)", search_scope="BASE",
                         attributes=["minPwdLength", "maxPwdAge", "minPwdAge", "lockoutThreshold",
                                     "lockoutDuration", "pwdHistoryLength", "pwdProperties",
                                     "ms-DS-MachineAccountQuota", "objectSid",
                                     "msDS-Behavior-Version"])
        if not self.conn.entries:
            return []
        e = self.conn.entries[0]
        g = lambda a: e[a].value if a in e else None  # noqa: E731
        rootdse = self.server.info
        try:
            complex_on = bool(int(g("pwdProperties") or 0) & 0x1)
        except (TypeError, ValueError):
            complex_on = False
        return [{
            "domain": self.domain,
            "domainSID": _sid(g("objectSid")),
            "domainFunctionalLevel": _s(g("msDS-Behavior-Version")),
            "minPwdLength": _s(g("minPwdLength")),
            "maxPwdAgeDays": _maxpwdage_days(g("maxPwdAge")),
            "minPwdAgeDays": _maxpwdage_days(g("minPwdAge")),
            "complexityEnabled": complex_on,
            "lockoutThreshold": _s(g("lockoutThreshold")),
            "lockoutDurationMin": _dur_min(g("lockoutDuration")),
            "pwdHistoryLength": _s(g("pwdHistoryLength")),
            "machineAccountQuota": _s(g("ms-DS-MachineAccountQuota")),
            "forestFunctionalLevel": _s(getattr(rootdse, "other", {}).get(
                "forestFunctionality", [""])[0] if rootdse else ""),
            "namingContexts": _s(getattr(rootdse, "naming_contexts", "")),
        }]

    def password_policy_compliance(self) -> list[dict]:
        """Default-domain-policy settings mapped to common benchmarks (ADRecon-style, but we read
        the live values). Static reference text; the current value is pulled from the directory."""
        di = self.domain_info()
        d = di[0] if di else {}
        def flag(cond):  # noqa: ANN001
            return "PASS" if cond else "REVIEW"
        try:
            minlen = int(d.get("minPwdLength") or 0)
        except ValueError:
            minlen = 0
        try:
            hist = int(d.get("pwdHistoryLength") or 0)
        except ValueError:
            hist = 0
        try:
            lock = int(d.get("lockoutThreshold") or 0)
        except ValueError:
            lock = 0
        maxage = d.get("maxPwdAgeDays")
        rows = [
            ("Minimum password length", d.get("minPwdLength"),
             "CIS: >=14", "PCI-DSS 4.0 8.3.6: >=12", flag(minlen >= 14)),
            ("Password history length", d.get("pwdHistoryLength"),
             "CIS: >=24", "PCI-DSS 8.3.7: >=4", flag(hist >= 24)),
            ("Maximum password age (days)", maxage,
             "CIS: <=365 (1-365)", "PCI-DSS 8.3.9: <=90 if sole factor", flag(str(maxage) != "never")),
            ("Account lockout threshold", d.get("lockoutThreshold"),
             "CIS: <=5, !=0", "PCI-DSS 8.3.4: <=10", flag(1 <= lock <= 5)),
            ("Lockout duration (min)", d.get("lockoutDurationMin"),
             "CIS: >=15", "PCI-DSS 8.3.4: >=30", flag(str(d.get("lockoutDurationMin")).isdigit()
                                                      and int(d.get("lockoutDurationMin")) >= 15)),
            ("Password complexity", "enabled" if d.get("complexityEnabled") else "disabled",
             "CIS: Enabled", "PCI-DSS 8.3.6", flag(d.get("complexityEnabled"))),
            ("Minimum password age (days)", d.get("minPwdAgeDays"),
             "CIS: >=1", "PCI-DSS", flag(str(d.get("minPwdAgeDays")) not in ("never", "0", ""))),
        ]
        return [{"policy": p, "currentValue": _s(v), "CIS Benchmark": c,
                 "PCI-DSS": pci, "status": st} for (p, v, c, pci, st) in rows]

    def password_policies_fgpp(self) -> list[dict]:
        flt = "(objectClass=msDS-PasswordSettings)"
        rows = self._search(flt, ["name", "msDS-PasswordSettingsPrecedence",
                                   "msDS-MinimumPasswordLength", "msDS-LockoutThreshold",
                                   "msDS-PasswordHistoryLength", "msDS-PSOAppliesTo"],
                            base=f"CN=Password Settings Container,CN=System,{self.base}")
        return [{
            "name": _s(r.get("name")),
            "precedence": _s(r.get("msDS-PasswordSettingsPrecedence")),
            "minPwdLength": _s(r.get("msDS-MinimumPasswordLength")),
            "lockoutThreshold": _s(r.get("msDS-LockoutThreshold")),
            "pwdHistory": _s(r.get("msDS-PasswordHistoryLength")),
            "appliesTo": _s(r.get("msDS-PSOAppliesTo")),
        } for r in rows]

    def domain_controllers(self) -> list[dict]:
        flt = ("(&(objectCategory=computer)(userAccountControl:1.2.840.113556.1.4.803:=8192))")
        rows = self._search(flt, ["name", "dNSHostName", "operatingSystem",
                                   "operatingSystemVersion", "lastLogonTimestamp", "objectSid"])
        amap = self._dns_a_map()
        return [{
            "name": _s(r.get("name")),
            "dnsHostName": _s(r.get("dNSHostName")),
            "ipv4": amap.get(_s(r.get("dNSHostName")).lower(), ""),
            "os": _s(r.get("operatingSystem")),
            "osVersion": _s(r.get("operatingSystemVersion")),
            "lastLogon": _ft(r.get("lastLogonTimestamp")),
            "sid": _sid(r.get("objectSid")),
        } for r in rows]

    def trusts(self) -> list[dict]:
        rows = self._search("(objectClass=trustedDomain)",
                            ["trustPartner", "trustDirection", "trustType", "trustAttributes"])
        dirs = {0: "Disabled", 1: "Inbound", 2: "Outbound", 3: "Bidirectional"}
        return [{
            "partner": _s(r.get("trustPartner")),
            "direction": dirs.get(int(r.get("trustDirection") or 0), _s(r.get("trustDirection"))),
            "type": _s(r.get("trustType")),
            "attributes": _s(r.get("trustAttributes")),
        } for r in rows]

    # ---- users (the big one, now ADRecon-depth) ----------------------------------------------
    def users(self) -> list[dict]:
        if self._users_cache is not None:
            return self._users_cache
        attrs = ["sAMAccountName", "userPrincipalName", "userAccountControl", "adminCount",
                 "servicePrincipalName", "pwdLastSet", "lastLogonTimestamp", "whenCreated",
                 "whenChanged", "memberOf", "description", "msDS-AllowedToDelegateTo",
                 "objectSid", "sIDHistory", "primaryGroupID", "accountExpires",
                 "mail", "manager", "department", "title", "company", "mobile",
                 "homeDirectory", "profilePath", "scriptPath",
                 "msDS-SupportedEncryptionTypes"]
        raw = self._search("(&(objectCategory=person)(objectClass=user))", attrs)
        out = []
        for r in raw:
            uac = r.get("userAccountControl")
            spn = r.get("servicePrincipalName")
            dn = r.get("_dn") or ""
            pls = r.get("pwdLastSet")
            enc = r.get("msDS-SupportedEncryptionTypes")
            try:
                enc = int(enc) if enc not in (None, "") else None
            except (TypeError, ValueError):
                enc = None
            out.append({
                "sAMAccountName": _s(r.get("sAMAccountName")),
                "userPrincipalName": _s(r.get("userPrincipalName")),
                "enabled": not _has(uac, "ACCOUNTDISABLE"),
                "adminCount": _s(r.get("adminCount")),
                "sid": _sid(r.get("objectSid")),
                "sidHistory": _sid(r.get("sIDHistory")) if r.get("sIDHistory") else "",
                "primaryGroupID": _s(r.get("primaryGroupID")),
                "hasSPN": bool(spn),
                "spn": _s(spn),
                "asrepRoastable": _has(uac, "DONT_REQ_PREAUTH"),
                "pwdNotRequired": _has(uac, "PASSWD_NOTREQD"),
                "pwdNeverExpires": _has(uac, "DONT_EXPIRE_PASSWORD"),
                "mustChangePwd": (str(pls) in ("0", "") or pls == 0),
                "cannotChangePwd": _has(uac, "PASSWD_CANT_CHANGE"),
                "reversiblePwdEncryption": _has(uac, "ENCRYPTED_TEXT_PWD_ALLOWED"),
                "smartcardRequired": _has(uac, "SMARTCARD_REQUIRED"),
                "kerberosDESOnly": _has(uac, "USE_DES_KEY_ONLY"),
                "accountLocked": _has(uac, "LOCKOUT"),
                "passwordExpired": _has(uac, "PASSWORD_EXPIRED"),
                "unconstrainedDeleg": _has(uac, "TRUSTED_FOR_DELEGATION"),
                "constrainedDeleg": _s(r.get("msDS-AllowedToDelegateTo")),
                "pwdLastSet": _ft(pls),
                "pwdAgeDays": _age_days(pls),
                "lastLogon": _ft(r.get("lastLogonTimestamp")),
                "logonAgeDays": _age_days(r.get("lastLogonTimestamp")),
                "dormant": (isinstance(_age_days(r.get("lastLogonTimestamp")), int)
                            and _age_days(r.get("lastLogonTimestamp")) > 90),
                "accountExpires": _ft(r.get("accountExpires")),
                "whenCreated": _s(r.get("whenCreated")),
                "whenChanged": _s(r.get("whenChanged")),
                "description": _s(r.get("description")),
                "title": _s(r.get("title")),
                "department": _s(r.get("department")),
                "company": _s(r.get("company")),
                "manager": _cn(_s(r.get("manager"))),
                "email": _s(r.get("mail")),
                "mobile": _s(r.get("mobile")),
                "homeDirectory": _s(r.get("homeDirectory")),
                "profilePath": _s(r.get("profilePath")),
                "scriptPath": _s(r.get("scriptPath")),
                "distinguishedName": dn,
                "canonicalName": _canonical(dn),
                "uacFlags": "; ".join(uac_flags(uac)),
                "_dn": dn,
            })
        self._users_cache = out
        return out

    def computers(self) -> list[dict]:
        if self._computers_cache is not None:
            return self._computers_cache
        attrs = ["name", "dNSHostName", "operatingSystem", "operatingSystemVersion",
                 "lastLogonTimestamp", "userAccountControl", "pwdLastSet", "whenCreated",
                 "whenChanged", "objectSid", "sIDHistory", "primaryGroupID", "description",
                 "msDS-AllowedToActOnBehalfOfOtherIdentity", "msDS-AllowedToDelegateTo"]
        raw = self._search("(objectClass=computer)", attrs)
        amap = self._dns_a_map()
        out = []
        for r in raw:
            uac = r.get("userAccountControl")
            dn = r.get("_dn") or ""
            out.append({
                "name": _s(r.get("name")),
                "dnsHostName": _s(r.get("dNSHostName")),
                "ipv4": amap.get(_s(r.get("dNSHostName")).lower(), ""),
                "os": _s(r.get("operatingSystem")),
                "osVersion": _s(r.get("operatingSystemVersion")),
                "enabled": not _has(uac, "ACCOUNTDISABLE"),
                "sid": _sid(r.get("objectSid")),
                "sidHistory": _sid(r.get("sIDHistory")) if r.get("sIDHistory") else "",
                "primaryGroupID": _s(r.get("primaryGroupID")),
                "lastLogon": _ft(r.get("lastLogonTimestamp")),
                "logonAgeDays": _age_days(r.get("lastLogonTimestamp")),
                "dormant": (isinstance(_age_days(r.get("lastLogonTimestamp")), int)
                            and _age_days(r.get("lastLogonTimestamp")) > 90),
                "pwdLastSet": _ft(r.get("pwdLastSet")),
                "pwdAgeDays": _age_days(r.get("pwdLastSet")),
                "unconstrainedDeleg": _has(uac, "TRUSTED_FOR_DELEGATION"),
                "constrainedDeleg": _s(r.get("msDS-AllowedToDelegateTo")),
                "rbcd": bool(r.get("msDS-AllowedToActOnBehalfOfOtherIdentity")),
                "description": _s(r.get("description")),
                "whenCreated": _s(r.get("whenCreated")),
                "whenChanged": _s(r.get("whenChanged")),
                "distinguishedName": dn,
                "_dn": dn,
            })
        self._computers_cache = out
        return out

    def groups(self) -> list[dict]:
        if self._groups_cache is not None:
            return self._groups_cache
        raw = self._search("(objectClass=group)",
                           ["name", "member", "adminCount", "description", "groupType",
                            "objectSid", "sIDHistory", "managedBy", "whenCreated", "whenChanged"])
        out = []
        for r in raw:
            m = r.get("member") or []
            m = m if isinstance(m, list) else [m]
            cat, scope = _grouptype(r.get("groupType"))
            dn = r.get("_dn") or ""
            out.append({
                "name": _s(r.get("name")),
                "groupCategory": cat,
                "groupScope": scope,
                "memberCount": len(m),
                "adminCount": _s(r.get("adminCount")),
                "sid": _sid(r.get("objectSid")),
                "sidHistory": _sid(r.get("sIDHistory")) if r.get("sIDHistory") else "",
                "managedBy": _cn(_s(r.get("managedBy"))),
                "description": _s(r.get("description")),
                "whenCreated": _s(r.get("whenCreated")),
                "whenChanged": _s(r.get("whenChanged")),
                "distinguishedName": dn,
                "_members": m,
                "_dn": dn,
            })
        self._groups_cache = out
        return out

    def privileged_group_members(self) -> list[dict]:
        """Direct members of the highest-value built-in groups."""
        priv = ["Domain Admins", "Enterprise Admins", "Schema Admins", "Administrators",
                "Account Operators", "Backup Operators", "Server Operators",
                "Print Operators", "DnsAdmins"]
        out = []
        for g in priv:
            self.conn.search(self.base, f"(&(objectClass=group)(cn={g}))",
                             search_scope=SUBTREE, attributes=["member"])
            for e in self.conn.entries:
                members = e["member"].value if "member" in e else []
                members = members if isinstance(members, list) else ([members] if members else [])
                for mdn in members:
                    out.append({"group": g, "memberDN": _s(mdn)})
        return out

    def ous(self) -> list[dict]:
        rows = self._search("(objectClass=organizationalUnit)", ["name", "description"])
        return [{"name": _s(r.get("name")), "description": _s(r.get("description")),
                 "dn": r.get("_dn")} for r in rows]

    def gpos(self) -> list[dict]:
        rows = self._search("(objectClass=groupPolicyContainer)",
                            ["displayName", "gPCFileSysPath", "whenCreated", "whenChanged"])
        return [{"displayName": _s(r.get("displayName")), "path": _s(r.get("gPCFileSysPath")),
                 "created": _s(r.get("whenCreated")), "changed": _s(r.get("whenChanged"))}
                for r in rows]

    # ---- derived (computed from users/computers, no extra queries) ----------------------------
    def kerberoastable(self) -> list[dict]:
        return [{"sAMAccountName": u["sAMAccountName"], "enabled": u["enabled"],
                 "adminCount": u["adminCount"], "spn": u["spn"], "pwdLastSet": u["pwdLastSet"]}
                for u in self.users()
                if u["hasSPN"] and u["sAMAccountName"].lower() != "krbtgt"]

    def asrep_roastable(self) -> list[dict]:
        return [{"sAMAccountName": u["sAMAccountName"], "enabled": u["enabled"],
                 "adminCount": u["adminCount"], "pwdLastSet": u["pwdLastSet"]}
                for u in self.users() if u["asrepRoastable"]]

    def delegation(self) -> list[dict]:
        out = []
        for u in self.users():
            if u["unconstrainedDeleg"]:
                out.append({"object": u["sAMAccountName"], "type": "user",
                            "delegation": "unconstrained", "detail": ""})
            if u["constrainedDeleg"]:
                out.append({"object": u["sAMAccountName"], "type": "user",
                            "delegation": "constrained", "detail": u["constrainedDeleg"]})
        for c in self.computers():
            if c["unconstrainedDeleg"]:
                out.append({"object": c["name"], "type": "computer",
                            "delegation": "unconstrained", "detail": ""})
            if c["constrainedDeleg"]:
                out.append({"object": c["name"], "type": "computer",
                            "delegation": "constrained", "detail": c["constrainedDeleg"]})
            if c["rbcd"]:
                out.append({"object": c["name"], "type": "computer",
                            "delegation": "resource-based (RBCD)", "detail": "see raw SD"})
        return out

    def privileged_users(self) -> list[dict]:
        return [{"sAMAccountName": u["sAMAccountName"], "enabled": u["enabled"],
                 "pwdNeverExpires": u["pwdNeverExpires"], "lastLogon": u["lastLogon"],
                 "description": u["description"]}
                for u in self.users() if str(u["adminCount"]) == "1"]

    # ---- ADRecon-parity collectors ------------------------------------------------------------
    def forest_info(self) -> list[dict]:
        info = self.server.info
        other = getattr(info, "other", {}) or {}
        g = lambda k: _s((other.get(k) or [""])[0]) if other.get(k) else ""  # noqa: E731
        return [{
            "domain": self.domain,
            "rootDomainNC": g("rootDomainNamingContext"),
            "schemaNC": _s(getattr(info, "schema_entry", "")),
            "forestFunctionality": g("forestFunctionality"),
            "domainFunctionality": g("domainFunctionality"),
            "dcFunctionality": g("domainControllerFunctionality"),
            "namingContexts": _s(getattr(info, "naming_contexts", "")),
            "dnsHostName": g("dnsHostName"),
        }]

    def sites(self) -> list[dict]:
        base = f"CN=Sites,CN=Configuration,{self.base}"
        try:
            rows = self._search("(objectClass=site)", ["name", "description", "whenCreated"], base=base)
        except Exception:  # noqa: BLE001
            return []
        return [{"name": _s(r.get("name")), "description": _s(r.get("description")),
                 "created": _s(r.get("whenCreated"))} for r in rows]

    def subnets(self) -> list[dict]:
        base = f"CN=Subnets,CN=Sites,CN=Configuration,{self.base}"
        try:
            rows = self._search("(objectClass=subnet)", ["name", "siteObject", "description"], base=base)
        except Exception:  # noqa: BLE001
            return []
        return [{"subnet": _s(r.get("name")), "site": _cn(_s(r.get("siteObject"))),
                 "description": _s(r.get("description"))} for r in rows]

    def group_members_all(self) -> list[dict]:
        """Every group -> every member, with Member SID + AccountType, INCLUDING primaryGroupID
        membership (Domain Users / Domain Computers etc.), which the `member` attribute omits."""
        groups = self.groups()
        users = self.users()
        computers = self.computers()
        # DN -> (sid, accountType, name) resolved from what we already pulled (no extra queries)
        dnmap: dict[str, tuple[str, str, str]] = {}
        for u in users:
            dnmap[u["_dn"].lower()] = (u["sid"], "user", u["sAMAccountName"])
        for c in computers:
            dnmap[c["_dn"].lower()] = (c["sid"], "computer", c["name"])
        for g in groups:
            dnmap[g["_dn"].lower()] = (g["sid"], "group", g["name"])
        out = []
        for g in groups:
            for mdn in g["_members"]:
                mdn = _s(mdn)
                sid, atype, name = dnmap.get(mdn.lower(), ("", "", _cn(mdn)))
                if not atype:
                    atype = "foreignSecurityPrincipal" if "CN=ForeignSecurityPrincipals" in mdn \
                        else "other"
                out.append({"group": g["name"], "memberName": name, "memberDN": mdn,
                            "memberSID": sid, "accountType": atype})
        # primary-group membership (primaryGroupID -> group via RID)
        dsid = self._domain_sid_val()
        rid2group = {}
        for g in groups:
            rid = _rid(g["sid"])
            if rid is not None:
                rid2group[rid] = g["name"]
        for coll, atype, namek in ((users, "user", "sAMAccountName"),
                                   (computers, "computer", "name")):
            for o in coll:
                try:
                    rid = int(o["primaryGroupID"])
                except (TypeError, ValueError):
                    continue
                gname = rid2group.get(rid) or _WELL_KNOWN_PRIMARY.get(rid)
                if not gname:
                    continue
                out.append({"group": gname, "memberName": o[namek], "memberDN": o["_dn"],
                            "memberSID": (f"{dsid}-{rid}" if dsid else o["sid"]),
                            "accountType": atype + " (primary)"})
        return out

    def gpo_links(self) -> list[dict]:
        import re
        self.conn.search(self.base, "(objectClass=groupPolicyContainer)", search_scope=SUBTREE,
                         attributes=["cn", "displayName"], paged_size=500)
        gmap = {}
        for e in self.conn.entries:
            cn = _s(e["cn"].value if "cn" in e else "").strip("{}").upper()
            gmap[cn] = _s(e["displayName"].value if "displayName" in e else "")
        # OUs + domain root + SITES (ADRecon includes site-linked GPOs)
        rows = self._search("(|(objectClass=organizationalUnit)(objectClass=domainDNS))",
                            ["gPLink", "gPOptions", "name"])
        try:
            rows += self._search("(objectClass=site)", ["gPLink", "gPOptions", "name"],
                                 base=f"CN=Sites,CN=Configuration,{self.base}")
        except Exception:  # noqa: BLE001
            pass
        out = []
        for r in rows:
            gpl = _s(r.get("gPLink"))
            if not gpl:
                continue
            try:
                block = bool(int(r.get("gPOptions") or 0) & 1)
            except (TypeError, ValueError):
                block = False
            # gPLink is "[LDAP://cn={GUID},...;flags][...]" ordered; order 1 = processed last
            links = re.findall(r"\[LDAP://[^;]*\{([0-9A-Fa-f-]{36})\}[^;]*;(\d+)\]", gpl)
            for order, (guid, flags) in enumerate(links, 1):
                fl = int(flags)
                out.append({"linkedTo": _s(r.get("_dn")),
                            "gpoName": gmap.get(guid.upper(), "(unknown)"),
                            "gpoGUID": guid, "order": order,
                            "linkEnabled": not (fl & 1), "enforced": bool(fl & 2),
                            "blockInheritance": block})
        return out

    # ---- DNS (now parses dnsRecord: type + data, across ALL zones incl. reverse) --------------
    def _dns_zone_bases(self) -> list[str]:
        return [f"CN=MicrosoftDNS,DC=DomainDnsZones,{self.base}",
                f"CN=MicrosoftDNS,DC=ForestDnsZones,{self.base}",
                f"CN=MicrosoftDNS,CN=System,{self.base}"]

    def _iter_dns_nodes(self):
        """Yield (zone, owner_name, [record_blobs]) for every dnsNode in every partition."""
        for b in self._dns_zone_bases():
            try:
                self.conn.search(b, "(objectClass=dnsNode)", search_scope=SUBTREE,
                                 attributes=["name", "dnsRecord"], paged_size=500)
            except Exception:  # noqa: BLE001
                continue
            # follow paging cookie so large zones aren't truncated
            while True:
                for e in self.conn.entries:
                    dn = str(e.entry_dn)
                    zone = dn.split(",DC=")[1].split(",")[0] if ",DC=" in dn else ""
                    name = _s(e["name"].value if "name" in e else "")
                    blobs = e["dnsRecord"].raw_values if "dnsRecord" in e else []
                    yield (zone, name, blobs)
                cookie = (self.conn.result.get("controls", {})
                          .get("1.2.840.113556.1.4.319", {})
                          .get("value", {}).get("cookie"))
                if not cookie:
                    break
                try:
                    self.conn.search(b, "(objectClass=dnsNode)", search_scope=SUBTREE,
                                     attributes=["name", "dnsRecord"], paged_size=500,
                                     paged_cookie=cookie)
                except Exception:  # noqa: BLE001
                    break

    def dns_records(self) -> list[dict]:
        out, seen = [], set()
        for zone, name, blobs in self._iter_dns_nodes():
            for blob in blobs:
                rtype, data = _parse_dnsrecord(blob)
                if rtype in ("TOMBSTONE", "?"):
                    continue
                key = (zone, name, rtype, data)
                if key in seen:
                    continue
                seen.add(key)
                owner = zone if name == "@" else (f"{name}.{zone}" if name else zone)
                out.append({"zone": zone, "record": owner, "type": rtype, "data": data})
        return out[:20000]

    def _dns_a_map(self) -> dict[str, str]:
        """{fqdn_lower: ipv4} from A records — used to give Computers/DCs an IPv4Address."""
        if self._dns_a_cache is not None:
            return self._dns_a_cache
        amap: dict[str, str] = {}
        try:
            for zone, name, blobs in self._iter_dns_nodes():
                if zone.endswith("in-addr.arpa"):
                    continue
                for blob in blobs:
                    rtype, data = _parse_dnsrecord(blob)
                    if rtype == "A" and data:
                        fqdn = (zone if name == "@" else f"{name}.{zone}").lower()
                        amap.setdefault(fqdn, data)
        except Exception:  # noqa: BLE001
            pass
        self._dns_a_cache = amap
        return amap

    def laps(self) -> list[dict]:
        """Dump LAPS passwords THIS account can read (legacy ms-Mcs-AdmPwd + Windows LAPS).
        A populated value here is itself a finding: the operator can read local-admin passwords."""
        out = []
        for pwd_attr, exp_attr in (("ms-Mcs-AdmPwd", "ms-Mcs-AdmPwdExpirationTime"),
                                   ("msLAPS-Password", "msLAPS-PasswordExpirationTime")):
            try:
                rows = self._search("(objectClass=computer)", ["name", pwd_attr, exp_attr])
            except Exception:  # noqa: BLE001
                continue
            for r in rows:
                val = r.get(pwd_attr)
                if val:
                    out.append({"computer": _s(r.get("name")), "lapsPassword": _s(val),
                                "expires": _ft(r.get(exp_attr)), "source": pwd_attr})
        return out
