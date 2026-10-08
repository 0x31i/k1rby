"""k1rby LDAP collector — read-only Active Directory enumeration.

Every operation here is an LDAP SEARCH. There are NO writes (the ldap3 connection is opened
read_only=True, which makes the library refuse add/modify/delete), NO authentication attempts
against user accounts (a single bind with the operator's own credentials), and NO exploitation.
So: no account lockout, no changes to the directory — the safe-recon floor by construction.

The data collected mirrors what ADRecon/PingCastle gather, straight from AD attributes.
"""

from __future__ import annotations

import datetime
from typing import Any

from ldap3 import ALL, NTLM, SUBTREE, Connection, Server

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


def _ft(v: Any) -> str:
    """AD FILETIME (100-ns ticks since 1601) or a tz-aware datetime -> 'YYYY-MM-DD HH:MM'."""
    if isinstance(v, datetime.datetime):
        return v.strftime("%Y-%m-%d %H:%M")
    try:
        t = int(v)
    except (TypeError, ValueError):
        return str(v or "")
    if t in (0, 9223372036854775807):
        return "never" if t else ""
    try:
        return (datetime.datetime(1601, 1, 1) + datetime.timedelta(seconds=t / 1e7)).strftime(
            "%Y-%m-%d %H:%M")
    except (OverflowError, OSError):
        return str(t)


def _s(v: Any) -> str:
    if isinstance(v, (list, tuple)):
        return "; ".join(str(x) for x in v)
    return "" if v is None else str(v)


def _maxpwdage_days(v: Any) -> str:
    try:
        t = abs(int(v))
        return "never" if t == 0 else str(round(t / 1e7 / 86400, 1))
    except (TypeError, ValueError):
        return ""


class Collector:
    """Opens ONE read-only bind and runs a battery of searches."""

    def __init__(self, dc: str, domain: str, username: str, password: str,
                 use_ssl: bool = False, port: int | None = None):
        self.dc = dc
        self.domain = domain
        self.base = "DC=" + ",DC=".join(domain.split("."))
        server = Server(dc, port=port, use_ssl=use_ssl, get_info=ALL)
        # read_only=True: ldap3 refuses add/modify/delete on this connection. NTLM bind as
        # DOMAIN\user. auto_bind raises on a bad bind rather than silently continuing.
        self.conn = Connection(
            server, user=f"{domain}\\{username}", password=password,
            authentication=NTLM, read_only=True, auto_bind=True)
        self.server = server
        self._users_cache: list[dict] | None = None
        self._computers_cache: list[dict] | None = None

    def close(self) -> None:
        try:
            self.conn.unbind()
        except Exception:  # noqa: BLE001
            pass

    # ---- generic paged search -----------------------------------------------------------------
    def _search(self, flt: str, attrs: list[str], base: str | None = None) -> list[dict]:
        self.conn.search(base or self.base, flt, search_scope=SUBTREE,
                         attributes=attrs, paged_size=500)
        out = []
        for e in self.conn.entries:
            d = {}
            for a in attrs:
                d[a] = e[a].value if a in e else None
            d["_dn"] = str(e.entry_dn)
            out.append(d)
        return out

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
        return [{
            "domain": self.domain,
            "domainSID": _s(g("objectSid")),
            "domainFunctionalLevel": _s(g("msDS-Behavior-Version")),
            "minPwdLength": _s(g("minPwdLength")),
            "maxPwdAgeDays": _maxpwdage_days(g("maxPwdAge")),
            "lockoutThreshold": _s(g("lockoutThreshold")),
            "lockoutDurationMin": (lambda x: abs(int(x)) // 10_000_000 // 60 if x else 0)(
                g("lockoutDuration")) if g("lockoutDuration") else "",
            "pwdHistoryLength": _s(g("pwdHistoryLength")),
            "machineAccountQuota": _s(g("ms-DS-MachineAccountQuota")),
            "forestFunctionalLevel": _s(getattr(rootdse, "other", {}).get(
                "forestFunctionality", [""])[0] if rootdse else ""),
            "namingContexts": _s(getattr(rootdse, "naming_contexts", "")),
        }]

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
                                   "operatingSystemVersion", "lastLogonTimestamp"])
        return [{
            "name": _s(r.get("name")),
            "dnsHostName": _s(r.get("dNSHostName")),
            "os": _s(r.get("operatingSystem")),
            "osVersion": _s(r.get("operatingSystemVersion")),
            "lastLogon": _ft(r.get("lastLogonTimestamp")),
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

    # ---- users (the big one) ------------------------------------------------------------------
    def users(self) -> list[dict]:
        if self._users_cache is not None:
            return self._users_cache
        attrs = ["sAMAccountName", "userPrincipalName", "userAccountControl", "adminCount",
                 "servicePrincipalName", "pwdLastSet", "lastLogonTimestamp", "whenCreated",
                 "memberOf", "description", "msDS-AllowedToDelegateTo"]
        raw = self._search("(&(objectCategory=person)(objectClass=user))", attrs)
        out = []
        for r in raw:
            uac = r.get("userAccountControl")
            spn = r.get("servicePrincipalName")
            out.append({
                "sAMAccountName": _s(r.get("sAMAccountName")),
                "userPrincipalName": _s(r.get("userPrincipalName")),
                "enabled": not _has(uac, "ACCOUNTDISABLE"),
                "adminCount": _s(r.get("adminCount")),
                "hasSPN": bool(spn),
                "spn": _s(spn),
                "asrepRoastable": _has(uac, "DONT_REQ_PREAUTH"),
                "pwdNotRequired": _has(uac, "PASSWD_NOTREQD"),
                "pwdNeverExpires": _has(uac, "DONT_EXPIRE_PASSWORD"),
                "unconstrainedDeleg": _has(uac, "TRUSTED_FOR_DELEGATION"),
                "constrainedDeleg": _s(r.get("msDS-AllowedToDelegateTo")),
                "pwdLastSet": _ft(r.get("pwdLastSet")),
                "lastLogon": _ft(r.get("lastLogonTimestamp")),
                "whenCreated": _s(r.get("whenCreated")),
                "description": _s(r.get("description")),
                "uacFlags": "; ".join(uac_flags(uac)),
                "_dn": r.get("_dn"),
            })
        self._users_cache = out
        return out

    def computers(self) -> list[dict]:
        if self._computers_cache is not None:
            return self._computers_cache
        attrs = ["name", "dNSHostName", "operatingSystem", "operatingSystemVersion",
                 "lastLogonTimestamp", "userAccountControl", "ms-Mcs-AdmPwd",
                 "msDS-AllowedToActOnBehalfOfOtherIdentity", "msDS-AllowedToDelegateTo"]
        raw = self._search("(objectClass=computer)", attrs)
        out = []
        for r in raw:
            uac = r.get("userAccountControl")
            out.append({
                "name": _s(r.get("name")),
                "dnsHostName": _s(r.get("dNSHostName")),
                "os": _s(r.get("operatingSystem")),
                "osVersion": _s(r.get("operatingSystemVersion")),
                "lastLogon": _ft(r.get("lastLogonTimestamp")),
                "enabled": not _has(uac, "ACCOUNTDISABLE"),
                "unconstrainedDeleg": _has(uac, "TRUSTED_FOR_DELEGATION"),
                "constrainedDeleg": _s(r.get("msDS-AllowedToDelegateTo")),
                "rbcd": bool(r.get("msDS-AllowedToActOnBehalfOfOtherIdentity")),
                "lapsReadable": bool(r.get("ms-Mcs-AdmPwd")),
                "_dn": r.get("_dn"),
            })
        self._computers_cache = out
        return out

    def groups(self) -> list[dict]:
        raw = self._search("(objectClass=group)", ["name", "member", "adminCount", "description"])
        out = []
        for r in raw:
            m = r.get("member") or []
            m = m if isinstance(m, list) else [m]
            out.append({
                "name": _s(r.get("name")),
                "memberCount": len(m),
                "adminCount": _s(r.get("adminCount")),
                "description": _s(r.get("description")),
                "_dn": r.get("_dn"),
            })
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
        return [{"subnet": _s(r.get("name")), "site": _s(r.get("siteObject")),
                 "description": _s(r.get("description"))} for r in rows]

    def group_members_all(self) -> list[dict]:
        """Every group -> every direct member (ADRecon's GroupMembers)."""
        self.conn.search(self.base, "(objectClass=group)", search_scope=SUBTREE,
                         attributes=["cn", "member"], paged_size=500)
        out = []
        for e in self.conn.entries:
            g = _s(e["cn"].value if "cn" in e else "")
            members = e["member"].value if "member" in e else []
            members = members if isinstance(members, list) else ([members] if members else [])
            for m in members:
                out.append({"group": g, "memberDN": _s(m)})
        return out

    def gpo_links(self) -> list[dict]:
        import re
        # GUID -> GPO display name
        self.conn.search(self.base, "(objectClass=groupPolicyContainer)", search_scope=SUBTREE,
                         attributes=["cn", "displayName"], paged_size=500)
        gmap = {}
        for e in self.conn.entries:
            cn = _s(e["cn"].value if "cn" in e else "").strip("{}").upper()
            gmap[cn] = _s(e["displayName"].value if "displayName" in e else "")
        rows = self._search("(|(objectClass=organizationalUnit)(objectClass=domainDNS))",
                            ["gPLink", "name"])
        out = []
        for r in rows:
            gpl = r.get("gPLink")
            if not gpl:
                continue
            for guid in re.findall(r"\{([0-9A-Fa-f-]{36})\}", str(gpl)):
                out.append({"linkedTo": _s(r.get("_dn")), "gpoName": gmap.get(guid.upper(), "(unknown)"),
                            "gpoGUID": guid})
        return out

    def dns_records(self) -> list[dict]:
        """AD-integrated DNS nodes (best-effort across the usual partitions)."""
        out, seen = [], set()
        bases = [f"CN=MicrosoftDNS,DC=DomainDnsZones,{self.base}",
                 f"CN=MicrosoftDNS,DC=ForestDnsZones,{self.base}",
                 f"CN=MicrosoftDNS,CN=System,{self.base}"]
        for b in bases:
            try:
                rows = self._search("(objectClass=dnsNode)", ["name", "dc"], base=b)
            except Exception:  # noqa: BLE001
                continue
            for r in rows:
                rec = _s(r.get("name") or r.get("dc"))
                zone = r.get("_dn", "").split(",DC=")[1].split(",")[0] if ",DC=" in r.get("_dn", "") else ""
                key = (zone, rec)
                if rec and key not in seen:
                    seen.add(key)
                    out.append({"zone": zone, "record": rec})
            if out:
                break
        return out[:10000]

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
