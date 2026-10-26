"""k1rby findings engine — the layer ADRecon doesn't have.

Takes the raw collected sections and derives SECURITY FINDINGS: severity-rated issues with the
exact affected objects, a remediation, and a MITRE ATT&CK mapping — plus an overall posture
score. This is the PingCastle/PurpleKnight-style analysis on top of the ADRecon-style inventory.
Every rule is pure analysis of already-collected read-only data (no extra queries).
"""

from __future__ import annotations

import datetime
from dataclasses import dataclass, field

SEV_ORDER = ["critical", "high", "medium", "low", "info"]
_SEV_WEIGHT = {"critical": 25, "high": 12, "medium": 5, "low": 1, "info": 0}
# Per-finding fraction of the *remaining* posture that a finding of each severity erodes. Used by
# posture_score's multiplicative model (see there). Chosen so a single critical lands ~78 and a
# badly-misconfigured domain trends toward the teens without ever flooring at 0.
_SEV_IMPACT = {"critical": 0.22, "high": 0.10, "medium": 0.04, "low": 0.01, "info": 0.0}


@dataclass
class Finding:
    id: str
    title: str
    severity: str
    category: str
    mitre: str
    remediation: str
    description: str
    affected: list = field(default_factory=list)

    @property
    def count(self) -> int:
        return len(self.affected)


# ---- helpers ----------------------------------------------------------------------------------
def _age_days(datestr: str) -> float | None:
    if not datestr or datestr in ("never", ""):
        return None
    for fmt in ("%Y-%m-%d %H:%M", "%Y-%m-%d"):
        try:
            d = datetime.datetime.strptime(str(datestr)[:16], fmt)
            return (datetime.datetime.now() - d).days
        except ValueError:
            continue
    return None


def _first(sections, name, default=None):
    rows = sections.get(name) or []
    return rows[0] if rows else (default or {})


# ---- rules: each returns the list of affected objects (empty = finding does not fire) ----------
def _r_krbtgt_old(s):
    for u in s.get("Users", []):
        if u.get("sAMAccountName", "").lower() == "krbtgt":
            age = _age_days(u.get("pwdLastSet"))
            if age and age > 180:
                return [{"account": "krbtgt", "pwdAgeDays": int(age)}]
    return []


def _r_mac_quota(s):
    q = _first(s, "Domain").get("machineAccountQuota")
    try:
        if q not in (None, "", "0") and int(q) > 0:
            return [{"ms-DS-MachineAccountQuota": q}]
    except (TypeError, ValueError):
        pass
    return []


def _r_kerberoast_priv(s):
    return [k for k in s.get("Kerberoastable", []) if str(k.get("adminCount")) == "1"]


def _r_kerberoast(s):
    return [k for k in s.get("Kerberoastable", []) if str(k.get("adminCount")) != "1"]


def _r_asrep_priv(s):
    return [a for a in s.get("AS-REP Roastable", []) if str(a.get("adminCount")) == "1"]


def _r_asrep(s):
    return [a for a in s.get("AS-REP Roastable", []) if str(a.get("adminCount")) != "1"]


def _r_unconstrained(s):
    dcs = {d.get("name", "").upper() for d in s.get("Domain Controllers", [])}
    out = []
    for d in s.get("Delegation", []):
        if "unconstrained" in str(d.get("delegation", "")) and d.get("object", "").upper().rstrip("$") not in dcs:
            out.append(d)
    return out


def _r_constrained(s):
    return [d for d in s.get("Delegation", []) if d.get("delegation") == "constrained"]


def _r_rbcd(s):
    return [d for d in s.get("Delegation", []) if "RBCD" in str(d.get("delegation", ""))]


def _r_pwd_not_req(s):
    return [{"account": u["sAMAccountName"]} for u in s.get("Users", [])
            if u.get("pwdNotRequired") and u.get("enabled")]


def _r_priv_never_expire(s):
    return [{"account": u.get("sAMAccountName")} for u in s.get("Privileged Users", [])
            if u.get("pwdNeverExpires")]


def _r_weak_policy(s):
    d = _first(s, "Domain")
    try:
        mpl = int(d.get("minPwdLength") or 0)
    except (TypeError, ValueError):
        return []
    if mpl and mpl < 12:
        return [{"minPwdLength": mpl, "recommended": "14+"}]
    return []


def _r_no_lockout(s):
    d = _first(s, "Domain")
    if str(d.get("lockoutThreshold")) == "0":
        return [{"lockoutThreshold": 0, "note": "accounts never lock — unlimited password guessing"}]
    return []


def _r_laps_readable(s):
    return s.get("LAPS", [])


def _r_stale_priv(s):
    out = []
    for u in s.get("Privileged Users", []):
        age = _age_days(u.get("lastLogon"))
        if u.get("enabled") and age is not None and age > 90:
            out.append({"account": u.get("sAMAccountName"), "lastLogonDays": int(age)})
    return out


def _r_eol_dc(s):
    eol = ("2000", "2003", "2008", "2012")
    return [{"dc": d.get("name"), "os": d.get("os")} for d in s.get("Domain Controllers", [])
            if any(y in str(d.get("os", "")) for y in eol)]


def _r_guest_enabled(s):
    return [{"account": u["sAMAccountName"]} for u in s.get("Users", [])
            if u.get("sAMAccountName", "").lower() == "guest" and u.get("enabled")]


def _r_old_pwd(s):
    out = []
    for u in s.get("Users", []):
        age = _age_days(u.get("pwdLastSet"))
        if u.get("enabled") and age is not None and age > 365:
            out.append({"account": u.get("sAMAccountName"), "pwdAgeDays": int(age)})
    return out[:500]


def _r_external_trusts(s):
    return [t for t in s.get("Trusts", []) if t.get("direction") in ("Bidirectional", "Outbound", "Inbound")]


def _r_schema_markers(s):
    markers = {"ms-mcs-admpwd": "LAPS (legacy)", "mslaps-password": "Windows LAPS",
               "mspki-certificate-templates": "AD CS", "ms-exch-schema-version-pt": "Exchange"}
    hits = []
    for r in s.get("Schema History", []):
        ln = str(r.get("ldapName", "")).lower()
        if ln in markers:
            hits.append({"feature": markers[ln], "schemaObject": r.get("name"),
                         "added": r.get("created")})
    return hits


def _r_anon_ldap(s):
    return [{"dSHeuristics": r.get("dSHeuristics")}
            for r in s.get("dSHeuristics", []) if r.get("anonymousAccess")]


# --- PurpleKnight-parity rules (derive from already-collected data) --------------------------
def _r_disabled_priv(s):
    return [{"account": u.get("sAMAccountName"), "description": u.get("description")}
            for u in s.get("Privileged Users", [])
            if u.get("enabled") is False and str(u.get("sAMAccountName", "")).lower() != "krbtgt"]


def _r_builtin_admin_oldpwd(s):
    out = []
    for u in s.get("Users", []):
        age = u.get("pwdAgeDays")
        if str(u.get("sid", "")).endswith("-500") and isinstance(age, int) and age > 180:
            out.append({"account": u.get("sAMAccountName"), "pwdAgeDays": age})
    return out


def _r_stale_computer(s):
    out = []
    for c in s.get("Computers", []):
        age = c.get("pwdAgeDays")
        if c.get("enabled") and isinstance(age, int) and age > 90:
            out.append({"computer": c.get("name"), "pwdAgeDays": age, "os": c.get("os")})
    return out


_EOL_OS = ("2000", "2003", "2008", "2012")


def _r_eol_computer(s):
    out = []
    for c in s.get("Computers", []):
        os_ = str(c.get("os", ""))
        if c.get("enabled") and any(y in os_ for y in _EOL_OS):
            out.append({"computer": c.get("name"), "os": os_})
    return out


def _r_priv_delegable(s):
    return [{"account": u.get("sAMAccountName")} for u in s.get("Users", [])
            if str(u.get("adminCount")) == "1" and u.get("enabled")
            and u.get("delegationPermitted") and str(u.get("sAMAccountName", "")).lower() != "krbtgt"]


def _r_spn_no_aes(s):
    return [{"account": u.get("sAMAccountName"), "spn": u.get("spn")} for u in s.get("Users", [])
            if u.get("hasSPN") and str(u.get("sAMAccountName", "")).lower() != "krbtgt"
            and not (u.get("kerberosAES128") or u.get("kerberosAES256"))]


def _r_schema_admins_nonempty(s):
    return [{"member": m.get("memberDN")} for m in s.get("Privileged Members", [])
            if str(m.get("group", "")).lower() == "schema admins"]


def _r_pwd_never_expires_all(s):
    return [{"account": u.get("sAMAccountName")} for u in s.get("Users", [])
            if u.get("enabled") and u.get("pwdNeverExpires")
            and str(u.get("sAMAccountName", "")).lower() != "krbtgt"]


def _effective_priv_dns(s):
    """DNs that are privileged via direct OR nested membership (transitive closure over the
    collected Group Members), so the orphan-adminCount rule doesn't false-positive on nested admins."""
    from collections import defaultdict
    priv = {"domain admins", "enterprise admins", "schema admins", "administrators",
            "account operators", "backup operators", "server operators", "print operators",
            "dnsadmins"}
    by_group = defaultdict(list)
    for r in s.get("Group Members", []):
        by_group[str(r.get("group", "")).lower()].append(r)
    seen, frontier, dns = set(), set(priv), set()
    while frontier:
        g = frontier.pop()
        if g in seen:
            continue
        seen.add(g)
        for r in by_group.get(g, []):
            dn = str(r.get("memberDN", "")).lower()
            dns.add(dn)
            if str(r.get("accountType", "")).lower().startswith("group"):
                cn = dn.split(",", 1)[0]
                if cn.startswith("cn="):
                    frontier.add(cn[3:])
    return dns


def _r_dc_weak_enc(s):
    dcnames = {str(d.get("name", "")).lower() for d in s.get("Domain Controllers", [])}
    out = []
    for c in s.get("Computers", []):
        if str(c.get("name", "")).lower() in dcnames and (c.get("kerberosRC4") or c.get("kerberosDESOnly")):
            out.append({"dc": c.get("name"), "rc4": bool(c.get("kerberosRC4")),
                        "desOnly": bool(c.get("kerberosDESOnly"))})
    return out


def _r_orphan_admincount(s):
    eff = _effective_priv_dns(s)
    out = []
    for u in s.get("Users", []):
        if str(u.get("adminCount")) != "1" or str(u.get("sAMAccountName", "")).lower() == "krbtgt":
            continue
        if str(u.get("sid", "")).endswith("-500"):
            continue
        dn = str(u.get("distinguishedName", "")).lower()
        if dn and dn not in eff:
            out.append({"account": u.get("sAMAccountName"), "dn": u.get("distinguishedName")})
    return out


# --- ACL rights analysis (consumes the off-host-decoded DACLs in the "ACLs (raw)" section) -----
_PRIV_GROUP_NAMES = {"domain admins", "enterprise admins", "schema admins", "administrators",
                     "account operators", "backup operators", "server operators",
                     "print operators", "dnsadmins", "key admins", "enterprise key admins",
                     "group policy creator owners", "cert publishers"}


def _sid_name_map(s):
    """SID -> (name, kind) over everything collected, so ACE holder SIDs resolve to principals."""
    m = {}
    for u in s.get("Users", []):
        if u.get("sid"):
            m[str(u["sid"])] = (u.get("sAMAccountName"), "user")
    for g in s.get("Groups", []):
        if g.get("sid"):
            m[str(g["sid"])] = (g.get("name"), "group")
    for c in s.get("Computers", []):
        if c.get("sid"):
            m[str(c["sid"])] = (c.get("name"), "computer")
    for f in s.get("Foreign Security Principals", []):
        if f.get("sid"):
            m[str(f["sid"])] = (f.get("name"), "foreign")
    return m


def _is_default_holder(sid, name):
    """True for principals whose broad control over objects is expected (built-in admin SIDs /
    the standard privileged RIDs), so they aren't reported as anomalous ACL grants."""
    from . import sddl
    if sid in sddl.WELLKNOWN_EXPECTED:
        return True
    rid = sddl.rid_of(sid or "")
    if rid in sddl.EXPECTED_RIDS:
        return True
    return str(name or "").lower() in {"domain admins", "enterprise admins", "schema admins",
                                       "administrators", "domain controllers",
                                       "enterprise domain controllers", "administrator"}


def _sensitive_dns(s):
    """DNs of objects whose compromise = privilege: privileged groups themselves, any adminCount=1
    user/group, and every principal that is privileged by direct or nested membership."""
    out = set(_effective_priv_dns(s))
    for g in s.get("Groups", []):
        dn = str(g.get("_dn") or g.get("distinguishedName") or "").lower()
        if dn and (str(g.get("name", "")).lower() in _PRIV_GROUP_NAMES
                   or str(g.get("adminCount")) == "1"):
            out.add(dn)
    for u in s.get("Users", []):
        if str(u.get("adminCount")) == "1":
            dn = str(u.get("distinguishedName", "")).lower()
            if dn:
                out.add(dn)
    return out


def _dn_is_domain_head(dn):
    parts = [p for p in str(dn).split(",") if p.strip()]
    return bool(parts) and all(p.strip().upper().startswith("DC=") for p in parts)


def _r_acl_dcsync(s):
    """Non-default principals holding DCSync rights on the domain head (DS-Replication-Get-Changes
    + ...-All, or GenericAll). Needs the domain-root SD (captured as kind='domain')."""
    from . import sddl
    names = _sid_name_map(s)
    out = []
    for row in s.get("ACLs (raw)", []):
        if not (row.get("kind") == "domain" or _dn_is_domain_head(row.get("dn", ""))):
            continue
        # aggregate replication rights per holder across that object's ACEs
        repl = {}
        for ace in row.get("_dangerous", []):
            sid = ace.get("sid")
            if _is_default_holder(sid, names.get(sid, (None,))[0]):
                continue
            rname = ace.get("objectRightName", "")
            flagset = repl.setdefault(sid, {"gaa": False, "getchanges": set(), "generic": False})
            if "GenericAll" in ace.get("rights", []):
                flagset["generic"] = True
            if ace.get("objectType") in sddl.DCSYNC_GUIDS:
                flagset["getchanges"].add(ace.get("objectType"))
        for sid, f in repl.items():
            has_dcsync = f["generic"] or (f["getchanges"] >= sddl.DCSYNC_GUIDS)
            if has_dcsync:
                nm, kind = names.get(sid, (sid, "?"))
                out.append({"principal": nm or sid, "sid": sid, "kind": kind,
                            "via": "GenericAll" if f["generic"] else "DS-Replication-Get-Changes(+All)"})
    return out


def _r_acl_adminsdholder(s):
    """Non-default principals with takeover rights on AdminSDHolder (its ACL is stamped onto every
    protected account by SDProp, so control here = persistent control of all admins)."""
    names = _sid_name_map(s)
    out = []
    for row in s.get("ACLs (raw)", []):
        if not (row.get("kind") == "adminsdholder"
                or str(row.get("dn", "")).lower().startswith("cn=adminsdholder,")):
            continue
        for ace in row.get("_dangerous", []):
            sid = ace.get("sid")
            nm = names.get(sid, (None,))[0]
            if _is_default_holder(sid, nm):
                continue
            out.append({"principal": nm or sid, "sid": sid, "rights": ", ".join(ace.get("rights", []))})
    return out


def _r_acl_priv_object(s):
    """Non-default principals holding takeover rights (GenericAll/WriteDacl/WriteOwner/GenericWrite/
    unscoped WriteProperty / force-password-reset) over a privileged object (a protected group,
    an admin account, or any nested-privileged principal)."""
    names = _sid_name_map(s)
    sens = _sensitive_dns(s)
    out = []
    seen = set()
    for row in s.get("ACLs (raw)", []):
        dn = str(row.get("dn", "")).lower()
        if dn not in sens:
            continue
        for ace in row.get("_dangerous", []):
            sid = ace.get("sid")
            nm = names.get(sid, (None,))[0]
            if _is_default_holder(sid, nm):
                continue
            rights = ace.get("rights", [])
            # on a privileged object even force-password-reset counts; dedupe principal->object
            key = (sid, dn)
            if key in seen:
                continue
            seen.add(key)
            out.append({"principal": nm or sid, "kind": names.get(sid, (None, "?"))[1],
                        "overObject": row.get("object"), "rights": ", ".join(rights)})
    return out[:500]


_RULES = [
    ("AD-001", "KRBTGT password not rotated (>180 days)", "critical", "Kerberos",
     "T1558.001 (Golden Ticket)",
     "Reset the krbtgt password TWICE (with a wait between) to invalidate forged tickets.",
     "A stale krbtgt password lets an attacker who ever obtained its hash forge Golden Tickets indefinitely.",
     _r_krbtgt_old),
    ("AD-002", "Unconstrained delegation on a non-DC", "critical", "Delegation",
     "T1558.003 / T1134",
     "Remove TRUSTED_FOR_DELEGATION; use constrained/RBCD, and add admins to Protected Users.",
     "A host with unconstrained delegation can capture and reuse any user's TGT (incl. DAs) that authenticates to it.",
     _r_unconstrained),
    ("AD-003", "Privileged account is Kerberoastable (has SPN)", "critical", "Kerberos",
     "T1558.003 (Kerberoasting)",
     "Use group-managed service accounts (gMSA) or 25+ char passwords; remove SPNs from admin accounts.",
     "An admin account with an SPN can be Kerberoasted and cracked offline -> direct path to privilege.",
     _r_kerberoast_priv),
    ("AD-004", "Domain controller on an end-of-life OS", "critical", "Infrastructure",
     "T1210",
     "Upgrade DCs to a supported Windows Server release and decommission EOL hosts.",
     "An unsupported DC receives no security patches (e.g. Zerologon-class bugs) and anchors the whole domain.",
     _r_eol_dc),
    ("AD-005", "Privileged account is AS-REP roastable", "critical", "Kerberos",
     "T1558.004 (AS-REP Roasting)",
     "Enable Kerberos pre-authentication (clear DONT_REQ_PREAUTH) on privileged accounts.",
     "An admin without pre-auth yields a crackable AS-REP to any unauthenticated attacker.",
     _r_asrep_priv),
    ("AD-006", "Machine account quota allows any user to add computers", "high", "Configuration",
     "T1136.001 / RBCD",
     "Set ms-DS-MachineAccountQuota to 0 and delegate computer-join to a dedicated group.",
     "With quota > 0, any authenticated user can create computer accounts, enabling RBCD and other attacks.",
     _r_mac_quota),
    ("AD-007", "AS-REP roastable accounts", "high", "Kerberos", "T1558.004",
     "Enable Kerberos pre-authentication on these accounts.",
     "Accounts without pre-auth yield offline-crackable AS-REP hashes.",
     _r_asrep),
    ("AD-008", "Kerberoastable service accounts", "high", "Kerberos", "T1558.003",
     "Move to gMSA or long random passwords; rotate regularly.",
     "SPN accounts can be Kerberoasted; weak passwords crack quickly.",
     _r_kerberoast),
    ("AD-009", "Accounts with 'password not required'", "high", "Accounts", "T1078",
     "Remove the PASSWD_NOTREQD flag and enforce the password policy on these accounts.",
     "These accounts can have empty/weak passwords regardless of policy.",
     _r_pwd_not_req),
    ("AD-010", "No account-lockout policy", "high", "Policy", "T1110",
     "Set a lockout threshold (e.g. 5-10) with a reasonable duration.",
     "Without lockout, online password guessing/spraying is unlimited.",
     _r_no_lockout),
    ("AD-011", "Weak domain minimum password length", "high", "Policy", "T1110",
     "Raise minimum length to 14+ and consider a passphrase/fine-grained policy.",
     "Short minimums make offline and online guessing far easier.",
     _r_weak_policy),
    ("AD-012", "Local-admin (LAPS) passwords readable by this account", "high", "Credentials",
     "T1552.006",
     "Scope ms-Mcs-AdmPwd / Windows LAPS read rights to admins only.",
     "If a non-admin can read LAPS passwords, local-admin creds are exposed broadly.",
     _r_laps_readable),
    ("AD-013", "Constrained delegation configured", "medium", "Delegation", "T1558.003",
     "Review each constrained-delegation target; remove where not required; prefer RBCD.",
     "Constrained delegation can be abused to impersonate users to the target service.",
     _r_constrained),
    ("AD-014", "Resource-based constrained delegation (RBCD) present", "medium", "Delegation",
     "T1134.001",
     "Audit msDS-AllowedToActOnBehalfOfOtherIdentity on these objects.",
     "RBCD entries can be an attacker-planted privilege-escalation path.",
     _r_rbcd),
    ("AD-015", "Privileged accounts with non-expiring passwords", "medium", "Accounts", "T1078",
     "Remove DONT_EXPIRE_PASSWORD on admin accounts; rotate regularly.",
     "Non-expiring admin passwords increase the window for credential compromise.",
     _r_priv_never_expire),
    ("AD-016", "Stale but enabled privileged accounts (>90d no logon)", "medium", "Accounts",
     "T1078",
     "Disable or review privileged accounts that are no longer in use.",
     "Unused admin accounts are prime, low-noise targets.",
     _r_stale_priv),
    ("AD-017", "User accounts with very old passwords (>1 year)", "medium", "Accounts", "T1110",
     "Enforce password rotation; investigate accounts that never rotate.",
     "Old passwords are more likely cracked/leaked and never re-secured.",
     _r_old_pwd),
    ("AD-018", "Guest account enabled", "low", "Accounts", "T1078.001",
     "Disable the built-in Guest account.",
     "An enabled Guest account is an unnecessary anonymous-ish foothold.",
     _r_guest_enabled),
    ("AD-019", "Active domain/forest trusts", "info", "Trusts", "T1482",
     "Review trust direction/type; ensure SID filtering on external trusts.",
     "Trusts expand the attack surface across security boundaries.",
     _r_external_trusts),
    ("AD-020", "Security-relevant schema extensions present", "info", "Infrastructure",
     "T1087",
     "Confirm LAPS/AD CS/Exchange are configured and access-scoped; an empty LAPS sheet with the "
     "LAPS schema present confirms read access is correctly privilege-gated (not that LAPS is absent).",
     "Schema extensions reveal deployed features (LAPS, AD CS, Exchange) worth auditing/targeting.",
     _r_schema_markers),
    ("AD-021", "Anonymous LDAP access enabled (dSHeuristics)", "high", "Configuration",
     "T1087",
     "Clear the 7th character of dSHeuristics (set it to 0) to disable anonymous LDAP binds/reads.",
     "Anonymous LDAP lets an unauthenticated client enumerate directory objects, exposing recon "
     "data without any credential.",
     _r_anon_ldap),
    ("AD-022", "Disabled account still flagged privileged (adminCount=1)", "low", "Accounts",
     "T1078",
     "Remove the disabled account from privileged groups and clear residual adminCount if stale.",
     "A disabled account retaining privileged-group residue can be re-enabled as a quiet path back "
     "to privilege.",
     _r_disabled_priv),
    ("AD-023", "Built-in Administrator password not rotated (>180 days)", "medium", "Accounts",
     "T1078.001",
     "Rotate the built-in Administrator (RID-500) password and restrict its use.",
     "The RID-500 account cannot be locked out and is a prime offline/brute target; a stale "
     "password widens that window.",
     _r_builtin_admin_oldpwd),
    ("AD-024", "Stale computer account (password unchanged >90 days)", "low", "Accounts",
     "T1078",
     "Disable and remove computer accounts that are no longer active (machine pwd auto-rotates ~30d).",
     "A computer whose password has not changed in >90 days is likely orphaned/offline and is an "
     "unmonitored account.",
     _r_stale_computer),
    ("AD-025", "Computer on an end-of-life operating system", "medium", "Infrastructure",
     "T1210",
     "Decommission or upgrade member hosts on unsupported Windows versions.",
     "EOL hosts receive no security patches and are reliable lateral-movement footholds.",
     _r_eol_computer),
    ("AD-026", "Privileged account can be delegated", "medium", "Delegation",
     "T1550",
     "Mark privileged accounts 'sensitive and cannot be delegated' (or add them to Protected Users).",
     "A privileged account that may be delegated can have its credentials captured and reused via a "
     "delegation-enabled host.",
     _r_priv_delegable),
    ("AD-027", "Service account (SPN) without AES Kerberos encryption", "medium", "Kerberos",
     "T1558.003 (Kerberoasting)",
     "Enable AES on the account (clear RC4-only) so its service tickets aren't RC4-crackable.",
     "An SPN account without AES yields RC4 service tickets that are far faster to crack offline.",
     _r_spn_no_aes),
    ("AD-028", "Schema Admins group is not empty", "high", "Accounts",
     "T1078.002",
     "Keep Schema Admins empty except during a planned, temporary schema change.",
     "Schema Admins can alter the forest schema (a forest-wide, hard-to-reverse change); standing "
     "membership is unnecessary risk.",
     _r_schema_admins_nonempty),
    ("AD-029", "Accounts configured with non-expiring passwords", "info", "Accounts",
     "T1078",
     "Remove DONT_EXPIRE_PASSWORD except for vetted service accounts (prefer gMSA).",
     "Passwords that never expire persist indefinitely if ever exposed.",
     _r_pwd_never_expires_all),
    ("AD-030", "Non-privileged account carries adminCount=1 (AdminSDHolder residue)", "low",
     "Accounts", "T1098",
     "Clear adminCount and re-enable inheritance on accounts no longer in a protected group.",
     "adminCount=1 on an account that is no longer (directly or via nesting) in a protected group "
     "leaves AdminSDHolder-tightened ACLs and signals past/stale privilege worth reviewing.",
     _r_orphan_admincount),
    ("AD-031", "Domain controller allows RC4/DES Kerberos encryption", "high", "Kerberos",
     "T1558",
     "Set msDS-SupportedEncryptionTypes on DCs to AES-only (clear RC4/DES) once all clients support AES.",
     "A DC that still accepts RC4/DES issues weak tickets that accelerate Kerberoasting/offline "
     "cracking against the domain.",
     _r_dc_weak_enc),
    ("AD-032", "DCSync rights held by a non-default principal", "critical", "ACL / Permissions",
     "T1003.006 (DCSync)",
     "Remove DS-Replication-Get-Changes / -All (and any GenericAll) on the domain head from every "
     "principal except Domain Controllers, Domain/Enterprise Admins and Administrators.",
     "A principal with both replication rights (or GenericAll) on the domain object can DCSync every "
     "account's hash, including krbtgt -> full domain compromise from a single delegated ACL.",
     _r_acl_dcsync),
    ("AD-033", "Dangerous rights on AdminSDHolder", "critical", "ACL / Permissions",
     "T1098 / T1222",
     "Remove GenericAll/WriteDacl/WriteOwner/GenericWrite on CN=AdminSDHolder from non-default "
     "principals; SDProp re-stamps this ACL onto every protected account hourly.",
     "AdminSDHolder's ACL is propagated to all protected (adminCount=1) accounts by SDProp, so "
     "takeover rights here are persistent, self-healing control over every privileged account.",
     _r_acl_adminsdholder),
    ("AD-034", "Non-default principal has control over a privileged object", "high",
     "ACL / Permissions", "T1098 (Account Manipulation)",
     "Audit and remove GenericAll/WriteDacl/WriteOwner/GenericWrite (and force-password-reset) held "
     "by non-default principals over protected groups and admin accounts.",
     "A non-default principal with takeover rights over a privileged group or admin account can add "
     "itself, reset the password, or rewrite the ACL to escalate to that privilege.",
     _r_acl_priv_object),
]


def analyze(sections: dict) -> list[Finding]:
    out = []
    for fid, title, sev, cat, mitre, rem, desc, check in _RULES:
        try:
            affected = check(sections) or []
        except Exception:  # noqa: BLE001
            affected = []
        if affected:
            out.append(Finding(fid, title, sev, cat, mitre, rem, desc, affected))
    out.sort(key=lambda f: (SEV_ORDER.index(f.severity), -f.count))
    return out


def posture_score(findings: list[Finding]) -> int:
    """100 = clean. Multiplicative 'defense-erosion' model: each finding removes a fraction of the
    *remaining* posture, so impact compounds but saturates — ten mediums never equal a wall of
    criticals, and the score trends toward (but never reaches) 0 as issues pile up rather than
    flooring there the moment a few serious findings fire. A finding that hits many objects erodes
    slightly more (saturating at +50%). Score = 100 * product(1 - impact_i)."""
    remaining = 1.0
    for f in findings:
        p = _SEV_IMPACT.get(f.severity, 0.0)
        if not p:
            continue
        scale = 1.0 + min(0.5, (f.count - 1) * 0.02) if f.count else 1.0
        remaining *= (1.0 - min(0.95, p * scale))
    return max(0, round(100 * remaining))


def severity_counts(findings: list[Finding]) -> dict:
    c = {s: 0 for s in SEV_ORDER}
    for f in findings:
        c[f.severity] += 1
    return c
